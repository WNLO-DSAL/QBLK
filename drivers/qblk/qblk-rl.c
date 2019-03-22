#include "qblk.h"

int qblk_rl_high_thrs(struct qblk_per_chnl_rl *rl)
{
	return rl->high;
}

unsigned long qblk_rl_nr_free_blks(struct qblk_per_chnl_rl *rl)
{
	return atomic_read(&rl->free_blocks);
}


static void qblk_rl_kick_u_timer(struct qblk_rl *rl)
{
	mod_timer(&rl->u_timer, jiffies + msecs_to_jiffies(5000));
}

void qblk_rl_inserted(struct qblk_rl *rl, int nr_entries)
{
	int rb_space = atomic_read(&rl->rb_space);

	if (unlikely(rb_space >= 0))
		atomic_sub(nr_entries, &rl->rb_space);
}

void qblk_rl_user_in(struct qblk_rl *rl, int nr_entries)
{
	atomic_add(nr_entries, &rl->rb_user_cnt);

	/* Release user I/O state. Protect from GC */
	smp_store_release(&rl->rb_user_active, 1);
	qblk_rl_kick_u_timer(rl);
}

void qblk_rl_gc_in(struct qblk_rl *rl, int nr_entries)
{
	atomic_add(nr_entries, &rl->rb_gc_cnt);
}


void qblk_rl_out(struct qblk_rl *rl,
					int nr_user, int nr_gc)
{
	atomic_sub(nr_user, &rl->rb_user_cnt);
	atomic_sub(nr_gc, &rl->rb_gc_cnt);
}


int qblk_rl_gc_maynot_insert(struct qblk_rl *rl,
					struct qblk_per_chnl_rl *pch_rl, int nr_entries)
{
	int rb_gc_cnt = atomic_read(&rl->rb_gc_cnt);
	int rb_user_active, rb_gc_max;

	/* If there is no user I/O let GC take over space on the write buffer */
	rb_user_active = READ_ONCE(rl->rb_user_active);
	rb_gc_max = atomic_read(&pch_rl->rb_gc_max);

	//pr_notice("%s, rb_gc_cnt[%d] rb_gc_max[%d] rb_user_active[%d]",
	//			__func__, rb_gc_cnt, rb_gc_max, rb_user_active);

	return rb_gc_cnt >= rb_gc_max && rb_user_active;
}



/* We can insert if we're under the global rb_user_max limit */
blk_status_t qblk_rl_user_may_insert(struct qblk *qblk, int nr_entries)
{
	struct qblk_rl *rl = &qblk->rl;

	/* If gc is not running, we can't limit the rate of user */
	if (qblk_gc_is_stopped(qblk))
		return BLK_STS_OK;
	if (atomic_read(&rl->rb_user_cnt) >= atomic_read(&rl->rb_user_max)) {
		//pr_err("%s, return busy[%d][%d]\n", __func__,
		//	atomic_read(&rl->rb_user_cnt),
		//	atomic_read(&rl->rb_user_max));
		return BLK_STS_RESOURCE;
	}
	//pr_notice("%s, return OK[%d][%d]\n",
	//		__func__,
	//		atomic_read(&rl->rb_user_cnt),
	//		atomic_read(&rl->rb_user_max));
	return BLK_STS_OK;
}

unsigned long qblk_rl_nr_user_free_blks(struct qblk_per_chnl_rl *rl)
{
	return atomic_read(&rl->free_user_blocks);
}


/*
 * When we start GC in a chnl, we may want to restrict userIO so that
 * we can have enough ring buffer space for GC.
 * This is achieved through global rate limiter(struct qblk_rl).
 * However, we manage gc in a per-channel manner. That is to say,
 * there is a possibility where channel A starts GC while channel B
 * doesn't. So, the idea is to give each channel a rate
 * limit budget(qblk_rl->per_chnl_limit).
 * Each channel can restrict a portion of the global rate limiter.
 *
 * Under current implementation, we don't restrict userIO when
 * a channel is under gc mid mode.
 * This is configurable.
 * Another option is to use part of per-channel rate limiter budget
 * when a channel is under GC mid mode and to use all the budget
 * when under GC low mode.
 * Be cautious when switching to this option, we should avoid limiting
 * the GC group in qblk_gc_run(). Otherwise, we may meet a gc deadlock
 * situation described below:
 * A channel switch from high mode to mid mode while others remain in
 * high mode. This channel restricts a small portion of user IO. However,
 * this channel doesn't issue GC IO because all of it's lines are in
 * chi->gc_low_list. Thus, userIO can't write to ringBuffer due to
 * the global rate limiter and no channel generates GC IO. It's a deadlock.
 */
static void qblk_rl_mid_to_high(struct qblk_per_chnl_rl *rl, struct qblk_rl *qblk_rl)
{
	//atomic_add(qblk_rl->per_chnl_limit, &qblk_rl->rb_user_max);
	atomic_set(&rl->rb_gc_max, 0);
	rl->chnl_state = QBLK_RL_HIGH;
	/*pr_notice("%s, rb_gc_max[%d] rb_user_max[%d]\n",
		__func__, atomic_read(&rl->rb_gc_max),
		atomic_read(&qblk_rl->rb_user_max));*/
	qblk_gc_should_stop(rl);
}

static void qblk_rl_high_to_mid(struct qblk_per_chnl_rl *rl, struct qblk_rl *qblk_rl)
{
	//atomic_sub(qblk_rl->per_chnl_limit, &qblk_rl->rb_user_max);
	atomic_set(&rl->rb_gc_max, qblk_rl->per_chnl_limit);
	rl->chnl_state = QBLK_RL_MID;
	/*pr_notice("%s, rb_gc_max[%d] rb_user_max[%d]\n",
		__func__, atomic_read(&rl->rb_gc_max),
		atomic_read(&qblk_rl->rb_user_max));*/
	qblk_gc_should_start(rl);
}

static void qblk_rl_low_to_mid(struct qblk_per_chnl_rl *rl, struct qblk_rl *qblk_rl)
{
	atomic_add(qblk_rl->per_chnl_limit << 1, &qblk_rl->rb_user_max);
	atomic_set(&rl->rb_gc_max, qblk_rl->per_chnl_limit);
	/*pr_notice("%s, rb_gc_max[%d] rb_user_max[%d]\n",
		__func__, atomic_read(&rl->rb_gc_max),
		atomic_read(&qblk_rl->rb_user_max));*/
	rl->chnl_state = QBLK_RL_MID;
}

static void qblk_rl_mid_to_low(struct qblk_per_chnl_rl *rl, struct qblk_rl *qblk_rl)
{
	atomic_sub(qblk_rl->per_chnl_limit << 1, &qblk_rl->rb_user_max);
	atomic_add(qblk_rl->per_chnl_limit, &rl->rb_gc_max);
	/*pr_notice("%s, rb_gc_max[%d] rb_user_max[%d]\n",
		__func__, atomic_read(&rl->rb_gc_max),
		atomic_read(&qblk_rl->rb_user_max));*/
	rl->chnl_state = QBLK_RL_LOW;
}


static void __qblk_rl_update_rates(struct qblk_per_chnl_rl *rl,
				   unsigned long free_blocks)
{
	struct qblk *qblk = rl->qblk;
	struct qblk_rl *qblk_rl = &qblk->rl;
	int current_state = rl->chnl_state;

	switch (current_state) {
	case QBLK_RL_HIGH:
		if (free_blocks < rl->high) {
			qblk_rl_high_to_mid(rl, qblk_rl);
			if (free_blocks <= rl->rsv_blocks)
				qblk_rl_mid_to_low(rl, qblk_rl);
		}
		break;
	case QBLK_RL_MID:
		if (free_blocks > rl->very_high)
			qblk_rl_mid_to_high(rl, qblk_rl);
		else if (free_blocks <= rl->rsv_blocks)
			qblk_rl_mid_to_low(rl, qblk_rl);
		break;
	case QBLK_RL_LOW:
		if (free_blocks > rl->mid_blocks) {
			qblk_rl_low_to_mid(rl, qblk_rl);
			if (free_blocks > rl->very_high)
				qblk_rl_mid_to_high(rl, qblk_rl);
		}
		break;
	}
}


void qblk_rl_update_rates(struct qblk_per_chnl_rl *rl)
{
	__qblk_rl_update_rates(rl, qblk_rl_nr_user_free_blks(rl));
}

void qblk_rl_free_lines_inc(struct qblk_per_chnl_rl *rl, struct qblk_line *line)
{
	int blk_in_line = atomic_read(&line->blk_in_line);
	int free_blocks;

	atomic_add(blk_in_line, &rl->free_blocks);
	free_blocks = atomic_add_return(blk_in_line, &rl->free_user_blocks);

	/* FIXME: If we close a line without writing
	 * all its data sectors, this calculation may be wrong?
	 */
	spin_lock(&rl->remain_secs_lock);
	rl->remain_secs += line->data_secs_in_line;
	//pr_notice("%s, remain_secs=%u, data_secs_in_line=%u\n",
	//	__func__, rl->remain_secs, line->data_secs_in_line);
	spin_unlock(&rl->remain_secs_lock);

	__qblk_rl_update_rates(rl, free_blocks);
}

void qblk_rl_free_lines_dec(struct qblk_per_chnl_rl *rl, struct qblk_line *line,
			    bool used)
{
	int blk_in_line = atomic_read(&line->blk_in_line);
	int free_blocks;

	atomic_sub(blk_in_line, &rl->free_blocks);

	if (used)
		free_blocks = atomic_sub_return(blk_in_line,
							&rl->free_user_blocks);
	else
		free_blocks = atomic_read(&rl->free_user_blocks);

	__qblk_rl_update_rates(rl, free_blocks);
}

static void qblk_rl_u_timer(struct timer_list *t)
{
	struct qblk_rl *rl = from_timer(rl, t, u_timer);

	/* Release user I/O state. Protect from GC */
	smp_store_release(&rl->rb_user_active, 0);
}


void qblk_rl_free(struct qblk_rl *rl)
{
	del_timer(&rl->u_timer);
}

int qblk_rl_init(struct qblk_rl *rl, int budget)
{
	struct qblk *qblk = container_of(rl, struct qblk, rl);
	int nr_chnls = qblk->nr_channels;
	int chnl_pw = get_count_order(nr_chnls);
	int budget_pw = get_count_order(budget);
	int per_ch_limit_pw;

	per_ch_limit_pw = budget_pw - chnl_pw -1;
	rl->per_chnl_limit = 1 << per_ch_limit_pw;

	/* To start with, all buffer is available to user I/O writers */
	atomic_set(&rl->rb_user_max, budget);
	atomic_set(&rl->rb_user_cnt, 0);
	
	atomic_set(&rl->rb_gc_cnt, 0);
	atomic_set(&rl->rb_space, -1);

	rl->rb_user_active = 0;

	timer_setup(&rl->u_timer, qblk_rl_u_timer, 0);

	pr_notice("%s, budgetpw=%d, chnlpw=%d, per_chnl_limit=%d\n",
					__func__, budget_pw,
					chnl_pw, rl->per_chnl_limit);

	return 0;
}

void qblk_per_chnl_rl_free(struct qblk_per_chnl_rl *rl)
{
}


/*
 * Calculate the per-channel rate limiter.
 */
void qblk_per_chnl_rl_init(struct qblk *qblk,
			struct ch_info *chi, struct qblk_per_chnl_rl *rl,
			int nr_free_blks)
{
	struct nvm_geo *geo = &qblk->dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	sector_t provisioned;
	int k;
	unsigned op_blks;

	rl->qblk = qblk;
	rl->chnl = chi->ch_index;
	

	provisioned = nr_free_blks;
	provisioned *= (100 - qblk->op);
	sector_div(provisioned, 100);

	op_blks = nr_free_blks - provisioned;
	qblk->rl.total_blocks += nr_free_blks;

	rl->rsv_blocks = meta->blk_per_chline * QBLK_GC_RSV_LINE;
	rl->mid_blocks = rl->rsv_blocks + meta->blk_per_chline * QBLK_GC_THRES_INTERVAL;
	for (k=0;;k++)
		if(op_blks + k * meta->blk_per_chline
				> rl->mid_blocks + meta->blk_per_chline)
			break;
	rl->high = op_blks + k * meta->blk_per_chline;
	rl->high_pw = get_count_order(rl->high);
	rl->very_high = rl->high + meta->blk_per_chline * QBLK_GC_THRES_INTERVAL;

	atomic_set(&rl->free_blocks, nr_free_blks);
	atomic_set(&rl->free_user_blocks, nr_free_blks);
	rl->chnl_state = QBLK_RL_HIGH;
	atomic_set(&rl->rb_gc_max, 0);

	/*
	 * rl->remain_secs holds the number
	 * of budget of free data sectors in this chnl.
	 * Since we need to maintain a data line and a
	 * data_next line for each channel, we should avoid
	 * fullfilling every sector in this channel.
	 * Instead, when we can't find another free line
	 * for data_next, we stop filling data into this channel.
	 */
	/* FIXME:
	 * If there are lots of bad blocks,
	 * this calculation may be incorrect?
	 */
	rl->remain_secs =
		nr_free_blks * geo->sec_per_chk
		- meta->sec_per_chline
		- (meta->smeta_sec + meta->emeta_sec[0])
			* (chi->nr_lines - 1);
	spin_lock_init(&rl->remain_secs_lock);

	if (chi->ch_index == 0)
		pr_notice("%s, remain_secs=%u\n", __func__, rl->remain_secs);

	if (chi->ch_index == 0)
		pr_notice("%s, ch[%d] veryhigh=%d,high=%d,mid=%d,rsv=%d\n",
					__func__, chi->ch_index,
					rl->very_high, rl->high,
					rl->mid_blocks, rl->rsv_blocks);

}


/*
 * Find out whether this channel has enough budget
 * for the drainning request.
 * If so, reserve enough space and return 0;
 * Otherwise, return -ENOSPC
 *
 * This function may be called by difference threads.
 */
int qblk_channel_may_writeback(struct qblk *qblk,
					struct ch_info *chi,
					unsigned int nr_sec_required)
{
	struct qblk_per_chnl_rl *rl = &chi->per_ch_rl;

	spin_lock(&rl->remain_secs_lock);
 	if (rl->remain_secs >= nr_sec_required) {
 		rl->remain_secs -= nr_sec_required;
		//pr_notice("%s, remain_secs=%u, nr_sec_required=%u\n",
		//		__func__, rl->remain_secs, nr_sec_required);
		spin_unlock(&rl->remain_secs_lock);
		return 0;
 	} else {
		spin_unlock(&rl->remain_secs_lock);
		return -ENOSPC;
 	}
}

