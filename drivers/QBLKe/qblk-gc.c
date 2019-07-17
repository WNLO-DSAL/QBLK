#include "qblk.h"
#include <linux/delay.h>

int qblk_gc_is_activated(struct qblk *qblk)
{
	return !bitmap_empty(qblk->gc_active, qblk->gc_active_size);
}

int qblk_gc_is_stopped(struct qblk *qblk)
{	
	return bitmap_empty(qblk->gc_active, qblk->gc_active_size);
}


static int qblk_perch_gc_activated(struct qblk *qblk, int chnl)
{
	int ret;

	spin_lock(&qblk->gc_active_lock);
	ret = test_bit(chnl, qblk->gc_active);
	spin_unlock(&qblk->gc_active_lock);
	return ret;
}

static void qblk_activate_perch_gc(struct qblk *qblk, int chnl)
{
	spin_lock(&qblk->gc_active_lock);
	set_bit(chnl, qblk->gc_active);
	spin_unlock(&qblk->gc_active_lock);
}

static void qblk_stop_perch_gc(struct qblk *qblk, int chnl)
{
	spin_lock(&qblk->gc_active_lock);
	clear_bit(chnl, qblk->gc_active);
	spin_unlock(&qblk->gc_active_lock);
}


static void qblk_gc_free_gc_rq(struct qblk_gc_rq *gc_rq)
{
	if (gc_rq->data)
		vfree(gc_rq->data);
	kfree(gc_rq);
}

static int qblk_gc_write(struct qblk_gc *gc)
{
	struct qblk *qblk = gc->qblk;
	struct qblk_gc_rq *gc_rq, *tgc_rq;
	struct qblk_line *line;
	LIST_HEAD(w_list);

	spin_lock(&gc->w_lock);
	if (list_empty(&gc->w_list)) {
		spin_unlock(&gc->w_lock);
		return 1;
	}

	list_cut_position(&w_list, &gc->w_list, gc->w_list.prev);
	gc->w_entries = 0;
	spin_unlock(&gc->w_lock);

	list_for_each_entry_safe(gc_rq, tgc_rq, &w_list, list) {
		qblk_write_gc_to_cache(qblk, gc_rq);
		list_del(&gc_rq->list);
		line = gc_rq->line;
		//if(!line->chi->ch_index)
		//	print_gcrq_status(gc_rq);
		kref_put(&line->ref, qblk_line_put);
		up(&gc->gc_sem);
		qblk_gc_free_gc_rq(gc_rq);
	}

	return 0;
}


static inline void qblk_gc_writer_kick(struct qblk_gc *gc)
{
	wake_up_process(gc->gc_writer_ts);
}

void qblk_gc_kick(struct qblk_gc *gc)
{
	//pr_notice("%s, chnl[%d]\n", __func__, gc->chnl);

	qblk_gc_writer_kick(gc);

	/* If we're shutting down GC, let's not start it up again */
	
	if (atomic_read(&gc->qblk->gc_enabled)) {
		wake_up_process(gc->gc_ts);
		mod_timer(&gc->gc_timer,
			  jiffies + msecs_to_jiffies(GC_TIME_MSECS));
	}
}

static void qblk_gc_timer(struct timer_list *t)
{
	struct qblk_gc *gc = from_timer(gc, t, gc_timer);

//	if(!gc->chnl)
//		pr_notice("%s\n", __func__);
	qblk_gc_kick(gc);
}


/*
 * Choose one with the least valid sector count
 */
static struct qblk_line *qblk_gc_get_victim_line(struct qblk *qblk,
						 struct list_head *group_list)
{
	struct qblk_line *line, *victim;
	int line_vsc, victim_vsc;

	victim = list_first_entry(group_list, struct qblk_line, list);
	victim_vsc = qblk_line_vsc(victim);
	list_for_each_entry(line, group_list, list) {
		line_vsc = le32_to_cpu(*line->vsc);
		if (victim_vsc > line_vsc) {
			victim = line;
			victim_vsc = line_vsc;
		}
	}

	return victim;
}


static bool inline qblk_gc_should_run(struct qblk_gc *gc, struct qblk_per_chnl_rl *per_ch_rl)
{
	unsigned int nr_blocks_free, nr_blocks_need;

	nr_blocks_need = qblk_rl_high_thrs(per_ch_rl);
	nr_blocks_free = qblk_rl_nr_free_blks(per_ch_rl);

	return (
			qblk_perch_gc_activated(gc->qblk,
										gc->chnl) &&
			(nr_blocks_free < nr_blocks_need)     &&
			atomic_add_unless(&gc->nr_gc_lines,
									1, QBLK_GC_QUOTAS)
			);
}


static int qblk_gc_free_full_lines(struct qblk_gc *gc, struct ch_info *chi)
{
	struct qblk_line *line;
	unsigned long flags;

	do {
		spin_lock(&chi->gc_lock);
		if (list_empty(&chi->gc_full_list)) {
			spin_unlock(&chi->gc_lock);
			return 0;
		}

		line = list_first_entry(&chi->gc_full_list,
							struct qblk_line, list);

		if(!atomic_add_unless(&gc->nr_gc_lines,
			1, QBLK_GC_QUOTAS)) {
			spin_unlock(&chi->gc_lock);
			return 1;
		}

		spin_lock_irqsave(&line->lock, flags);
		WARN_ON(line->state != QBLK_LINESTATE_CLOSED);
		line->state = QBLK_LINESTATE_GC;
		spin_unlock_irqrestore(&line->lock, flags);

		list_del(&line->list);
		spin_unlock(&chi->gc_lock);

		//if (!chi->ch_index)
		//	pr_notice("%s, line[%d]\n", __func__, line->id);

		kref_put(&line->ref, qblk_line_put);
	} while (1);
	return 0;
}


/* This function should release the gc->gc_sem */
static void qblk_gc_line_ws(struct work_struct *work)
{
	struct qblk_line_ws *gc_rq_ws = container_of(work,
						struct qblk_line_ws, ws);
	struct qblk *qblk = gc_rq_ws->qblk;
	struct nvm_tgt_dev *dev = qblk->dev;
	struct qblk_line *line = gc_rq_ws->line;
	struct nvm_geo *geo = &dev->geo;
	struct ch_info *chi = line->chi;
	//struct qblk_metainfo *meta = &qblk->metainfo;
	int chnl = chi->ch_index;
	struct qblk_gc *gc = &qblk->per_channel_gc[chnl];
	struct qblk_gc_rq *gc_rq = gc_rq_ws->priv;
	int ret;

	gc_rq->chi = chi;
	gc_rq->data = vmalloc(gc_rq->nr_secs * geo->sec_size);
	if (!gc_rq->data) {
		pr_err("qblk: could not GC line:%d (%d/%d)\n",
					line->id, le32_to_cpu(*line->vsc), gc_rq->nr_secs);
		goto out;
	}

	ret = qblk_submit_read_gc(gc, gc_rq);
	if (ret) {
		pr_err("qblk: failed GC read in line:%d (err:%d)\n",
								line->id, ret);
		goto out;
	}

	if (!gc_rq->secs_to_gc)
		goto out;

	/*if(!chi->ch_index)
		pr_notice("%s, line[%d] nrsec[%d]\n",
			__func__, line->id, gc_rq->nr_secs);*/
retry:
	spin_lock(&gc->w_lock);
	if (gc->w_entries >= QBLK_GC_RQ_QD) {
		spin_unlock(&gc->w_lock);
		qblk_gc_writer_kick(gc);
		usleep_range(128, 256);
		goto retry;
	}
	gc->w_entries++;
	list_add_tail(&gc_rq->list, &gc->w_list);
	spin_unlock(&gc->w_lock);

	qblk_gc_writer_kick(gc);

	kfree(gc_rq_ws);
	return;

out:
	up(&gc->gc_sem);
	qblk_gc_free_gc_rq(gc_rq);
	kref_put(&line->ref, qblk_line_put);
	kfree(gc_rq_ws);
}


//gc a line
static void qblk_gc_line(struct work_struct *work)
{
	struct qblk_line_gc_ws *gc_ws = container_of(work, struct qblk_line_gc_ws, ws);
	struct qblk *qblk = gc_ws->qblk;
	struct qblk_gc *gc = gc_ws->gc;
	struct qblk_line *line = gc_ws->line;
	struct chnl_emeta *emeta_buf;
	unsigned long *invalid_bitmap;
	struct qblk_metainfo *meta = &qblk->metainfo;
	int ret;
	int sec_left; //nr invalid sectors in this line
	unsigned long bit, nr_secs;
	__le64 *lba_list;
	struct qblk_gc_rq *gc_rq;
	struct qblk_line_ws *gc_rq_ws;
	unsigned long flags;

	/*if(!gc->chnl)
		pr_notice("%s, line[%d] vsd[%d]\n", __func__,
						line->id, qblk_line_vsc(line));*/

	gc_ws->invalid_bitmap = invalid_bitmap
		= kmalloc(meta->sec_bitmap_len, GFP_KERNEL);
	if (!invalid_bitmap) {
		pr_err("qblk: could not allocate GC invalid bitmap\n");
		goto fail_free_ws;
	}

	gc_ws->emeta_buf = emeta_buf
		= qblk_malloc(meta->emeta_len[0], meta->emeta_alloc_type,
									GFP_KERNEL);
	if (!emeta_buf) {
		pr_err("qblk: cannot use GC emeta\n");
		goto fail_free_bitmap;
	}

	ret = qblk_line_read_emeta(qblk, line, emeta_buf);
	if (unlikely(ret)) {
		pr_err("qblk: read emeta failed. ch[%d] line[%d] ret[%d]\n",
					gc->chnl, line->id, ret);
		goto fail_free_emeta;
	}

	/* If this read fails, it means that emeta is corrupted. For now, leave
	 * the line untouched. TODO: Implement a recovery routine that scans and
	 * moves all sectors on the line.
	 */
	ret = qblk_recov_check_emeta(qblk, emeta_buf);
	if (ret) {
		pr_err("qblk: inconsistent emeta (line %d) retVal[%d]\n",
						line->id, ret);
		goto fail_free_emeta;
	}
	lba_list = emeta_to_lbas(qblk, emeta_buf);
	if (!lba_list) {
		pr_err("qblk: could not interpret emeta (line %d)\n", line->id);
		goto fail_free_emeta;
	}

	spin_lock_irqsave(&line->lock, flags);
	bitmap_copy(invalid_bitmap, line->invalid_bitmap, meta->sec_per_chline);
	sec_left = qblk_line_vsc(line);
	spin_unlock_irqrestore(&line->lock, flags);

	if (sec_left < 0) {
		pr_err("qblk: corrupted GC line (%d)\n", line->id);
		goto fail_free_emeta;
	}

	bit = -1;
next_rq:
	gc_rq = kmalloc(sizeof(struct qblk_gc_rq), GFP_KERNEL);
	if (!gc_rq)
		goto fail_free_emeta;

	nr_secs = 0;
	do {
		bit = find_next_zero_bit(invalid_bitmap, meta->sec_per_chline,
								bit + 1);
		if (bit > line->emeta_ssec)
			break;
		
		gc_rq->paddr_list[nr_secs] = bit;
		gc_rq->lba_list[nr_secs++] = le64_to_cpu(lba_list[bit]);
	} while (nr_secs < qblk->max_write_pgs);

	if (unlikely(!nr_secs)) {
		kfree(gc_rq);
		goto out;
	}

	gc_rq->nr_secs = nr_secs;
	gc_rq->line = line;

	gc_rq_ws = kmalloc(sizeof(struct qblk_line_ws), GFP_KERNEL);
	if (!gc_rq_ws)
		goto fail_free_gc_rq;

	gc_rq_ws->qblk = qblk;
	gc_rq_ws->line = line;
	gc_rq_ws->priv = gc_rq;

	/* The write GC path can be much slower than the read GC one due to
	 * the budget imposed by the rate-limiter. Balance in case that we get
	 * back pressure from the write GC path.
	 */
	while (down_timeout(&gc->gc_sem, msecs_to_jiffies(30000))) {
		io_schedule();
	}

	kref_get(&line->ref);

	INIT_WORK(&gc_rq_ws->ws, qblk_gc_line_ws);
	queue_work(gc->gc_line_reader_wq, &gc_rq_ws->ws);

	sec_left -= nr_secs;
	if (sec_left > 0)
		goto next_rq;

out:
	qblk_mfree(emeta_buf, meta->emeta_alloc_type);
	kfree(invalid_bitmap);

	kref_put(&line->ref, qblk_line_put);

	kfree(gc_ws);

	return;
fail_free_gc_rq:
	kfree(gc_rq);
fail_free_emeta:
	qblk_mfree(emeta_buf, meta->emeta_alloc_type);
fail_free_bitmap:
	kfree(invalid_bitmap);
fail_free_ws:
	kref_put(&line->ref, qblk_line_put);
	kfree(gc_ws);

	pr_err("qblk: Failed to GC line %d\n", line->id);
}


/*
 * Lines with no valid sectors will be returned to the free list immediately. If
 * GC is activated - either because the free block count is under the determined
 * threshold, or because it is being forced from user space - only lines with a
 * high count of invalid sectors will be recycled.
 */
static inline int qblk_gc_run(struct qblk_gc *gc)
{
	struct qblk *qblk = gc->qblk;
	int chnl = gc->chnl;
	struct ch_info *chi = &qblk->ch[chnl];
	struct qblk_line *line;
	struct list_head *group_list;
	bool run_gc;
	int gc_group = 0;
	struct qblk_line_gc_ws *gc_ws;
	unsigned long flags;

	if(qblk_gc_free_full_lines(gc, chi))
		return 0;
	run_gc = qblk_gc_should_run(gc, &chi->per_ch_rl);
	if (!run_gc)
		return 0;

	/*
	 * TODO:
	 * Currently, when GC is enabled, we will always find a line
	 * to gc. If all lines contains a large amount of valid sectors,
	 * this may cause tremendous sector migration.
	 * This situation may happen when QBLK users don't
	 * submit discard/trim requests.
	 */
next_gc_group:
	//gc_group < chi->per_ch_rl.chnl_state
	if (likely(gc_group < QBLK_GC_NR_LISTS)) {
		group_list = chi->gc_lists[gc_group++];
		
		spin_lock(&chi->gc_lock);
		if (list_empty(group_list)) {
			spin_unlock(&chi->gc_lock);
			goto next_gc_group;
		}

		gc_ws = (struct qblk_line_gc_ws *)kmalloc(sizeof(*gc_ws), GFP_ATOMIC);
		if (!gc_ws) {
			atomic_dec(&gc->nr_gc_lines);
			return 0;
		}
			
		line = qblk_gc_get_victim_line(qblk, group_list);
			
		spin_lock_irqsave(&line->lock, flags);
		WARN_ON(line->state != QBLK_LINESTATE_CLOSED);
		line->state = QBLK_LINESTATE_GC;
		spin_unlock_irqrestore(&line->lock, flags);
		
		list_del(&line->list);
		spin_unlock(&chi->gc_lock);

		INIT_WORK(&gc_ws->ws, qblk_gc_line);
		gc_ws->line = line;
		gc_ws->gc = gc;
		gc_ws->qblk = qblk;
		queue_work(gc->gc_line_wq, &gc_ws->ws);
	}  else {
		atomic_dec(&gc->nr_gc_lines);
	}
	return 1;
}


static int qblk_gc_ts(void *data)
{
	struct qblk_gc *gc = data;

	while (!kthread_should_stop()) {
		if(qblk_gc_run(gc))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return 0;
}

static int qblk_gc_writer_ts(void *data)
{
	struct qblk_gc *gc = data;
	//struct qblk *qblk = gc->qblk;

	while (!kthread_should_stop()) {
		if (!qblk_gc_write(gc))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}

static void qblk_gc_start(struct qblk_gc *gc)
{
	qblk_activate_perch_gc(gc->qblk, gc->chnl);
	/*if(!gc->chnl)
		pr_notice("qblk: gc[%d] start\n", gc->chnl);*/
}


void qblk_gc_should_start(struct qblk_per_chnl_rl *rl)
{
	int chnl = rl->chnl;
	struct qblk *qblk = rl->qblk;
	struct qblk_gc *gc = &qblk->per_channel_gc[chnl];

	/*pr_notice("%s, chnl[%d], enabled=%d, active=%d\n",
				__func__, chnl,
				atomic_read(&gc->gc_enabled),
				qblk_perch_gc_activated(qblk, chnl));*/

	if (atomic_read(&qblk->gc_enabled) && !qblk_perch_gc_activated(qblk, chnl)) {
		qblk_gc_start(gc);
		qblk_gc_kick(gc);
	}
}

void qblk_gc_should_stop(struct qblk_per_chnl_rl *rl)
{
	int chnl = rl->chnl;
	struct qblk *qblk = rl->qblk;
	struct qblk_gc *gc = &qblk->per_channel_gc[chnl];

	if (qblk_perch_gc_activated(qblk, gc->chnl) && !gc->gc_forced)
		qblk_stop_perch_gc(qblk, chnl);
}


void qblk_gc_should_kick(struct qblk *qblk)
{
	int chnl = qblk->nr_channels;
	while (chnl--)
		qblk_rl_update_rates(&qblk->ch[chnl].per_ch_rl);
}

int qblk_gc_init(struct qblk *qblk)
{
	struct qblk_gc *gc_array, *gc;
	int ret;
	int nr_chnls = qblk->nr_channels;
	int ch;
	char tsname[16];

	/* Initialize global GC variables */
	spin_lock_init(&qblk->gc_active_lock);
	qblk->gc_active_size = BITS_TO_LONGS(nr_chnls) * sizeof(long);
	qblk->gc_active = kzalloc(qblk->gc_active_size, GFP_KERNEL);
	if (!qblk->gc_active)
		return -ENOMEM;

	gc_array = qblk->per_channel_gc = kmalloc_array(nr_chnls, sizeof(struct qblk_gc), GFP_KERNEL);
	if (!gc_array) {
		ret = -ENOMEM;
		goto fail_free_gc_active;
	}

	/* Initialize per-chnl GC */
	for (ch = 0; ch < nr_chnls; ch++) {
		struct ch_info *chi = &qblk->ch[ch];
		
		chi->gc = gc = &gc_array[ch];
		gc->qblk = qblk;
		gc->chnl = ch;
		gc->gc_forced = 0;
		gc->w_entries = 0;
		atomic_set(&gc->nr_gc_lines, 0);
		INIT_LIST_HEAD(&gc->w_list);
		spin_lock_init(&gc->w_lock);
		sema_init(&gc->gc_sem, QBLK_GC_RQ_QD);

		sprintf(tsname, "qblk_gc_%u", ch);
		gc->gc_ts = kthread_create(qblk_gc_ts, gc, tsname);
		if (IS_ERR(gc->gc_ts)) {
			pr_err("qblk: could not allocate GC[%d] main kthread\n",
							ch);
			ret = PTR_ERR(gc->gc_ts);
			goto fail_alloc_main_kthread;
		}

		sprintf(tsname, "q-gc-w_%u", ch);
		gc->gc_writer_ts = kthread_create(qblk_gc_writer_ts,
								gc, tsname);
		if (IS_ERR(gc->gc_writer_ts)) {
			pr_err("qblk: could not allocate GC[%d] writer kthread\n",
							ch);
			ret = PTR_ERR(gc->gc_writer_ts);
			goto fail_free_main_kthread;
		}

		/* Workqueue that GC lines */
		sprintf(tsname, "qblk_gcline_%u", ch);
		gc->gc_line_wq = alloc_workqueue(tsname,
						WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
		if (!gc->gc_line_wq) {
			pr_err("qblk: could not allocate gc_line_wq\n");
			ret = -ENOMEM;
			goto fail_free_writer_ts;
		}

		/* Workqueue that reads valid sectors from a line and submit them to the
		 * GC writer to be recycled.
		 */
		sprintf(tsname, "q-gc-lrwq_%u", ch);
		gc->gc_line_reader_wq = alloc_workqueue(tsname,
				WQ_MEM_RECLAIM | WQ_UNBOUND, QBLK_GC_MAX_READERS);
		if (!gc->gc_line_reader_wq) {
			pr_err("qblk: could not allocate GC line reader workqueue\n");
			ret = -ENOMEM;
			goto fail_free_gcline;
		}

		timer_setup(&gc->gc_timer, qblk_gc_timer, 0);
		mod_timer(&gc->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));
	}

	atomic_set(&qblk->gc_enabled, 1);

	return 0;
fail_free_gcline:
	destroy_workqueue(gc->gc_line_wq);
fail_free_writer_ts:
	kthread_stop(gc->gc_writer_ts);
fail_free_main_kthread:
	kthread_stop(gc->gc_ts);
fail_alloc_main_kthread:
	while (ch--) {
		gc = &gc_array[ch];
		destroy_workqueue(gc->gc_line_reader_wq);
		kthread_stop(gc->gc_writer_ts);
		kthread_stop(gc->gc_ts);
	}
	kfree(gc_array);
fail_free_gc_active:
	kfree(qblk->gc_active);
	return ret;
}


#if 0
int qblk_gc_init(struct qblk *qblk)
{
	struct qblk_gc *gc_array, *gc;
	int ret;
	int nr_chnls = qblk->nr_channels;
	int ch;
	char tsname[16];

	spin_lock_init(&qblk->gc_active_lock);
	qblk->gc_active_size = BITS_TO_LONGS(nr_chnls) * sizeof(long);
	qblk->gc_active = kzalloc(qblk->gc_active_size, GFP_KERNEL);
	if (!qblk->gc_active)
		return -ENOMEM;

	gc_array = qblk->per_channel_gc = kmalloc_array(nr_chnls, sizeof(struct qblk_gc), GFP_KERNEL);
	if (!gc_array) {
		ret = -ENOMEM;
		goto fail_free_gc_active;
	}

	for (ch = 0; ch < nr_chnls; ch++) {
		gc = &gc_array[ch];
		gc->qblk = qblk;
		gc->chnl = ch;
		gc->gc_forced = 0;
		atomic_set(&gc->gc_enabled, 1);
		gc->w_entries = 0;
		atomic_set(&gc->read_inflight_gc, 0);
		atomic_set(&gc->pipeline_gc, 0);
		spin_lock_init(&gc->w_lock);
		spin_lock_init(&gc->r_lock);
		atomic_set(&gc->readline_count, 0);
		sema_init(&gc->gc_sem, QBLK_GC_RQ_QD);
		INIT_LIST_HEAD(&gc->w_list);
		INIT_LIST_HEAD(&gc->r_list);
#if 1
		sprintf(tsname, "q-gc-ts_%u", ch);//
		gc->gc_ts = kthread_create(qblk_gc_ts, gc, tsname);//
		if (IS_ERR(gc->gc_ts)) {
			pr_err("qblk: could not allocate GC[%d] main kthread\n",
							ch);
			ret = PTR_ERR(gc->gc_ts);
			goto fail_alloc_main_kthread;
		}

		sprintf(tsname, "q-gc-w_%u", ch);//
		gc->gc_writer_ts = kthread_create(qblk_gc_writer_ts,
								gc, tsname);
		if (IS_ERR(gc->gc_writer_ts)) {
			pr_err("qblk: could not allocate GC[%d] writer kthread\n",
							ch);
			ret = PTR_ERR(gc->gc_writer_ts);
			goto fail_free_main_kthread;
		}

		sprintf(tsname, "q-gc-r_%u", ch);
		gc->gc_reader_ts = kthread_create(qblk_gc_reader_ts,
								gc, tsname);
		if (IS_ERR(gc->gc_reader_ts)) {
			pr_err("qblk: could not allocate GC reader kthread\n");
			ret = PTR_ERR(gc->gc_reader_ts);
			goto fail_free_writer_kthread;
		}

		/* Workqueue that reads valid sectors from a line and submit them to the
		 * GC writer to be recycled.
		 */
		sprintf(tsname, "q-gc-lrwq_%u", ch);//
		gc->gc_line_reader_wq = alloc_workqueue(tsname,
				WQ_MEM_RECLAIM | WQ_UNBOUND, QBLK_GC_MAX_READERS);
		if (!gc->gc_line_reader_wq) {
			pr_err("qblk: could not allocate GC line reader workqueue\n");
			ret = -ENOMEM;
			goto fail_free_reader_kthread;
		}

		/* Workqueue that prepare lines for GC */
		sprintf(tsname, "qgc-rwq_%u", ch);
		gc->gc_reader_wq = alloc_workqueue(tsname,
						WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
		if (!gc->gc_reader_wq) {
			pr_err("qblk: could not allocate GC reader workqueue\n");
			ret = -ENOMEM;
			goto fail_free_reader_line_wq;
		}
#endif
		timer_setup(&gc->gc_timer, qblk_gc_timer, 0);
		mod_timer(&gc->gc_timer, jiffies + msecs_to_jiffies(GC_TIME_MSECS));
		atomic_set(&gc->nr_gc_lines, 0);
	}

	return 0;

	destroy_workqueue(gc->gc_reader_wq);
fail_free_reader_line_wq:
	destroy_workqueue(gc->gc_line_reader_wq);
fail_free_reader_kthread:
	kthread_stop(gc->gc_reader_ts);
fail_free_writer_kthread:
	kthread_stop(gc->gc_writer_ts);
fail_free_main_kthread:
	kthread_stop(gc->gc_ts);
fail_alloc_main_kthread:
	while (ch--) {
		gc = &gc_array[ch];
		destroy_workqueue(gc->gc_reader_wq);
		destroy_workqueue(gc->gc_line_reader_wq);
		kthread_stop(gc->gc_reader_ts);
		kthread_stop(gc->gc_writer_ts);
		kthread_stop(gc->gc_ts);
	}
	kfree(gc_array);
fail_free_gc_active:
	kfree(qblk->gc_active);
	return ret;
}

#endif

void qblk_gc_exit(struct qblk *qblk)
{
	struct qblk_gc *gc_array = qblk->per_channel_gc;
	struct qblk_gc *gc;
	int ch = qblk->nr_channels;

	//pr_notice("%s\n", __func__);
	if (!gc_array)
		return;

	atomic_set(&qblk->gc_enabled, 0);
	while (ch--) {
		gc = &gc_array[ch];

		del_timer_sync(&gc->gc_timer);

		flush_workqueue(gc->gc_line_wq);
		if(gc->gc_line_wq)
			destroy_workqueue(gc->gc_line_wq);
		flush_workqueue(gc->gc_line_reader_wq);
		if(gc->gc_line_reader_wq)
			destroy_workqueue(gc->gc_line_reader_wq);

		if (gc->gc_writer_ts)
			kthread_stop(gc->gc_writer_ts);
		if (gc->gc_ts)
			kthread_stop(gc->gc_ts);

	}
	kfree(gc_array);
	kfree(qblk->gc_active);
}
