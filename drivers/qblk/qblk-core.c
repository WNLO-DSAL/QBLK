#include "qblk.h"

static void qblk_bio_map_addr_endio(struct bio *bio)
{
	bio_put(bio);
}

struct bio *qblk_bio_map_addr(struct qblk *qblk,
		void *data, unsigned int nr_secs,
		unsigned int len, int alloc_type,
		gfp_t gfp_mask)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	void *kaddr = data;
	struct page *page;
	struct bio *bio;
	int i, ret;

	if (alloc_type == QBLK_KMALLOC_META)
		return bio_map_kern(dev->q, kaddr, len, gfp_mask);

	bio = bio_kmalloc(gfp_mask, nr_secs);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < nr_secs; i++) {
		page = vmalloc_to_page(kaddr);
		if (!page) {
			pr_err("qblk: could not map vmalloc bio\n");
			bio_put(bio);
			bio = ERR_PTR(-ENOMEM);
			goto out;
		}

		ret = bio_add_pc_page(dev->q, bio, page, PAGE_SIZE, 0);
		if (ret != PAGE_SIZE) {
			pr_err("qblk: could not add page to bio\n");
			bio_put(bio);
			bio = ERR_PTR(-ENOMEM);
			goto out;
		}

		kaddr += PAGE_SIZE;
	}

	bio->bi_end_io = qblk_bio_map_addr_endio;
out:
	return bio;
}

void qblk_line_close_ws(struct work_struct *work)
{
	struct qblk_line_ws *line_ws = container_of(work, struct qblk_line_ws,
									ws);
	struct qblk *qblk = line_ws->qblk;
	struct qblk_line *line = line_ws->line;

	//pr_notice("%s,ch=%d,line=%u\n",__func__,line->chi->ch_index,line->id);

	qblk_line_close(qblk, line);
	mempool_free(line_ws, qblk->gen_ws_pool);
}

void qblk_gen_run_ws(struct qblk *qblk,
			struct qblk_line *line, void *priv,
		    void (*work)(struct work_struct *),
		    gfp_t gfp_mask,
		    struct workqueue_struct *wq)
{
	struct qblk_line_ws *line_ws;

	//pr_notice("%s,ch=%d,line=%u\n",__func__,line->chi->ch_index,line->id);

	line_ws = mempool_alloc(qblk->gen_ws_pool, gfp_mask);

	line_ws->qblk = qblk;
	line_ws->line = line;
	line_ws->priv = priv;

	INIT_WORK(&line_ws->ws, work);
	queue_work(wq, &line_ws->ws);
}

void __qblk_map_invalidate(struct qblk *qblk,
			struct ch_info *chi,
			struct qblk_line *line,
			u64 offset_in_line)
{
	struct list_head *move_list = NULL;

	/* Lines being reclaimed (GC'ed) cannot be invalidated. Before the L2P
	 * table is modified with reclaimed sectors, a check is done to endure
	 * that newer updates are not overwritten.
	 */
#if 0
	pr_notice("%s, ch[%d], line[%d], off[%llu]\n",
	 					__func__, chi->ch_index,
	 					line->id, offset_in_line);
#endif
	spin_lock(&line->lock);
	WARN_ON(line->state == QBLK_LINESTATE_FREE);

	if (test_and_set_bit(offset_in_line, line->invalid_bitmap)) {
		WARN_ONCE(1, "qblk: double invalidate\n");
		spin_unlock(&line->lock);
		return;
	}
	le32_add_cpu(line->vsc, -1);

	//pr_notice("%s, invalidBM=0x%lx\n", __func__, *line->invalid_bitmap);

	if (line->state == QBLK_LINESTATE_CLOSED)
		move_list = qblk_line_gc_list(qblk, chi, line);
	spin_unlock(&line->lock);

	if (move_list) {
		spin_lock(&chi->gc_lock);
		spin_lock(&line->lock);
		/* Prevent moving a line that
		 * has just been chosen for GC,
		 * or has just been opened.
		 */
		if (line->state != QBLK_LINESTATE_CLOSED) {
			spin_unlock(&line->lock);
			spin_unlock(&chi->gc_lock);
			return;
		}
		spin_unlock(&line->lock);

		list_move_tail(&line->list, move_list);
		spin_unlock(&chi->gc_lock);
	}
}

/* Invalidate a ppa */
void qblk_map_invalidate(struct qblk *qblk, struct ppa_addr ppa)
{
	struct ch_info *chi;

#ifdef CONFIG_NVM_DEBUG
	/* Callers must ensure that the ppa points to a device address */
	BUG_ON(qblk_addr_in_cache(ppa));
	BUG_ON(qblk_ppa_empty(ppa));
#endif

	//pr_notice("%s, invalidate 0x%llx\n", __func__, ppa.ppa);
	chi = qblk_ppa_to_chi(qblk, ppa);
	__qblk_map_invalidate(qblk, chi,
		&chi->lines[qblk_ppa_to_line(ppa)],
		gen_ppa_to_offset_in_line(qblk,ppa));
}

struct list_head *qblk_line_gc_list(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line *line)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct list_head *move_list = NULL;
	int vsc = le32_to_cpu(*line->vsc);

	lockdep_assert_held(&line->lock);

	if (!vsc) {
		if (line->gc_group != QBLK_LINEGC_FULL) {
			line->gc_group = QBLK_LINEGC_FULL;
			move_list = &chi->gc_full_list;
			//pr_notice("%s,move to gcfulllist\n",__func__);
		}
	} else if (vsc < meta->high_thrs) {
		if (line->gc_group != QBLK_LINEGC_HIGH) {
			line->gc_group = QBLK_LINEGC_HIGH;
			move_list = &chi->gc_high_list;
			//pr_notice("%s,move to gchighlist\n",__func__);
		}
	} else if (vsc < meta->mid_thrs) {
		if (line->gc_group != QBLK_LINEGC_MID) {
			line->gc_group = QBLK_LINEGC_MID;
			move_list = &chi->gc_mid_list;
			//pr_notice("%s,move to gcmidlist\n",__func__);
		}
	} else if (vsc < line->sec_in_line) {
		if (line->gc_group != QBLK_LINEGC_LOW) {
			line->gc_group = QBLK_LINEGC_LOW;
			move_list = &chi->gc_low_list;
			//pr_notice("%s,move to gclowlist\n",__func__);
		}
	} else if (vsc == line->sec_in_line) {
		if (line->gc_group != QBLK_LINEGC_EMPTY) {
			line->gc_group = QBLK_LINEGC_EMPTY;
			move_list = &chi->gc_empty_list;
			//pr_notice("%s,move to gcemptylist\n",__func__);
		}
	} else {
		line->state = QBLK_LINESTATE_CORRUPT;
		line->gc_group = QBLK_LINEGC_NONE;
		move_list =  &chi->corrupt_list;
		pr_err("qblk: corrupted vsc for line %d, vsc:%d (%d/%d/%d)\n",
				line->id, vsc,
				line->sec_in_line,
				meta->high_thrs, meta->mid_thrs);
	}

	return move_list;
}

int qblk_calc_secs(struct qblk *qblk,
			unsigned long secs_avail,
			unsigned long secs_to_flush)
{
	//int max = qblk->max_write_pgs;
	int max = qblk->sec_per_write;
	int min = qblk->min_write_pgs;
	int secs_to_sync = 0;

	if (secs_avail >= max)
		secs_to_sync = max;
	else if (secs_avail >= min)
		secs_to_sync = min * (secs_avail / min);
	else if (secs_to_flush)
		secs_to_sync = min;

	//pr_notice("%s,secsToSync=%d\n",__func__,secs_to_sync);

	return secs_to_sync;
}

struct qblk_line *qblk_line_get_data(struct ch_info *chi)
{
	struct qblk_line *line;

	might_sleep();
retry:
	spin_lock(&chi->free_lock);
	if (chi->replacing) {
		//someone is replacing data line, we need to wait and retry
		spin_unlock(&chi->free_lock);
		schedule();
		goto retry;
	}
	line = chi->data_line;
	spin_unlock(&chi->free_lock);
	return line;
}

struct qblk_line *qblk_line_get_erase(struct ch_info *chi)
{
	return chi->data_next;
}

void qblk_log_write_err(struct qblk *qblk, struct nvm_rq *rqd)
{
	atomic_long_inc(&qblk->write_failed);
#ifdef CONFIG_NVM_DEBUG
	qblk_print_failed_rqd(qblk, rqd, rqd->error);
	printRqdStatus(rqd);
#endif
}

static void qblk_setup_e_rq(struct qblk *qblk,
			struct nvm_rq *rqd,
			struct ppa_addr ppa)
{
	ppa.g.pg = ppa.g.sec = 0;
	rqd->opcode = NVM_OP_ERASE;
	rqd->ppa_addr = ppa;
	rqd->nr_ppas = 1;
	rqd->flags = qblk_set_progr_mode(qblk, QBLK_ERASE);
	rqd->bio = NULL;
}

/*
 * Write the bad block information to the underlying device.
 */
static void qblk_line_mark_bb(struct work_struct *work)
{
	struct qblk_line_ws *line_ws = container_of(work, struct qblk_line_ws,
									ws);
	struct qblk *qblk = line_ws->qblk;
	struct nvm_tgt_dev *dev = qblk->dev;
	struct ppa_addr *ppa = line_ws->priv;
	int ret;

	ret = nvm_set_tgt_bb_tbl(dev, ppa, 1, NVM_BLK_T_GRWN_BAD);
	if (ret) {
		struct qblk_line *line = qblk_ppa_to_structline(qblk, *ppa);
		int pos = qblk_ppa_to_posinsidechnl(&dev->geo, *ppa);

		pr_err("qblk: failed to mark bb, line:%d, pos:%d\n",
				line->id, pos);
	}

	kfree(ppa);
	mempool_free(line_ws, qblk->gen_ws_pool);
}

/*
 * Dynamically mark bad block inside a line.
 */
static void qblk_mark_bb(struct qblk *qblk, struct qblk_line *line,
			 struct ppa_addr *ppa)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int pos = qblk_ppa_to_posinsidechnl(geo, *ppa);

	pr_debug("qblk: erase failed: line:%d, pos:%d\n", line->id, pos);
	atomic_long_inc(&qblk->erase_failed);

	atomic_dec(&line->blk_in_line);
	if (test_and_set_bit(pos, line->blk_bitmap))
		pr_err("qblk: attempted to erase bb: line:%d, pos:%d\n",
							line->id, pos);

	qblk_gen_run_ws(qblk, NULL, ppa, qblk_line_mark_bb,
						GFP_ATOMIC, qblk->bb_wq);
}

static void __qblk_end_io_erase(struct qblk *qblk, struct nvm_rq *rqd)
{
	int ch_idx = rqd->ppa_addr.g.ch;
	int lineID = rqd->ppa_addr.g.blk;
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct qblk_line *line = &chi->lines[lineID];

	atomic_dec(&line->left_seblks);

	if (rqd->error) {
		struct ppa_addr *ppa;

		ppa = kmalloc(sizeof(struct ppa_addr), GFP_ATOMIC);
		if (!ppa)
			return;

		*ppa = rqd->ppa_addr;
		qblk_mark_bb(qblk, line, ppa);
	}

	atomic_dec(&qblk->inflight_io);
}

/* Erase completion assumes that only one block is erased at the time */
static void qblk_end_io_erase(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;

	__qblk_end_io_erase(qblk, rqd);
	mempool_free(rqd, qblk->e_rq_pool);
}

int qblk_blk_erase_sync(struct qblk *qblk, struct ppa_addr ppa)
{
	struct nvm_rq rqd;
	int ret = 0;

	//if(ppa.g.ch <2)
	//	pr_notice("%s,ppa=0x%llx\n",__func__,ppa.ppa);

	memset(&rqd, 0, sizeof(struct nvm_rq));

	qblk_setup_e_rq(qblk, &rqd, ppa);

	ret = qblk_submit_io_sync(qblk, &rqd);
	if (ret) {
		pr_err("qblk: could not sync erase ppa:0x%llx\n",
					ppa.ppa);
		rqd.error = ret;
		goto out;
	}
out:
	rqd.private = qblk;
	__qblk_end_io_erase(qblk, &rqd);
	return ret;
}

int qblk_blk_erase_async(struct qblk *qblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int err;

	//pr_notice("%s, ppa[0x%llx]\n",
	//		__func__, ppa.ppa);

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_ERASE);
	if (!rqd)
		return -ENOMEM;

	qblk_setup_e_rq(qblk, rqd, ppa);

	rqd->end_io = qblk_end_io_erase;
	rqd->private = qblk;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	err = qblk_submit_io(qblk, rqd);
	if (err) {
		//struct nvm_tgt_dev *dev = qblk->dev;
		//struct nvm_geo *geo = &dev->geo;
		pr_err("qblk: could not async erase line:%d,ppa:0x%llx\n",
					qblk_ppa_to_line(ppa),
					ppa.ppa);
	}

	return err;
}

u64 qblk_lookup_page(struct qblk *qblk, struct qblk_line *line)
{
	u64 paddr;

	spin_lock(&line->lock);
	paddr = find_next_zero_bit(line->map_bitmap,
					qblk->metainfo.sec_per_chline, line->cur_sec);
	spin_unlock(&line->lock);

	return paddr;
}

static int qblk_line_submit_smeta_io(struct qblk *qblk,
						struct qblk_line *line,
						u64 offset_in_line, int dir)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct bio *bio;
	struct nvm_rq rqd;
	__le64 *lba_list = NULL;
	int i, ret;
	int cmd_op, bio_op;
	int flags;
	struct ch_info *chi = line->chi;
	struct ppa_addr ppa;
	//int debugindex;
	//struct qblk_debug_entry debugentry;

	if (dir == QBLK_WRITE) {
		bio_op = REQ_OP_WRITE;
		cmd_op = NVM_OP_PWRITE;
		flags = qblk_set_progr_mode(qblk, QBLK_WRITE);
		lba_list = emeta_to_lbas(qblk, line->emeta->buf);
	} else if (dir == QBLK_READ_RECOV || dir == QBLK_READ) {
		bio_op = REQ_OP_READ;
		cmd_op = NVM_OP_PREAD;
		flags = qblk_set_read_mode(qblk, QBLK_READ_SEQUENTIAL);
	} else
		return -EINVAL;

	memset(&rqd, 0, sizeof(struct nvm_rq));

	rqd.meta_list = nvm_dev_dma_alloc(dev->parent, GFP_ATOMIC,
							&rqd.dma_meta_list);
	if (!rqd.meta_list)
		return -ENOMEM;

	rqd.ppa_list = rqd.meta_list + qblk_dma_meta_size;
	rqd.dma_ppa_list = rqd.dma_meta_list + qblk_dma_meta_size;

	bio = bio_map_kern(dev->q, line->smeta, meta->smeta_len, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto free_ppa_list;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, bio_op, 0);

	rqd.bio = bio;
	rqd.opcode = cmd_op;
	rqd.flags = flags;
	rqd.nr_ppas = meta->smeta_sec;

	ppa = offset_in_line_to_gen_ppa(qblk, offset_in_line, chi->ch_index, line->id);

	for (i = 0; i < meta->smeta_sec;
					i++, offset_in_line++,
					ppa = gen_ppa_add_one_inside_chnl(qblk, ppa)) {
		struct qblk_sec_meta *meta_list = rqd.meta_list;

		rqd.ppa_list[i] = ppa;
		//pr_notice("%s,ppa_addr=0x%llx\n",__func__,rqd.ppa_list[i].ppa);

		if (dir == QBLK_WRITE) {
			__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

			meta_list[i].lba = lba_list[offset_in_line] = addr_empty;
		}
	}

	//pr_notice("%s\n", __func__);
	//printRqdStatus(&rqd);

	/*
	 * This I/O is sent by the write thread when a line is replace. Since
	 * the write thread is the only one sending write and erase commands,
	 * there is no need to take the LUN semaphore.
	 */
	//debugentry.type = QBLK_SUBMIT_SMETA;
	//debugentry.firstppa = rqd.ppa_list[0];
	//debugentry.nr_secs = rqd.nr_ppas;
	//qblk_debug_time_irqsave(qblk,
	//		&debugindex, chi->ch_index, debugentry);
	ret = qblk_submit_io_sync(qblk, &rqd);
	if (ret) {
		pr_err("qblk: smeta I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto free_ppa_list;
	}
	//qblk_debug_complete_time(qblk,debugindex, chi->ch_index);

	atomic_dec(&qblk->inflight_io);

	if (rqd.error) {
		if (dir == QBLK_WRITE)
			qblk_log_write_err(qblk, &rqd);
		else if (dir == QBLK_READ)
			qblk_log_read_err(qblk, &rqd);
	}

free_ppa_list:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);

	return ret;
}


static int qblk_line_init_bb(struct qblk *qblk,
				struct ch_info *chi,
				struct qblk_line *line,
			    int init)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	int nr_bb = 0;
	u64 off;
	int bit = -1;

	line->sec_in_line = meta->sec_per_chline;

	/* Capture bad block information on line mapping bitmaps */
	while ((bit = find_next_bit(line->blk_bitmap, meta->blk_per_chline,
					bit + 1)) < meta->blk_per_chline) {
		off = bit * geo->sec_per_pl;
		bitmap_shift_left(chi->bb_aux, chi->bb_template, off,
							meta->sec_per_chline);
		bitmap_or(line->map_bitmap, line->map_bitmap, chi->bb_aux,
							meta->sec_per_chline);
		line->sec_in_line -= geo->sec_per_chk;
		if (bit >= meta->emeta_bb)
			nr_bb++;
	}

	/* Mark smeta metadata sectors as bad sectors */
	bit = find_first_zero_bit(line->blk_bitmap, meta->blk_per_chline);
	off = bit * geo->sec_per_pl;
	bitmap_set(line->map_bitmap, off, meta->smeta_sec);
	line->sec_in_line -= meta->smeta_sec;
	line->smeta_ssec = off;
	line->cur_sec = off + meta->smeta_sec;
	//pr_notice("%s,ch[%d],bit=%d,off=0x%llx,line->sec_in_line=%u,line->smeta_ssec=0x%llx,cur_sec=%u\n",
	//	__func__,chi->ch_index,bit,off,line->sec_in_line,line->smeta_ssec,line->cur_sec);

	if (init && qblk_line_submit_smeta_io(qblk, line, off, QBLK_WRITE)) {
		pr_debug("qblk: line smeta I/O failed. Retry\n");
		return 1;
	}

	bitmap_copy(line->invalid_bitmap, line->map_bitmap, meta->sec_per_chline);

	/* Mark emeta metadata sectors as bad sectors. We need to consider bad
	 * blocks to make sure that there are enough sectors to store emeta
	 */
	off = meta->sec_per_chline - meta->emeta_sec[0];
	bitmap_set(line->invalid_bitmap, off, meta->emeta_sec[0]);
	while (nr_bb) {
		off -= geo->sec_per_pl;
		if (!test_bit(off, line->invalid_bitmap)) {
			bitmap_set(line->invalid_bitmap, off, geo->sec_per_pl);
			nr_bb--;
		}
	}

	line->sec_in_line -= meta->emeta_sec[0];
	line->emeta_ssec = off;
	line->nr_valid_lbas = 0;
	line->left_msecs = line->sec_in_line;
	*line->vsc = cpu_to_le32(line->sec_in_line);

	if (meta->sec_per_chline - line->sec_in_line !=
		bitmap_weight(line->invalid_bitmap, meta->sec_per_chline)) {
		spin_lock(&line->lock);
		line->state = QBLK_LINESTATE_BAD;
		spin_unlock(&line->lock);

		list_add_tail(&line->list, &chi->bad_list);
		pr_err("qblk: unexpected line %d is bad\n", line->id);

		return 0;
	}
	//if (chi->ch_index == 1)
	//	pr_notice("%s, line->sec_in_line=%u\n", __func__, line->sec_in_line);

	return 1;
}

static void __qblk_line_put(struct qblk *qblk, struct qblk_line *line)
{
	struct ch_info *chi = line->chi;
	struct qblk_gc *gc = &qblk->per_channel_gc[chi->ch_index];

	atomic_dec(&gc->readline_count);

	spin_lock(&line->lock);
	WARN_ON(line->state != QBLK_LINESTATE_GC);
	line->state = QBLK_LINESTATE_FREE;
	line->gc_group = QBLK_LINEGC_NONE;
	qblk_line_free(qblk, line);
	spin_unlock(&line->lock);
#if 0
	atomic_dec(&gc->pipeline_gc);
#endif
	spin_lock(&chi->free_lock);
	list_add_tail(&line->list, &chi->free_list);
	chi->nr_free_lines++;
	spin_unlock(&chi->free_lock);

	qblk_rl_free_lines_inc(&chi->per_ch_rl, line);
}

void qblk_line_put(struct kref *ref)
{
	struct qblk_line *line = container_of(ref, struct qblk_line, ref);
	struct qblk *qblk = line->qblk;

	__qblk_line_put(qblk, line);
}

static void qblk_line_put_ws(struct work_struct *work)
{
	struct qblk_line_ws *line_put_ws = container_of(work,
						struct qblk_line_ws, ws);
	struct qblk *qblk = line_put_ws->qblk;
	struct qblk_line *line = line_put_ws->line;

	__qblk_line_put(qblk, line);
	mempool_free(line_put_ws, qblk->gen_ws_pool);
}

void qblk_line_put_wq(struct kref *ref)
{
	struct qblk_line *line = container_of(ref, struct qblk_line, ref);
	struct qblk *qblk = line->qblk;
	struct qblk_line_ws *line_put_ws;

	line_put_ws = mempool_alloc(qblk->gen_ws_pool, GFP_ATOMIC);
	if (!line_put_ws)
		return;

	line_put_ws->qblk = qblk;
	line_put_ws->line = line;
	line_put_ws->priv = NULL;

	INIT_WORK(&line_put_ws->ws, qblk_line_put_ws);
	queue_work(qblk->r_end_wq, &line_put_ws->ws);
}

static int qblk_line_prepare(struct qblk *qblk, struct qblk_line *line)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	int blk_in_line = atomic_read(&line->blk_in_line);

	//pr_notice("%s\n",__func__);

	line->map_bitmap = kzalloc(meta->sec_bitmap_len, GFP_ATOMIC);
	if (!line->map_bitmap)
		return -ENOMEM;

	/* will be initialized using bb info from map_bitmap */
	line->invalid_bitmap = kmalloc(meta->sec_bitmap_len, GFP_ATOMIC);
	if (!line->invalid_bitmap) {
		kfree(line->map_bitmap);
		return -ENOMEM;
	}

	spin_lock(&line->lock);

	if (line->state != QBLK_LINESTATE_FREE) {
		kfree(line->map_bitmap);
		kfree(line->invalid_bitmap);
		spin_unlock(&line->lock);
		WARN(1, "qblk: corrupted line %d, state %d\n",
							line->id, line->state);
		return -EAGAIN;
	}

	line->state = QBLK_LINESTATE_OPEN;

	atomic_set(&line->left_eblks, blk_in_line);
	atomic_set(&line->left_seblks, blk_in_line);

	line->meta_distance = meta->meta_distance;
	spin_unlock(&line->lock);

	/* Bad blocks do not need to be erased */
	bitmap_copy(line->erase_bitmap, line->blk_bitmap, meta->blk_per_chline);

	kref_init(&line->ref);

	return 0;
}

//Erase a line and wait for finish.
int qblk_line_erase(struct qblk *qblk,
			int ch_idx, struct qblk_line *line)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct nvm_geo *geo = &qblk->dev->geo;
	struct ppa_addr ppa;
	int ret, bit = -1;
	//int pl;

	/* Erase only good blocks, one at a time */
	for (;;) {
		spin_lock(&line->lock);

		bit = find_next_zero_bit(line->erase_bitmap, meta->blk_per_chline,
								bit + 1);
		if (bit >= meta->blk_per_chline) {
			spin_unlock(&line->lock);
			break;
		}
		//pr_notice("%s,line->erase_bitmap=0x%lx,bit=%d\n",
		//				__func__, *line->erase_bitmap, bit);

		ppa = qblk->luns[qblk_chlun_to_lunidx(geo, ch_idx, bit)].bppa; /* set ch and lun */
		ppa.g.blk = line->id;

		//pr_notice("%s,channel[%d],bit found=%d,ppa of that block=0x%llx\n",
		//				__func__, ch_idx, bit,ppa.ppa);

		atomic_dec(&line->left_eblks);
		WARN_ON(test_and_set_bit(bit, line->erase_bitmap));
		spin_unlock(&line->lock);
		//for(pl=0;pl<geo->nr_planes;pl++){
		//	ppa.g.pl = pl;
			ret = qblk_blk_erase_sync(qblk, ppa);
			if (ret) {
				pr_err("qblk: failed to erase line %d\n", line->id);
				return ret;
			}
		//}
	}

	return 0;
}


static void qblk_line_setup_metadata(struct qblk_line *line,
				     struct ch_info *chi,
				     struct qblk_metainfo *meta)
{
	int meta_line;

	lockdep_assert_held(&chi->free_lock);

	//pr_notice("%s,line[%u]\n",__func__,line->id);

retry_meta:
	meta_line = find_first_zero_bit(&chi->meta_bitmap, QBLK_DATA_LINES);
	if (meta_line == QBLK_DATA_LINES) {
		spin_unlock(&chi->free_lock);
		io_schedule();
		spin_lock(&chi->free_lock);
		goto retry_meta;
	}

	set_bit(meta_line, &chi->meta_bitmap);
	line->meta_line = meta_line;

	line->smeta = chi->sline_meta[meta_line];
	line->emeta = chi->eline_meta[meta_line];

	memset(line->smeta, 0, meta->smeta_len);
	memset(line->emeta->buf, 0, meta->emeta_len[0]);

	line->emeta->mem = 0;
	atomic_set(&line->emeta->sync, 0);
}

static int qblk_line_init_metadata(struct qblk *qblk,
				struct ch_info *chi, struct qblk_line *line,
				struct qblk_line *cur)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_emeta *emeta = line->emeta;
	struct chnl_emeta *emeta_buf = emeta->buf;
	struct chnl_smeta *smeta_buf = (struct chnl_smeta *)line->smeta;
	int nr_blk_line;

	/* After erasing the line, new bad blocks might appear and we risk
	 * having an invalid line
	 */
	//pr_notice("%s,line[%d],cur[%d]\n",__func__,(line==NULL)?-1:(int)(line->id),(cur==NULL)?-1:(int)(cur->id));
	nr_blk_line = meta->blk_per_chline -
			bitmap_weight(line->blk_bitmap, meta->blk_per_chline);
	if (nr_blk_line < meta->min_blk_line) {
		spin_lock(&chi->free_lock);
		spin_lock(&line->lock);
		line->state = QBLK_LINESTATE_BAD;
		spin_unlock(&line->lock);

		list_add_tail(&line->list, &chi->bad_list);
		spin_unlock(&chi->free_lock);

		pr_debug("qblk: line %d is bad\n", line->id);

		return 0;
	}
	//pr_notice("%s,nr_blk_line=%d\n",__func__,nr_blk_line);

	/* Run-time metadata */
	line->lun_bitmap = ((void *)(smeta_buf)) + sizeof(struct chnl_smeta);

	/* Mark LUNs allocated in this line (all for now) */
	bitmap_set(line->lun_bitmap, 0, meta->lun_bitmap_len);

	smeta_buf->header.identifier = cpu_to_le32(QBLK_MAGIC);
	memcpy(smeta_buf->header.uuid, qblk->instance_uuid, 16);
	smeta_buf->header.id = cpu_to_le32(line->id);
	smeta_buf->header.type = cpu_to_le16(line->type);
	smeta_buf->header.version = SMETA_VERSION;

	/* Start metadata */
	smeta_buf->seq_nr = cpu_to_le64(line->seq_nr);
	smeta_buf->window_wr_lun = cpu_to_le32(geo->nr_luns);

	/* Fill metadata among lines */
	if (cur) {
		memcpy(line->lun_bitmap, cur->lun_bitmap, meta->lun_bitmap_len);
		smeta_buf->prev_id = cpu_to_le32(cur->id);
		cur->emeta->buf->next_id = cpu_to_le32(line->id);
	} else {
		smeta_buf->prev_id = cpu_to_le32(QBLK_LINE_EMPTY);
	}

	/* All smeta must be set at this point */
	smeta_buf->header.crc = cpu_to_le32(
			qblk_calc_meta_header_crc(qblk, &smeta_buf->header));
	smeta_buf->crc = cpu_to_le32(qblk_calc_smeta_crc(qblk, smeta_buf));

	/* End metadata */
	memcpy(&emeta_buf->header, &smeta_buf->header,
						sizeof(struct line_header));

	emeta_buf->seq_nr = cpu_to_le64(line->seq_nr);
	emeta_buf->nr_lbas = cpu_to_le64(line->sec_in_line);
	emeta_buf->nr_valid_lbas = cpu_to_le64(0);
	emeta_buf->next_id = cpu_to_le32(QBLK_LINE_EMPTY);
	emeta_buf->crc = cpu_to_le32(0);
	emeta_buf->prev_id = smeta_buf->prev_id;

	return 1;
}


#if 1
//replace the data line of @chi
struct qblk_line *qblk_line_replace_data(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line *cur,
			struct qblk_line *newline)
{
	unsigned int left_seblks;

	//pr_notice("%s\n", __func__);

	lockdep_assert_held(&chi->free_lock);
	//this function should return with free lock held

	if (!newline)
		goto out;

	/*
	 * We need to check whether the new line has already been fully erased.
	 * If so, we shift the data_line to newline and initialize it.
	 * If not, we don't modify anything, release the current line.
	 * After that, we call someone to erase the new line and return NULL.
	 */
//retry_erase:
	left_seblks = atomic_read(&newline->left_seblks);
	if (left_seblks) {
		/* If line is not fully erased, erase it */
		if (atomic_read(&newline->left_eblks)) {
			//it's weird to get here.
			pr_err("Weird!, %s, line=%d\n", __func__, __LINE__);
			return NULL;
		/*
			//new line isn't prepared, we need to syncronize erase it
			if (qblk_line_erase(qblk, chi->ch_index, newline))
				goto retry_erase;
		*/
		} else {
			return NULL;
		}
		//goto retry_erase;
	}

	chi->replacing = 1;

	if (qblk->state != QBLK_STATE_RUNNING) {
		pr_notice("Weird!, %s, line=%d\n", __func__, __LINE__);
		chi->data_line = NULL;
		chi->data_next = NULL;
		goto out;
	}

	qblk_line_setup_metadata(newline, chi, &qblk->metainfo);

	spin_unlock(&chi->free_lock);
//retry_setup:
	if (!qblk_line_init_metadata(qblk, chi, newline, cur)) {
		/*
		newline = pblk_line_retry(pblk, newline);//---
		if (!newline){
			pr_notice("Weird!,%s,line=%d\n",__func__,__LINE__);
			goto out;
		}

		goto retry_setup;
		*/
		pr_err("%s,line(%d),qblk_line_init_metadata() failed\n", __func__, __LINE__);
			return NULL;
	}

	if (!qblk_line_init_bb(qblk, chi, newline, 1)) {
#if 0
		newline = pblk_line_retry(pblk, newline);//---
		if (!newline){
			pr_notice("Weird!,%s,line=%d\n",__func__,__LINE__);
			goto out;
		}

		goto retry_setup;
#endif
		pr_err("%s,line(%d), qblk init bb failed\n", __func__, __LINE__);
			return NULL;
	}
	spin_lock(&chi->free_lock);
	chi->replacing = 0;
	chi->data_line = newline;

	qblk_rl_free_lines_dec(&chi->per_ch_rl, newline, true);

	/* Allocate next line for preparation */
	chi->data_next = qblk_line_get(qblk, chi);
	if (!chi->data_next) {
		/* If we cannot get a new line, we need to stop the pipeline.
		 * Only allow as many writes in as we can store safely and then
		 * fail gracefully
		 */
		pr_err("Weird!,%s,line=%d\n", __func__, __LINE__);
		qblk_stop_writers(qblk, qblk->nr_queues);
		chi->data_next = NULL;
	} else {
		chi->data_next->seq_nr = chi->d_seq_nr++;
		chi->data_next->type = QBLK_LINETYPE_DATA;
	}

out:
	return newline;
}
#endif

void qblk_set_sec_per_write(struct qblk *qblk, int sec_per_write)
{
	qblk->sec_per_write = sec_per_write;
}

struct ppa_addr __qblk_alloc_page(struct qblk *qblk,
				struct qblk_line *line, int nr_secs)
{
	u64 offset_in_line;
	int i;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct ch_info *chi = line->chi;

	lockdep_assert_held(&line->lock);
	//pr_notice("%s,1:map_bitmap=0x%lx\n",__func__,*line->map_bitmap);
	/* logic error: ppa out-of-bounds. Prevent generating bad address */
	if (line->cur_sec + nr_secs > meta->sec_per_chline) {
		WARN(1, "qblk: page allocation out of bounds\n");
		nr_secs = meta->sec_per_chline - line->cur_sec;
	}

	line->cur_sec = offset_in_line = find_next_zero_bit(line->map_bitmap,
					meta->sec_per_chline, line->cur_sec);
	/*
	 * For now, since we just drain min_write_pages per time,
	 * it ok to simply add one at addr.
	 * If more pages needed, simply adding 1 can not fully exploit
	 * the LUN level parallelism potential.
	 */
	for (i = 0; i < nr_secs; i++, line->cur_sec++)
		WARN_ON(test_and_set_bit(line->cur_sec, line->map_bitmap));
	//pr_notice("%s,2:map_bitmap=0x%lx\n",__func__,*line->map_bitmap);
	return offset_in_line_to_gen_ppa(qblk,
			offset_in_line, chi->ch_index, line->id);
}

#if 1
//-----
static void qblk_line_should_sync_meta(struct qblk *qblk, struct ch_info *chi)
{
	/*
	if (pblk_rl_is_limit(&qblk->rl))
		qblk_line_close_meta_sync(qblk, chi);
	*/
}

void qblk_line_close(struct qblk *qblk, struct qblk_line *line)
{
	struct list_head *move_list;
	struct ch_info *chi = line->chi;

#ifdef CONFIG_NVM_DEBUG
	struct qblk_metainfo *meta = &qblk->metainfo;

	WARN(!bitmap_full(line->map_bitmap, meta->sec_per_chline),
				"qblk: corrupt closed line %d\n", line->id);
#endif

	//pr_notice("%s,close ch [%d] line [%u]\n",__func__,chi->ch_index,line->id);


	spin_lock(&chi->free_lock);
	WARN_ON(!test_and_clear_bit(line->meta_line, &chi->meta_bitmap));
	spin_unlock(&chi->free_lock);

	spin_lock(&chi->gc_lock);
	spin_lock(&line->lock);
	WARN_ON(line->state != QBLK_LINESTATE_OPEN);
	line->state = QBLK_LINESTATE_CLOSED;
	move_list = qblk_line_gc_list(qblk, chi, line);

	list_add_tail(&line->list, move_list);

	kfree(line->map_bitmap);
	line->map_bitmap = NULL;
	line->smeta = NULL;
	line->emeta = NULL;

	spin_unlock(&line->lock);
	spin_unlock(&chi->gc_lock);
}

void qblk_line_close_meta(struct qblk *qblk,
				struct ch_info *chi, struct qblk_line *line)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_emeta *emeta = line->emeta;
	struct chnl_emeta *emeta_buf = emeta->buf;

	//pr_notice("%s,close meta line of ch[%d],line[%u]\n",__func__,chi->ch_index,line->id);

	/* No need for exact vsc value; avoid a big line lock and take aprox. */
	memcpy(emeta_to_vsc(qblk, emeta_buf), chi->vsc_list, meta->vsc_list_len);
	memcpy(emeta_to_bb(emeta_buf), line->blk_bitmap, meta->blk_bitmap_len);

	emeta_buf->nr_valid_lbas = cpu_to_le64(line->nr_valid_lbas);
	emeta_buf->crc = cpu_to_le32(qblk_calc_emeta_crc(qblk, emeta_buf));

	spin_lock(&chi->close_lock);
	spin_lock(&line->lock);
	list_add_tail(&line->list, &chi->emeta_list);
	spin_unlock(&line->lock);
	spin_unlock(&chi->close_lock);

	qblk_line_should_sync_meta(qblk, chi);
}
#if 0
static void __qblk_down_page(struct qblk *qblk, struct ppa_addr *ppa_list,
			     int nr_ppas, int lunidx)
{
	struct qblk_lun *rlun = &qblk->luns[lunidx];
	int ret;
	/*
	 * Only send one inflight I/O per LUN. Since we map at a page
	 * granurality, all ppas in the I/O will map to the same LUN
	 */
#ifdef CONFIG_NVM_DEBUG
	int i;

	for (i = 1; i < nr_ppas; i++)
		WARN_ON(ppa_list[0].g.ch != ppa_list[i].g.ch);
#endif

	//pr_notice("%s,get sem of lunidx %d\n",__func__,lunidx);
	ret = down_timeout(&rlun->wr_sem, msecs_to_jiffies(30000));
	if (ret == -ETIME || ret == -EINTR)
		pr_err("qblk: taking lun semaphore timed out: err %d,ch=%d,lunidx=%d\n",
								-ret, ppa_list[0].g.ch, lunidx);
}
#endif

void qblk_rq_get_semaphores(struct qblk *qblk,
		struct ch_info *chi, unsigned long *lun_bitmap)
{
	struct nvm_geo *geo = &qblk->dev->geo;
	int lun = -1;
	int ch_idx = chi->ch_index;
	struct qblk_lun *rlun;
	int nr_luns = geo->nr_luns;
	int ret;

	while ((lun = find_next_bit(lun_bitmap, nr_luns, lun + 1)) < nr_luns) {
		rlun = &qblk->luns[qblk_chlun_to_lunidx(geo, ch_idx, lun)];
		ret = down_timeout(&rlun->wr_sem, msecs_to_jiffies(30000));
		if (ret == -ETIME || ret == -EINTR)
			pr_err("qblk: taking lun semaphore timed out: err %d,ch=%d,lun=%d\n",
							-ret, ch_idx, lun);
	}
}


void qblk_mark_rq_luns(struct qblk *qblk,
			struct ppa_addr *ppa_list,
			int nr_ppas, unsigned long *lun_bitmap)
{
	struct nvm_geo *geo = &qblk->dev->geo;
	int pos = qblk_ppa_to_posinsidechnl(geo, ppa_list[0]);

	//pr_notice("%s,nr_ppa=%d,lunBitmap=0x%lx,pos=%d\n",__func__,nr_ppas,*lun_bitmap,pos);

	/* If the LUN has been locked for this same request, do no attempt to
	 * lock it again
	 */
	//if (test_and_set_bit(pos, lun_bitmap))
	//	return;

	test_and_set_bit(pos, lun_bitmap);

	//__qblk_down_page(qblk, ppa_list, nr_ppas, qblk_chlun_to_lunidx(geo,ppa_list->g.ch,ppa_list->g.lun));
}

void qblk_up_rq(struct qblk *qblk,
		struct ppa_addr *ppa_list, int nr_ppas,
		unsigned long *lun_bitmap)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_lun *rlun;
	int ch_idx = ppa_list->g.ch;
	int nr_luns = geo->nr_luns;
	int lun = -1;

	//pr_notice("%s,ch=%d,lunbitmap=0x%lx\n",__func__,ch_idx,*lun_bitmap);

	while ((lun = find_next_bit(lun_bitmap, nr_luns, lun + 1)) < nr_luns) {
		rlun = &qblk->luns[qblk_chlun_to_lunidx(geo, ch_idx, lun)];
		up(&rlun->wr_sem);
	}
	kfree(lun_bitmap);
}

void qblk_dealloc_page(struct qblk *qblk, struct ch_info *chi, struct qblk_line *line, int nr_secs)
{
	u64 addr;
	int i;

	spin_lock(&line->lock);
	addr = find_next_zero_bit(line->map_bitmap,
					qblk->metainfo.sec_per_chline, line->cur_sec);
	line->cur_sec = addr - nr_secs;

	for (i = 0; i < nr_secs; i++, line->cur_sec--)
		WARN_ON(!test_and_clear_bit(line->cur_sec, line->map_bitmap));
	spin_unlock(&line->lock);
}

//allocate a flashpage inside a channel
struct ppa_addr qblk_alloc_page(struct qblk *qblk,
		struct ch_info *chi, struct qblk_line **pline,
		int nr_secs)
{
	struct ppa_addr addr;
	struct qblk_line *prev_line;
	struct qblk_line *line = qblk_line_get_data(chi);

	might_sleep();

	/* Lock needed in case a write fails and a recovery needs to remap
	 * failed write buffer entries
	 */
retry:
	spin_lock(&line->lock);
	if (line->left_msecs < nr_secs) {
		//not enough space inside this line, we need to replace a new line.
		spin_unlock(&line->lock);
		//start to replace data line and then retry allocation
		spin_lock(&chi->free_lock);
		if (chi->replacing) {
			/*
			 * If we get here, it means someone is replacing the data line.
			 * After that guy finished, probably we don't need to replace the data_line anymore.
			 * So, what we need to do is to wait and then retry.
			 */
			spin_unlock(&chi->free_lock);
			schedule();
			line = qblk_line_get_data(chi);
			goto retry;
		}
		//Now we replace it!
		prev_line = chi->data_line;
		spin_lock(&prev_line->lock);
		if (prev_line->left_msecs < nr_secs) {
			spin_unlock(&prev_line->lock);
			//we need to replace the data line
			line = qblk_line_replace_data(qblk, chi, prev_line, chi->data_next);
			if (!line) {
				/*
				 * Replace data line failed.
				 * Probably because someone is erasing the data_next.
				 * Data line lock has already been released by
				 * qblk_line_replace_data().
				 * We release the free_lock, schedule and then retry.
				 */
				spin_unlock(&chi->free_lock);
				io_schedule();
				line = qblk_line_get_data(chi);
				goto retry;
			}
			spin_unlock(&chi->free_lock);
			//The one who does the replacement job also need to close the current line.
			qblk_line_close_meta(qblk, chi, prev_line);
			goto retry;
		} else {
			//someone else has replaced the data line
			spin_unlock(&prev_line->lock);
			spin_unlock(&chi->free_lock);
			line = prev_line;
			goto retry;
		}
	}
	//by the time we get here, we've got a line with sufficient space
	lockdep_assert_held(&line->lock);
	addr = __qblk_alloc_page(qblk, line, nr_secs);
	line->left_msecs -= nr_secs;
	WARN(line->left_msecs < 0, "qblk: page allocation out of bounds\n");
	spin_unlock(&line->lock);
	*pline = line;

	//pr_notice("%s,addr=0x%llx\n",__func__,addr.ppa);

	return addr;
}

#endif

//---not finished yet!
void qblk_discard_req(struct qblk *qblk, struct request *req)
{
#if 0
	struct bio *bio;

	__rq_for_each_bio(bio, req) {
		sector_t slba = qblk_get_lba(bio);
		sector_t nr_secs = qblk_get_secs(bio);
		//---
		/*pblk_invalidate_range(qblk, slba, nr_secs);*/
	}
	#endif
}

int qblk_update_map_gc(struct qblk *qblk, struct qblk_rb *rb,
				sector_t lba, struct ppa_addr ppa_new,
		       struct qblk_line *gc_line, u64 paddr_gc)
{
	struct ppa_addr ppa_gc;
	int ret = 1;
#ifdef QBLK_TRANSMAP_LOCK
	struct ppa_addr ppa_l2p;
#endif

#ifdef CONFIG_NVM_DEBUG
	/* Callers must ensure that the ppa points to a cache address */
	BUG_ON(!qblk_addr_in_cache(ppa_new));
	BUG_ON(qblk_rb_pos_oob(rb, qblk_addr_to_cacheline(ppa_new)));
#endif

	/* logic error: lba out-of-bounds. Ignore update */
	if (!(lba < qblk->rl.nr_secs)) {
		WARN(1, "qblk: corrupted L2P map request\n");
		return 0;
	}

	ppa_gc = offset_in_line_to_gen_ppa(qblk, paddr_gc,
				gc_line->chi->ch_index, gc_line->id);

#ifdef QBLK_TRANSMAP_LOCK
	spin_lock(&qblk->trans_lock);
	ppa_l2p = qblk_trans_map_get(qblk, lba);
				
	/* Do not update L2P if the cacheline has been updated. In this case,
	 * the mapped ppa must be invalidated
	 */
	if (!qblk_ppa_comp(ppa_l2p, ppa_gc)) {
			if (!qblk_ppa_empty(ppa_new))
				qblk_map_invalidate(qblk, ppa_new);
			goto out;
	}
				
#ifdef CONFIG_NVM_DEBUG
	WARN_ON(!qblk_addr_in_cache(ppa_l2p) && !qblk_ppa_empty(ppa_l2p));
#endif
	qblk_trans_map_set(qblk, lba, ppa_new);
out:
	spin_unlock(&qblk->trans_lock);
#else
	/* When cmp_and_xchg failed,
	 * it means that @ppa_gc holds out-dated data.
	 * We'll return 0 so that caller will
	 * delete cacheline's lba.
	 */
	if (qblk_trans_map_tomic_cmp_and_xchg(qblk, lba,
				ppa_gc, ppa_new))
			ret = 0;
#endif

	return ret;
}

void qblk_update_map_dev(struct qblk *qblk,
			sector_t lba, struct ppa_addr ppa_mapped,
			struct ppa_addr ppa_cache)
{
#ifdef QBLK_TRANSMAP_LOCK
	struct ppa_addr ppa_l2p;
#endif
	//pr_notice("%s,lba=%lu,ppa_mapped=0x%llx,ppa_cache=0x%llx\n",__func__,lba,ppa_mapped.ppa,ppa_cache.ppa);

#ifdef CONFIG_NVM_DEBUG
	/* Callers must ensure that the ppa points to a device address */
	BUG_ON(qblk_addr_in_cache(ppa_mapped));
#endif
	/* Invalidate and discard padded entries */
	if (lba == ADDR_EMPTY) {
#ifdef CONFIG_NVM_DEBUG
		atomic_long_inc(&qblk->padded_wb);
#endif
		if (!qblk_ppa_empty(ppa_mapped))
			qblk_map_invalidate(qblk, ppa_mapped);

		return;
	}

	/* logic error: lba out-of-bounds. Ignore update */
	if (!(lba < qblk->rl.nr_secs)) {
		WARN(1, "qblk: corrupted L2P map request\n");
		return;
	}
#ifdef QBLK_TRANSMAP_LOCK
	spin_lock(&qblk->trans_lock);
	ppa_l2p = qblk_trans_map_get(qblk, lba);

	/* Do not update L2P if the cacheline has been updated. In this case,
	 * the mapped ppa must be invalidated
	 */
	if (!qblk_ppa_comp(ppa_l2p, ppa_cache)) {
		if (!qblk_ppa_empty(ppa_mapped))
			qblk_map_invalidate(qblk, ppa_mapped);
		goto out;
	}

#ifdef CONFIG_NVM_DEBUG
	WARN_ON(!qblk_addr_in_cache(ppa_l2p) && !qblk_ppa_empty(ppa_l2p));
#endif

	qblk_trans_map_set(qblk, lba, ppa_mapped);
out:
	spin_unlock(&qblk->trans_lock);
#else
	if (qblk_trans_map_tomic_cmp_and_xchg(qblk, lba,
					ppa_cache, ppa_mapped)) {
		/* cmp_and_xchg failed.
		 * This measn that this cacheline holds out-dated data.
		 * We need to invalidate the ppa
		 */
		if  (!qblk_ppa_empty(ppa_mapped))
			qblk_map_invalidate(qblk, ppa_mapped);
	}
#endif
}

void qblk_update_map(struct qblk *qblk, sector_t lba, struct ppa_addr ppa)
{
	struct ppa_addr ppa_l2p;
	/* logic error: lba out-of-bounds. Ignore update */
	if (!(lba < qblk->rl.nr_secs)) {
		WARN(1, "qblk: corrupted L2P map request\n");
		return;
	}
#ifdef QBLK_TRANSMAP_LOCK
	spin_lock(&qblk->trans_lock);
	ppa_l2p = qblk_trans_map_get(qblk, lba);

	if (!qblk_addr_in_cache(ppa_l2p) && !qblk_ppa_empty(ppa_l2p))
		qblk_map_invalidate(qblk, ppa_l2p);
	
	qblk_trans_map_set(qblk, lba, ppa);
	spin_unlock(&qblk->trans_lock);
#else
	ppa_l2p = qblk_trans_map_atomic_get_and_set(qblk, lba, ppa);

	if (!qblk_addr_in_cache(ppa_l2p) && !qblk_ppa_empty(ppa_l2p))
		qblk_map_invalidate(qblk, ppa_l2p);
#endif
}

void qblk_update_map_cache(struct qblk *qblk,
			struct qblk_rb *rb, sector_t lba, struct ppa_addr ppa)
{
#ifdef CONFIG_NVM_DEBUG
	/* Callers must ensure that the ppa points to a cache address */
	BUG_ON(!qblk_addr_in_cache(ppa));
	BUG_ON(qblk_rb_pos_oob(rb, qblk_addr_to_cacheline(ppa)));
#endif
	qblk_update_map(qblk, lba, ppa);
}

//---
/* Caller must guarantee that the request is a valid type */
struct nvm_rq *qblk_alloc_rqd_nowait(struct qblk *qblk, int type)
{
	mempool_t *pool;
	struct nvm_rq *rqd;
	int rq_size;

	switch (type) {
	case QBLK_WRITE:
	case QBLK_WRITE_INT:
		pool = qblk->w_rq_pool;
		rq_size = qblk_w_rq_size;
		break;
	case QBLK_READ:
		pool = qblk->r_rq_pool;
		rq_size = qblk_g_rq_size;
		break;
	default:
		pool = qblk->e_rq_pool;
		rq_size = qblk_g_rq_size;
	}

	rqd = mempool_alloc(pool, GFP_ATOMIC);
	if (!rqd)
		return NULL;
	memset(rqd, 0, rq_size);

	return rqd;
}

void qblk_free_rqd(struct qblk *qblk, struct nvm_rq *rqd, int type)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	mempool_t *pool;

	switch (type) {
	case QBLK_WRITE:
	case QBLK_WRITE_INT:
		pool = qblk->w_rq_pool;
		break;
	case QBLK_READ:
		pool = qblk->r_rq_pool;
		break;
	case QBLK_ERASE:
		pool = qblk->e_rq_pool;
		break;
	default:
		pr_err("qblk: trying to free unknown rqd type\n");
		return;
	}

	nvm_dev_dma_free(dev->parent, rqd->meta_list, rqd->dma_meta_list);
	mempool_free(rqd, pool);
}

int qblk_submit_io(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct nvm_tgt_dev *dev = qblk->dev;
#if 0
	int ret;

	ret = qblk_check_io(qblk, rqd);//---
	if (ret)
		return ret;
#endif
	atomic_inc(&qblk->inflight_io);
	return nvm_submit_io(dev, rqd);
}

int qblk_submit_io_sync(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct nvm_tgt_dev *dev = qblk->dev;

#if 0
	int ret;

	ret = pblk_check_io(pblk, rqd);
	if (ret)
		return ret;
#endif

	atomic_inc(&qblk->inflight_io);
	return nvm_submit_io_sync(dev, rqd);
}

int qblk_line_read_emeta(struct qblk *qblk, struct qblk_line *line,
			 void *emeta_buf)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct ch_info *chi = line->chi;
	struct nvm_geo *geo = &dev->geo;
	void *ppa_list, *meta_list;
	struct bio *bio;
	struct nvm_rq rqd;
	dma_addr_t dma_ppa_list, dma_meta_list;
	int min = qblk->min_write_pgs;
	int left_ppas = meta->emeta_sec[0];
	int id = line->id;
	int rq_ppas, rq_len;
	int cmd_op, bio_op;
	int i, j;
	int ret;
	u64 paddr = line->emeta_ssec;

	bio_op = REQ_OP_READ;
	cmd_op = NVM_OP_PREAD;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&dma_meta_list);
	if (!meta_list)
		return -ENOMEM;

	ppa_list = meta_list + qblk_dma_meta_size;
	dma_ppa_list = dma_meta_list + qblk_dma_meta_size;

next_rq:
	memset(&rqd, 0, sizeof(struct nvm_rq));

	rq_ppas = qblk_calc_secs(qblk, left_ppas, 0);
	rq_len = rq_ppas * geo->sec_size;

	bio = qblk_bio_map_addr(qblk, emeta_buf, rq_ppas, rq_len,
					meta->emeta_alloc_type, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto free_rqd_dma;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, bio_op, 0);

	rqd.bio = bio;
	rqd.meta_list = meta_list;
	rqd.ppa_list = ppa_list;
	rqd.dma_meta_list = dma_meta_list;
	rqd.dma_ppa_list = dma_ppa_list;
	rqd.opcode = cmd_op;
	rqd.nr_ppas = rq_ppas;

	for (i = 0; i < rqd.nr_ppas; ) {
		struct ppa_addr ppa = offset_in_line_to_gen_ppa(qblk, paddr, chi->ch_index, id);
		int pos = qblk_ppa_to_posinsidechnl(geo, ppa);
		int read_type = QBLK_READ_RANDOM;

		if (qblk_io_aligned(qblk, rq_ppas))
			read_type = QBLK_READ_SEQUENTIAL;
		rqd.flags = qblk_set_read_mode(qblk, read_type);

		while (test_bit(pos, line->blk_bitmap)) {
			paddr += min;
			if (qblk_boundary_paddr_checks(qblk, paddr)) {
				pr_err("qblk: corrupt emeta line:%d\n",
							line->id);
				bio_put(bio);
				ret = -EINTR;
				goto free_rqd_dma;
			}

			ppa = offset_in_line_to_gen_ppa(qblk, paddr, chi->ch_index, id);
			pos = qblk_ppa_to_posinsidechnl(geo, ppa);
		}

		if (qblk_boundary_paddr_checks(qblk, paddr + min)) {
			pr_err("pblk: corrupt emeta line:%d\n",
							line->id);
			bio_put(bio);
			ret = -EINTR;
			goto free_rqd_dma;
		}
		for (j = 0; j < min; j++, i++, paddr++)
			rqd.ppa_list[i] =
				offset_in_line_to_gen_ppa(qblk, paddr, chi->ch_index, id);
	}

	//printRqdStatus(&rqd);
	ret = qblk_submit_io_sync(qblk, &rqd);
	if (ret) {
		pr_err("qblk: emeta I/O submission failed: %d\n", ret);
		bio_put(bio);
		goto free_rqd_dma;
	}

	atomic_dec(&qblk->inflight_io);

	if (rqd.error)
		qblk_log_read_err(qblk, &rqd);

	emeta_buf += rq_len;
	left_ppas -= rq_ppas;
	if (left_ppas)
		goto next_rq;
free_rqd_dma:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	return ret;
}

void qblk_log_read_err(struct qblk *qblk, struct nvm_rq *rqd)
{
	/* Empty page read is not necessarily an error (e.g., L2P recovery) */
	if (rqd->error == NVM_RSP_ERR_EMPTYPAGE) {
		atomic_long_inc(&qblk->read_empty);
		return;
	}

	switch (rqd->error) {
	case NVM_RSP_WARN_HIGHECC:
		atomic_long_inc(&qblk->read_high_ecc);
		break;
	case NVM_RSP_ERR_FAILECC:
	case NVM_RSP_ERR_FAILCRC:
		atomic_long_inc(&qblk->read_failed);
		break;
	default:
		pr_err("qblk: unknown read error:%d\n", rqd->error);
	}
}

void qblk_bio_free_pages(struct qblk *qblk,
			struct bio *bio, int off, int nr_pages)
{
	struct bio_vec bv;
	int i;

	WARN_ON(off + nr_pages != bio->bi_vcnt);

	for (i = off; i < nr_pages + off; i++) {
		bv = bio->bi_io_vec[i];
		mempool_free(bv.bv_page, qblk->page_bio_pool);
	}
}

int qblk_bio_add_pages(struct qblk *qblk,
			struct bio *bio, gfp_t flags,
		    int nr_pages)
{
	struct request_queue *q = qblk->dev->q;
	struct page *page;
	int i, ret;

	for (i = 0; i < nr_pages; i++) {
		page = mempool_alloc(qblk->page_bio_pool, flags);

		ret = bio_add_pc_page(q, bio, page, QBLK_EXPOSED_PAGE_SIZE, 0);
		if (ret != QBLK_EXPOSED_PAGE_SIZE) {
			pr_err("qblk: could not add page to bio\n");
			mempool_free(page, qblk->page_bio_pool);
			goto err;
		}
	}

	return 0;
err:
	qblk_bio_free_pages(qblk, bio, 0, i - 1);
	return -1;
}

u64 qblk_line_smeta_start(struct qblk *qblk, struct qblk_line *line)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	int bit;

	/* This usually only happens on bad lines */
	bit = find_first_zero_bit(line->blk_bitmap, meta->blk_per_chline);
	if (bit >= meta->blk_per_chline)
		return -1;

	return bit * geo->sec_per_pl;
}

int qblk_line_read_smeta(struct qblk *qblk, struct qblk_line *line)
{
	u64 bpaddr = qblk_line_smeta_start(qblk, line);

	return qblk_line_submit_smeta_io(qblk, line, bpaddr, QBLK_READ_RECOV);
}

void qblk_line_free(struct qblk *qblk, struct qblk_line *line)
{
	kfree(line->map_bitmap);
	kfree(line->invalid_bitmap);

	*line->vsc = cpu_to_le32(EMPTY_ENTRY);

	line->map_bitmap = NULL;
	line->invalid_bitmap = NULL;
	line->smeta = NULL;
	line->emeta = NULL;
}

struct qblk_line *qblk_line_get(struct qblk *qblk, struct ch_info *chi)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_line *line;
	int ret, bit;

	lockdep_assert_held(&chi->free_lock);

retry:
	if (list_empty(&chi->free_list)) {
		pr_err("qblk: no free lines, ch=%d\n",
									chi->ch_index);
		return NULL;
	}

	line = list_first_entry(&chi->free_list, struct qblk_line, list);
	list_del(&line->list);
	chi->nr_free_lines--;

	bit = find_first_zero_bit(line->blk_bitmap, meta->blk_per_chline);
	if (unlikely(bit >= meta->blk_per_chline)) {
		spin_lock(&line->lock);
		line->state = QBLK_LINESTATE_BAD;
		spin_unlock(&line->lock);

		list_add_tail(&line->list, &chi->bad_list);

		pr_debug("qblk: line %d is bad\n", line->id);
		goto retry;
	}

	ret = qblk_line_prepare(qblk, line);
	if (ret) {
		if (ret == -EAGAIN) {
			list_add(&line->list, &chi->corrupt_list);
			goto retry;
		} else {
			pr_err("qblk: failed to prepare line %d\n", line->id);
			list_add(&line->list, &chi->free_list);
			chi->nr_free_lines++;
			return NULL;
		}
	}
	/*if (!chi->ch_index)
		pr_notice("%s,ch=%d,get line=%d\n",__func__,chi->ch_index,line->id);*/
	return line;
}


//return 0 if succeed
int qblk_line_get_first_data(struct qblk *qblk)
{
	struct ch_info *chi;
	int ch_idx;
	struct qblk_line *line, *nextline;

	for (ch_idx = 0; ch_idx < qblk->nr_channels; ch_idx++) {
		chi = &qblk->ch[ch_idx];
		spin_lock(&chi->free_lock);
		line = qblk_line_get(qblk, chi);
		if (!line) {
			spin_unlock(&chi->free_lock);
			return -ENOSPC;
		}
		line->seq_nr = chi->d_seq_nr++;
		line->type = QBLK_LINETYPE_DATA;
		chi->data_line = line;
		qblk_line_setup_metadata(line, chi, &qblk->metainfo);
		/* Allocate next line for preparation */
		nextline = chi->data_next = qblk_line_get(qblk, chi);
		if (!nextline) {
			/* If we cannot get a new line, we need to stop the pipeline.
			 * Only allow as many writes in as we can store safely and then
			 * fail gracefully
			 */
			//pblk_set_space_limit(pblk);
			//chi->data_next = NULL;
			pr_err("qblk can't allocate data next\n");
			return -ENOSPC;
		}
		nextline->seq_nr = chi->d_seq_nr++;
		nextline->type = QBLK_LINETYPE_DATA;

		spin_unlock(&chi->free_lock);
		if (qblk_line_erase(qblk, ch_idx, line)) {
			/*line = pblk_line_retry(pblk, line);//----
			if (!line)
				return NULL;*/
			pr_err("%s,line(%d),qblk_line_erase() failed\n",
						__func__, __LINE__);
			return -EIO;
		}
		if (qblk_line_erase(qblk, ch_idx, nextline)) {
			/*line = pblk_line_retry(pblk, line);//----
			if (!line)
				return NULL;*/
			pr_err("%s,line(%d),qblk_line_erase() failed\n",
						__func__, __LINE__);
			return -EIO;
		}

	//retry_setup:
		if (!qblk_line_init_metadata(qblk, chi, line, NULL)) {
			/*line = pblk_line_retry(pblk, line);
			if (!line)
				return NULL;

			goto retry_setup;*/
			pr_err("%s,line(%d),qblk_line_init_metadata() failed\n",
							__func__, __LINE__);
			return -ENOSPC;
		}

		if (!qblk_line_init_bb(qblk, chi, line, 1)) {
			/*line = pblk_line_retry(pblk, line);//---
			if (!line)
				return NULL;

			goto retry_setup;*/
			pr_err("%s,line(%d),qblk init bb failed\n",
							__func__, __LINE__);
			return -ENOSPC;
		}

		qblk_rl_free_lines_dec(&chi->per_ch_rl, line, true);

	}

	return 0;
}


void qblk_write_should_kick(struct qblk *qblk, int index)
{
	unsigned int secs_avail = qblk_rb_read_count(&qblk->mqrwb[index]);

	if (secs_avail >= qblk->min_write_pgs)
		qblk_write_kick(qblk, index);
}

#ifdef QBLK_TRANSMAP_LOCK
struct ppa_addr qblk_lookup_l2p(struct qblk *qblk,
			 sector_t blba)
{
	struct ppa_addr ppa;

	spin_lock(&qblk->trans_lock);
	ppa = qblk_trans_map_get(qblk, blba);
	if (!qblk_ppa_empty(ppa) && !qblk_addr_in_cache(ppa)) {
		struct qblk_line *line = qblk_ppa_to_structline(qblk, ppa);

		kref_get(&line->ref);
	}
	spin_unlock(&qblk->trans_lock);
	return ppa;
}
#endif


