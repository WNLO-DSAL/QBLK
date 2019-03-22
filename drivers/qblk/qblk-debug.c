#include "qblk.h"
#define DEBUGCHNLS (2)


#define TEST_SECS_PER_REQ (8)
#define TEST_SECS_ORDER_PER_REQ (3)

static struct qblk *debugqblk;

static char ls_name[30][30] = {"TYPE_FREE",
								"TYPE_LOG",
								"TYPE_DATA",
								"",
								"",
								"",
								"",
								"",
								"",
								"NEW",
								"FREE",
								"OPEN",
								"CLOSED",
								"GC",
								"BAD",
								"CORRUPT",
								"",
								"",
								"",
								"",
								"GC_NONE",
								"GC_EMPTY",
								"GC_LOW",
								"GC_MID",
								"GC_HIGH",
								"GC_FULL"
								};

void printRqdStatus(struct nvm_rq *rqd)
{
	int i;
	struct ppa_addr *p_ppa;

	pr_notice("---------%s-------\n", __func__);

	pr_notice("opcode[%d] nr_ppas[%u] \n",
				rqd->opcode, rqd->nr_ppas);
	if (rqd->nr_ppas == 1) {
		pr_notice("ppa[%llx]\n", rqd->ppa_addr.ppa);
	}
	else {
		p_ppa = rqd->ppa_list;
		for (i = 0; i < rqd->nr_ppas; i++) {
			pr_notice("ppa[%llx]\n", p_ppa->ppa);
			p_ppa++;
		}
	}
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}


void printBufSample(void *data)
{
	int i;
	unsigned long long *p = data;

	pr_notice("---------%s-------\n", __func__);
	for (i = 0; i < 16; i++) {
		pr_notice("0x%llx\n", *p);
		p++;
	}
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

void print_gcrq_status(struct qblk_gc_rq *gc_rq)
{
	int nsec = gc_rq->nr_secs;
	int i;

	pr_notice("---------%s-------\n", __func__);
	pr_notice("ch[%d], line[%u], nrsecs[%d], secstogc[%d]\n",
				gc_rq->chi->ch_index, gc_rq->line->id,
				gc_rq->nr_secs,
				gc_rq->secs_to_gc);
	for (i = 0; i < nsec; i++) {
		pr_notice("lba[0x%llx], ppa[0x%llx]\n",
						gc_rq->lba_list[i],
						gc_rq->paddr_list[i]);
	}
	
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

/*-------------------------------printDebug------------------------------*/

static void qblk_print_debugentry(struct qblk_debug_entry *entry, int index)
{
	struct timeval *time1 = &entry->time;
	struct timeval *time2 = &entry->time2;
	struct timeval *time3 = &entry->time3;

	pr_notice("type=%d=TS=%ld=ppa=%x=%x=%x=%x=%x=%x=NS=%d=ts1=%ld=tus1=%ld=ts2=%ld=tus2=%ld=ts3=%ld=tus3=%ld\n",
		entry->type,
		1000000 * (time2->tv_sec-time1->tv_sec) +
			time2->tv_usec - time1->tv_usec,
		entry->firstppa.g.ch, entry->firstppa.g.lun,
		entry->firstppa.g.pl, entry->firstppa.g.sec,
		entry->firstppa.g.pg, entry->firstppa.g.blk,
		entry->nr_secs,
		time1->tv_sec, time1->tv_usec,
		time2->tv_sec, time2->tv_usec,
		time3->tv_sec, time3->tv_usec
		);
}

static void qblk_print_debug(struct qblk *qblk,
			int chnl, int irqsave)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];
	unsigned long flags;
	int i;
	int end;

	if (chnl >= DEBUGCHNLS)
		return;

	if (irqsave)
		spin_lock_irqsave(&qblk->debug_printing_lock, flags);
	else
		spin_lock(&qblk->debug_printing_lock);
	spin_lock(&header->lock);
	end = header->p;
	pr_notice("------------print logs of ch[%d]---------------\n", chnl);
	for (i = 0; i < end; i++)
		qblk_print_debugentry(&header->entries[i], i);
	pr_notice("============print logs of ch[%d]===============\n", chnl);
	spin_unlock(&header->lock);
	if (irqsave)
		spin_unlock_irqrestore(&qblk->debug_printing_lock, flags);
	else
		spin_unlock(&qblk->debug_printing_lock);
}

void qblk_debug_complete_time(struct qblk *qblk,
			int index, int chnl)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];

	if (!qblk->debugstart)
		return;
	if (chnl >= DEBUGCHNLS)
		return;
	if (index < 0)
		return;
	do_gettimeofday(&header->entries[index].time2);
}

void qblk_debug_complete_time3(struct qblk *qblk,
			int index, int chnl)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];

	if (!qblk->debugstart)
		return;
	if (chnl >= DEBUGCHNLS)
		return;
	if (index < 0)
		return;
	do_gettimeofday(&header->entries[index].time3);
}

void qblk_debug_time_irqsave(struct qblk *qblk,
			int *pindex, int chnl,
			struct qblk_debug_entry entry)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];
	unsigned long flags;
	int index;
	struct qblk_debug_entry *debug_entry;

	if (!qblk->debugstart)
		return;
	if (chnl >= DEBUGCHNLS)
		return;
	spin_lock_irqsave(&header->lock, flags);
	index = header->p++;
	if (index >= QBLK_DEBUG_ENTRIES_PER_CHNL) {
		header->p--;
		spin_unlock_irqrestore(&header->lock, flags);
		if (pindex)
			*pindex = -1;
		return;
	}
	spin_unlock_irqrestore(&header->lock, flags);

	debug_entry = &header->entries[index];
	debug_entry->type = entry.type;
	debug_entry->firstppa = entry.firstppa;
	debug_entry->nr_secs = entry.nr_secs;
	do_gettimeofday(&debug_entry->time);
	if (pindex)
		*pindex = index;
}

void qblk_debug_time(struct qblk *qblk,
				int *pindex, int chnl,
				struct qblk_debug_entry entry)
{
	struct qblk_debug_header *header =
				&qblk->debugHeaders[chnl];
	int index;
	struct qblk_debug_entry *debug_entry;

	if (chnl >= DEBUGCHNLS)
		return;
	if (!qblk->debugstart)
		return;
	spin_lock(&header->lock);
	index = header->p++;
	if (index >= QBLK_DEBUG_ENTRIES_PER_CHNL) {
		header->p--;
		spin_unlock(&header->lock);
		if (pindex)
			*pindex = -1;
		return;
	}
	spin_unlock(&header->lock);

	debug_entry = &header->entries[index];
	debug_entry->type = entry.type;
	debug_entry->firstppa = entry.firstppa;
	debug_entry->nr_secs = entry.nr_secs;
	do_gettimeofday(&header->entries[index].time);
	if (pindex)
		*pindex = index;
}


/*-------------------------------IOtest------------------------------*/

static void qblk_end_test_ioerase(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;

	mempool_free(rqd, qblk->e_rq_pool);
	atomic_dec(&qblk->inflight_io);
}


int qblk_blk_erase_test_async(struct qblk *qblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int err;

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_ERASE);
	if (!rqd)
		return -ENOMEM;

	rqd->opcode = NVM_OP_ERASE;
	rqd->ppa_addr = ppa;
	rqd->nr_ppas = 1;
	rqd->flags = qblk_set_progr_mode(qblk, QBLK_ERASE);
	rqd->bio = NULL;

	rqd->end_io = qblk_end_test_ioerase;
	rqd->private = qblk;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	err = qblk_submit_io(qblk, rqd);
	if (err)
		pr_err("qblk: could not async erase line:%d,ppa:0x%llx\n",
					qblk_ppa_to_line(ppa),
					ppa.ppa);

	return err;
}


static void qblk_end_test_async_iowrite(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		pr_err("%s, err=%d\n", __func__, rqd->error);
		return;
	}
	if (c_ctx->nr_padded)
		qblk_debug_complete_time(qblk, c_ctx->logindex, c_ctx->ch_index);
	atomic_dec(&qblk->inflight_io);
	free_pages((unsigned long)c_ctx->lun_bitmap, TEST_SECS_ORDER_PER_REQ);
	bio_put(rqd->bio);
	qblk_free_rqd(qblk, rqd, QBLK_WRITE);
	if (c_ctx->nr_padded)
		qblk_debug_complete_time3(qblk, c_ctx->logindex, c_ctx->ch_index);
}


static int qblk_submit_test_iowrite_async(struct qblk *qblk,
				struct ppa_addr ppa_addr, int logtime)
{
	struct nvm_rq *rqd;
	struct bio *bio;
	unsigned long data;
	int i;
	struct request_queue *q = qblk->dev->q;
	struct ppa_addr *ppa_list;
	struct qblk_debug_entry logentry;
	struct qblk_c_ctx *c_ctx;
	int err;

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_WRITE);
	if (!rqd) {
		pr_notice("%s: not enough space for rqd\n", __func__);
		return 1;
	}

	bio = bio_alloc(GFP_KERNEL, TEST_SECS_PER_REQ);
	if (!bio) {
		pr_err("%s: not enough space for bio\n", __func__);
		return 1;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);


	qblk_alloc_w_rq(qblk, rqd, TEST_SECS_PER_REQ,
				qblk_end_test_async_iowrite);

	rqd->bio = bio;

	data = __get_free_pages(GFP_ATOMIC, TEST_SECS_ORDER_PER_REQ);
	if (!data) {
		pr_err("%s: not enough space for data\n", __func__);
		return 1;
	}
	for (i = 0; i < TEST_SECS_PER_REQ; i++) {
		struct page *page = virt_to_page(data+i*PAGE_SIZE);

		bio_add_pc_page(q, bio, page, PAGE_SIZE, 0);
	}

	ppa_list = rqd->ppa_list;
	for (i = 0 ; i < TEST_SECS_PER_REQ; i++) {
		ppa_list[i] = ppa_addr;
		ppa_addr = gen_ppa_add_one_inside_chnl(qblk, ppa_addr);
	}

	c_ctx = nvm_rq_to_pdu(rqd);
	c_ctx->ch_index = ppa_addr.g.ch;
	c_ctx->lun_bitmap = (unsigned long *)data;
	logentry.type = QBLK_SUBMIT_IOWRITE;
	logentry.firstppa = rqd->ppa_list[0];
	logentry.nr_secs = rqd->nr_ppas;
	c_ctx->nr_padded = logtime;
	if (logtime)
		qblk_debug_time_irqsave(qblk, &c_ctx->logindex,
						ppa_addr.g.ch, logentry);
	err = qblk_submit_io(qblk, rqd);
	if (err) {
		pr_err("qblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}
	return 0;

}


static int qblk_submit_test_iowrite_sync(struct qblk *qblk,
					struct ppa_addr ppa_addr, int logtime)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_rq rqd;
	struct bio *bio;
	unsigned long data;
	int i;
	struct request_queue *q = qblk->dev->q;
	struct ppa_addr *ppa_list;
	struct qblk_debug_entry logentry;
	int logindex;
	int err;

	memset(&rqd, 0, sizeof(struct nvm_rq));

	bio = bio_alloc(GFP_KERNEL, TEST_SECS_PER_REQ);
	if (!bio) {
		pr_err("%s: not enough space for bio\n", __func__);
		return 1;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd.bio = bio;
	data = __get_free_pages(GFP_ATOMIC, TEST_SECS_ORDER_PER_REQ);
	if (!data) {
		pr_err("%s: not enough space for data\n", __func__);
		return 1;
	}
	for (i = 0; i < TEST_SECS_PER_REQ; i++) {
		struct page *page = virt_to_page(data+i*PAGE_SIZE);

		bio_add_pc_page(q, bio, page, PAGE_SIZE, 0);
	}

	rqd.meta_list = nvm_dev_dma_alloc(dev->parent, GFP_ATOMIC,
							&rqd.dma_meta_list);
	if (!rqd.meta_list)
		return -ENOMEM;

	rqd.ppa_list = rqd.meta_list + qblk_dma_meta_size;
	rqd.dma_ppa_list = rqd.dma_meta_list + qblk_dma_meta_size;

	rqd.opcode = NVM_OP_PWRITE;
	rqd.flags = qblk_set_progr_mode(qblk, QBLK_WRITE);
	rqd.nr_ppas = TEST_SECS_PER_REQ;

	ppa_list = rqd.ppa_list;
	for (i = 0; i < TEST_SECS_PER_REQ; i++) {
		ppa_list[i] = ppa_addr;
		ppa_addr = gen_ppa_add_one_inside_chnl(qblk, ppa_addr);
	}

	logentry.type = QBLK_SUBMIT_IOWRITE;
	logentry.firstppa = rqd.ppa_list[0];
	logentry.nr_secs = rqd.nr_ppas;
	if (logtime)
		qblk_debug_time_irqsave(qblk, &logindex, ppa_addr.g.ch, logentry);
	err = qblk_submit_io_sync(qblk, &rqd);
	if (err) {
		pr_err("qblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}
	if (logtime)
		qblk_debug_complete_time(qblk, logindex, ppa_addr.g.ch);
	atomic_dec(&qblk->inflight_io);

	if (rqd.error)
		pr_err("%s, err = %d\n", __func__, rqd.error);

	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	free_pages(data, TEST_SECS_ORDER_PER_REQ);
	bio_put(bio);
	return 0;

}

static void qblk_iotest(struct qblk *qblk)
{
	struct ppa_addr ppa;
	//int logindex;
	struct qblk_debug_entry entry;
	int ch, lun;
	int pg;
	int blk;
	int pl;

	return;

	pr_notice("--------------------------------test begin\n");
	ppa.g.ch = 0;
	ppa.g.lun = 0;
	ppa.g.pl = 0;
	ppa.g.sec = 0;
	ppa.g.blk = 6;

	entry.nr_secs = 1;
	entry.type = QBLK_SUBMIT_SYNC_ERASE;
	for (blk = 2; blk < 2; blk++) {
		pr_emerg("%s, erasing blk[%d]\n", __func__, blk);
		for (ch = 0; ch < 17; ch++) {
			for (lun = 0; lun < 4; lun++) {
				for (pl = 0; pl < 2; pl++) {
					ppa.g.ch = ch;
					ppa.g.lun = lun;
					ppa.g.blk = blk;
					ppa.g.pl = pl;
					entry.firstppa = ppa;
					//qblk_debug_time_irqsave(qblk, &logindex, ch, entry);
					qblk_blk_erase_test_async(qblk, ppa);
					//qblk_debug_complete_time(qblk, logindex, ch);
				}
			}
		}
	}
	//msleep(1000);

	ppa.g.blk = 6;
	for (pg = 0; pg < 4; pg++) {
		for (lun = 0; lun < 4; lun++) {
			for (ch = 0; ch < 1; ch++) {
				ppa.g.pg = pg;
				ppa.g.ch = ch;
				ppa.g.lun = lun;
				//qblk_submit_test_iowrite_async(qblk, ppa,1);
				qblk_submit_test_iowrite_sync(qblk, ppa, 1);

			}
		}
	}

	//msleep(1000);
	for (pg = 0; pg < 4; pg++) {
		for (lun = 0; lun < 4; lun++) {
			for (ch = 0; ch < 1; ch++) {
				ppa.g.pg = pg;
				ppa.g.ch = ch;
				ppa.g.lun = lun;
				//qblk_submit_test_iowrite_async(qblk, ppa,1);
				qblk_submit_test_iowrite_sync(qblk, ppa, 1);

			}
		}
	}

	for (pg = 0; pg < 4; pg++) {
		for (lun = 0; lun < 4; lun++) {
			for (ch = 0; ch < 1; ch++) {
				ppa.g.pg = pg;
				ppa.g.ch = ch;
				ppa.g.lun = lun;
				//qblk_submit_test_iowrite_async(qblk, ppa,1);
				qblk_submit_test_iowrite_sync(qblk, ppa, 1);
			}
		}
	}

	//msleep(1000);
	qblk_print_debug(qblk, 0, 1);
	return;
//=================================================================
	ppa.g.blk = 6;
	ppa.g.ch = 17;
	ppa.g.lun = 0;

	for (pg = 0; pg < 8; pg++) {
		qblk_submit_test_iowrite_async(qblk, ppa, 0);
		ppa.g.pg++;
	}
//-----------------------------------------------------------------
	ppa.g.ch = ch;
	ppa.g.lun = lun;
	ppa.g.blk = blk;
	entry.firstppa = ppa;
	//qblk_debug_time_irqsave(qblk, &logindex, ch, entry);
	qblk_blk_erase_test_async(qblk, ppa);
	//qblk_debug_complete_time(qblk, logindex, ch);
}
//-------------------------------------------------------------------------------------------------


/*-------------------------------debugA------------------------------*/
static void debugA(void)
{
	struct qblk *qblk = debugqblk;
	struct qblk_gc *gc_array = qblk->per_channel_gc;
	//struct qblk_gc *gc;
	//int ch = qblk->nr_channels;
	//int i;

	pr_notice("%s, gc_array=%p\n", __func__, gc_array);
#if 0
	gc = &gc_array[1];
	del_timer(&gc->gc_timer);
	pr_notice("del_timer finished\n");
	gc = &gc_array[2];
	del_timer_sync(&gc->gc_timer);
	pr_notice("del_timer_sync finished\n");
#endif

#if 0
	for (i = 0; i < ch; i++) {
		gc = &gc_array[i];
		atomic_set(&gc->gc_enabled, 0);
		atomic_set(&gc->gc_active, 0);
		del_timer_sync(&gc->gc_timer);
		//del_timer(&gc->gc_timer);
	}
#endif
#if 0
#if 1
	while (ch--) {
		gc = &gc_array[ch];
		atomic_set(&gc->gc_enabled, 0);
		atomic_set(&gc->gc_active, 0);
		del_timer_sync(&gc->gc_timer);

		flush_workqueue(gc->gc_reader_wq);
		if (gc->gc_reader_wq)
			destroy_workqueue(gc->gc_reader_wq);

		flush_workqueue(gc->gc_line_reader_wq);
		if(gc->gc_line_reader_wq)
			destroy_workqueue(gc->gc_line_reader_wq);

		if (gc->gc_reader_ts)
			kthread_stop(gc->gc_reader_ts);
		if (gc->gc_writer_ts)
			kthread_stop(gc->gc_writer_ts);
		if (gc->gc_ts)
			kthread_stop(gc->gc_ts);
	}
#endif
	kfree(gc_array);
#endif
	qblk_gc_exit(qblk);
}

/* usage: "e @chnl @lun @pl @blk @page @sector"*/
static void qblk_test_erase(struct qblk *qblk,char *usrCommand)
{
	struct ppa_addr ppa;
	int ch, lun, pl, blk, pg, sec;
	sscanf(usrCommand, "%d %d %d %d %d %d", &ch, &lun,
					&pl, &blk, &pg, &sec);
	ppa.g.ch = ch;
	ppa.g.lun =lun;
	ppa.g.pl = pl;
	ppa.g.blk = blk;
	ppa.g.pg = pg;
	ppa.g.sec = sec;
	pr_notice("%s, ppa = 0x%llx\n",
						__func__, ppa.ppa);

	qblk_blk_erase_test_async(qblk, ppa);
	return;
}


static void __print_line_info(struct qblk *qblk,
					int ch_idx, int line_id)
{
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct qblk_line *line = &chi->lines[line_id];

	pr_notice("----%s,ch[%d] line[%d]-----\n",
						__func__, ch_idx, line_id);

	pr_notice("left_eblks(Blocks left for erasing)=%u\n", atomic_read(&line->left_eblks));
	pr_notice("left_seblks(Blocks left for sync erasing)=%u\n", atomic_read(&line->left_seblks));
	pr_notice("left_msecs(Sectors left for mapping)=%d\n", line->left_msecs);
	pr_notice("ref=%u\n", kref_read(&line->ref));
	pr_notice("vsc=%d\n", qblk_line_vsc(line));
	pr_notice("nr_valid_lbas=%u\n", line->nr_valid_lbas);
	pr_notice("smetaSsec[%llu] emetaSsec[%llu]\n",
				line->smeta_ssec, line->emeta_ssec);
	pr_notice("lineState=%s(%d)\n", ls_name[line->state],line->state);
	pr_notice("lineRef[%d]\n", kref_read(&line->ref));
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "l @chnl @lineID"*/
static void qblk_printLineInfo(struct qblk *qblk, char *usrCommand)
{
	int ch_idx, line_id;

	sscanf(usrCommand, "%d %d", &ch_idx, &line_id);
	__print_line_info(qblk, ch_idx, line_id);
}

static void __print_rl_info(struct qblk *qblk, int chnl)
{
	struct qblk_per_chnl_rl *rl = &qblk->ch[chnl].per_ch_rl;

	pr_notice("----%s,ch[%d]-----\n",
						__func__, chnl);

	pr_notice("veryHigh[%u] high[%u] mid[%u] rsv[%u]\n",
			rl->very_high, rl->high, rl->mid_blocks, rl->rsv_blocks);
	pr_notice("free_blks[%u] free_usrBlks[%u]\n",
			atomic_read(&rl->free_blocks), atomic_read(&rl->free_user_blocks));
	pr_notice("rb_gc_max[%u] chnl_state[%d](high1 mid2 low3)\n",
			atomic_read(&rl->rb_gc_max), rl->chnl_state);
	spin_lock(&rl->remain_secs_lock);
	pr_notice("remain_secs=%u\n", rl->remain_secs);
	spin_unlock(&rl->remain_secs_lock);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "r @chnl"*/
static void qblk_printRlInfo(struct qblk *qblk, char *usrCommand)
{
	int ch_idx;

	sscanf(usrCommand, "%d", &ch_idx);
	__print_rl_info(qblk, ch_idx);
}

static void __print_gc_info(struct qblk *qblk, int ch_idx)
{
	struct qblk_gc *gc = &qblk->per_channel_gc[ch_idx];
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct list_head *group_list;
	int gc_group;
	struct qblk_line *line;

	pr_notice("----%s,ch[%d]-----\n",
						__func__, ch_idx);
	pr_notice("gc->gc_enabled[%d]\n",
			atomic_read(&gc->gc_enabled)
			);
	for (gc_group = 0;
			gc_group < QBLK_GC_NR_LISTS;
			gc_group++) {
		group_list = chi->gc_lists[gc_group];
		if(list_empty(group_list)) {
			pr_notice("grouplist[%d] empty\n", gc_group);
			continue;
		}
		pr_notice("grouplist[%d] {\n", gc_group);
		list_for_each_entry(line, group_list, list) {
			pr_notice("<%u>\n", line->id);
		}
		pr_notice("}\n");
	}
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "c @chnl"*/
static void qblk_printGcInfo(struct qblk *qblk,char *usrCommand)
{
	int ch_idx;

	sscanf(usrCommand, "%d", &ch_idx);
	__print_gc_info(qblk, ch_idx);
}


/* usage: "g"*/
static void qblk_printGlobalRlInfo(struct qblk *qblk,char *usrCommand)
{
	struct qblk_rl *rl = &qblk->rl;

	pr_notice("----%s-----\n",
						__func__);

	pr_notice("nrsecs=%llu, total_blocks=%lu\n",
						rl->nr_secs,
						rl->total_blocks);
	pr_notice("per_chnl_limit=%d,rb_user_active=%d\n",
							rl->per_chnl_limit,
							rl->rb_user_active
							);
	pr_notice("rb_user_max=%d, rb_user_cnt=%d\n",
							atomic_read(&rl->rb_user_max),
							atomic_read(&rl->rb_user_cnt)
							);
	pr_notice("rb_gc_cnt=%d, rb_space=%d\n",
								atomic_read(&rl->rb_gc_cnt),
								atomic_read(&rl->rb_space)
							);
	pr_notice("gc_active=0x%lx\n", *qblk->gc_active);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}


static void __print_rb_info(struct qblk *qblk, int rb_idx)
{
	struct qblk_rb *rb = &qblk->mqrwb[rb_idx];

	printRbStatus(rb, rb_idx);
}

/* usage: "b @rb_index"*/
static void qblk_printRbInfo(struct qblk *qblk, char *usrCommand)
{
	int rb_idx;

	sscanf(usrCommand, "%d", &rb_idx);
	__print_rb_info(qblk, rb_idx);
	
}

/* usage: "s"*/
static void qblk_printSInfo(struct qblk *qblk,char *usrCommand)
{
	int nr_chnl = qblk->nr_channels;
	int nr_rb = qblk->nr_queues;
	int i, j;
	struct ch_info *chi;
	long totalvsc, chnlvsc;

	pr_notice("----%s  rbinfo-----\n", __func__);
	pr_notice("*************************************\n");
	for (i=0;i<nr_rb;i++)
		__print_rb_info(qblk, i);
	pr_notice("----%s  global rl-----\n", __func__);
	pr_notice("*************************************\n");
	qblk_printGlobalRlInfo(qblk, usrCommand);
	pr_notice("----%s  per_ch rl+gc+line-----\n", __func__);
	pr_notice("*************************************\n");
	totalvsc = 0;
	for (i = 0;i < nr_chnl; i++) {
		pr_notice("((((((((((chnl[%d]((((((((\n", i);
		chi = &qblk->ch[i];
		pr_notice("dataline=%u, datanext=%u\n",
							chi->data_line->id,
							chi->data_next->id);
		__print_rl_info(qblk, i);
		__print_gc_info(qblk, i);
		chnlvsc = 0;
		for (j = 0; j < chi->nr_lines; j++) {
			struct qblk_line *line = &chi->lines[j];
			int vsc;
			
			__print_line_info(qblk, i, j);
			vsc = qblk_line_vsc(line);
			if (vsc > 0) {
				chnlvsc += vsc;
				totalvsc += vsc;
			}
		}
		pr_notice(")))))chnl[%d] chnlvsc[%ld])))\n", i, chnlvsc);
	}
	pr_notice("<<<<<<<<<<<<%s>>totalvsc[%ld]>>>>>>>\n",
					__func__, totalvsc);
}


/* usage: "z"*/
static void qblk_printGeoInfo(struct qblk *qblk,char *usrCommand)
{
	struct nvm_geo *geo = &qblk->dev->geo;


	pr_notice("--------%s-----\n",
							__func__);
	pr_notice("max_rq_size[%d]\n", geo->max_rq_size);
	pr_notice("nr_chnls[%d] all_luns[%d] nr_luns[%d] nr_chks[%d]\n",
							geo->nr_chnls,
							geo->all_luns,
							geo->nr_luns,
							geo->nr_chks);
	pr_notice("ppaf:\n");
	pr_notice("blk_len[%d] blk_offset[%d] ch_len[%d] ch_offset[%d]\n",
		geo->ppaf.blk_len,
		geo->ppaf.blk_offset,
		geo->ppaf.ch_len,
		geo->ppaf.ch_offset);
	pr_notice("lun_len[%d] lun_offset[%d] pg_len[%d] pg_offset[%d]\n",
		geo->ppaf.lun_len,
		geo->ppaf.lun_offset,
		geo->ppaf.pg_len,
		geo->ppaf.pg_offset);
	pr_notice("pln_len[%d] pln_offset[%d] sect_len[%d] sect_offset[%d]\n",
		geo->ppaf.pln_len,
		geo->ppaf.pln_offset,
		geo->ppaf.sect_len,
		geo->ppaf.sect_offset);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>\n",
							__func__);
}


static ssize_t qblkDebug_write(struct file *file,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	char usrCommand[512];
	int ret;
	int i;
	struct qblk *qblk = debugqblk;

	ret = copy_from_user(usrCommand, buffer,count);
	//pr_notice("command:%s",usrCommand);
	switch (usrCommand[0]) {
	case 'a':
		pr_notice("%s, a\n", __func__);
		debugA();
		break;
	case 'b':
		pr_notice("%s, b\n", __func__);
		qblk_printRbInfo(qblk, &usrCommand[1]);
		break;
	case 'c':
		pr_notice("%s, c\n", __func__);
		qblk_printGcInfo(qblk, &usrCommand[1]);
		break;
	case 'e':
		qblk_test_erase(qblk, &usrCommand[1]);
		break;
	case 'g':
		pr_notice("%s, g\n", __func__);
		qblk_printGlobalRlInfo(qblk, &usrCommand[1]);
		break;
		break;
	case 'p':
		pr_notice("%s, p\n", __func__);
		for (i = 0; i < DEBUGCHNLS; i++)
			qblk_print_debug(qblk, i, 1);
		break;
	case 't':
		pr_notice("%s, t\n", __func__);
		qblk_iotest(qblk);
		break;
	case 'l':
		pr_notice("%s, l\n", __func__);
		qblk_printLineInfo(qblk, &usrCommand[1]);
		break;
	case 'r':
		pr_notice("%s, r\n", __func__);
		qblk_printRlInfo(qblk, &usrCommand[1]);
		break;
	case 's':
		pr_notice("%s, s\n", __func__);
		qblk_printSInfo(qblk, &usrCommand[1]);
		break;
	case 'z':
		pr_notice("%s, z\n", __func__);
		qblk_printGeoInfo(qblk, &usrCommand[1]);
		break;
	}
	return count;
}


static const struct file_operations qblkDebug_proc_fops = {
  .owner = THIS_MODULE,
  .write = qblkDebug_write,
};

void qblk_debug_init(struct qblk *qblk)
{
	int i;
	struct qblk_debug_header *header;

	debugqblk = qblk;
	qblk->debugHeaders = kmalloc_array(DEBUGCHNLS,
			sizeof(*qblk->debugHeaders), GFP_KERNEL);
	if (!qblk->debugHeaders)
		return;
	for (i = 0; i < DEBUGCHNLS; i++) {
		header = &qblk->debugHeaders[i];
		spin_lock_init(&header->lock);
		header->p = 0;
	}
	spin_lock_init(&qblk->debug_printing_lock);
	proc_create("qblkDebug", 0, NULL, &qblkDebug_proc_fops);
	qblk->debugstart = 1;
}

void qblk_debug_exit()
{
	remove_proc_entry("qblkDebug", NULL);
	kfree(debugqblk->debugHeaders);
}

