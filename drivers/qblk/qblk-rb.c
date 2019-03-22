#include <linux/circ_buf.h>

#include "qblk.h"

//declaration lock
static DECLARE_RWSEM(qblk_rb_lock);


#define qblk_rb_ring_count(head, tail, size) CIRC_CNT(head, tail, size)
#define qblk_rb_ring_space(rb, head, tail, size) \
					(CIRC_SPACE(head, tail, size))


unsigned int qblk_rb_sync_init(struct qblk_rb *rb, unsigned long *flags)
	__acquires(&rb->s_lock)
{
	if (flags)
		spin_lock_irqsave(&rb->s_lock, *flags);
	else
		spin_lock_irq(&rb->s_lock);

	//return rb->sync;
	return READ_ONCE(rb->sync);
}

void qblk_rb_sync_end(struct qblk_rb *rb, unsigned long *flags)
	__releases(&rb->s_lock)
{
	lockdep_assert_held(&rb->s_lock);

	if (flags)
		spin_unlock_irqrestore(&rb->s_lock, *flags);
	else
		spin_unlock_irq(&rb->s_lock);
}

unsigned int qblk_rb_sync_advance(struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int sync, flush_point;

	lockdep_assert_held(&rb->s_lock);

	sync = READ_ONCE(rb->sync);
	flush_point = READ_ONCE(rb->flush_point);

	//pr_notice("%s,sync=%u,flushpoint=%u\n",__func__,sync,flush_point);

	if (flush_point != EMPTY_ENTRY) {
		unsigned int secs_to_flush;

		secs_to_flush = qblk_rb_ring_count(flush_point, sync,
					rb->nr_entries);
		if (secs_to_flush < nr_entries) {
			/* Protect flush points */
			smp_store_release(&rb->flush_point, EMPTY_ENTRY);
		}
	}

	sync = (sync + nr_entries) & (rb->nr_entries - 1);

	/* Protect from counts */
	smp_store_release(&rb->sync, sync);
	//pr_notice("%s,sync=%u stored\n",__func__,sync);

	return sync;
}

/*
 * Buffer count is calculated with respect to the submission entry signaling the
 * entries that are available to send to the media
 */
unsigned int qblk_rb_read_count(struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int subm = READ_ONCE(rb->subm);

	return qblk_rb_ring_count(mem, subm, rb->nr_entries);
}

unsigned int qblk_rb_sync_count(struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int sync = READ_ONCE(rb->sync);

	return qblk_rb_ring_count(mem, sync, rb->nr_entries);
}

unsigned int qblk_rb_read_commit(struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int subm;

	subm = READ_ONCE(rb->subm);
	/* Commit read means updating submission pointer */
	smp_store_release(&rb->subm,
				(subm + nr_entries) & (rb->nr_entries - 1));

	return subm;
}

struct qblk_w_ctx *qblk_rb_w_ctx(struct qblk_rb *rb, unsigned int pos)
{
	unsigned int entry = pos & (rb->nr_entries - 1);

	return &rb->entries[entry].w_ctx;
}

/* Calculate how many sectors to submit up to the current flush point. */
unsigned int qblk_rb_flush_point_count(struct qblk_rb *rb)
{
	unsigned int subm, sync, flush_point;
	unsigned int submitted, to_flush;

	/* Protect flush points */
	flush_point = smp_load_acquire(&rb->flush_point);
	if (flush_point == EMPTY_ENTRY)
		return 0;

	/* Protect syncs */
	sync = smp_load_acquire(&rb->sync);

	subm = READ_ONCE(rb->subm);
	submitted = qblk_rb_ring_count(subm, sync, rb->nr_entries);

	/* The sync point itself counts as a sector to sync */
	to_flush = qblk_rb_ring_count(flush_point, sync, rb->nr_entries) + 1;

	return (submitted < to_flush) ? (to_flush - submitted) : 0;
}

static void clean_wctx(struct qblk_w_ctx *w_ctx)
{
	int flags;

try:
	flags = READ_ONCE(w_ctx->flags);
	if (!(flags & QBLK_SUBMITTED_ENTRY))
		goto try;

	/* Release flags on context. Protect from writes and reads */
	smp_store_release(&w_ctx->flags, QBLK_WRITABLE_ENTRY);
	qblk_ppa_set_empty(&w_ctx->ppa);
	w_ctx->lba = ADDR_EMPTY;
}

static int __qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int to_update)
{
	struct qblk_line *line;
	struct qblk_rb_entry *entry;
	struct qblk_w_ctx *w_ctx;
	unsigned int user_io = 0, gc_io = 0;
	unsigned int i;
	int flags;

	for (i = 0; i < to_update; i++) {
		entry = &rb->entries[rb->l2p_update];
		w_ctx = &entry->w_ctx;

		flags = READ_ONCE(entry->w_ctx.flags);
		if (flags & QBLK_IOTYPE_USER)
			user_io++;
		else if (flags & QBLK_IOTYPE_GC)
			gc_io++;
		else
			WARN(1, "qblk: unknown IO type\n");

		qblk_update_map_dev(qblk, w_ctx->lba, w_ctx->ppa,
							entry->cacheline);
		line = qblk_ppa_to_structline(qblk, w_ctx->ppa);
		kref_put(&line->ref, qblk_line_put);
		//pr_notice("%s,put the reference of line[%u]\n",__func__,line->id);
		clean_wctx(w_ctx);
		rb->l2p_update = (rb->l2p_update + 1) & (rb->nr_entries - 1);
	}

	qblk_rl_out(&qblk->rl,
			user_io, gc_io);

	return 0;
}


/*
 * When we move the l2p_update pointer, we update the l2p table - lookups will
 * point to the physical address instead of to the cacheline in the write buffer
 * from this moment on.
 */
static int qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int nr_entries,
			      unsigned int mem, unsigned int sync)
{
	unsigned int space, count;
	int ret = 0;

	lockdep_assert_held(&rb->w_lock);

	/* Update l2p only as buffer entries are being overwritten */
	space = qblk_rb_ring_space(rb, mem, rb->l2p_update, rb->nr_entries);
	if (space > nr_entries)
		goto out;

	count = nr_entries - space;
	/* l2p_update used exclusively under rb->w_lock */
	ret = __qblk_rb_update_l2p(qblk, rb, count);

out:
	return ret;
}

/*
 * Update the l2p entry for all sectors stored on the write buffer. This means
 * that all future lookups to the l2p table will point to a device address, not
 * to the cacheline in the write buffer.
 */
static void qblk_rb_sync_l2p(struct qblk *qblk, struct qblk_rb *rb)
{
	unsigned int sync;
	unsigned int to_update;

	spin_lock(&rb->w_lock);

	/* Protect from reads and writes */
	sync = smp_load_acquire(&rb->sync);

	to_update = qblk_rb_ring_count(sync, rb->l2p_update, rb->nr_entries);
	__qblk_rb_update_l2p(qblk, rb, to_update);

	spin_unlock(&rb->w_lock);
}

void qblk_rb_sync_all_l2p(struct qblk *qblk)
{
	unsigned int queue_count = qblk->nr_queues;
	while (queue_count--)
		qblk_rb_sync_l2p(qblk, &qblk->mqrwb[queue_count]);
}

static int __qblk_rb_may_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
				unsigned int *pos)
{
	unsigned int mem;
	unsigned int sync;

	sync = READ_ONCE(rb->sync);
	mem = READ_ONCE(rb->mem);

	//pr_notice("%s:sync=0x%x,mem=0x%x\n",__func__,sync,mem);

	if (qblk_rb_ring_space(rb, mem, sync, rb->nr_entries) < nr_entries)
		return 0;

	if (qblk_rb_update_l2p(qblk, rb, nr_entries, mem, sync))
		return 0;

	*pos = mem;

	return 1;
}


static int qblk_rb_may_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
			    unsigned int *pos)
{
	if (!__qblk_rb_may_write(qblk, rb, nr_entries, pos))
		return 0;

	/* Protect from read count */
	smp_store_release(&rb->mem, (*pos + nr_entries) & (rb->nr_entries - 1));
	return 1;
}

static int qblk_rb_may_write_flush(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
				unsigned int *pos, struct bio *bio,
				blk_status_t *io_ret)
{
	unsigned int mem;

	*pos = READ_ONCE(rb->mem);


	if (!__qblk_rb_may_write(qblk, rb, nr_entries, pos))
		return 0;


	mem = (*pos + nr_entries) & (rb->nr_entries - 1);
	*io_ret = BLK_STS_OK;
/*
	if (bio->bi_opf & REQ_PREFLUSH) {
		unsigned int nr_rb = qblk->nr_queues+1;
		#ifdef CONFIG_NVM_DEBUG
				atomic_long_inc(&qblk->nr_flush);
		#endif
		while(nr_rb--)
			pblk_rb_flush_point_set(&qblk->mqrwb[nr_rb], bio, mem);//---
		*io_ret = BLK_STS_OK;
	}
*/

	/* Protect from read count */
	smp_store_release(&rb->mem, mem);

	return 1;
}

/*
 * Atomically check that (i) there is space on the write buffer for the
 * incoming I/O, and (ii) the current I/O type has enough budget in the write
 * buffer (rate-limiter).
 */
blk_status_t qblk_rb_may_write_user(struct qblk *qblk,
				unsigned int rbid,
				struct qblk_rb *rb, struct bio *bio,
				unsigned int nr_entries, unsigned int *pos)
{
	blk_status_t io_ret;

	spin_lock(&rb->w_lock);
	io_ret = qblk_rl_user_may_insert(qblk, nr_entries);
	if (io_ret) {
		spin_unlock(&rb->w_lock);
		return io_ret;
	}

	if (!qblk_rb_may_write_flush(qblk, rb, nr_entries, pos, bio, &io_ret)) {
		spin_unlock(&rb->w_lock);
		return BLK_STS_RESOURCE;
	}
	
	qblk_rl_user_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	//pr_notice("%s:ret=%d\n",__func__,io_ret);

	return io_ret;
}

/*
 * Write @nr_entries to ring buffer from @data buffer if there is enough space.
 * Typically, 4KB data chunks coming from a bio will be copied to the ring
 * buffer, thus the write will fail if not all incoming data can be copied.
 *
 */
static void __qblk_rb_write_entry(struct qblk_rb *rb, void *data,
				  struct qblk_w_ctx w_ctx,
				  struct qblk_rb_entry *entry)
{
	memcpy(entry->data, data, rb->seg_size);

	entry->w_ctx.lba = w_ctx.lba;
	entry->w_ctx.ppa = w_ctx.ppa;
}

void qblk_rb_write_entry_user(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
				struct qblk_w_ctx w_ctx, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = &rb->entries[ring_pos];
	flags = READ_ONCE(entry->w_ctx.flags);
	//---
#if 0
#ifdef CONFIG_NVM_DEBUG
	/* Caller must guarantee that the entry is free */
	BUG_ON(!(flags & QBLK_WRITABLE_ENTRY));
#endif
#endif
	//pr_notice("%s,ringpos=%u\n",__func__,ring_pos);
	//printPageSample(data);

	__qblk_rb_write_entry(rb, data, w_ctx, entry);

	qblk_update_map_cache(qblk, rb, w_ctx.lba, entry->cacheline);
	flags = w_ctx.flags | QBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

void qblk_rb_write_entry_gc(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
			    struct qblk_w_ctx w_ctx, struct qblk_line *line,
			    u64 paddr, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = &rb->entries[ring_pos];
	flags = READ_ONCE(entry->w_ctx.flags);
#ifdef CONFIG_NVM_DEBUG
	/* Caller must guarantee that the entry is free */
	BUG_ON(!(flags & QBLK_WRITABLE_ENTRY));
#endif

	__qblk_rb_write_entry(rb, data, w_ctx, entry);


	if (!qblk_update_map_gc(qblk, rb, w_ctx.lba, entry->cacheline, line, paddr))
		entry->w_ctx.lba = ADDR_EMPTY;

	flags = w_ctx.flags | QBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

void qblk_rb_data_free(struct qblk_rb *rb)
{
	struct qblk_rb_pages *p, *t;

	down_write(&qblk_rb_lock);
	list_for_each_entry_safe(p, t, &rb->pages, list) {
		free_pages((unsigned long)page_address(p->pages), p->order);
		list_del(&p->list);
		kfree(p);
	}
	up_write(&qblk_rb_lock);
}

/*
 * Initialize ring buffer. The data and metadata buffers must be previously
 * allocated and their size must be a power of two
 * (Documentation/circular-buffers.txt)
 */
int qblk_rb_init(struct qblk *qblk, struct qblk_rb *rb,
		unsigned int rbIndex, struct qblk_rb_entry *rb_entry_base,
		unsigned int power_size, unsigned int power_seg_sz)
{
	unsigned int init_entry = 0;
	unsigned int alloc_order = power_size;
	unsigned int max_order = MAX_ORDER - 1;
	unsigned int order, iter;

	//pr_notice("%s, powersize=%u, power_seg_sz=%u\n",
	//			__func__, power_size, power_seg_sz);

	down_write(&qblk_rb_lock);
	rb->rb_index = rbIndex;
	rb->entries = rb_entry_base;
	rb->seg_size = (1 << power_seg_sz);
	rb->nr_entries = (1 << power_size);
	rb->mem = rb->subm = rb->sync = rb->l2p_update = 0;
	rb->flush_point = EMPTY_ENTRY;

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->s_lock);

	INIT_LIST_HEAD(&rb->pages);

	if (alloc_order >= max_order) {
		order = max_order;
		iter = (1 << (alloc_order - max_order));
	} else {
		order = alloc_order;
		iter = 1;
	}

	do {
		struct qblk_rb_entry *entry;
		struct qblk_rb_pages *page_set;
		void *kaddr;
		unsigned long set_size;
		int i;

		page_set = kmalloc(sizeof(struct qblk_rb_pages), GFP_KERNEL);
		if (!page_set) {
			up_write(&qblk_rb_lock);
			return -ENOMEM;
		}

		page_set->order = order;
		page_set->pages = alloc_pages(GFP_KERNEL, order);
		if (!page_set->pages) {
			kfree(page_set);
			qblk_rb_data_free(rb);
			up_write(&qblk_rb_lock);
			return -ENOMEM;
		}
		kaddr = page_address(page_set->pages);

		entry = &rb->entries[init_entry];
		entry->data = kaddr;
		entry->cacheline = qblk_cacheline_to_addr(rbIndex, init_entry++);
		entry->w_ctx.flags = QBLK_WRITABLE_ENTRY;

		set_size = (1 << order);
		for (i = 1; i < set_size; i++) {
			entry = &rb->entries[init_entry];
			entry->cacheline = qblk_cacheline_to_addr(rbIndex, init_entry++);
			entry->data = kaddr + (i * rb->seg_size);
			entry->w_ctx.flags = QBLK_WRITABLE_ENTRY;
			bio_list_init(&entry->w_ctx.bios);
		}

		list_add_tail(&page_set->list, &rb->pages);
		iter--;
	} while (iter > 0);
	up_write(&qblk_rb_lock);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&rb->inflight_flush_point, 0);
#endif

	qblk->total_buf_entries += rb->nr_entries;
	pr_notice("%s, rb[%u] init finished with %lu entries\n",
				__func__, rbIndex, (1UL << order));

	return 0;
}

/*
 * qblk_rb_calculate_size -- calculate the size of the write buffer
 */
unsigned int qblk_rb_calculate_size(unsigned int nr_entries)
{
	/* Alloc a write buffer that can at least fit 128 entries */
	return (1 << max(get_count_order(nr_entries), 7));
}


void *qblk_rb_entries_ref(struct qblk_rb *rb)
{
	return rb->entries;
}

int qblk_rb_tear_down_check(struct qblk_rb *rb)
{
	struct qblk_rb_entry *entry;
	int i;
	int ret = 0;

	spin_lock(&rb->w_lock);
	spin_lock_irq(&rb->s_lock);

	if ((rb->mem == rb->subm) && (rb->subm == rb->sync) &&
				(rb->sync == rb->l2p_update) &&
				(rb->flush_point == EMPTY_ENTRY)) {
		goto out;
	}

	if (!rb->entries) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < rb->nr_entries; i++) {
		entry = &rb->entries[i];

		if (!entry->data) {
			ret = 1;
			goto out;
		}
	}

out:
	spin_unlock(&rb->w_lock);
	spin_unlock_irq(&rb->s_lock);

	return ret;
}

int qblk_rb_pos_oob(struct qblk_rb *rb, u64 pos)
{
	return (pos >= rb->nr_entries);
}

void printRbStatus(struct qblk_rb *ringBuffer, unsigned int rbIndex)
{
	int i;

	spin_lock(&ringBuffer->w_lock);
	pr_notice("''''''''''''''%s''''''''''''''\n",	__func__);
	pr_notice("rb[%u] status: flushpoint=%u, l2pupdate=%u, mem=%u,subm=%u,sync=%u\n",
		rbIndex, READ_ONCE(ringBuffer->flush_point),
		READ_ONCE(ringBuffer->l2p_update),
		READ_ONCE(ringBuffer->mem),
		READ_ONCE(ringBuffer->subm),
		READ_ONCE(ringBuffer->sync));
	for (i = 0; i < 8; i++) {
		pr_notice("[%d]:cacheline=0x%llx, wctxflags=0x%x, wctxlba=0x%llx, wctxppa=0x%llx\n",
			i,
			ringBuffer->entries[i].cacheline.ppa,
			ringBuffer->entries[i].w_ctx.flags,
			ringBuffer->entries[i].w_ctx.lba,
			ringBuffer->entries[i].w_ctx.ppa.ppa);
	}
	//pr_notice("%s^^^^^^^^^^^^^END^^^^^^^^^^^^^^^^^^^^^\n",
	//													__func__);
	spin_unlock(&ringBuffer->w_lock);
}

/*
void printReadSubmitStatus(struct nvm_rq *rqd){
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	int i;
	pr_notice("----------printReadSubmitStatus-----------\n");

	pr_notice("opcode=0x%x,nr_pages=0x%x\n",rqd->opcode,rqd->nr_ppas);
	pr_notice("rctx->lba=0x%llx\n",r_ctx->lba);
	if(rqd->nr_ppas == 1){
		pr_notice("lba=0x%llx,ppa=0x%llx\n",r_ctx->lba,rqd->ppa_addr.ppa);
	}
	else{
		for(i=0;i<rqd->nr_ppas;i++){
			pr_notice("[%d]: lba(le64)=0x%llx,lba=0x%llx,ppa=0x%llx\n",i,meta_list[i].lba,le64_to_cpu(meta_list[i].lba),rqd->ppa_list[i].ppa);
		}

	}

	pr_notice("---------------------------------------------------\n");
}
*/

blk_status_t qblk_rq_write_to_cache(struct qblk *qblk,
				struct qblk_queue *pq,
				struct request *req,
				unsigned long flags)
{
	struct request_queue *q = req->q;
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	int i;
	blk_status_t ret;
	struct bio *bio;
	unsigned int rbIndex = pq->rb_idx;
	struct qblk_rb *ringBuffer = pq->rb;
	unsigned long start_time = jiffies;
	sector_t lba;
	int nr_entries;
	unsigned int qid;

	generic_start_io_acct(q, WRITE, blk_rq_sectors(req), &qblk->disk->part0);

	__rq_for_each_bio(bio, req) {
		lba = qblk_get_lba(bio);
		nr_entries = qblk_get_secs(bio);
		qid = pq->rb_idx;

		//bio_get(bio);/////////

		//pr_notice("write command, rbIndex=%u, lba=%lu, nrEntries=%d\n",rbIndex,lba,nr_entries);


		/* Update the write buffer head (mem) with the entries that we can
		 * write. The write in itself cannot fail, so there is no need to
		 * rollback from here on.
		 */
		ret = qblk_rb_may_write_user(qblk, qid, ringBuffer, bio, nr_entries, &bpos);
		switch (ret) {
		case BLK_STS_RESOURCE:
			//pr_notice("%s,return with BLK_STS_RESOURCE\n",__func__);
			//printRbStatus(ringBuffer, rbIndex);
			return BLK_STS_RESOURCE;
		case BLK_STS_IOERR:
			/*pblk_pipeline_stop(pblk);*/ //---
			break;
		}
		//printRbStatus(ringBuffer,rbIndex);
		if (unlikely(!bio_has_data(bio)))
			break;

		qblk_ppa_set_empty(&w_ctx.ppa);
		w_ctx.flags = flags;
		if (bio->bi_opf & REQ_PREFLUSH)
			w_ctx.flags |= QBLK_FLUSH_ENTRY;

		for (i = 0; i < nr_entries; i++) {
			void *data = bio_data(bio);

			w_ctx.lba = lba + i;
			//pr_notice("%s:wctx[%d].lba=0x%llx\n", __func__, i, w_ctx.lba);

			pos = qblk_rb_wrap_pos(ringBuffer, bpos + i);
			qblk_rb_write_entry_user(qblk, ringBuffer, data, w_ctx, pos);

			bio_advance(bio, QBLK_EXPOSED_PAGE_SIZE);
		}

/*
#ifdef CONFIG_NVM_DEBUG
		atomic_long_add(nr_entries, &qblk->inflight_writes);
		atomic_long_add(nr_entries, &qblk->req_writes);
#endif
*/

		qblk_rl_inserted(&qblk->rl, nr_entries);
		//break;
	}
	generic_end_io_acct(q, WRITE, &qblk->disk->part0, start_time);
	//pr_notice("%s,endrequest with BLK_STS_OK,lba=%lu, nrEntries=%d\n",__func__,lba,nr_entries);
	blk_mq_end_request(req, BLK_STS_OK);
	qblk_write_should_kick(qblk, rbIndex);
	//pr_notice("%s,ret=%d\n", __func__, ret);
	return ret;
}

unsigned int qblk_rb_wrap_pos(struct qblk_rb *rb, unsigned int pos)
{
	return (pos & (rb->nr_entries - 1));
}

/*
 * Read available entries on rb and add them to the given bio. To avoid a memory
 * copy, a page reference to the write buffer is used to be added to the bio.
 *
 * This function is used by the write thread to form the write bio that will
 * persist data on the write buffer to the media.
 */
unsigned int qblk_rb_read_to_bio(struct qblk *qblk,
				struct qblk_rb *rb, struct nvm_rq *rqd,
				unsigned int pos, unsigned int nr_entries,
				unsigned int count)
{
	struct request_queue *q = qblk->dev->q;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;
	struct qblk_rb_entry *entry;
	struct page *page;
	unsigned int pad = 0, to_read = nr_entries;
	unsigned int i;
	int flags;

	if (count < nr_entries) {
		pad = nr_entries - count;
		to_read = count;
	}

	c_ctx->sentry = pos;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	//pr_notice("%s,rb=%lu,pos=%u,nr_entries=%u,count=%u\n", __func__,
	//	((unsigned long)rb - (unsigned long)qblk->mqrwb)/sizeof(struct qblk_rb),
	//	pos,nr_entries,count);

	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[pos];

		/* A write has been allowed into the buffer, but data is still
		 * being copied to it. It is ok to busy wait.
		 */
retry:
		flags = READ_ONCE(entry->w_ctx.flags);
		if (!(flags & QBLK_WRITTEN_DATA)) {
			io_schedule();
			goto retry;
		}

		page = virt_to_page(entry->data);
		if (!page) {
			pr_err("qblk: could not allocate write bio page\n");
			flags &= ~QBLK_WRITTEN_DATA;
			flags |= QBLK_SUBMITTED_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		if (bio_add_pc_page(q, bio, page, rb->seg_size, 0) !=
								rb->seg_size) {
			pr_err("qblk: could not add page to write bio\n");
			flags &= ~QBLK_WRITTEN_DATA;
			flags |= QBLK_SUBMITTED_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		flags &= ~QBLK_WRITTEN_DATA;
		flags |= QBLK_SUBMITTED_ENTRY;

		/* Release flags on context. Protect from writes */
		smp_store_release(&entry->w_ctx.flags, flags);

		pos = (pos + 1) & (rb->nr_entries - 1);
	}

	if (pad) {
		if (qblk_bio_add_pages(qblk, bio, GFP_KERNEL, pad)) {
			pr_err("qblk: could not pad page in write bio\n");
			return NVM_IO_ERR;
		}
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(pad, &qblk->padded_writes);
#endif

	return NVM_IO_OK;
}

/*
 * Look at qblk_rb_may_write_user comment
 */
static int qblk_rb_may_write_gc(struct qblk *qblk,
			struct qblk_rb *rb, struct ch_info *chi,
			unsigned int nr_entries,
			unsigned int *pos)
{
	spin_lock(&rb->w_lock);
	if (qblk_rl_gc_maynot_insert(&qblk->rl, &chi->per_ch_rl, nr_entries)) {
		spin_unlock(&rb->w_lock);
		return 0;
	}

	if (!qblk_rb_may_write(qblk, rb, nr_entries, pos)) {
		spin_unlock(&rb->w_lock);
		return 0;
	}

	qblk_rl_gc_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	return 1;
}

#if 0
/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int qblk_write_gc_to_cache(struct qblk *qblk, struct qblk_gc_rq *gc_rq)
{
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	void *data = gc_rq->data;
	int i, valid_entries;
	int cpuid;
	struct qblk_rb *rb;
	struct ch_info *chi = gc_rq->chi;
	int waitCount=0;
	
	//pr_notice("%s, nr_secs=%d\n",__func__, gc_rq->nr_secs);
	//for(i=0;i<gc_rq->nr_secs;i++)
	//	pr_notice("paddr=0x%llx\n",gc_rq->paddr_list[i]);//this value stores offset_in_chline


	/* Update the write buffer head (mem) with the entries that we can
	 * write.
	 */
retry:
	cpuid = get_cpu();
	rb = &qblk->mqrwb[cpuid];

	if (!qblk_rb_may_write_gc(qblk, rb, chi, gc_rq->secs_to_gc, &bpos)) {
		put_cpu();
		if(!waitCount) {
			waitCount++;
			//pr_notice("%s, cannot insert gc to rb\n", __func__);
		}
		io_schedule();
		goto retry;
	}

	
	w_ctx.flags = QBLK_IOTYPE_GC;
	qblk_ppa_set_empty(&w_ctx.ppa);

	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;
				
		w_ctx.lba = gc_rq->lba_list[i];

		pos = qblk_rb_wrap_pos(rb, bpos + i);
		qblk_rb_write_entry_gc(qblk, rb, data,
						w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], pos);
		
		data += QBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;
	}
			
	WARN_ONCE(gc_rq->secs_to_gc != valid_entries,
					"qblk: inconsistent GC write\n");
					
#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(valid_entries, &qblk->inflight_writes);
	atomic_long_add(valid_entries, &qblk->recov_gc_writes);
#endif
					
	qblk_write_should_kick(qblk, rb->rb_index);
	put_cpu();

	return NVM_IO_OK;

}
#endif


/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int qblk_write_gc_to_cache(struct qblk *qblk, struct qblk_gc_rq *gc_rq)
{
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	void *data = gc_rq->data;
	int i, valid_entries;
	int cpuid;
	struct qblk_rb *rb;
	struct ch_info *chi = gc_rq->chi;

	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;
retry:
		cpuid = get_cpu();
		rb = &qblk->mqrwb[cpuid];

		if (!qblk_rb_may_write_gc(qblk, rb, chi, 1, &bpos)) {
			put_cpu();
			io_schedule();
			goto retry;
		}
		w_ctx.flags = QBLK_IOTYPE_GC;
		qblk_ppa_set_empty(&w_ctx.ppa);
		w_ctx.lba = gc_rq->lba_list[i];
		pos = qblk_rb_wrap_pos(rb, bpos);
		qblk_rb_write_entry_gc(qblk, rb, data,
						w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], pos);
		
		data += QBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;
		put_cpu();

	}

	WARN_ONCE(gc_rq->secs_to_gc != valid_entries,
					"qblk: inconsistent GC write\n");
					
#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(valid_entries, &qblk->inflight_writes);
	atomic_long_add(valid_entries, &qblk->recov_gc_writes);
#endif
					
	qblk_write_should_kick(qblk, rb->rb_index);
	return NVM_IO_OK;

}

