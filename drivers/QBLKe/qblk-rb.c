#include <linux/circ_buf.h>

#include "qblk.h"

//declaration lock
static DECLARE_RWSEM(qblk_rb_lock);

#define qblk_rb_ring_count(head, tail, size) \
	({int mid = (head) - (tail);  \
		int tempsize = (size); \
		mid < 0 ? (mid + tempsize) : mid;})
#define qblk_rb_ring_space(head, tail, size) \
	qblk_rb_ring_count((tail), ((head) + 1), (size))

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
	unsigned int boundary;

	lockdep_assert_held(&rb->s_lock);

	boundary = READ_ONCE(rb->boundary);

	sync = READ_ONCE(rb->sync);
	flush_point = READ_ONCE(rb->flush_point);

	//pr_notice("%s,rb[%u]sync=%u,flushpoint=%u,nrEntry[%u]\n",
	//			__func__, rb->rb_index,
	//			sync, flush_point, nr_entries);

	if (flush_point != EMPTY_ENTRY) {
		unsigned int secs_to_flush;
		
		secs_to_flush = qblk_rb_ring_count(flush_point, sync,
					boundary);
		if (secs_to_flush < nr_entries) {
			/* Protect flush points */
			smp_store_release(&rb->flush_point, EMPTY_ENTRY);
		}
	}

	sync += nr_entries;
	if (sync >= boundary)
		sync -= boundary;

	/* Protect from counts */
	smp_store_release(&rb->sync, sync);
	//pr_notice("%s,sync=%u stored\n", __func__, sync);

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
	unsigned int boundary = READ_ONCE(rb->boundary);

	return qblk_rb_ring_count(mem, subm, boundary);
}

unsigned int qblk_rb_sync_count(struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int sync = READ_ONCE(rb->sync);
	unsigned int boundary = READ_ONCE(rb->boundary);

	return qblk_rb_ring_count(mem, sync, boundary);
}

unsigned int qblk_rb_read_commit(struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int subm, ret;
	unsigned int boundary;

	boundary = READ_ONCE(rb->boundary);

	/* There are only two situations that move the boundary:
	 *    1) rb->mem pushes it.
	 *    2) rb->l2p shrinks it.
	 * Neither of the cases will rb->subm cross the boundary.
	 * In other words, if rb->subm is about
	 * to cross the boundary, the boundary
	 * itself remains stable.
	 */

	ret = subm = READ_ONCE(rb->subm);
	subm += nr_entries;
	if (subm >= boundary)
		subm -= boundary;
	
	/* Commit read means updating submission pointer */
	smp_store_release(&rb->subm, subm);

	return ret;
}

/* Caller must assure that pos donot exceed the boundary of rb */
inline struct qblk_w_ctx *qblk_rb_w_ctx(struct qblk_rb *rb, unsigned int pos)
{
	return &rb->entries[pos].w_ctx;
}

/* Calculate how many sectors to submit up to the current flush point. */
unsigned int qblk_rb_flush_point_count(struct qblk_rb *rb)
{
	unsigned int subm, sync, flush_point;
	unsigned int submitted, to_flush, boundary;

	/* Protect flush points */
	flush_point = smp_load_acquire(&rb->flush_point);
	if (flush_point == EMPTY_ENTRY)
		return 0;

	/* Protect syncs */
	sync = smp_load_acquire(&rb->sync);

	subm = READ_ONCE(rb->subm);
	boundary = READ_ONCE(rb->boundary);
	submitted = qblk_rb_ring_count(subm, sync, boundary);

	/* The sync point itself counts as a sector to sync */
	to_flush = qblk_rb_ring_count(flush_point, sync, boundary) + 1;

	return (submitted < to_flush) ? (to_flush - submitted) : 0;
}

static void clean_wctx(struct qblk_w_ctx *w_ctx)
{
	int flags;
	int nr_retry = 0;

try:
	flags = READ_ONCE(w_ctx->flags);
	if (!(flags & (QBLK_SUBMITTED_ENTRY | QBLK_WRITABLE_ENTRY))) {
		nr_retry++;
 		if (nr_retry > 1024) {
			pr_err("%s, retry too much, flags=0x%x\n",
						__func__, flags);
			goto force_clean;
 		}
		goto try;
	}

force_clean:
	/* Release flags on context. Protect from writes and reads */
	smp_store_release(&w_ctx->flags, QBLK_WRITABLE_ENTRY);
	qblk_ppa_set_empty(&w_ctx->ppa);
	w_ctx->lba = ADDR_EMPTY;
}

/* When we get here, it's garanteed that
 * we've already had enough space from l2p_update to sync.
 * This is achieved by __qblk_rb_may_write()'s first check.
 * As a result, there is no need to check for the rb->sync pointer.
 */
static int __qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int to_update)
{
	struct qblk_line *line;
	struct qblk_rb_entry *entry;
	struct qblk_w_ctx *w_ctx;
	unsigned int user_io = 0, gc_io = 0;
	unsigned int i;
	int flags;

	for (i = 0; i < to_update; i++) {
		unsigned int l2p_update = READ_ONCE(rb->l2p_update);
		unsigned int boundary;

		entry = &rb->entries[l2p_update];
		w_ctx = &entry->w_ctx;

		flags = READ_ONCE(entry->w_ctx.flags);
		if (flags & QBLK_IOTYPE_USER)
			user_io++;
		else if (flags & QBLK_IOTYPE_GC)
			gc_io++;

		qblk_update_map_dev(qblk, w_ctx->lba, w_ctx->ppa,
							entry->cacheline);
		if (!qblk_ppa_empty(w_ctx->ppa)){
			line = qblk_ppa_to_structline(qblk, w_ctx->ppa);
			kref_put(&line->ref, qblk_line_put);
		}
		//pr_notice("%s,put the reference of line[%u]\n",__func__,line->id);
		clean_wctx(w_ctx);

		boundary  = READ_ONCE(rb->boundary);

		l2p_update++;
		if (l2p_update >= boundary)
			l2p_update -= boundary;

		smp_store_release(&rb->l2p_update, l2p_update);
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
static inline int qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int nr_entries,
			      unsigned int mem, unsigned int sync)
{
	unsigned int space, count;
	int ret = 0;

	lockdep_assert_held(&rb->w_lock);

	/* Update l2p only as buffer entries are being overwritten */
	space = qblk_rb_ring_space(mem, READ_ONCE(rb->l2p_update), READ_ONCE(rb->boundary));
	//pr_notice("%s, space[%u] nrentries[%u] extraSpace[%u]\n",
	//			__func__, space, nr_entries, extraSpace);
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
	unsigned int l2p_update;
	unsigned int to_update;

	spin_lock(&rb->w_lock);

	/* Protect from reads and writes */
	sync = smp_load_acquire(&rb->sync);
	l2p_update = READ_ONCE(rb->l2p_update);

	to_update = qblk_rb_ring_count(sync, l2p_update, READ_ONCE(rb->boundary));
	__qblk_rb_update_l2p(qblk, rb, to_update);

	spin_unlock(&rb->w_lock);
}

void qblk_rb_sync_all_l2p(struct qblk *qblk)
{
	unsigned int queue_count = qblk->nr_queues;
	while (queue_count--)
		qblk_rb_sync_l2p(qblk, &qblk->mqrwb[queue_count]);
}

static void qblk_free_rbpage(struct work_struct *work)
{
	struct qblk_rb *rb = container_of(work, struct qblk_rb, shrink_dwork.work);
	struct qblk *qblk = rb->qblk;
	unsigned int boundary_small;

	spin_lock(&rb->w_lock);
	
	boundary_small = READ_ONCE(rb->boundary_small);

	if (boundary_small) {
		unsigned int sync = READ_ONCE(rb->sync);
		unsigned int mem = READ_ONCE(rb->mem);

		if (sync <= mem) {
			unsigned int oldl2p = READ_ONCE(rb->l2p_update);
			unsigned int boundary = READ_ONCE(rb->boundary);

			if (oldl2p > sync)
				__qblk_rb_update_l2p(qblk, rb, boundary - oldl2p);

			if (mem >= boundary_small) {
				int dummyp;
				int nrdummy;
				int nstuck;
				struct qblk_rb_entry *entry;
				int flags;
				unsigned int subm;

				/* If mem is greater than mid_threshold,
				 * we should issue some dummy requests
				 * before shrinking rb.
				 * Here, we have:
				 * l2p   sync  subm   b_s   mem      b
				 *  |    |      |     |     |        |
				 * [0]   []     []    []    []    []
				 * We 1st shrink boundary to mem+1.
				 * Then, move l2p by min_write_pgs entries
				 * so that we have enough space for
				 * dummy requests.
				 * Then, we issue dummy requests.
				 */
				if (boundary > mem + 1) {
					smp_store_release(&rb->boundary, mem + 1);
					qblk_free_page_from_rb(qblk, rb, mem + 1, boundary);
				}

				subm = READ_ONCE(rb->subm);
				nrdummy = qblk->min_write_pgs;
				nstuck = qblk_rb_ring_count(mem, subm, mem + 1);
				if (nstuck < nrdummy)
					nrdummy -= nstuck;

				/* Now we need to issue
				 * @nrdummy dummy requests.
				 */
				if (qblk_rb_ring_space(mem, sync, boundary) < nrdummy)
					goto tryLater;

				qblk_rb_update_l2p(qblk, rb, nrdummy, mem, sync);

				//Issue dummy requests
				for (dummyp = mem;
						dummyp != nrdummy - 1;
						dummyp = qblk_rb_wrap_pos(rb, dummyp + 1)) {
					entry = &rb->entries[dummyp];
					entry->w_ctx.lba = ADDR_EMPTY;
					entry->w_ctx.ppa.ppa = ADDR_EMPTY;
					flags = entry->w_ctx.flags | QBLK_WRITTEN_DATA;
					smp_store_release(&entry->w_ctx.flags, flags);
				}
				smp_store_release(&rb->mem, dummyp);
				goto tryLater;
			}
			
			smp_store_release(&rb->boundary, boundary_small);
			smp_store_release(&rb->boundary_small, 0);
			qblk_free_page_from_rb(qblk, rb, boundary_small, boundary);
			spin_unlock(&rb->w_lock);

			return;
		}
tryLater:
		spin_unlock(&rb->w_lock);
		mod_delayed_work_on(rb->rb_index, system_wq,
			&rb->shrink_dwork, __msecs_to_jiffies(40));
		return;
	}
	spin_unlock(&rb->w_lock);

}


/* Check whether the rb have enough space for the comming request.
 * Return:
 * 0: space is sufficient.
 * n: space is in-sufficient.
 *    n = boundary_small?boundary_small:boundary;
 */
static int __qblk_rb_maynot_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int sync = READ_ONCE(rb->sync);
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int boundary = READ_ONCE(rb->boundary);
	unsigned int boundary_small = READ_ONCE(rb->boundary_small);

	if (unlikely(boundary_small && mem < boundary_small)) {
		/* mem < boundary_small
		 * In this case, rb->mem should never go
		 * beyond boundary_small
		 */
		
		// Be careful about sync>=boundary_small
		if (sync >= boundary_small) {
			if (mem + nr_entries >= boundary_small)
				return boundary_small;
			// We have enough space before boundary_small
			qblk_rb_update_l2p(qblk, rb, nr_entries, mem, sync);
			return 0;
		} else {
			if (qblk_rb_ring_space(mem, sync, boundary_small) < nr_entries)
				return boundary_small;

			/* Be careful! We have two possible situations here!
			 * 1) sync <= mem < boundary_small
			 *       In this situation, we have tremendous
			 *       amount of usable memory and we should
			 *       shrink the ringBuffer.  
			 * 2) mem < sync < boundary_small
			 *       In this situation, we have enough memory
			 *       for this IO but we can't shrink the rb.
			 */
			if (sync <= mem) {
				unsigned int oldl2p = READ_ONCE(rb->l2p_update);

				/* if(sync <= mem < l2p < boundary)
				 * We need to push l2p to 0.
				 */
				if (oldl2p > sync)
					__qblk_rb_update_l2p(qblk, rb, boundary - oldl2p);
				smp_store_release(&rb->boundary, boundary_small);
				smp_store_release(&rb->boundary_small, 0);
				qblk_free_page_from_rb(qblk, rb, boundary_small, boundary);
			}
			qblk_rb_update_l2p(qblk, rb, nr_entries, mem, sync);
		
			return 0;
		}
	}

	/* In case of (boundary_small != 0 && mem >= boundary_small)
	 * we just temporarily ignore the boundary_small.
	 */

	if (qblk_rb_ring_space(mem, sync, boundary) < nr_entries)
		return (boundary_small ? boundary_small : boundary);

	qblk_rb_update_l2p(qblk, rb, nr_entries, mem, sync);
	return 0;
}


static int qblk_rb_may_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
			    unsigned int *pos)
{
	unsigned int boundary;
	unsigned int mem = READ_ONCE(rb->mem);

	*pos = mem;

	if (__qblk_rb_maynot_write(qblk, rb, nr_entries))
		return 0;

	boundary = READ_ONCE(rb->boundary);

	/* Now we'll move the rb->mem pointer. */
	mem += nr_entries;
	if (mem >= boundary) {
		unsigned int boundary_large = READ_ONCE(rb->boundary_large);

		if (likely(!boundary_large)) {
			mem -= boundary;
		} else {
			/* By the time we get here, we need to push
			 * the rb->boundary towards boundary_large
			 */
			 if (mem + 1 > boundary_large) {
				boundary = boundary_large;
				mem -= boundary;
			 	smp_store_release(&rb->boundary_large, 0);
			 } else {
				boundary = mem + 1;
			 }
			 smp_store_release(&rb->boundary, boundary);
		}
	}

	smp_store_release(&rb->mem, mem);
	return 1;
}

static int qblk_rb_maynot_write_flush(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
				unsigned int *pos, struct bio *bio)
{
	unsigned int boundary;
	unsigned int mem = READ_ONCE(rb->mem);
	int ret;

	*pos = mem;
	smp_store_release(&rb->rb_active, 1);

	ret = __qblk_rb_maynot_write(qblk, rb, nr_entries);
	if (ret)
		return ret;
	
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

	boundary = READ_ONCE(rb->boundary);

	/* Now we'll move the rb->mem pointer. */
	mem += nr_entries;
	if (mem >= boundary) {
		unsigned int boundary_large = READ_ONCE(rb->boundary_large);

		if (likely(!boundary_large)) {
			mem -= boundary;
		} else {
			/* By the time we get here, we need to push
			 * the rb->boundary towards boundary_large
			 */
			if (mem + 1 > boundary_large) {
				boundary = boundary_large;
				mem -= boundary;
				smp_store_release(&rb->boundary_large, 0);
			} else {
				boundary = mem + 1;
			}
			smp_store_release(&rb->boundary, boundary);
		}
	}

	smp_store_release(&rb->mem, mem);
		
	return 0;
}

/*
 * Atomically check that (i) there is space on the write buffer for the
 * incoming I/O, and (ii) the current I/O type has enough budget in the write
 * buffer (rate-limiter).
 * Return value:
 * 0: OK
 * 1: Rate limiter may not insert
 * >1: Not enough space for ring buffer. See __qblk_rb_maynot_write();
 * -1: Err
 */
static int qblk_rb_may_write_user(struct qblk *qblk,
				unsigned int rbid,
				struct qblk_rb *rb, struct bio *bio,
				unsigned int nr_entries, unsigned int *pos)
{
	int ret;

	if (qblk_rl_user_maynot_insert(qblk, nr_entries))
		return 1;

	spin_lock(&rb->w_lock);
	ret = qblk_rb_maynot_write_flush(qblk, rb, nr_entries, pos, bio);
	if (ret) {
		spin_unlock(&rb->w_lock);
		//pr_notice("%s:qblk_rb_may_write_flush ret 0\n", __func__);
		atomic_add_unless(&rb->complaint, 1, QBLK_RB_MAX_COMPLAINT);
		return ret;
	}
	
	qblk_rl_user_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	//pr_notice("%s:ret=%d\n",__func__,io_ret);
#ifdef QBLK_COUNT_RB_REQ
	if (qblk->rb_need_count)
		qblk->rb_req_count[rbid]++;
#endif


	return 0;
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

static void qblk_rb_write_entry_user(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
				struct qblk_w_ctx w_ctx, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = &rb->entries[ring_pos];
	flags = READ_ONCE(entry->w_ctx.flags);

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

static void qblk_rb_write_entry_gc(struct qblk *qblk,
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
}

int qblk_alloc_freepage_to_rb(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int startEntry, unsigned int nr_entries)
{
	struct qblk_rb_pages *page_set;
	unsigned int entryIter = startEntry;
	struct qblk_rb_entry *entry;
	unsigned long flags;
	int bit;

	if (!nr_entries)
		return 0;

	list_for_each_entry(page_set, &qblk->rbpages, list) {
		void *kaddr = page_address(page_set->pages);

		spin_lock_irqsave(&page_set->alloc_lock, flags);
		if (!page_set->nr_free_pages) {
			spin_unlock_irqrestore(&page_set->alloc_lock, flags);
			continue;
		}
		if (nr_entries <= page_set->nr_free_pages) {
			atomic_sub(nr_entries, &qblk->nr_free_pages);
			//There are enough pages in this page_set
			while (nr_entries--) {
				entry = &rb->entries[entryIter];
				
				bit = find_first_bit(page_set->free_bitmap, 1 << page_set->order);
				clear_bit(bit, page_set->free_bitmap);
				entry->data = kaddr + (bit * rb->seg_size);
				entry->page_set = page_set;
				entry->offset = bit;
				page_set->nr_free_pages--;
				entryIter++;
			}
			spin_unlock_irqrestore(&page_set->alloc_lock, flags);
			return 0;
		}
		atomic_sub(page_set->nr_free_pages, &qblk->nr_free_pages);
		while (page_set->nr_free_pages--) {
			entry = &rb->entries[entryIter];
			
			bit = find_first_bit(page_set->free_bitmap, 1 << page_set->order);
			clear_bit(bit, page_set->free_bitmap);
			entry->data = kaddr + (bit * rb->seg_size);
			entry->page_set = page_set;
			entry->offset = bit;
			nr_entries--;
			entryIter++;
		}
		page_set->nr_free_pages++;
		spin_unlock_irqrestore(&page_set->alloc_lock, flags);
	}
	return -ENOMEM;
}

void qblk_free_page_from_rb(struct qblk *qblk,
					struct qblk_rb *rb,
					unsigned int startEntry,
					unsigned int endEntry)
{
	struct qblk_rb_entry *entry;
	struct qblk_rb_pages *page_set;
	unsigned int iter = endEntry;

	lockdep_assert_held(&rb->w_lock);

	while (iter-- > startEntry) {
		entry = &rb->entries[iter];
		page_set = entry->page_set;

		spin_lock(&page_set->alloc_lock);
		set_bit(entry->offset, page_set->free_bitmap);
		page_set->nr_free_pages++;
		spin_unlock(&page_set->alloc_lock);
	}
	atomic_add(endEntry - startEntry, &qblk->nr_free_pages);
#ifdef QBLK_TRACE_RB_CHANGE
	qblk_trace_rbChange(rb->rb_index, 1, endEntry - startEntry);
#endif
}

int qblk_init_global_rb(struct qblk *qblk, unsigned int order, unsigned int iter)
{
	struct qblk_rb_pages *page_set;
	struct qblk_rb_pages *free_p, *free_t;

	INIT_LIST_HEAD(&qblk->rbpages);

	pr_notice("%s, order=%u, iter=%u\n",
				__func__, order, iter);

	atomic_set(&qblk->nr_free_pages, 0);

	down_write(&qblk_rb_lock);
	while(iter--) {
		page_set = (struct qblk_rb_pages *)kmalloc(sizeof(struct qblk_rb_pages), GFP_KERNEL);
		if (!page_set)
			goto err_out;

		page_set->order = order;
		spin_lock_init(&page_set->alloc_lock);
		page_set->pages = alloc_pages(GFP_KERNEL, order);
		if (!page_set->pages)
			goto err_out_free_pgset;
		page_set->free_bitmap = kmalloc(BITS_TO_LONGS(1 << order) * sizeof(long), GFP_KERNEL);
		if (!page_set->free_bitmap)
			goto err_out_free_pages;

		memset(page_set->free_bitmap, 0xff, BITS_TO_LONGS(1 << order) * sizeof(long));
		page_set->nr_free_pages = 1 << order;
		atomic_add(page_set->nr_free_pages, &qblk->nr_free_pages);

		list_add_tail(&page_set->list, &qblk->rbpages);
	}
	up_write(&qblk_rb_lock);
	return 0;
err_out_free_pages:
	free_pages((unsigned long)page_address(page_set->pages), order);
err_out_free_pgset:
	kfree(page_set);
err_out:
	/* Free already allocated pages */
	list_for_each_entry_safe(free_p, free_t, &qblk->rbpages, list) {
		kfree(free_p->free_bitmap);
		free_pages((unsigned long)page_address(free_p->pages), free_p->order);
		list_del(&free_p->list);
		kfree(free_p);
	}
	up_write(&qblk_rb_lock);
	return -ENOMEM;
}

void qblk_free_global_rb(struct qblk *qblk)
{
	struct qblk_rb_pages *free_p, *free_t;

	down_write(&qblk_rb_lock);
	list_for_each_entry_safe(free_p, free_t, &qblk->rbpages, list) {
		kfree(free_p->free_bitmap);
		free_pages((unsigned long)page_address(free_p->pages), free_p->order);
		list_del(&free_p->list);
		kfree(free_p);
	}
	up_write(&qblk_rb_lock);
}

int qblk_rb_init(struct qblk *qblk, struct qblk_rb *rb,
		unsigned int rbIndex, struct qblk_rb_entry *rb_entry_base,
		unsigned long init_entries, int sec_size)
{
	unsigned int i;
	struct qblk_rb_entry *entry;

	pr_notice("%s, rbIndex[%u], init_entries[%lu]\n",
				__func__, rbIndex, init_entries);

	down_write(&qblk_rb_lock);
	rb->qblk = qblk;
	rb->rb_index = rbIndex;
	rb->entries = rb_entry_base;
	rb->seg_size = sec_size;
	rb->boundary = init_entries;
	rb->boundary_large = rb->boundary_small = 0;
	rb->mem = rb->subm = rb->sync = rb->l2p_update = 0;
	rb->flush_point = EMPTY_ENTRY;

	atomic_set(&rb->complaint, 0);
	rb->rb_active = 0;

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->s_lock);

	INIT_DELAYED_WORK(&rb->shrink_dwork, qblk_free_rbpage);

	if(qblk_alloc_freepage_to_rb(qblk, rb, 0, init_entries)) {
		up_write(&qblk_rb_lock);
		pr_notice("%s, cannot alloc free pages to rb[%u]\n",
					__func__, rbIndex);
		return -ENOMEM;
	}

	for (i = 0; i < qblk->rb_max_thres; i++) {
		entry = &rb->entries[i];
		entry->cacheline = qblk_cacheline_to_addr(rbIndex, i);
		entry->w_ctx.flags = QBLK_WRITABLE_ENTRY;
		bio_list_init(&entry->w_ctx.bios);
	}

	up_write(&qblk_rb_lock);

#ifdef CONFIG_NVM_DEBUG
	atomic_set(&rb->inflight_flush_point, 0);
#endif

	pr_notice("%s, rb[%u] init finished with %lu entries\n",
				__func__, rbIndex, init_entries);

	return 0;
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
	unsigned int boundary;

	spin_lock(&rb->w_lock);
	spin_lock(&rb->s_lock);

	if ((rb->mem == rb->subm) && (rb->subm == rb->sync) &&
				(rb->sync == rb->l2p_update) &&
				(rb->flush_point == EMPTY_ENTRY)) {
		goto out;
	}

	if (!rb->entries) {
		ret = 1;
		goto out;
	}

	boundary = READ_ONCE(rb->boundary);
	for (i = 0; i < boundary; i++) {
		entry = &rb->entries[i];

		if (!entry->data) {
			ret = 1;
			goto out;
		}
	}

out:
	
	spin_unlock(&rb->s_lock);
	spin_unlock(&rb->w_lock);
	return ret;
}

int qblk_rb_pos_oob(struct qblk_rb *rb, u64 pos)
{
	return (pos >= READ_ONCE(rb->boundary));
}

void printRbStatus(struct qblk_rb *ringBuffer, unsigned int rbIndex)
{
	int i;

	spin_lock(&ringBuffer->w_lock);
	pr_notice("''''''''''''''%s''''''''''''''\n",	__func__);
	pr_notice("rb[%u] status: flushpoint=%u, l2pupdate=%u, mem=%u,subm=%u,sync=%u,boundary=%u,boundaryLarge=%u,boundarySmall=%u\n",
		rbIndex, READ_ONCE(ringBuffer->flush_point),
		READ_ONCE(ringBuffer->l2p_update),
		READ_ONCE(ringBuffer->mem),
		READ_ONCE(ringBuffer->subm),
		READ_ONCE(ringBuffer->sync),
		READ_ONCE(ringBuffer->boundary),
		READ_ONCE(ringBuffer->boundary_large),
		READ_ONCE(ringBuffer->boundary_small));
	for (i = 0; i < 8; i++) {
		pr_notice("[%d]:cacheline=0x%llx, wctxflags=0x%x, wctxlba=0x%llx, wctxppa=0x%llx\n",
			i,
			ringBuffer->entries[i].cacheline.ppa,
			ringBuffer->entries[i].w_ctx.flags,
			ringBuffer->entries[i].w_ctx.lba,
			ringBuffer->entries[i].w_ctx.ppa.ppa);
	}
	pr_notice("rb ring space: %d\n",
	qblk_rb_ring_space(ringBuffer->mem,
					ringBuffer->sync,
					READ_ONCE(ringBuffer->boundary)));
	
	//pr_notice("%s^^^^^^^^^^^^^END^^^^^^^^^^^^^^^^^^^^^\n",
	//													__func__);
	spin_unlock(&ringBuffer->w_lock);
}

blk_status_t qblk_rq_write_to_cache(struct qblk *qblk,
				struct qblk_queue *pq,
				struct request *req,
				unsigned long flags)
{
	struct request_queue *q = req->q;
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	int i;
	int writeUserRet;
	struct bio *bio, *newbio;
	unsigned int rbIndex = pq->rb_idx;
	struct qblk_rb *ringBuffer = pq->rb;
	unsigned long start_time = jiffies;
	sector_t lba;
	int nr_entries;
	unsigned int qid;
	int max_payload_pgs;

	generic_start_io_acct(q, WRITE, blk_rq_sectors(req), &qblk->disk->part0);

	__rq_for_each_bio(bio, req) {
		lba = qblk_get_lba(bio);
		nr_entries = qblk_get_secs(bio);
		qid = pq->rb_idx;

		//bio_get(bio);/////////

		//pr_notice("write command, rbIndex=%u, lba=%lu, nrEntries=%d\n",rbIndex,lba,nr_entries);
		if (qblk->print_rq_status) {
			pr_notice("%s, [%d]\n", __func__, __LINE__);
			pr_notice("rbIndex[%u], lba[%lu], nrEntries[%d], bio[%p] bi_opf[0x%x]\n",
					rbIndex, lba, nr_entries, bio, bio->bi_opf);
			dump_stack();

		}

		/* Update the write buffer head (mem) with the entries that we can
		 * write. The write in itself cannot fail, so there is no need to
		 * rollback from here on.
		 */
		writeUserRet = qblk_rb_may_write_user(qblk, qid, ringBuffer, bio, nr_entries, &bpos);
		switch (writeUserRet) {
		case 0:
			//pr_notice("%s,return with 0\n",__func__);
			//break switch
			break;
		case -1:
			/*pblk_pipeline_stop(pblk);*/ //---
			//pr_notice("%s,return with -1\n",__func__);
			return BLK_STS_IOERR;
		case 1:
			//pr_notice("%s,return with 1\n",__func__);
			return BLK_STS_RESOURCE;
		default:
			/* In case of not enough space inside ring buffer,
			 * we should check whether our requested nr_engries
			 * is too large.
			 */
			//pr_notice("%s,return with %d\n",__func__, writeUserRet);
			//pr_notice("%s,return with BLK_STS_RESOURCE\n",__func__);
			//printRbStatus(ringBuffer, rbIndex);

			max_payload_pgs = writeUserRet - qblk->min_write_pgs;

			/* We only split bios that exceed ringBuffer's capacity */
			if (nr_entries <= max_payload_pgs)
				return BLK_STS_RESOURCE;

			//pr_notice("%s, split bio-maxPayloadPgs, %d\n", __func__, max_payload_pgs);
			max_payload_pgs >>= 1;
			//pr_notice("%s, split bio-actualSplit, %d\n", __func__, max_payload_pgs);
			
			newbio = bio_split(bio,
						max_payload_pgs << 3,
						GFP_ATOMIC, q->bio_split);
			//bio_chain(newbio, bio);
			newbio->bi_opf |= REQ_NOMERGE;
			newbio->bi_next = bio->bi_next;
			bio->bi_next = newbio;
			//qblk_debug_printBioStatus(newbio);
			//qblk_debug_printBioStatus(bio);
			
			return BLK_STS_RESOURCE;
		
		}
		//printRbStatus(ringBuffer,rbIndex);
		if (unlikely(!bio_has_data(bio)))
			continue;

		qblk_ppa_set_empty(&w_ctx.ppa);
		w_ctx.flags = flags;
		if (bio->bi_opf & REQ_PREFLUSH)
			w_ctx.flags |= QBLK_FLUSH_ENTRY;

		for (i = 0; i < nr_entries; i++) {
			void *data = bio_data(bio);

			w_ctx.lba = lba + i;
			//pr_notice("%s:wctx[%d].lba=0x%llx\n", __func__, i, w_ctx.lba);

			/* Here, we wrap the position of bpos+i.
			 * We can assure that bpos+1 is between
			 * rb->subm and rb->mem.
			 * Note that we only modify rb->boundary
			 * when both the current and new value
			 * of rb->boundary is between
			 * rb->mem and rb->l2p_update.
			 * As a result, it's safe here to
			 * read rb->boundary without acquiring
			 * rb->w_lock.
			 */
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
	return BLK_STS_OK;
}

unsigned int qblk_rb_wrap_pos(struct qblk_rb *rb, unsigned int pos)
{
	unsigned int boundary = READ_ONCE(rb->boundary);

	while (pos >= boundary)
		pos -= boundary;
	return pos;
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
	unsigned int boundary;

	if (count < nr_entries) {
		pad = nr_entries - count;
		to_read = count;
	}

	c_ctx->sentry =	pos;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	//pr_notice("%s,rb=%u,pos=%u,nr_entries=%u,count=%u\n", __func__,
	//	rb->rb_index,
	//	pos, nr_entries, count);

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

		//pr_notice("%s, %d\n", __func__, __LINE__);

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

		boundary = READ_ONCE(rb->boundary);

		pos++;
		if (pos >= boundary)
			pos -= boundary;

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
	if (qblk_rl_gc_maynot_insert(&qblk->rl, &chi->per_ch_rl, nr_entries))
		return 0;

	spin_lock(&rb->w_lock);
	if (!qblk_rb_may_write(qblk, rb, nr_entries, pos)) {
		spin_unlock(&rb->w_lock);
		atomic_add_unless(&rb->complaint, 1, QBLK_RB_MAX_COMPLAINT);
		return 0;
	}

	qblk_rl_gc_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	return 1;
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int qblk_write_gc_to_cache(struct qblk *qblk, struct qblk_gc_rq *gc_rq)
{
	struct qblk_w_ctx w_ctx;
	unsigned int bpos;
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

		/* Since we only write one entry here,
		 * we don't need to wrap the bpos.
		 */
		qblk_rb_write_entry_gc(qblk, rb, data,
						w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], bpos);
		
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

/* Return the number of pages that truely allocated */
static int qblk_rb_coordinator_allocpage(struct qblk *qblk,
			int rb_idx, unsigned int nr_alloc)
{
	struct qblk_rb *rb;
	unsigned int boundary, boundary_large, boundary_small;
	int ret;

	rb = &qblk->mqrwb[rb_idx];

	spin_lock(&rb->w_lock);
	boundary = READ_ONCE(rb->boundary);
	boundary_small = READ_ONCE(rb->boundary_small);
	boundary_large = READ_ONCE(rb->boundary_large);

	if (likely(!boundary_large)) {
		if (likely(!boundary_small)) {
			if (nr_alloc + boundary > qblk->rb_max_thres)
				nr_alloc = qblk->rb_max_thres - boundary;
			qblk_alloc_freepage_to_rb(qblk, rb, boundary, nr_alloc);
			smp_store_release(&rb->boundary_large, boundary + nr_alloc);
			ret = nr_alloc;
		} else {
			//We just simply cancel the free operation.
			smp_store_release(&rb->boundary_small, 0);
			ret = 0;
		}
	} else {
		if (nr_alloc + boundary_large > qblk->rb_max_thres)
			nr_alloc = qblk->rb_max_thres - boundary_large;
		qblk_alloc_freepage_to_rb(qblk, rb, boundary_large, nr_alloc);
		smp_store_release(&rb->boundary_large, boundary_large + nr_alloc);
		ret = nr_alloc;
	}
	spin_unlock(&rb->w_lock);
	return ret;
}

static void inline qblk_save_coordinator_op(struct qblk *qblk, int rb_index, int op)
{
	qblk->op_saved[rb_index * QBLK_NR_SAVED_OP + qblk->op_saved_iter]
				= op;
}

static int inline qblk_read_coordinator_op(struct qblk *qblk, int rb_index, int iter)
{
	return qblk->op_saved[rb_index * QBLK_NR_SAVED_OP + iter];
}


static inline void qblk_incr_ops_iter(struct qblk *qblk)
{
	qblk->op_saved_iter++;
	if (qblk->op_saved_iter >= QBLK_NR_SAVED_OP)
		qblk->op_saved_iter = 0;
}

static inline int qblk_op_prev(struct qblk *qblk, int k)
{
	int iter = qblk->op_saved_iter - k;
	if (iter < 0)
		return iter + QBLK_NR_SAVED_OP;
	else
		return iter;
}

void qblk_rb_coordinator_fn(struct work_struct *work)
{
	struct qblk *qblk = container_of(work, struct qblk, rb_coordinator.work);
	unsigned int nr_rb = qblk->nr_queues;
	unsigned int i;
	static int free_iter = 0;
	unsigned int totalComplaint = 0;
	unsigned int totalFree = atomic_read(&qblk->nr_free_pages);
	struct qblk_rb *rb;

	for (i = 0; i < nr_rb; i++) {
		rb = &qblk->mqrwb[i];
		qblk->complaints[i] = atomic_xchg(&rb->complaint, 0);
		totalComplaint += qblk->complaints[i];
		rb->rb_active_cache = READ_ONCE(rb->rb_active);
		smp_store_release(&rb->rb_active, 0);
	}

	if (totalComplaint < QBLK_COMPLAINT_THRESHOLD)
		totalFree = (totalFree * totalComplaint) / QBLK_COMPLAINT_THRESHOLD;

	//pr_notice("%s, totalComplaint=%u, totalFree=%u, nrrb[%u]\n",
	//		__func__, totalComplaint, totalFree, nr_rb);

	//alloc free pages to rb
	if (totalComplaint) {
		unsigned int nr_alloc;

		for (i = 0; i < nr_rb; i++) {
			nr_alloc = (totalFree * qblk->complaints[i]) / totalComplaint;
			if (nr_alloc && nr_alloc <= totalFree)
				nr_alloc = qblk_rb_coordinator_allocpage(qblk, i, nr_alloc);
#ifdef QBLK_TRACE_RB_CHANGE
			if (nr_alloc && nr_alloc <= totalFree) {
#if 0
				pr_notice("%s,complaint=%u,totalComplaint=%u\n",
							__func__,
							qblk->complaints[i],
							totalComplaint);
#endif
				qblk_trace_rbChange(i, 0, nr_alloc);
			}
#endif
			qblk_save_coordinator_op(qblk, i, nr_alloc);
		}
	}

	//free pages from rb
	totalFree = atomic_read(&qblk->nr_free_pages);
	if (totalFree < qblk->free_pool_threshold) {
		struct qblk_rb *rb;
		int toFree;
		int rb_to_free;
		unsigned int boundary, boundary_small, boundary_large;
		unsigned int rb_remain;

		//Free memory from rb
		toFree = qblk->free_pool_threshold - totalFree;

		/* Iterate rb to free some space */
		for (i = 0; toFree > 0 && i < nr_rb; i++, free_iter++) {

			if (free_iter >= nr_rb)
				free_iter = 0;
			if (qblk->complaints[free_iter])
				continue;

			rb = &qblk->mqrwb[free_iter];

			spin_lock(&rb->w_lock);
			boundary_small = READ_ONCE(rb->boundary_small);
			if (boundary_small)
				boundary = boundary_small;
			else
				boundary = READ_ONCE(rb->boundary);

			//rb_to_free = min(rb_remain, QBLK_RB_MAX_FREE_PER_TURN, toFree)
			if (boundary > qblk->rb_mid_thres) {
				int lastfree;
				int prev = qblk_read_coordinator_op(qblk,
							free_iter,
							qblk_op_prev(qblk, 1));


				if (prev < 0 - QBLK_RB_MAX_FREE_PER_TURN)
					lastfree = 0 - prev;
				else
					lastfree = QBLK_RB_MAX_FREE_PER_TURN;	

				/* last free is positive,
				 * rb_to_free must be greater
				 * than it */
				if (!rb->rb_active_cache && prev < 0)
					rb_to_free = lastfree << 1;
				else
					rb_to_free = QBLK_RB_MAX_FREE_PER_TURN;


				/* Be careful about overflow */
				if (rb_to_free < lastfree ||
						boundary <= rb_to_free ||
						boundary - rb_to_free < qblk->rb_mid_thres)
					rb_to_free = boundary - qblk->rb_mid_thres;

			} else {
				rb_remain = boundary - qblk->rb_min_thres;
				rb_to_free =
					(QBLK_RB_MAX_FREE_PER_TURN < rb_remain) ? QBLK_RB_MAX_FREE_PER_TURN : rb_remain;
			}
			rb_to_free = (toFree < rb_to_free) ? toFree : rb_to_free;

			if (!rb_to_free) {
				spin_unlock(&rb->w_lock);
				continue;
			}

			//free @rb_to_free amount of memory from this rb.
			boundary_large = READ_ONCE(rb->boundary_large);
			if (unlikely(boundary_large)) {
				smp_store_release(&rb->boundary_large, 0);
				qblk_free_page_from_rb(qblk, rb, boundary, boundary_large);
				spin_unlock(&rb->w_lock);
				toFree -= boundary_large - boundary;
				qblk_save_coordinator_op(qblk, free_iter, boundary - boundary_large);
#ifdef QBLK_TRACE_RB_CHANGE
				qblk_trace_rbChange(free_iter, 1, boundary_large - boundary);
#endif
				
			} else {
				smp_store_release(&rb->boundary_small, boundary - rb_to_free);
				spin_unlock(&rb->w_lock);
				toFree -= rb_to_free;
				qblk_save_coordinator_op(qblk, free_iter, 0 - rb_to_free);
				mod_delayed_work_on(rb->rb_index, system_wq, &rb->shrink_dwork, 0);

			}

		}
	}

	qblk_incr_ops_iter(qblk);

	if(atomic_read(&qblk->run_coordinator))
		schedule_delayed_work(&qblk->rb_coordinator,
					__msecs_to_jiffies(400));
	else
		/* Set the flag as 2 to indicate the termination of this coordinator */
		atomic_set(&qblk->run_coordinator, 2);

}

