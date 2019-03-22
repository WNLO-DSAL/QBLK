#include "qblk.h"

//---
static void qblk_map_page_data(struct qblk *qblk,
			struct ch_info *chi, unsigned int sentry,
			struct ppa_addr *ppa_list,
			unsigned long *lun_bitmap,
			struct qblk_sec_meta *meta_list,
			unsigned int valid_secs, unsigned int rb_count)
{
	struct qblk_line *line;
	struct qblk_emeta *emeta;
	struct qblk_w_ctx *w_ctx;
	__le64 *lba_list;
	struct ppa_addr newpage;
	u64 offset_in_line;
	int nr_secs = qblk->min_write_pgs;
	int i;

	//pr_notice("%s,sentry=%u,valid_secs=%u,rb_count=%u\n",__FUNCTION__,sentry,valid_secs,rb_count);

	newpage = qblk_alloc_page(qblk, chi, &line, nr_secs);
	offset_in_line = gen_ppa_to_offset_in_line(qblk, newpage);

	emeta = line->emeta;
	lba_list = emeta_to_lbas(qblk, emeta->buf);

	for (i = 0; i < nr_secs;
			i++, offset_in_line++,
			newpage = gen_ppa_add_one_inside_chnl(qblk, newpage)) {
		__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

		/* ppa to be sent to the device */
		ppa_list[i] = newpage;

		//pr_notice("%s,ppalist[%d]=0x%llx\n",__FUNCTION__,i,ppa_list[i].ppa);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and a single writer thread have access to each specific entry
		 * at a time. Thus, it is safe to modify the context for the
		 * entry we are setting up for submission without taking any
		 * lock or memory barrier.
		 */
		if (i < valid_secs) {
			kref_get(&line->ref);
			//pr_notice("%s,get ref of ch[%d],line[%u]\n",__FUNCTION__,chi->ch_index,line->id);
			w_ctx = qblk_rb_w_ctx(&qblk->mqrwb[rb_count], sentry + i);
			w_ctx->ppa = ppa_list[i];
			meta_list[i].lba = cpu_to_le64(w_ctx->lba);
			lba_list[offset_in_line] = cpu_to_le64(w_ctx->lba);
			if (lba_list[offset_in_line] != addr_empty)
				line->nr_valid_lbas++;
			//else
			//	atomic64_inc(&pblk->pad_wa);
			//pr_notice("i=%d,meta_list[i].lba(cpu)=0x%llx,ppa=0x%llx\n",i,w_ctx->lba,ppa_list[i].ppa);
		} else {
			lba_list[offset_in_line] = meta_list[i].lba = addr_empty;
			__qblk_map_invalidate(qblk, chi, line, offset_in_line);
		}
	}
	//pr_notice("------%s---END-----\n",__FUNCTION__);

	qblk_mark_rq_luns(qblk, ppa_list, nr_secs, lun_bitmap);
}


void qblk_map_rq(struct qblk *qblk, struct ch_info *chi,
			struct nvm_rq *rqd, unsigned int sentry,
			unsigned long *lun_bitmap,
			unsigned int valid_secs,
			unsigned int off, unsigned int rb_count)
{
	struct qblk_sec_meta *meta_list = rqd->meta_list;
	unsigned int map_secs;
	int min = qblk->min_write_pgs;
	int i;

	//pr_notice("%s,sentry=%u,valid_secs=%u,off=%u,rb_count=%u\n",
	//	__FUNCTION__,sentry,valid_secs,off,rb_count);

	for (i = off; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		qblk_map_page_data(qblk, chi, sentry + i, &rqd->ppa_list[i],
					lun_bitmap, &meta_list[i], map_secs, rb_count);
	}
}

void qblk_map_erase_rq(struct qblk *qblk,
			struct ch_info *chi, struct nvm_rq *rqd,
		    unsigned int sentry, unsigned long *lun_bitmap,
		    unsigned int valid_secs, struct ppa_addr *erase_ppa,
		    unsigned int rb_count)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_sec_meta *meta_list = rqd->meta_list;
	struct qblk_line *e_line, *d_line;
	unsigned int map_secs;
	int min = qblk->min_write_pgs;
	int i, erase_lun;

	//pr_notice("%s,sentry=%u,valid_secs=%u,rb_count=%u\n",
	//	__FUNCTION__,sentry,valid_secs,rb_count);

	for (i = 0; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		qblk_map_page_data(qblk, chi, sentry + i, &rqd->ppa_list[i],
					lun_bitmap, &meta_list[i], map_secs, rb_count);

		erase_lun = qblk_ppa_to_posinsidechnl(geo, rqd->ppa_list[i]);

		/* line can change after page map. We might also be writing the
		 * last line.
		 */
		e_line = qblk_line_get_erase(chi);
		if (!e_line)
			return qblk_map_rq(qblk, chi, rqd, sentry, lun_bitmap,
							valid_secs, i + min, rb_count);

		spin_lock(&e_line->lock);
		if (!test_bit(erase_lun, e_line->erase_bitmap)) {
			set_bit(erase_lun, e_line->erase_bitmap);
			atomic_dec(&e_line->left_eblks);

			*erase_ppa = rqd->ppa_list[i];
			erase_ppa->g.blk = e_line->id;

			spin_unlock(&e_line->lock);

			/* Avoid evaluating e_line->left_eblks */
			return qblk_map_rq(qblk, chi, rqd, sentry, lun_bitmap,
							valid_secs, i + min, rb_count);
		}
		spin_unlock(&e_line->lock);
	}

	d_line = qblk_line_get_data(chi);

	/* line can change after page map. We might also be writing the
	 * last line.
	 */
	e_line = qblk_line_get_erase(chi);
	if (!e_line)
		return;

	/* Erase blocks that are bad in this line but might not be in next */
	if (unlikely(qblk_ppa_empty(*erase_ppa)) &&
			bitmap_weight(d_line->blk_bitmap, meta->blk_per_chline)) {
		int bit = -1;

retry:
		bit = find_next_bit(d_line->blk_bitmap,
						meta->blk_per_chline, bit + 1);
		if (bit >= meta->blk_per_chline)
			return;

		spin_lock(&e_line->lock);
		if (test_bit(bit, e_line->erase_bitmap)) {
			spin_unlock(&e_line->lock);
			goto retry;
		}
		spin_unlock(&e_line->lock);

		set_bit(bit, e_line->erase_bitmap);
		atomic_dec(&e_line->left_eblks);
		*erase_ppa = qblk->luns[bit].bppa; /* set ch and lun */
		erase_ppa->g.blk = e_line->id;
	}

}

