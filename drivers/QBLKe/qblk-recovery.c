#include"qblk.h"

/* Check the CRC of emeta, return 0 if succeed. */
int qblk_recov_check_emeta(struct qblk *qblk, struct chnl_emeta *emeta_buf)
{
	u32 crc;

	crc = qblk_calc_emeta_crc(qblk, emeta_buf);
	if (le32_to_cpu(emeta_buf->crc) != crc)
		return -1;

	if (le32_to_cpu(emeta_buf->header.identifier) != QBLK_MAGIC)
		return -2;

	return 0;
}

/* Return 0 if succeed. */
int qblk_recov_l2p(struct qblk *qblk)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct ch_info *chi;
	struct qblk_line *line;
	struct qblk_smeta *smeta;
	struct qblk_emeta *emeta;
	struct chnl_smeta *smeta_buf;
	int found_lines = 0, recovered_lines = 0;
	int meta_line;
	int i;
	int ch_idx;
	LIST_HEAD(recov_list);

	for (ch_idx = 0; ch_idx < qblk->nr_channels; ch_idx++) {
		chi = &qblk->ch[ch_idx];
		spin_lock(&chi->free_lock);
		meta_line = find_first_zero_bit(&chi->meta_bitmap,
							QBLK_DATA_LINES);
		set_bit(meta_line, &chi->meta_bitmap);
		smeta = chi->sline_meta[meta_line];
		emeta = chi->eline_meta[meta_line];
		smeta_buf = (struct chnl_smeta *)smeta;
		spin_unlock(&chi->free_lock);

		for (i = 0; i < chi->nr_lines; i++) {
			u32 crc;

			line = &chi->lines[i];

			memset(smeta, 0, meta->smeta_len);
			line->smeta = smeta;
			line->lun_bitmap = ((void *)(smeta_buf)) +
							sizeof(struct chnl_smeta);

			/* Lines that cannot be read are assumed as not written here */
			if (qblk_line_read_smeta(qblk, line))
				continue;

			crc = qblk_calc_smeta_crc(qblk, smeta_buf);
			if (le32_to_cpu(smeta_buf->crc) != crc)
				continue;

			if (le32_to_cpu(smeta_buf->header.identifier)
							!= QBLK_MAGIC)
				continue;
			pr_err("%s, found lines, i = %d\n",
								__func__, i);
#if 0
			if (smeta_buf->header.version != SMETA_VERSION) {
				pr_err("qblk: found incompatible line version %u\n",
						le16_to_cpu(smeta_buf->header.version));
				return ERR_PTR(-EINVAL);
			}

			/* The first valid instance uuid is used for initialization */
			if (!valid_uuid) {
				memcpy(qblk->instance_uuid, smeta_buf->header.uuid, 16);
				valid_uuid = 1;
			}

			if (memcmp(qblk->instance_uuid, smeta_buf->header.uuid, 16)) {
				pr_debug("qblk: ignore line %u due to uuid mismatch\n",
						i);
				continue;
			}

			/* Update line metadata */
			spin_lock(&line->lock);
			line->id = le32_to_cpu(smeta_buf->header.id);
			line->type = le16_to_cpu(smeta_buf->header.type);
			line->seq_nr = le64_to_cpu(smeta_buf->seq_nr);
			spin_unlock(&line->lock);

			/* Update general metadata */
			spin_lock(&chi->free_lock);
			if (line->seq_nr >= chi->d_seq_nr)
				chi->d_seq_nr = line->seq_nr + 1;
			chi->nr_free_lines--;
			spin_unlock(&chi->free_lock);

			//--------

			if (pblk_line_recov_alloc(pblk, line))
				goto next_chnl;

			pblk_recov_line_add_ordered(&recov_list, line);
			found_lines++;
			pr_debug("pblk: recovering data line %d, seq:%llu\n",
					line->id, smeta_buf->seq_nr);
#endif
		}

		if (!found_lines) {
			qblk_setup_uuid(qblk);

			spin_lock(&chi->free_lock);
			WARN_ON_ONCE(!test_and_clear_bit(meta_line,
							&chi->meta_bitmap));
			spin_unlock(&chi->free_lock);

			goto next_chnl;
		}
		pr_err("%s, found lines!\n", __func__);
#if 0
		/* Verify closed blocks and recover this portion of L2P table*/
		list_for_each_entry_safe(line, tline, &recov_list, list) {
			recovered_lines++;

			line->emeta_ssec = pblk_line_emeta_start(pblk, line);
			line->emeta = emeta;
			memset(line->emeta->buf, 0, lm->emeta_len[0]);

			if (pblk_line_read_emeta(pblk, line, line->emeta->buf)) {
				pblk_recov_l2p_from_oob(pblk, line);
				goto next;
			}

			if (pblk_recov_check_emeta(pblk, line->emeta->buf)) {
				pblk_recov_l2p_from_oob(pblk, line);
				goto next;
			}

			if (pblk_recov_l2p_from_emeta(pblk, line))
				pblk_recov_l2p_from_oob(pblk, line);

next:
			if (pblk_line_is_full(line)) {
				struct list_head *move_list;

				spin_lock(&line->lock);
				line->state = PBLK_LINESTATE_CLOSED;
				move_list = pblk_line_gc_list(pblk, line);
				spin_unlock(&line->lock);

				spin_lock(&l_mg->gc_lock);
				list_move_tail(&line->list, move_list);
				spin_unlock(&l_mg->gc_lock);

				kfree(line->map_bitmap);
				line->map_bitmap = NULL;
				line->smeta = NULL;
				line->emeta = NULL;
			} else {
				if (open_lines > 1)
					pr_err("pblk: failed to recover L2P\n");

				open_lines++;
				line->meta_line = meta_line;
				data_line = line;
			}
		}

		spin_lock(&chi->free_lock);
		if (!open_lines) {
			WARN_ON_ONCE(!test_and_clear_bit(meta_line,
								&l_mg->meta_bitmap));
			pblk_line_replace_data(pblk);
		} else {
			/* Allocate next line for preparation */
			chi->data_next = pblk_line_get(pblk);
			if (l_mg->data_next) {
				l_mg->data_next->seq_nr = l_mg->d_seq_nr++;
				l_mg->data_next->type = PBLK_LINETYPE_DATA;
				is_next = 1;
			}
		}
		spin_unlock(&chi->free_lock);

		if (is_next)
			pblk_line_erase(pblk, l_mg->data_next);
#endif
next_chnl:
		if (found_lines != recovered_lines) {
			pr_err("%s, failed to recover lines ch=%d, found_lines=%d, recovered_lines=%d\n",
							__func__, chi->ch_index, found_lines, recovered_lines);
			return -EIO;
		}
	}

	return 0;

}

