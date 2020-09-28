#include "qblk.h"

static struct kmem_cache *qblk_ws_cache, *qblk_rec_cache;
static struct kmem_cache *qblk_g_rq_cache, *qblk_w_rq_cache;

static DECLARE_RWSEM(qblk_lock);

static int qblk_hw_queue_depth = 64;
module_param_named(hw_queue_depth, qblk_hw_queue_depth, int, 0444);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: 64");

static int qblk_home_node = NUMA_NO_NODE;
module_param_named(home_node, qblk_home_node, int, 0444);
MODULE_PARM_DESC(home_node, "Home node for the device. Default: NUMA_NO_NODE");

static sector_t qblk_capacity(void *private)
{
	struct qblk *qblk = private;

	return qblk->capacity * NR_PHY_IN_LOG;
}

static int qblk_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int hctx_idx)
{
	struct qblk *qblk = data;
	struct nvm_geo *geo = &qblk->dev->geo;
	struct qblk_queue *pq = &qblk->queues[hctx_idx];

	hctx->driver_data = pq;
	//initialize pq
	pq->hctx = hctx;
	pq->hctx_idx = hctx_idx;
	pq->rb_idx = hctx_idx;
	pq->rb = &qblk->mqrwb[hctx_idx];

	atomic_set(&pq->map_chnl, hctx_idx % geo->nr_chnls);
	atomic_set(&pq->inflight_write_secs, 0);
	pq->wbchnl = hctx_idx % geo->nr_chnls;
	return 0;
}

static void qblk_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
}

static void qblk_cleanup_queues(struct qblk *qblk)
{
	//per-queue removal is in qblk_exit_hctx()
	kfree(qblk->queues);
}

static int qblk_setup_queues(struct qblk *qblk,	unsigned int *dev_NRQ)
{
	*dev_NRQ = qblk->nr_queues = num_possible_cpus();
	/*
	if(*dev_NRQ < qblk->nr_queues)
		qblk->nr_queues = *dev_NRQ;
	else
		*dev_NRQ = qblk->nr_queues;
	*/
	qblk->queues = kcalloc(*dev_NRQ, sizeof(struct qblk_queue), GFP_KERNEL);
	if (!qblk->queues)
		return -ENOMEM;
	qblk->queue_depth = qblk_hw_queue_depth;
	//per-queue initialization is in qblk_init_hctx()
	return 0;
}

static const struct block_device_operations qblk_fops = {
	.owner		= THIS_MODULE,
};

static int qblk_gendisk_register(struct qblk *qblk,
					struct gendisk **ptdisk,
					struct nvm_ioctl_create *create)
{
	struct gendisk *disk;

	disk = qblk->disk = alloc_disk(0);
	if (!disk)
		return -ENOMEM;
	set_capacity(disk, qblk->capacity * NR_PHY_IN_LOG);
	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major		= 0;
	disk->first_minor	= 0;
	disk->fops		= &qblk_fops;
	disk->private_data	= qblk;
	disk->queue		= qblk->q;
	strlcpy(disk->disk_name, create->tgtname, sizeof(disk->disk_name));
	*ptdisk = qblk->disk = disk;
	add_disk(disk);
	return 0;
}

static blk_status_t qblk_write_req(struct request_queue *q,
						struct qblk *qblk, struct qblk_queue *pq,
						struct request *req)
{
	return qblk_rq_write_to_cache(qblk, pq, req, QBLK_IOTYPE_USER);
}


//submit a request to ring buffer
//By the time we get here, we've already got the lock of qblk_queue
static blk_status_t qblk_mq_submit_cmd_nowait(struct request_queue *q,
			struct blk_mq_hw_ctx *hctx,
			struct qblk_queue *pq,
			struct request *req,
			struct qblk_mq_cmd *cmd)
{
	struct qblk *qblk = q->queuedata;
	blk_status_t ret = BLK_STS_OK;

	switch (req_op(req)) {
	case REQ_OP_WRITE_ZEROES:
		/* currently only aliased to deallocate for a few ctrls: */
	case REQ_OP_DISCARD:
		qblk_discard_req(qblk, req);
		blk_mq_end_request(req, BLK_STS_OK);
		break;
	case REQ_OP_READ:
		ret = qblk_read_req_nowait(q, qblk, req);
		break;
	case REQ_OP_FLUSH:
	case REQ_OP_WRITE:
		ret = qblk_write_req(q, qblk, pq, req);
		break;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	return ret;
}


static blk_status_t qblk_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct qblk_mq_cmd *qblk_cmd = blk_mq_rq_to_pdu(bd->rq);
	struct qblk_queue *pq = hctx->driver_data;
	//unsigned long flags;
	blk_status_t ret;

	qblk_cmd->gb_req = bd->rq;
	qblk_cmd->qblkQueue = pq;
	qblk_cmd->error = BLK_STS_OK;

	blk_mq_start_request(bd->rq);

	ret = qblk_mq_submit_cmd_nowait(hctx->queue, hctx,
								pq, bd->rq, qblk_cmd);
	return ret;
}


static void qblk_irq_done_fn(struct request *rq)
{
	struct qblk_mq_cmd *qblk_cmd = blk_mq_rq_to_pdu(rq);
	//pr_notice("%s, end request with %d\n", __func__, qblk_cmd->error);
	blk_mq_end_request(rq, qblk_cmd->error);
}


static const struct blk_mq_ops qblk_mq_ops = {
	.queue_rq       = qblk_queue_rq,
	.complete	= qblk_irq_done_fn,
	.init_hctx	= qblk_init_hctx,
	.exit_hctx	= qblk_exit_hctx,
};


static int qblk_init_tag_set(struct qblk *qblk, struct blk_mq_tag_set *set)
{
	set->ops = &qblk_mq_ops;
	set->nr_hw_queues = qblk->nr_queues;
	set->queue_depth = qblk_hw_queue_depth;
	set->numa_node = qblk_home_node;
	set->cmd_size	= sizeof(struct qblk_mq_cmd);
	set->flags = BLK_MQ_F_SHOULD_MERGE;
	set->flags |= BLK_MQ_F_NO_SCHED;
	set->driver_data = qblk;
	return blk_mq_alloc_tag_set(set);
}

static int qblk_init_global_caches(struct qblk *qblk)
{
	down_write(&qblk_lock);

	qblk_ws_cache = kmem_cache_create("qblk_blk_ws",
				sizeof(struct qblk_line_ws), 0, 0, NULL);
	if (!qblk_ws_cache)
		goto out1;

	qblk_rec_cache = kmem_cache_create("qblk_rec",
				sizeof(struct qblk_rec_ctx), 0, 0, NULL);
	if (!qblk_rec_cache)
		goto out2;

	qblk_g_rq_cache = kmem_cache_create("qblk_g_rq", qblk_g_rq_size,
				0, 0, NULL);
	if (!qblk_g_rq_cache)
		goto out3;

	qblk_w_rq_cache = kmem_cache_create("qblk_w_rq", qblk_w_rq_size,
				0, 0, NULL);
	if (!qblk_w_rq_cache)
		goto out4;

	up_write(&qblk_lock);
	return 0;

out4:
	kmem_cache_destroy(qblk_g_rq_cache);
out3:
	kmem_cache_destroy(qblk_rec_cache);
out2:
	kmem_cache_destroy(qblk_ws_cache);
out1:
	up_write(&qblk_lock);
	return -ENOMEM;
}

static void qblk_free_global_caches(struct qblk *qblk)
{
	kmem_cache_destroy(qblk_ws_cache);
	kmem_cache_destroy(qblk_rec_cache);
	kmem_cache_destroy(qblk_g_rq_cache);
	kmem_cache_destroy(qblk_w_rq_cache);
}

static int qblk_set_ppaf(struct qblk *qblk)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct nvm_addr_format ppaf = geo->ppaf;
	int power_len;

	/* Re-calculate channel and lun format to adapt to configuration */
	power_len = get_count_order(geo->nr_chnls);
	if (1 << power_len != geo->nr_chnls) {
		pr_err("qblk: supports only power-of-two channel config.\n");
		return -EINVAL;
	}
	ppaf.ch_len = power_len;

	power_len = get_count_order(geo->nr_luns);
	if (1 << power_len != geo->nr_luns) {
		pr_err("qblk: supports only power-of-two LUN config.\n");
		return -EINVAL;
	}
	ppaf.lun_len = power_len;

	qblk->ppaf.sec_offset = 0;
	qblk->ppaf.pln_offset = ppaf.sect_len;
	qblk->ppaf.ch_offset = qblk->ppaf.pln_offset + ppaf.pln_len;
	qblk->ppaf.lun_offset = qblk->ppaf.ch_offset + ppaf.ch_len;
	qblk->ppaf.pg_offset = qblk->ppaf.lun_offset + ppaf.lun_len;
	qblk->ppaf.blk_offset = qblk->ppaf.pg_offset + ppaf.pg_len;
	qblk->ppaf.lun_offset_inchnl = qblk->ppaf.ch_offset;
	qblk->ppaf.pg_offset_inchnl = qblk->ppaf.lun_offset_inchnl + ppaf.lun_len;
	qblk->ppaf.sec_mask = (1ULL << ppaf.sect_len) - 1;
	qblk->ppaf.pln_mask = ((1ULL << ppaf.pln_len) - 1) <<
							qblk->ppaf.pln_offset;
	qblk->ppaf.ch_mask = ((1ULL << ppaf.ch_len) - 1) <<
							qblk->ppaf.ch_offset;
	qblk->ppaf.lun_mask = ((1ULL << ppaf.lun_len) - 1) <<
							qblk->ppaf.lun_offset;
	qblk->ppaf.pg_mask = ((1ULL << ppaf.pg_len) - 1) <<
							qblk->ppaf.pg_offset;
	qblk->ppaf.blk_mask = ((1ULL << ppaf.blk_len) - 1) <<
							qblk->ppaf.blk_offset;

	qblk->ppaf.lun_mask_inchnl = ((1ULL << ppaf.lun_len) - 1) <<
							qblk->ppaf.lun_offset_inchnl;
	qblk->ppaf.pg_mask_inchnl = ((1ULL << ppaf.pg_len) - 1) <<
							qblk->ppaf.pg_offset_inchnl;

	qblk->ppaf_bitsize = qblk->ppaf.blk_offset + ppaf.blk_len;
	/*
	pr_notice("secoff=%d,plnoff=%d,choff=%d,lunoff=%d,pgoff=%d,blkoff=%d\n",
		qblk->ppaf.sec_offset, qblk->ppaf.pln_offset, qblk->ppaf.ch_offset,
		qblk->ppaf.lun_offset, qblk->ppaf.pg_offset, qblk->ppaf.blk_offset);
	pr_notice("ppaf_bitsize=%d\n", qblk->ppaf_bitsize);
	 */

	return 0;
}

static size_t qblk_trans_map_size(struct qblk *qblk)
{
	int entry_size = 8;

	if (qblk->ppaf_bitsize < 32)
		entry_size = 4;

	return entry_size * qblk->rl.nr_secs;
}

#ifdef CONFIG_NVM_DEBUG
static u32 qblk_l2p_crc(struct qblk *qblk)
{
	size_t map_size;
	u32 crc = ~(u32)0;

	map_size = qblk_trans_map_size(qblk);
	crc = crc32_le(crc, qblk->trans_map, map_size);
	return crc;
}
#endif

static void qblk_l2p_free(struct qblk *qblk)
{
	vfree(qblk->trans_map);
}

static int qblk_l2p_init(struct qblk *qblk)
{
	sector_t i;
	struct ppa_addr ppa;
	size_t map_size;

	map_size = qblk_trans_map_size(qblk);
	qblk->trans_map = vmalloc(map_size);
	if (!qblk->trans_map)
		return -ENOMEM;

	qblk_ppa_set_empty(&ppa);
#ifdef QBLK_TRANSMAP_LOCK
	spin_lock_init(&qblk->trans_lock);
	spin_lock(&qblk->trans_lock);
	for (i = 0; i < qblk->rl.nr_secs; i++)
		qblk_trans_map_set(qblk, i, ppa);
	spin_unlock(&qblk->trans_lock);
#else
	for (i = 0; i < qblk->rl.nr_secs; i++)
		qblk_trans_map_atomic_set(qblk, i, ppa);
#endif

	return 0;
}


static int qblk_core_init(struct qblk *qblk, unsigned int hwqc)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int i;

	qblk->pgs_in_buffer = NVM_MEM_PAGE_WRITE * geo->sec_per_pg *
							geo->nr_planes * geo->nr_luns;

	//pr_notice("%s, pgs_in_buffer = %d\n", __func__, qblk->pgs_in_buffer);

	if (qblk_init_global_caches(qblk))
		return -ENOMEM;

	/* Internal bios can be at most the sectors signaled by the device. */

	qblk->page_bio_pool = mempool_create_page_pool(nvm_max_phys_sects(dev), 0);

	if (!qblk->page_bio_pool)
		goto free_global_caches;

	qblk->gen_ws_pool = mempool_create_slab_pool(QBLK_GEN_WS_POOL_SIZE,
							qblk_ws_cache);
	if (!qblk->gen_ws_pool)
		goto free_page_bio_pool;

	qblk->rec_pool = mempool_create_slab_pool(geo->all_luns,
							qblk_rec_cache);
	if (!qblk->rec_pool)
		goto free_gen_ws_pool;

	qblk->r_rq_pool = mempool_create_slab_pool(geo->all_luns,
							qblk_g_rq_cache);
	if (!qblk->r_rq_pool)
		goto free_rec_pool;

	qblk->e_rq_pool = mempool_create_slab_pool(geo->all_luns,
							qblk_g_rq_cache);
	if (!qblk->e_rq_pool)
		goto free_r_rq_pool;

	qblk->w_rq_pool = mempool_create_slab_pool(geo->all_luns,
							qblk_w_rq_cache);
	if (!qblk->w_rq_pool)
		goto free_e_rq_pool;

	qblk->close_wq = alloc_workqueue("qblk-close-wq",
			WQ_MEM_RECLAIM | WQ_UNBOUND, QBLK_NR_CLOSE_JOBS);
	if (!qblk->close_wq)
		goto free_w_rq_pool;

	qblk->bb_wq = alloc_workqueue("qblk-bb-wq",
			WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!qblk->bb_wq)
		goto free_close_wq;

	qblk->r_end_wq = alloc_workqueue("qblk-read-end-wq",
			WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!qblk->r_end_wq)
		goto free_bb_wq;
	 

	if (qblk_set_ppaf(qblk))
		goto free_r_end_wq;

	//Initialize per queue complete_list
	qblk->complete_list_mq = kmalloc_array(hwqc, sizeof(struct list_head), GFP_KERNEL);
	for (i = 0; i < hwqc; i++)
		INIT_LIST_HEAD(&qblk->complete_list_mq[i]);
	return 0;

free_r_end_wq:
	destroy_workqueue(qblk->r_end_wq);
free_bb_wq:
	destroy_workqueue(qblk->bb_wq);
free_close_wq:
	destroy_workqueue(qblk->close_wq);
free_w_rq_pool:
	mempool_destroy(qblk->w_rq_pool);
free_e_rq_pool:
	mempool_destroy(qblk->e_rq_pool);
free_r_rq_pool:
	mempool_destroy(qblk->r_rq_pool);
free_rec_pool:
	mempool_destroy(qblk->rec_pool);
free_gen_ws_pool:
	mempool_destroy(qblk->gen_ws_pool);
free_page_bio_pool:
	mempool_destroy(qblk->page_bio_pool);
free_global_caches:
	qblk_free_global_caches(qblk);
	return -ENOMEM;
}

static void qblk_core_free(struct qblk *qblk)
{
	if (qblk->close_wq)
		destroy_workqueue(qblk->close_wq);

	/*
	if (qblk->r_end_wq)
		destroy_workqueue(qblk->r_end_wq);
	*/

	if (qblk->bb_wq)
		destroy_workqueue(qblk->bb_wq);

	mempool_destroy(qblk->page_bio_pool);
	mempool_destroy(qblk->gen_ws_pool);
	mempool_destroy(qblk->rec_pool);
	mempool_destroy(qblk->r_rq_pool);
	mempool_destroy(qblk->e_rq_pool);
	mempool_destroy(qblk->w_rq_pool);

	qblk_free_global_caches(qblk);
}

static void qblk_set_provision_step1(struct qblk * qblk)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;

	if (geo->op == NVM_TARGET_DEFAULT_OP)
		qblk->op = QBLK_DEFAULT_OP;
	else
		qblk->op = geo->op;
	//pr_notice("qblk->op=%d\n",qblk->op);
	qblk->rl.total_blocks = 0;
}


/*
 * Calculate the provision of QBLK.
 *
 * @nr_free_blks is the number of good chunks in OCSSD.
 * 		A chunk is multiple blocks inside one LUN with
 * 		identical block number but different plane number.
 * 
 * SSD capacity = (nr_chunks - @A - @B) * (100 - @OP)/100
 * @A is the number of chunks used to store smeta, emeta etc.
 * @B is the minimum reserved chunks.
 * @OP is the percentage of over-provisioning.
 */
static void qblk_set_provision_step2(struct qblk *qblk, long nr_free_blks)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	sector_t provisioned;
	int sec_meta, sec_resv;
	int i;
	struct qblk_metainfo *meta = &qblk->metainfo;


	/* Consider sectors used for metadata */
	sec_meta = 0;
	for (i = 0; i < qblk->nr_channels; i++)
		sec_meta += (meta->smeta_sec + meta->emeta_sec[0]) * qblk->ch[i].nr_free_lines;
	//pr_notice("%s, sec_meta = %d\n", __func__, sec_meta);

	sec_resv = (
				meta->sec_per_chline
				- (meta->smeta_sec + meta->emeta_sec[0])
				) * QBLK_RESERVED_LINES;
	//pr_notice("%s, sec_resv = %d\n", __func__, sec_resv);

	provisioned = nr_free_blks * geo->sec_per_chk
					- sec_meta - sec_resv;
	provisioned *= (100 - qblk->op);
	sector_div(provisioned, 100);
	qblk->capacity = provisioned;

	//pr_notice("%s, capacity = %ld\n", __func__, provisioned);

	/* Internally qblk manages all free blocks, but all calculations based
	 * on user capacity consider only provisioned blocks
	 */
	qblk->rl.nr_secs = provisioned;

}


static void qblk_rwb_mq_free(struct qblk *qblk, unsigned int qcount)
{
	while (qcount--) {
		if (qblk_rb_tear_down_check(&qblk->mqrwb[qcount]))
			pr_err("qblk: write buffer error on tear down\n");

		qblk_rb_data_free(&qblk->mqrwb[qcount]);
		vfree(qblk_rb_entries_ref(&qblk->mqrwb[qcount]));
	}
	kfree(qblk->mqrwb);
}


/*
 * We'll initialize hw_queue_count+1 ringBuffers.
 */
static int qblk_rwb_mq_init(struct qblk *qblk, unsigned int queue_count)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_rb_entry *entries;
	unsigned long nr_entries; //number of ringbuffer entries per queue
	unsigned int power_size, power_seg_sz;
	unsigned int i;
	int ret;
	struct qblk_rb *rwbArray;

	nr_entries = qblk_rb_calculate_size(qblk->pgs_in_buffer);
	//pr_notice("%s:nr_entries=0x%lx, nr_rb=0x%x\n",
	//			__func__, nr_entries, hw_queue_count+1);

	rwbArray = qblk->mqrwb = kmalloc_array(queue_count, sizeof(struct qblk_rb), GFP_KERNEL);
	if (!rwbArray)
		return -ENOMEM;

	qblk->total_buf_entries = 0;
	for (i = 0; i < queue_count; i++) {
		entries = vzalloc(nr_entries * sizeof(struct qblk_rb_entry));
		if (!entries)
			return -ENOMEM;

		power_size = get_count_order(nr_entries);
		power_seg_sz = get_count_order(geo->sec_size);

		ret = qblk_rb_init(qblk, &qblk->mqrwb[i], i,
					entries, power_size, power_seg_sz);
		//printRbStatus(&pblk->mqrwb[i], i);
		if (ret)
			goto err_out_free_mem;
	}
	return ret;

err_out_free_mem:
	qblk_rwb_mq_free(qblk, i);
	return -ENOMEM;
}

/* See comment over struct chnl_emeta definition */
static unsigned int calc_emeta_len(struct qblk *qblk, struct qblk_metainfo *meta)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;

	/* Round to sector size so that lba_list starts on its own sector */
	meta->emeta_sec[1] = DIV_ROUND_UP(
			sizeof(struct chnl_emeta) + meta->blk_bitmap_len,
			geo->sec_size);
	meta->emeta_len[1] = meta->emeta_sec[1] * geo->sec_size;

	/* Round to sector size so that vsc_list starts on its own sector */
	meta->datasec_per_ch = meta->sec_per_chline - meta->emeta_sec[0];
	meta->emeta_sec[2] = DIV_ROUND_UP(meta->datasec_per_ch * sizeof(u64),
			geo->sec_size);
	meta->emeta_len[2] = meta->emeta_sec[2] * geo->sec_size;

	meta->emeta_sec[3] = DIV_ROUND_UP(geo->nr_chks * sizeof(u32),
			geo->sec_size);
	meta->emeta_len[3] = meta->emeta_sec[3] * geo->sec_size;

	meta->vsc_list_len = geo->nr_chks * sizeof(u32);

	return (meta->emeta_len[1] + meta->emeta_len[2] + meta->emeta_len[3]);
}


static inline void qblk_metainfo_init(struct qblk *qblk, struct nvm_geo *geo)
{
	unsigned int smeta_len, emeta_len;
	struct qblk_metainfo *meta = &qblk->metainfo;
	int i;

	//meta->lbalen = DIV_ROUND_UP(get_count_order_long(qblk->capacity), 8);
	//meta->lbalen = 1UL << get_count_order(meta->lbalen);
	meta->sec_per_chline = geo->sec_per_chk * geo->nr_luns;
	meta->sec_per_chwrite = geo->nr_luns * geo->sec_per_pl * (geo->sec_size / PAGE_SIZE);
	meta->blk_per_chline = geo->nr_luns;

	meta->blk_bitmap_len = BITS_TO_LONGS(geo->nr_luns) * sizeof(long);//8
	meta->sec_bitmap_len = BITS_TO_LONGS(meta->sec_per_chline) * sizeof(long);//2048
	meta->lun_bitmap_len = BITS_TO_LONGS(geo->nr_luns) * sizeof(long);//8
	//pr_notice("%s,blk_bitmap_len=%u,sec_bitmap_len=%u,lun_bitmap_len=%u\n",
	//	__func__, meta->blk_bitmap_len,
	//	meta->sec_bitmap_len, meta->lun_bitmap_len);
	meta->mid_thrs = meta->sec_per_chline / 2; //8192
	meta->high_thrs = meta->sec_per_chline / 4; //4096
	//pr_notice("%s,mid_thrs=%u,high_thrs=%u\n",
	//	__func__, meta->mid_thrs, meta->high_thrs);
	meta->meta_distance = (geo->nr_luns / 2) * qblk->min_write_pgs;//16
	//pr_notice("%s, meta_distance = %u\n",
	//		__func__, meta->meta_distance);

	meta->smeta_sec = geo->ws_opt;
	meta->smeta_len = meta->smeta_sec * geo->sec_size;

	/* Calculate necessary pages for smeta. See comment over struct
	 * line_smeta definition
	 */
	i = 1;
add_smeta_page:
	meta->smeta_sec = i * geo->sec_per_pl;
	meta->smeta_len = meta->smeta_sec * geo->sec_size;

	smeta_len = sizeof(struct chnl_smeta) + meta->lun_bitmap_len;
	if (smeta_len > meta->smeta_len) {
		i++;
		goto add_smeta_page;
	}

	i = 1;
add_emeta_page:
	meta->emeta_sec[0] = i * geo->sec_per_pl;
	meta->emeta_len[0] = meta->emeta_sec[0] * geo->sec_size;

	emeta_len = calc_emeta_len(qblk, meta);
	if (emeta_len > meta->emeta_len[0]) {
		i++;
		goto add_emeta_page;
	}

	pr_notice("%s, datasec_per_ch=%u, emeta_len=%u, emeta_sec=%u, sec_per_ch=%u, sec_per_chwrite=%u, smeta_sec=%u\n",
		__func__, meta->datasec_per_ch, meta->emeta_len[0], meta->emeta_sec[0],
		meta->sec_per_chline, meta->sec_per_chwrite, meta->smeta_sec);

	meta->emeta_bb = geo->nr_luns > i ? geo->nr_luns - i : 0;

	meta->min_blk_line = 1;
	if (geo->num_lun > 1)
		meta->min_blk_line += DIV_ROUND_UP(meta->smeta_sec +
					meta->emeta_sec[0], geo->sec_per_chk);
	pr_notice("%s, meta->min_blk_line = %u\n",
				__func__, meta->min_blk_line);

	if (meta->min_blk_line > meta->blk_per_chline) {
		pr_err("qblk: config. not supported. Min. LUN in line:%d\n",
							meta->blk_per_chline);
		return;
	}

}

void qblk_stop_writers(struct qblk *qblk, unsigned int nr_writers)
{
	/* The pipeline must be stopped and the write buffer emptied before the
	 * write thread is stopped
	 */
	//del_timer_sync(&qblk->mq_timer_list[qcount].timer);
	while (nr_writers--) {
		del_timer_sync(&qblk->wtimers[nr_writers].timer);
		WARN(qblk_rb_read_count(&qblk->mqrwb[nr_writers]),
				"Stopping not fully persisted write buffer\n");

		WARN(qblk_rb_sync_count(&qblk->mqrwb[nr_writers]),
				"Stopping not fully synced write buffer\n");
		if (qblk->mq_writer_ts[nr_writers])
			kthread_stop(qblk->mq_writer_ts[nr_writers]);
	}
}

static int qblk_init_writers(struct qblk *qblk,
			unsigned int nr_writers)
{
	char tsname[64];
	unsigned int i;
	struct task_struct **writer_ts_array;
	struct qblk_writer_param *params;

	params = qblk->params =
		kmalloc_array(nr_writers, sizeof(struct qblk_writer_param), GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	writer_ts_array = qblk->mq_writer_ts =
		kmalloc_array(nr_writers, sizeof(struct task_struct *), GFP_KERNEL);
	if (!writer_ts_array)
		goto outFreeParam;
	for (i = 0; i < nr_writers; i++) {
		sprintf(tsname, "qblk_writer_%u", i);
		params[i].qblk = qblk;
		params[i].qcount = i;
		qblk->mq_writer_ts[i] = kthread_create(qblk_writer_thread_fn, &params[i], tsname);
		if (IS_ERR(qblk->mq_writer_ts[i])) {
			int err = PTR_ERR(qblk->mq_writer_ts[i]);

			if (err != -EINTR)
				pr_err("qblk: could not allocate writer_%d err=(%d)\n", i, err);
			goto outFreeMem;
		}
	}

	qblk->wtimers = kmalloc_array(nr_writers, sizeof(struct qblk_timer), GFP_KERNEL);
	if (!qblk->wtimers)
		goto outFreeMem;

	for (i = 0; i < nr_writers; i++) {
		qblk->wtimers[i].qblk = qblk;
		qblk->wtimers[i].index = i;
		timer_setup(&qblk->wtimers[i].timer, qblk_timer_fn, 0);
		mod_timer(&qblk->wtimers[i].timer, jiffies + msecs_to_jiffies(100));
	}

	return 0;
outFreeMem:
	qblk_stop_writers(qblk, i);
	kfree(writer_ts_array);
outFreeParam:
	kfree(params);
	return -ENOMEM;
}

static void qblk_line_meta_free(struct qblk *qblk, struct ch_info *chi)
{
	int i;
	struct qblk_metainfo *meta = &qblk->metainfo;

	kfree(chi->vsc_list);

	for (i = 0; i < QBLK_DATA_LINES; i++) {
		kfree(chi->sline_meta[i]);
		qblk_mfree(chi->eline_meta[i]->buf, meta->emeta_alloc_type);
		kfree(chi->eline_meta[i]);
	}
}

static int qblk_lines_alloc_metadata(struct qblk *qblk, struct ch_info *chi)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	int i;

	/* smeta is always small enough to fit on a kmalloc memory allocation,
	 * emeta depends on the number of LUNs allocated to the qblk instance
	 */
	for (i = 0; i < QBLK_DATA_LINES; i++) {
		chi->sline_meta[i] = kmalloc(meta->smeta_len, GFP_KERNEL);
		if (!chi->sline_meta[i])
			goto fail_free_smeta;
	}

	/* emeta allocates three different buffers for managing metadata with
	 * in-memory and in-media layouts
	 */
	for (i = 0; i < QBLK_DATA_LINES; i++) {
		struct qblk_emeta *emeta;

		emeta = kmalloc(sizeof(struct qblk_emeta), GFP_KERNEL);
		if (!emeta)
			goto fail_free_emeta;

		if (meta->emeta_len[0] > KMALLOC_MAX_CACHE_SIZE) {
			meta->emeta_alloc_type = QBLK_VMALLOC_META;

			emeta->buf = vmalloc(meta->emeta_len[0]);
			if (!emeta->buf) {
				kfree(emeta);
				goto fail_free_emeta;
			}

			emeta->nr_entries = meta->emeta_sec[0];
			chi->eline_meta[i] = emeta;
		} else {
			meta->emeta_alloc_type = QBLK_KMALLOC_META;

			emeta->buf = kmalloc(meta->emeta_len[0], GFP_KERNEL);
			if (!emeta->buf) {
				kfree(emeta);
				goto fail_free_emeta;
			}

			emeta->nr_entries = meta->emeta_sec[0];
			chi->eline_meta[i] = emeta;
		}
	}

	chi->vsc_list = kcalloc(chi->nr_lines, sizeof(__le32), GFP_KERNEL);
	if (!chi->vsc_list)
		goto fail_free_emeta;

	for (i = 0; i < chi->nr_lines; i++)
		chi->vsc_list[i] = cpu_to_le32(EMPTY_ENTRY);

	return 0;

fail_free_emeta:
	while (--i >= 0) {
		if (meta->emeta_alloc_type == QBLK_VMALLOC_META)
			vfree(chi->eline_meta[i]->buf);
		else
			kfree(chi->eline_meta[i]->buf);
		kfree(chi->eline_meta[i]);
	}
fail_free_smeta:
	for (i = 0; i < QBLK_DATA_LINES; i++)
		kfree(chi->sline_meta[i]);
	return -ENOMEM;
}

static int qblk_alloc_line_bitmaps(struct qblk *qblk, struct qblk_line *line)
{
	struct qblk_metainfo *meta = &qblk->metainfo;

	//pr_notice("%s,meta->blk_bitmap_len=%d\n",__func__,meta->blk_bitmap_len);
	//meta->blk_bitmap_len == 8
	line->blk_bitmap = kzalloc(meta->blk_bitmap_len, GFP_KERNEL);
	if (!line->blk_bitmap)
		return -ENOMEM;

	line->erase_bitmap = kzalloc(meta->blk_bitmap_len, GFP_KERNEL);
	if (!line->erase_bitmap) {
		kfree(line->blk_bitmap);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Discovery bad block information from device.
 */
static int qblk_bb_discovery(struct nvm_tgt_dev *dev, struct qblk_lun *rlun)
{
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr ppa;
	u8 *blks;
	int nr_blks, ret;
	//int i;

	nr_blks = geo->nr_chks * geo->plane_mode;
	blks = kmalloc(nr_blks, GFP_KERNEL);
	if (!blks)
		return -ENOMEM;

	ppa.ppa = 0;
	ppa.g.ch = rlun->bppa.g.ch;
	ppa.g.lun = rlun->bppa.g.lun;

	ret = nvm_get_tgt_bb_tbl(dev, ppa, blks);
	if (ret)
		goto out;

	nr_blks = nvm_bb_tbl_fold(dev->parent, blks, nr_blks);
	if (nr_blks < 0) {
		ret = nr_blks;
		goto out;
	}
#if 0
	pr_notice("%s---\n", __func__);
	for (i = 0; i < nr_blks; i++) {
		pr_notice("blks[%d]=0x%x\n",i,blks[i]);
	}
	pr_notice("%s===\n",__func__);
#endif
	rlun->bb_list = blks;

	return 0;
out:
	kfree(blks);
	return ret;
}

static int qblk_bb_line(struct qblk *qblk, struct qblk_line *line,
			int blk_per_line)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_lun *rlun;
	int bb_cnt = 0;
	int i;
	int ch_idx = line->chi->ch_index;

	for (i = 0; i < blk_per_line; i++) {
		rlun = &qblk->luns[qblk_chlun_to_lunidx(geo, ch_idx, i)];
		if (rlun->bb_list[line->id] == NVM_BLK_T_FREE)
			continue;
		set_bit(qblk_ppa_to_posinsidechnl(geo, rlun->bppa), line->blk_bitmap);
		bb_cnt++;
	}

	return bb_cnt;
}

static void qblk_luns_free(struct qblk *qblk)
{
	kfree(qblk->luns);
}

static int qblk_luns_init(struct qblk *qblk, struct ppa_addr *luns,
							int sem_init_val)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_lun *rlun;
	int i, ret;

	/* TODO: Implement unbalanced LUN support */
	if (geo->nr_luns < 0) {
		pr_err("qblk: unbalanced LUN config.\n");
		return -EINVAL;
	}

	qblk->luns = kcalloc(geo->all_luns, sizeof(struct qblk_lun),
								GFP_KERNEL);
	if (!qblk->luns)
		return -ENOMEM;

	for (i = 0; i < geo->all_luns; i++) {
		/* Stripe across channels */
		int ch = i % geo->nr_chnls;
		int lun_raw = i / geo->nr_chnls;
		int lunid = lun_raw + ch * geo->nr_luns;

		rlun = &qblk->luns[i];
		rlun->bppa = luns[lunid];
		//pr_notice("%s,i=%d,ch=%d,lun_raw=%d,lunid=%d,bppa=0x%lx\n",
		//	__func__,i,ch,lun_raw,lunid,rlun->bppa.ppa);

		sema_init(&rlun->wr_sem, sem_init_val);

		ret = qblk_bb_discovery(dev, rlun);
		if (ret) {
			pr_err("%s,qblk_bb_discovery returns err,%d\n", __func__, ret);
			while (--i >= 0)
				kfree(qblk->luns[i].bb_list);
			return ret;
		}
	}
#if 0
	pr_notice("%s\n", __func__);
	qblkPrintBB(qblk);
#endif

	return 0;
}

static void qblk_free_line_bitmaps(struct qblk_line *line)
{
	kfree(line->blk_bitmap);
	kfree(line->erase_bitmap);
}

static void qblk_per_channel_free(struct qblk *qblk,
				int ch_index)
{
	int i;
	struct ch_info *this_ch = &qblk->ch[ch_index];

	qblk_per_chnl_rl_free(&this_ch->per_ch_rl);
	i = this_ch->nr_lines;
	while (--i >= 0)
		qblk_free_line_bitmaps(&this_ch->lines[i]);
	kfree(this_ch->lines);
	kfree(this_ch->bb_aux);
	kfree(this_ch->bb_template);
	qblk_line_meta_free(qblk, this_ch);
}

/*
 * return 0 if succeed.
 */
static int qblk_per_channel_init(struct qblk *qblk,
				int ch_index)
{
	struct ch_info *this_ch = &qblk->ch[ch_index];
	struct nvm_geo *geo = &qblk->dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	int bb_distance, ret, nr_free_blks, nr_bad_blks;
	int i;
	struct qblk_line *line;

	this_ch->ch_index = ch_index;
	this_ch->nr_lines = geo->nr_chks;

	this_ch->data_line = NULL;
	this_ch->replacing = 0;
	this_ch->nr_free_lines = 0;
	bitmap_zero(&this_ch->meta_bitmap, QBLK_DATA_LINES);
	this_ch->l_seq_nr = this_ch->d_seq_nr = 0;

	ret = qblk_lines_alloc_metadata(qblk, this_ch);
	if (ret)
		goto fail;

	this_ch->bb_template = kzalloc(meta->sec_bitmap_len, GFP_KERNEL);
	if (!this_ch->bb_template) {
		ret = -ENOMEM;
		goto fail_free_meta;
	}

	this_ch->bb_aux = kzalloc(meta->sec_bitmap_len, GFP_KERNEL);
	if (!this_ch->bb_aux) {
		ret = -ENOMEM;
		goto fail_free_bb_template;
	}

	bb_distance = (geo->nr_luns) * geo->sec_per_pl;
	for (i = 0; i < meta->sec_per_chline; i += bb_distance)
		bitmap_set(this_ch->bb_template, i, geo->sec_per_pl);

	INIT_LIST_HEAD(&this_ch->free_list);
	INIT_LIST_HEAD(&this_ch->corrupt_list);
	INIT_LIST_HEAD(&this_ch->bad_list);
	INIT_LIST_HEAD(&this_ch->gc_full_list);
	INIT_LIST_HEAD(&this_ch->gc_high_list);
	INIT_LIST_HEAD(&this_ch->gc_mid_list);
	INIT_LIST_HEAD(&this_ch->gc_low_list);
	INIT_LIST_HEAD(&this_ch->gc_empty_list);

	INIT_LIST_HEAD(&this_ch->emeta_list);

	this_ch->gc_lists[0] = &this_ch->gc_high_list;
	this_ch->gc_lists[1] = &this_ch->gc_mid_list;
	this_ch->gc_lists[2] = &this_ch->gc_low_list;

	spin_lock_init(&this_ch->free_lock);
	spin_lock_init(&this_ch->close_lock);
	spin_lock_init(&this_ch->gc_lock);
	mutex_init(&this_ch->dataline_lock);

	spin_lock_init(&this_ch->gc_rb_lock);

	this_ch->lines = kcalloc(this_ch->nr_lines, sizeof(struct qblk_line),
								GFP_KERNEL);
	if (!this_ch->lines) {
		ret = -ENOMEM;
		goto fail_free_bb_aux;
	}

	this_ch->data_secs_in_ch = 0;
	nr_free_blks = 0;
	for (i = 0; i < this_ch->nr_lines; i++) {
		int blk_in_line;

		line = &this_ch->lines[i];

		line->qblk = qblk;
		line->chi = this_ch;
		line->id = i;
		line->type = QBLK_LINETYPE_FREE;
		line->state = QBLK_LINESTATE_FREE;
		line->gc_group = QBLK_LINEGC_NONE;
		line->vsc = &this_ch->vsc_list[i];
		spin_lock_init(&line->lock);

		ret = qblk_alloc_line_bitmaps(qblk, line);
		if (ret)
			goto fail_free_lines;

		nr_bad_blks = qblk_bb_line(qblk, line, meta->blk_per_chline);
		if (nr_bad_blks < 0 || nr_bad_blks > meta->blk_per_chline) {
			pr_notice("%s, nr_bad_blks invalid value:%d\n", __func__, nr_bad_blks);
			qblk_free_line_bitmaps(line);
			ret = -EINVAL;
			goto fail_free_lines;
		}
		//pr_notice("%s,ch=%d,line=%d,nr_bad_blks=%d\n",__func__,ch_index,i,nr_bad_blks);

		blk_in_line = meta->blk_per_chline - nr_bad_blks;
		if (blk_in_line < meta->min_blk_line) {
			pr_notice("%s, line is bad, ch=%d, lineID=%d\n",
						__func__, ch_index, i);
			line->state = QBLK_LINESTATE_BAD;
			list_add_tail(&line->list, &this_ch->bad_list);
			continue;
		}

		nr_free_blks += blk_in_line;
		atomic_set(&line->blk_in_line, blk_in_line);
		line->data_secs_in_line = blk_in_line * geo->sec_per_chk - (meta->smeta_sec + meta->emeta_sec[0]);
		this_ch->data_secs_in_ch += line->data_secs_in_line;
		this_ch->nr_free_lines++;
		list_add_tail(&line->list, &this_ch->free_list);
	}

	qblk_per_chnl_rl_init(qblk, this_ch, &this_ch->per_ch_rl, nr_free_blks);

	return 0;
	qblk_per_chnl_rl_free(&this_ch->per_ch_rl);
	i = this_ch->nr_lines;
fail_free_lines:
	while (--i >= 0)
		qblk_free_line_bitmaps(&this_ch->lines[i]);
	kfree(this_ch->lines);
fail_free_bb_aux:
	kfree(this_ch->bb_aux);
fail_free_bb_template:
	kfree(this_ch->bb_template);
fail_free_meta:
	qblk_line_meta_free(qblk, this_ch);
fail:
	return ret;
}

static void qblk_channels_free(struct qblk *qblk, int nr_ch)
{
	int i;
	if (qblk->ch) {
		for (i = 0; i < nr_ch; i++)
			qblk_per_channel_free(qblk, i);
		kfree(qblk->ch);
	}
}

static int qblk_channels_init(struct qblk *qblk, int nr_ch)
{
	int i;
	int ret;
	struct nvm_geo *geo = &qblk->dev->geo;

	qblk->nr_channels = nr_ch;
	qblk->current_channel = 0;
	spin_lock_init(&qblk->current_channel_lock);
	qblk->ch = kmalloc_array(nr_ch,
					sizeof(struct ch_info), GFP_KERNEL);

	if (!qblk->ch)
		return -ENOMEM;
	for (i = 0; i < nr_ch; i++) {
		ret = qblk_per_channel_init(qblk, i);
		if (ret)
			goto err_init_chnl;
	}
	/* Cleanup per-LUN bad block lists - managed within lines on run-time */
	for (i = 0; i < geo->all_luns; i++)
		kfree(qblk->luns[i].bb_list);
	return 0;
err_init_chnl:
	while (i--)
		qblk_per_channel_free(qblk, i);
	kfree(qblk->ch);
	/* Cleanup per-LUN bad block lists - managed within lines on run-time */
	for (i = 0; i < geo->all_luns; i++)
		kfree(qblk->luns[i].bb_list);
	return ret;
}

static void qblk_lines_free(struct qblk *qblk)
{
	struct qblk_line *line;
	int i;
	int ch_idx;
	struct ch_info *chi;

	for (ch_idx = 0; ch_idx < qblk->nr_channels; ch_idx++) {
		chi = &qblk->ch[ch_idx];
		spin_lock(&chi->free_lock);
		for (i = 0; i < chi->nr_lines; i++) {
			line = &chi->lines[i];
			qblk_line_free(qblk, line);
			qblk_free_line_bitmaps(line);
		}
		spin_unlock(&chi->free_lock);
	}


}

static int qblk_lines_configure(struct qblk *qblk, int flags)
{
	int ret = 0;

	if (!(flags & NVM_TARGET_FACTORY)) {
		ret = qblk_recov_l2p(qblk);
		if (ret) {
			pr_err("qblk: could not recover l2p table\n");
			return ret;
		}
	}

#ifdef CONFIG_NVM_DEBUG
	pr_info("qblk init: L2P CRC: %x\n", qblk_l2p_crc(qblk));
#endif

	/* Free full lines directly as GC has not been started yet */
	//pblk_gc_free_full_lines(pblk);

	if (!ret) {
		/* Configure next line for user data */
		ret = qblk_line_get_first_data(qblk);
		if (ret)
			pr_err("qblk: line list corrupted\n");
	}

	return ret;
}

#if 0
static void qblk_init_wbtimer(struct qblk *qblk)
{
	timer_setup(&qblk->wb_timer, qblk_writeback_timer_fn, 0);
	mod_timer(&qblk->wb_timer, jiffies + msecs_to_jiffies(100));
}

static void qblk_destroy_wbtimer(struct qblk *qblk)
{
	del_timer(&qblk->wb_timer);
}
#endif

static void *qblk_init(struct nvm_tgt_dev *dev, struct gendisk **ptdisk,
							struct nvm_ioctl_create *create)
{
	int flags = create->flags;
	struct nvm_geo *geo = &dev->geo;
	struct request_queue *bqueue = dev->q;
	struct request_queue *blk_queue;
	struct qblk *qblk;
	unsigned int queue_count;
	int ret;

	if (dev->identity.dom & NVM_RSP_L2P) {
		pr_err("qblk: host-side L2P table not supported. (%x)\n",
							dev->identity.dom);
		return ERR_PTR(-EINVAL);
	}

	qblk = kzalloc(sizeof(struct qblk), GFP_KERNEL);
	if (!qblk)
		return ERR_PTR(-ENOMEM);

	qblk->pgs_in_buffer = NVM_MEM_PAGE_WRITE * geo->sec_per_pg *
							geo->nr_planes * geo->nr_luns;

	qblk->dev = dev;
	qblk->state = QBLK_STATE_RUNNING;

	qblk_set_provision_step1(qblk);

	if (flags & NVM_TARGET_FACTORY)
		qblk_setup_uuid(qblk);

	/* We'll setup nr_cpu queues and nr_cpu+1 ringBuffers.
	 * Ringbuffer[0] is used for GC
	 * multiqueue[k] corresponds to ringbuffer[k+1]
	 */
	ret = qblk_setup_queues(qblk, &queue_count);
	if (ret)
		goto fail;

	/*
	 * we must initialize mqrwb prior to the initialization of
	 * multiqueue because qblk_queue->rb should points to the ring buffer
	 */
	ret = qblk_rwb_mq_init(qblk, queue_count);
	if (ret) {
		pr_err("qblk: could not initialize multiqueue write buffer\n");
		goto fail_cleanup_queues;
	}

	qblk->tag_set = &qblk->__tag_set;
	ret = qblk_init_tag_set(qblk, qblk->tag_set);
	if (ret)
		goto fail_free_rwbmq;

	blk_queue = qblk->q = blk_mq_init_queue(qblk->tag_set);
	if (IS_ERR(qblk->q)) {
		ret = -ENOMEM;
		goto fail_free_tagset;
	}

	blk_queue_logical_block_size(blk_queue, queue_physical_block_size(bqueue));
	blk_queue_physical_block_size(blk_queue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(blk_queue, queue_max_hw_sectors(bqueue));
	blk_queue->limits.discard_granularity = geo->sec_per_chk * geo->sec_size;
	blk_queue->limits.discard_alignment = 0;
	blk_queue->queuedata = qblk;

	blk_queue_write_cache(blk_queue, true, false);

	blk_queue_max_discard_sectors(blk_queue, UINT_MAX >> 9);
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, blk_queue);
	queue_flag_set_unlocked(QUEUE_FLAG_NOMERGES, blk_queue);
//	blk_queue_flag_set(QUEUE_FLAG_DISCARD, blk_queue);
//	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, blk_queue);

	pr_notice("qblk:logical bs=%u,physical bs=%u, maxhwsectors=%u\n",
		queue_physical_block_size(bqueue), queue_physical_block_size(bqueue), queue_max_hw_sectors(bqueue));


#ifdef CONFIG_NVM_DEBUG
	atomic_long_set(&qblk->inflight_writes, 0);
	atomic_long_set(&qblk->padded_writes, 0);
	atomic_long_set(&qblk->padded_wb, 0);
	atomic_long_set(&qblk->nr_flush, 0);
	atomic_long_set(&qblk->req_writes, 0);
	atomic_long_set(&qblk->sub_writes, 0);
	atomic_long_set(&qblk->sync_writes, 0);
	atomic_long_set(&qblk->inflight_reads, 0);
	atomic_long_set(&qblk->cache_reads, 0);
	atomic_long_set(&qblk->sync_reads, 0);
	atomic_long_set(&qblk->recov_writes, 0);
	atomic_long_set(&qblk->recov_writes, 0);
	atomic_long_set(&qblk->recov_gc_writes, 0);
	atomic_long_set(&qblk->recov_gc_reads, 0);
#endif

	atomic_set(&qblk->inflight_io, 0);
	atomic_long_set(&qblk->read_failed, 0);
	atomic_long_set(&qblk->read_empty, 0);
	atomic_long_set(&qblk->read_high_ecc, 0);
	atomic_long_set(&qblk->read_failed_gc, 0);
	atomic_long_set(&qblk->write_failed, 0);
	atomic_long_set(&qblk->erase_failed, 0);

	ret = qblk_luns_init(qblk, dev->luns, 8);
	if (ret) {
		pr_err("qblk: could not initialize luns\n");
		goto fail_free_blkmq_queue;
	}

	qblk->min_write_pgs = geo->sec_per_pl * (geo->sec_size / PAGE_SIZE);
	qblk->max_write_pgs = nvm_max_phys_sects(dev);
	if (qblk->min_write_pgs * geo->nr_luns < qblk->max_write_pgs)
		qblk->max_write_pgs = qblk->min_write_pgs * geo->nr_luns;

#ifdef QBLK_MIN_DRAIN
	qblk_set_sec_per_write(qblk, qblk->min_write_pgs);
	//pr_notice("Drain with min_write_pgs:%d\n", qblk->min_write_pgs);
#else
	qblk_set_sec_per_write(qblk, qblk->max_write_pgs);
	//pr_notice("Drain with max_write_pgs:%d\n", qblk->max_write_pgs);
#endif

	ret = qblk_core_init(qblk, queue_count);
	if (ret) {
		pr_err("qblk: could not initialize core\n");
		goto fail_free_line_meta;
	}
#if 0
	pr_notice("%s\n",__func__);
	qblkPrintBB(qblk);
#endif

	qblk_metainfo_init(qblk, &dev->geo);

	ret = qblk_channels_init(qblk, geo->nr_chnls);
	if (ret) {
		pr_err("qblk: could not initialize channels\n");
		goto fail_free_core;
	}

	qblk_set_provision_step2(qblk, qblk->rl.total_blocks);

	/*
	 * Initialize rate-limiter, which controls access to the write buffer
	 * but user and GC I/O
	 */
	ret = qblk_rl_init(&qblk->rl, qblk->total_buf_entries);
	if (ret) {
		pr_err("qblk: could not initialize rl\n");
			goto fail_free_channels;
	}

	ret = qblk_l2p_init(qblk);
	if (ret) {
		pr_err("qblk: could not initialize maps\n");
		goto fail_free_per_rb_rl;
	}

	ret = qblk_lines_configure(qblk, flags);
	if (ret) {
		pr_err("qblk: could not configure lines\n");
			goto fail_free_l2p;

	}

	//Since we have qcount+1 ringbuffers, we'll have qcount+1 writers.
	ret = qblk_init_writers(qblk, queue_count);
	if (ret) {
		if (ret != -EINTR)
			pr_err("qblk: could not initialize multiqueue write thread\n");
		goto fail_free_lines;
	}

#if 1
	ret = qblk_gc_init(qblk);
	if (ret) {
		pr_err("qblk: could not initialize gc\n");
		goto fail_stop_writer_mq;
	}
#endif
	/* Check if we need to start GC */
	qblk_gc_should_kick(qblk);

	qblk_debug_init(qblk);

	ret = qblk_gendisk_register(qblk, ptdisk, create);

	if (ret)
		goto out_stop_gc;

	return qblk;

out_stop_gc:
	qblk_gc_exit(qblk);
fail_stop_writer_mq:
	qblk_stop_writers(qblk, queue_count);
	kfree(qblk->mq_writer_ts);
	kfree(qblk->wtimers);
	kfree(qblk->params);
fail_free_lines:
	qblk_lines_free(qblk);
fail_free_l2p:
	qblk_l2p_free(qblk);
fail_free_per_rb_rl:
fail_free_channels:
	qblk_channels_free(qblk, geo->nr_chnls);
fail_free_core:
	qblk_core_free(qblk);
fail_free_line_meta:
	qblk_luns_free(qblk);
fail_free_blkmq_queue:
	blk_cleanup_queue(qblk->q);
fail_free_tagset:
	blk_mq_free_tag_set(qblk->tag_set);
fail_free_rwbmq:
	qblk_rwb_mq_free(qblk, queue_count);
fail_cleanup_queues:
	qblk_cleanup_queues(qblk);
fail:
	kfree(qblk);
	return ERR_PTR(ret);
}

static void qblk_tear_down(struct qblk *qblk)
{
	/*pblk_pipeline_stop(pblk);*/
	flush_workqueue(qblk->bb_wq);
	//qblk_destroy_wbtimer(qblk);
	qblk_stop_writers(qblk, qblk->nr_queues);
	kfree(qblk->mq_writer_ts);
	kfree(qblk->wtimers);
	kfree(qblk->params);
	qblk_channels_free(qblk, qblk->dev->geo.nr_chnls);
	qblk_rb_sync_all_l2p(qblk);
	qblk_rl_free(&qblk->rl);

	pr_debug("qblk: consistent tear down\n");
}

static void qblk_free(struct qblk *qblk)
{
	qblk_l2p_free(qblk);
	qblk_core_free(qblk);
	blk_cleanup_queue(qblk->q);
	blk_mq_free_tag_set(qblk->tag_set);
	qblk_cleanup_queues(qblk);
	qblk_rwb_mq_free(qblk, qblk->nr_queues);
	kfree(qblk);
}

static void qblk_exit(void *private)
{
	struct qblk *qblk = private;

	pr_notice("%s\n", __func__);
	qblk_debug_exit();
	down_write(&qblk_lock);
	qblk_gc_exit(qblk);
	qblk_tear_down(qblk);

#ifdef CONFIG_NVM_DEBUG
	pr_info("qblk exit: L2P CRC: %x\n", qblk_l2p_crc(qblk));
#endif

	qblk_free(qblk);
	up_write(&qblk_lock);
}

/* physical block device target */
static struct nvm_tgt_type tt_qblk = {
	.name		= "qblk",
	.version	= {1, 0, 0},

	.capacity	= qblk_capacity,

	.init		= qblk_init,
	.exit		= qblk_exit,

	.owner		= THIS_MODULE,
};

static int __init qblk_module_init(void)
{
	return nvm_register_tgt_type(&tt_qblk);
}

static void qblk_module_exit(void)
{
	nvm_unregister_tgt_type(&tt_qblk);
}

module_init(qblk_module_init);
module_exit(qblk_module_exit);
MODULE_AUTHOR("Hongwei Qin <glqhw@hust.edu.cn>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("QHW's Physical Block-Device for Open-Channel SSDs");

