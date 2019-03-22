#ifndef QBLK_H_
#define QBLK_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/crc32.h>
#include <linux/uuid.h>
#include <linux/cpumask.h>
#include <linux/lightnvm.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>

/* Uncomment to use a global transmap lock */
//#define QBLK_TRANSMAP_LOCK

/* Uncomment to drain data with min_write_pgs granularity */
//#define QBLK_MIN_DRAIN

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 5
#define GC_TIME_MSECS 1000

#define QBLK_SECTOR (512)
#define QBLK_EXPOSED_PAGE_SIZE (4096)
#define QBLK_SECTOR_SHIFT (9)
#define QBLK_EXPOSED_PAGE_SHIFT (12)
#define QBLK_MAX_REQ_ADDRS (64)
#define QBLK_MAX_REQ_ADDRS_PW (6)

#define QBLK_NR_CLOSE_JOBS (4)

#define QBLK_CACHE_NAME_LEN (DISK_NAME_LEN + 16)

#define QBLK_COMMAND_TIMEOUT_MS 30000

/* Max 512 LUNs per device */
#define QBLK_MAX_LUNS_BITMAP (4)

#define NR_PHY_IN_LOG (QBLK_EXPOSED_PAGE_SIZE / QBLK_SECTOR)
#define QBLK_LBA_SHIFT (QBLK_EXPOSED_PAGE_SHIFT - QBLK_SECTOR_SHIFT)

/* Static pool sizes */
#define QBLK_GEN_WS_POOL_SIZE (2)

#define QBLK_DEFAULT_OP (11)
#define QBLK_RESERVED_LINES (4)

#define NVM_MEM_PAGE_WRITE (8)

#define QBLK_WB_CHECK_PERIOD (500)
#define QBLK_INCREASEMENT_HIGH (2000000)
#define QBLK_INCREASEMENT_LOW (50)

#define QBLK_DRAIN_RETRY_THRESHOLD (8)

enum {
	QBLK_READ		= READ,
	QBLK_WRITE		= WRITE,/* Write from write buffer */
	QBLK_WRITE_INT,			/* Internal write - no write buffer */
	QBLK_READ_RECOV,		/* Recovery read - errors allowed */
	QBLK_ERASE,
};

enum {
	/* IO Types */
	QBLK_IOTYPE_USER	= 1 << 0,
	QBLK_IOTYPE_GC		= 1 << 1,

	/* Write buffer flags */
	QBLK_FLUSH_ENTRY	= 1 << 2,
	QBLK_WRITTEN_DATA	= 1 << 3,
	QBLK_SUBMITTED_ENTRY	= 1 << 4,
	QBLK_WRITABLE_ENTRY	= 1 << 5,
};

enum {
	QBLK_BLK_ST_OPEN =	0x1,
	QBLK_BLK_ST_CLOSED =	0x2,
};

struct qblk_sec_meta {
	u64 reserved;
	__le64 lba;
};

/* The number of GC lists and the rate-limiter states go together. This way the
 * rate-limiter can dictate how much GC is needed based on resource utilization.
 */
#define QBLK_GC_NR_LISTS (3)

enum {
	QBLK_RL_HIGH = 1,
	QBLK_RL_MID = 2,
	QBLK_RL_LOW = 3,
};

#define qblk_dma_meta_size (sizeof(struct qblk_sec_meta) * QBLK_MAX_REQ_ADDRS)
#define qblk_dma_ppa_size (sizeof(u64) * QBLK_MAX_REQ_ADDRS)

/* write buffer completion context */
struct qblk_c_ctx {
	struct list_head list;		/* Head for out-of-order completion */

	unsigned long *lun_bitmap;	/* Luns used on current request */
	unsigned int sentry;
	unsigned int nr_valid;
	unsigned int nr_padded;
	unsigned int rb_count;
	int ch_index;
	int logindex;
};

/* read context */
struct qblk_g_ctx {
	void *private;
	unsigned long start_time;
	struct request *req;
	int logindex;
};

/* Recovery context */
struct qblk_rec_ctx {
	struct qblk *pblk;
	struct nvm_rq *rqd;
	struct list_head failed;
	struct work_struct ws_rec;
};

/* Write context */
struct qblk_w_ctx {
	struct bio_list bios;		/* Original bios - used for completion
					 * in REQ_FUA, REQ_FLUSH case
					 */
	u64 lba;			/* Logic addr. associated with entry */
	struct ppa_addr ppa;		/* Physic addr. associated with entry */
	int flags;			/* Write context flags */
};


struct qblk_rb_entry {
	struct ppa_addr cacheline;	/* Cacheline for this entry */
	void *data;			/* Pointer to data on this entry */
	struct qblk_w_ctx w_ctx;	/* Context for this entry */
	struct list_head index;		/* List head to enable indexes */
};

#define EMPTY_ENTRY (~0U)

struct qblk_rb_pages {
	struct page *pages;
	int order;
	struct list_head list;
};

struct qblk_rb {
	struct qblk_rb_entry *entries;	/* Ring buffer entries */
	unsigned int rb_index; /* the index of this ring buffer */
	unsigned int mem;		/* Write offset - points to next
					 * writable entry in memory
					 */
	unsigned int subm;		/* Read offset - points to last entry
					 * that has been submitted to the media
					 * to be persisted
					 */
	unsigned int sync;		/* Synced - backpointer that signals
					 * the last submitted entry that has
					 * been successfully persisted to media
					 */
	unsigned int flush_point;/* Sync point - last entry that must be
				  * flushed to the media. Used with
				  * REQ_FLUSH and REQ_FUA
				  */
	unsigned int l2p_update;	/* l2p update point - next entry for
					 * which l2p mapping will be updated to
					 * contain a device ppa address (instead
					 * of a cacheline
					 */
	unsigned int nr_entries;	/* Number of entries in write buffer -
					 * must be a power of two
					 */
	unsigned int seg_size;		/* Size of the data segments being
					 * stored on each entry. Typically this
					 * will be 4KB
					 */

	struct list_head pages;		/* List of data pages */

	spinlock_t w_lock;		/* Write lock */
	spinlock_t s_lock;		/* Sync lock */

#ifdef CONFIG_NVM_DEBUG
	atomic_t inflight_flush_point;	/* Not served REQ_FLUSH | REQ_FUA */
#endif
};

struct qblk_addr_format {
	u64	ch_mask;
	u64	lun_mask;
	u64	pln_mask;
	u64	blk_mask;
	u64	pg_mask;
	u64	sec_mask;
	u64 lun_mask_inchnl;
	u64 pg_mask_inchnl;
	u8	ch_offset;
	u8	lun_offset;
	u8	pln_offset;
	u8	blk_offset;
	u8	pg_offset;
	u8	sec_offset;
	u8  lun_offset_inchnl;
	u8  pg_offset_inchnl;
};


enum {
	QBLK_STATE_RUNNING = 0,
	QBLK_STATE_STOPPING = 1,
	QBLK_STATE_RECOVERING = 2,
	QBLK_STATE_STOPPED = 3,
};

enum {
	QBLK_READ_RANDOM	= 0,
	QBLK_READ_SEQUENTIAL	= 1,
};


struct qblk_queue {
	struct qblk_rb *rb;
	struct blk_mq_hw_ctx *hctx;
	unsigned int hctx_idx;
	unsigned int rb_idx; /* ring buffer index */
	atomic_t map_chnl;
	atomic_t inflight_write_secs;
	int wbchnl;
};

struct qblk_mq_cmd {
	struct request *gb_req;
	struct qblk_queue *qblkQueue;
	blk_status_t error;
};

/*
 * Per-channel thresholds divide channel status into 3 areas
 * (QBLK_RL_HIGH QBLK_RL_MID and QBLK_RL_LOW).
 * In order to diminish fluctuations, we use 4 thresholds:
 * rl->veryhigh rl->high rl->mid_blocks rl->rsv_blocks
 */
struct qblk_per_chnl_rl {
	struct qblk *qblk;
	int chnl;
	unsigned int very_high;	/* Threshold from mid to high */
	unsigned int high;	/* Threshold from high to mid */
	unsigned int high_pw;	/* High rounded up as a power of 2 */

	unsigned int mid_blocks;	/* Threshold from low to mid */
	unsigned int rsv_blocks;	/* Threshold from mid to low */

//	unsigned op_blks; /* Number of per-channel over provision blocks */
//	unsigned total_blocks; /* Number of good blocks inside this channel */
//	unsigned nr_secs; /* Number of good sectors inside this channel */

	atomic_t free_blocks;		/* Total number of free blocks (+ OP) */
	atomic_t free_user_blocks;	/* Number of user free blocks (no OP) */

	atomic_t rb_gc_max;		/* Max buffer entries available for GC I/O */

	int chnl_state; /* Rate-limiter current state */

	unsigned remain_secs; /* Number of budget of free data sectors in this chnl */
	spinlock_t remain_secs_lock;
};

struct qblk_rl {
	
#define QBLK_USER_HIGH_THRS 8	/* Begin write limit at 12% available blks */
#define QBLK_USER_LOW_THRS 10	/* Aggressive GC at 10% available blocks */

	atomic_t rb_user_max;	/* Max buffer entries available for user I/O */
	atomic_t rb_user_cnt;	/* User I/O buffer counter */
	atomic_t rb_gc_cnt;	/* GC I/O buffer counter */
	atomic_t rb_space;	/* Space limit in case of reaching capacity */

	int rb_user_active;

	unsigned long long nr_secs;
	unsigned long total_blocks;

	struct timer_list u_timer;

	int per_chnl_limit;	/* Per-channel budget for QBLK_RL_MID mode */

};

#define QBLK_LINE_EMPTY (~0U)


enum {
	/* Line Types */
	QBLK_LINETYPE_FREE = 0,
	QBLK_LINETYPE_LOG = 1,
	QBLK_LINETYPE_DATA = 2,

	/* Line state */
	//QBLK_LINESTATE_NEW = 9,
	QBLK_LINESTATE_FREE = 10,
	QBLK_LINESTATE_OPEN = 11,
	QBLK_LINESTATE_CLOSED = 12,
	QBLK_LINESTATE_GC = 13,
	QBLK_LINESTATE_BAD = 14,
	QBLK_LINESTATE_CORRUPT = 15,

	/* GC group */
	QBLK_LINEGC_NONE = 20,
	QBLK_LINEGC_EMPTY = 21,
	QBLK_LINEGC_LOW = 22,
	QBLK_LINEGC_MID = 23,
	QBLK_LINEGC_HIGH = 24,
	QBLK_LINEGC_FULL = 25,
};

enum {
	QBLK_KMALLOC_META = 1,
	QBLK_VMALLOC_META = 2,
};

#define QBLK_MAGIC 0x87654321 //qblk
#define SMETA_VERSION cpu_to_le16(1)


struct line_header {
	__le32 crc;
	__le32 identifier;	/* pblk identifier */
	__u8 uuid[16];		/* instance uuid */
	__le16 type;		/* line type */
	__le16 version;		/* type version */
	__le32 id;		/* line id for current line */
};


struct chnl_smeta {
	struct line_header header;

	__le32 crc;		/* Full structure including struct crc */
	/* Previous line metadata */
	__le32 prev_id;		/* Line id for previous line */

	/* Current line metadata */
	__le64 seq_nr;		/* Sequence number for current line */

	/* Active writers */
	__le32 window_wr_lun;	/* Number of parallel LUNs to write */

	__le32 rsvd[2];

	__le64 lun_bitmap[];
};


/*
 * Metadata layout in media:
 *	First sector:
 *		1. struct line_emeta
 *		2. bad block bitmap (u64 * window_wr_lun)
 *	Mid sectors (start at lbas_sector):
 *		3. nr_lbas (u64) forming lba list
 *	Last sectors (start at vsc_sector):
 *		4. u32 valid sector count (vsc) for all lines (~0U: free line)
 */
struct chnl_emeta {
	struct line_header header;

	__le32 crc;		/* Full structure including struct crc */

	/* Previous line metadata */
	__le32 prev_id;		/* Line id for prev line */

	/* Current line metadata */
	__le64 seq_nr;		/* Sequence number for current line */

	/* Active writers */
	__le32 window_wr_lun;	/* Number of parallel LUNs to write */

	/* Bookkeeping for recovery */
	__le32 next_id;		/* Line id for next line */
	__le64 nr_lbas;		/* Number of lbas mapped in line */
	__le64 nr_valid_lbas;	/* Number of valid lbas mapped in line */
	__le64 bb_bitmap[];	/* Updated bad block bitmap for line */
};

struct qblk_emeta {
	struct chnl_emeta *buf;		/* emeta buffer in media format */
	int mem;			/* Write offset - points to next
					 * writable entry in memory
					 */
	atomic_t sync;			/* Synced - backpointer that signals the
					 * last entry that has been successfully
					 * persisted to media
					 */
	unsigned int nr_entries;	/* Number of emeta entries */
};

struct qblk_smeta {
	struct chnl_smeta *buf;		/* smeta buffer in persistent format */
};


struct qblk_line {
	struct qblk *qblk;

	struct ch_info *chi;

	unsigned int id;		/* Line number corresponds to the
					 * block line
					 */

	unsigned int seq_nr;		/* Unique line sequence number */

	int state;			/* QBLK_LINESTATE_X */
	int type;			/* QBLK_LINETYPE_X */
	int gc_group;			/* QBLK_LINEGC_X */
	struct list_head list;		/* Free, GC lists */

	unsigned long *lun_bitmap;	/* Bitmap for LUNs mapped in line */

	//struct nvm_chk_meta *chks;	/* Chunks forming line */

	struct qblk_smeta *smeta;	/* Start metadata */
	struct qblk_emeta *emeta;	/* End medatada */

	int meta_line;			/* Metadata line id */
	int meta_distance;		/* Distance between data and metadata */

	u64 smeta_ssec;			/* Sector where smeta starts */
	u64 emeta_ssec;			/* Sector where emeta starts */

	unsigned int sec_in_line;	/* Number of usable secs in line */
	unsigned int data_secs_in_line; /* Number of data sectors in line */

	atomic_t blk_in_line;		/* Number of good blocks in line */
	unsigned long *blk_bitmap;	/* Bitmap for valid/invalid blocks */
	unsigned long *erase_bitmap;	/* Bitmap for erased blocks */


	unsigned long *map_bitmap;	/* Bitmap for mapped sectors in line */
	unsigned long *invalid_bitmap;	/* Bitmap for invalid sectors in line */


	atomic_t left_eblks;		/* Blocks left for erasing */
	atomic_t left_seblks;		/* Blocks left for sync erasing */

	int left_msecs;			/* Sectors left for mapping */

	unsigned int cur_sec;		/* Sector map pointer */

	unsigned int nr_valid_lbas;	/* Number of valid lbas in line */

	__le32 *vsc;			/* Valid sector count in line */


	struct kref ref;		/* Write buffer L2P references */

	spinlock_t lock;		/* Necessary for invalid_bitmap only */

};
#define QBLK_DATA_LINES 4


struct ch_info {
	int ch_index;
	int nr_lines;	/* Total number of full lines */
	int nr_free_lines;		/* Number of full lines in free list */

	struct qblk_line *data_line;	/* Current data line */
	struct qblk_line *data_next;	/* Next data line */

	spinlock_t free_lock;
	spinlock_t close_lock;
	spinlock_t gc_lock;
	struct mutex dataline_lock;

	spinlock_t gc_rb_lock;

	/*
	 * Indicates whether someone is replacing the data_line.
	 * Replacing a data_line may need to wait for erasing the current data_next.
	 * Thus, the replacement thread needs to release the free_lock.
	 * In order to avoid qblk_alloc_page() from getting invalid data_line,
	 * the replacement thread sets <replacing> into 1.
	 * It will reset it into 0 when its job is done.
	 */
	int replacing;

	/* Pre-allocated metadata for data lines */
	struct qblk_smeta *sline_meta[QBLK_DATA_LINES];
	struct qblk_emeta *eline_meta[QBLK_DATA_LINES];
	unsigned long meta_bitmap;


	unsigned long d_seq_nr;		/* Data line unique sequence number */
	unsigned long l_seq_nr;		/* Log line unique sequence number */

	__le32 *vsc_list;		/* Valid sector counts for all lines */

	/* Helpers for fast bitmap calculations */
	unsigned long *bb_template;
	unsigned long *bb_aux;

	/* Free lists - use free_lock */
	struct list_head free_list;	/* Full lines ready to use */
	struct list_head corrupt_list;	/* Full lines corrupted */
	struct list_head bad_list;	/* Full lines bad */

	/* GC lists - use gc_lock */
	struct list_head *gc_lists[QBLK_GC_NR_LISTS];
	struct list_head gc_high_list;	/* Full lines ready to GC, high isc */
	struct list_head gc_mid_list;	/* Full lines ready to GC, mid isc */
	struct list_head gc_low_list;	/* Full lines ready to GC, low isc */

	struct list_head gc_full_list;	/* Full lines ready to GC, no valid */
	struct list_head gc_empty_list;	/* Full lines close, all valid */

	struct list_head emeta_list;	/* Lines queued to schedule emeta */

	struct qblk_line *lines;		/* Line array */
	unsigned int data_secs_in_ch; /* Number of data sectors in this channel */

	struct qblk_per_chnl_rl per_ch_rl; /* Per-channel rate limiter */

};

struct qblk_metainfo {
	unsigned int smeta_len; /* Total length for smeta */
	unsigned int smeta_sec; /* number of memory pages that smeta consumes */
	unsigned int emeta_sec[4]; /* number of memory pages that emeta consumes */
	unsigned int emeta_len[4]; /* emeta length in bytes */
	unsigned int sec_per_chline; /* Number of sectors in a line inside a channel */
	unsigned int sec_per_chwrite; /* Number of sectors in a channel which can be accessed in parallel */
	unsigned int blk_per_chline; /* Number of blocks in a line inside a channel */
	unsigned int datasec_per_ch; /* Number of data sectors in a channel(including smeta sectors) */

	unsigned int lun_bitmap_len; /* Length for lun bitmap in line */
	unsigned int sec_bitmap_len; /* Length for sector bitmap in line */
	unsigned int blk_bitmap_len; /* Length for block bitmap in line */
	unsigned int mid_thrs; /* Threshold for GC mid list */
	unsigned int high_thrs; /* Threshold for GC high list */
	unsigned int vsc_list_len; /* Length for vsc list */
	unsigned int emeta_bb; /* Boundary for bb that affects emeta */
	unsigned int min_blk_line; /* Min. number of good blocks in line */
	int emeta_alloc_type;
	unsigned int meta_distance; /* Distance between data and metadata */
};

struct qblk_lun {
	struct ppa_addr bppa;
	u8 *bb_list;			/* Bad block list for LUN. Only used on
					 * bring up. Bad blocks are managed
					 * within lines on run-time.
					 */
	struct semaphore wr_sem;
};


struct qblk_writer_param {
	struct qblk *qblk;
	unsigned int qcount;
};

struct qblk_timer {
	struct timer_list timer;
	struct qblk *qblk;
	int index;
};

#define QBLK_DEBUG_ENTRIES_PER_CHNL (64)

enum qblk_log_type {
	QBLK_SUBMIT_IOWRITE = 1,
	QBLK_COMPLETE_IOWRITE,
	QBLK_SUBMIT_SMETA,
	QBLK_COMPLETE_SMETA,
	QBLK_SUBMIT_EMETA, //5
	QBLK_COMPLETE_EMETA,
	QBLK_SUBMIT_SYNC_ERASE, //7
	QBLK_COMPLETE_SYNC_ERASE, //8
	QBLK_SUBMIT_ASYNC_ERASE,
	QBLK_COMPLETE_ASYNC_ERASE, //10
	QBLK_DRAIN_MARK1, //11
};

struct qblk_debug_entry {
	struct timeval time;
	struct timeval time2;
	struct timeval time3;
	enum qblk_log_type type;
	struct ppa_addr firstppa;
	int nr_secs;
};

struct qblk_debug_header {
	spinlock_t lock;
	int p;
	struct qblk_debug_entry entries[QBLK_DEBUG_ENTRIES_PER_CHNL];
};

struct qblk_gc_rq {
	struct ch_info *chi;
	struct qblk_line *line;
	void *data;
	u64 paddr_list[QBLK_MAX_REQ_ADDRS];
	u64 lba_list[QBLK_MAX_REQ_ADDRS];
	int nr_secs;
	int secs_to_gc;
	struct list_head list;
};

struct qblk_gc {
	struct qblk *qblk;
	int chnl;
	int nr_print;

	/* These states are not protected by a lock since (i) they are in the
	 * fast path, and (ii) they are not critical.
	 */
	atomic_t gc_enabled;
	int gc_forced;

	struct task_struct *gc_ts;
	struct task_struct *gc_writer_ts;
	struct task_struct *gc_reader_ts;

	struct workqueue_struct *gc_line_reader_wq;
	struct workqueue_struct *gc_reader_wq;

	struct timer_list gc_timer;

	struct semaphore gc_sem;
	atomic_t read_inflight_gc; /* Number of lines with inflight GC reads */
	atomic_t pipeline_gc;	   /* Number of lines in the GC pipeline -
				    * started reads to finished writes
				    */
	int w_entries;

	struct list_head w_list;
	struct list_head r_list;

	spinlock_t lock;
	spinlock_t w_lock;
	spinlock_t r_lock;

	atomic_t readline_count;
};


struct qblk {
	struct nvm_tgt_dev *dev;
	struct gendisk *disk;

	struct blk_mq_tag_set *tag_set;
	struct blk_mq_tag_set __tag_set;

	struct request_queue *q;
	struct qblk_queue *queues;
	unsigned int queue_depth;
	unsigned int nr_queues;

	//struct kobject kobj;
	spinlock_t debug_printing_lock;
	struct qblk_debug_header *debugHeaders;
	int debugstart;

	struct qblk_lun *luns;

	int ppaf_bitsize;
	struct qblk_addr_format ppaf;

	struct qblk_rb *mqrwb;
	unsigned int total_buf_entries;

	struct qblk_writer_param *params;

	int state;			/* qblk line state */


	int min_write_pgs; /* Minimum amount of pages required by controller */
	int max_write_pgs; /* Maximum amount of pages supported by controller */

	int pgs_in_buffer; /* Number of pages that need to be held in buffer to
			    * guarantee successful reads.
			    */

	sector_t capacity; /* Device capacity when bad blocks are subtracted */


	int op;      /* Percentage of device used for over-provisioning */

	/* qblk provisioning values. Used by rate limiter */
	struct qblk_rl rl;

	int sec_per_write;

	unsigned char instance_uuid[16];

#ifdef CONFIG_NVM_DEBUG
	/* All debug counters apply to 4kb sector I/Os */

	atomic_long_t inflight_writes;	/* Inflight writes (user and gc) */
	atomic_long_t padded_writes;	/* Sectors padded due to flush/fua */
	atomic_long_t padded_wb;	/* Sectors padded in write buffer */
	atomic_long_t nr_flush;		/* Number of flush/fua I/O */
	atomic_long_t req_writes;	/* Sectors stored on write buffer */
	atomic_long_t sub_writes;	/* Sectors submitted from buffer */
	atomic_long_t sync_writes;	/* Sectors synced to media */
	atomic_long_t inflight_reads;	/* Inflight sector read requests */
	atomic_long_t cache_reads;	/* Read requests that hit the cache */
	atomic_long_t sync_reads;	/* Completed sector read requests */
	atomic_long_t recov_writes;	/* Sectors submitted from recovery */
	atomic_long_t recov_gc_writes;	/* Sectors submitted from write GC */
	atomic_long_t recov_gc_reads;	/* Sectors submitted from read GC */
#endif

	atomic_long_t read_failed;
	atomic_long_t read_empty;
	atomic_long_t read_high_ecc;
	atomic_long_t read_failed_gc;
	atomic_long_t write_failed;
	atomic_long_t erase_failed;

	atomic_t inflight_io;		/* General inflight I/O counter */

	//struct task_struct *writer_ts;
	struct task_struct **mq_writer_ts;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device.
	 */
	unsigned char *trans_map;

#ifdef QBLK_TRANSMAP_LOCK
	spinlock_t trans_lock;
#endif

	//struct list_head compl_list;
	struct list_head *complete_list_mq;

	mempool_t *page_bio_pool;
	mempool_t *gen_ws_pool;
	mempool_t *rec_pool;
	mempool_t *r_rq_pool;
	mempool_t *w_rq_pool;
	mempool_t *e_rq_pool;//not initialized by qblk_core_init() yet

	struct workqueue_struct *close_wq;
	struct workqueue_struct *bb_wq;
	struct workqueue_struct *r_end_wq;

	struct qblk_timer *wtimers;
	struct timer_list wb_timer;

	struct qblk_gc *per_channel_gc;

	struct qblk_metainfo metainfo;
	int nr_channels;
	int current_channel;
	spinlock_t current_channel_lock;
	struct ch_info *ch;

	//TODO: use atomic bitmask
	spinlock_t gc_active_lock;
	int gc_active_size;
	unsigned long *gc_active;
};

struct qblk_line_ws {
	struct qblk *qblk;
	struct qblk_line *line;
	void *priv;
	struct work_struct ws;
};


static inline void *qblk_malloc(size_t size,
					int type, gfp_t flags)
{
	if (type == QBLK_KMALLOC_META)
		return kmalloc(size, flags);
	return vmalloc(size);
}

static inline void qblk_mfree(void *ptr, int type)
{
	if (type == QBLK_KMALLOC_META)
		kfree(ptr);
	else
		vfree(ptr);
}

static inline u32 qblk_calc_meta_header_crc(struct qblk *qblk,
					    struct line_header *header)
{
	u32 crc = ~(u32)0;

	crc = crc32_le(crc, (unsigned char *)header + sizeof(crc),
				sizeof(struct line_header) - sizeof(crc));

	return crc;
}


static inline u32 qblk_calc_smeta_crc(struct qblk *qblk,
				      struct chnl_smeta *smeta)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	u32 crc = ~(u32)0;

	crc = crc32_le(crc, (unsigned char *)smeta +
				sizeof(struct line_header) + sizeof(crc),
				meta->smeta_len -
				sizeof(struct line_header) - sizeof(crc));

	return crc;
}


#define qblk_g_rq_size (sizeof(struct nvm_rq) + sizeof(struct qblk_g_ctx))
#define qblk_w_rq_size (sizeof(struct nvm_rq) + sizeof(struct qblk_c_ctx))

static inline struct nvm_rq *nvm_rq_from_c_ctx(void *c_ctx)
{
	return c_ctx - sizeof(struct nvm_rq);
}

static inline void *emeta_to_lbas(struct qblk *qblk, struct chnl_emeta *emeta)
{
	return ((void *)emeta + qblk->metainfo.emeta_len[1]);
}

static inline void *emeta_to_bb(struct chnl_emeta *emeta)
{
	return emeta->bb_bitmap;
}

static inline void *emeta_to_vsc(struct qblk *qblk, struct chnl_emeta *emeta)
{
	return (emeta_to_lbas(qblk, emeta) + qblk->metainfo.emeta_len[2]);
}

static inline int qblk_line_vsc(struct qblk_line *line)
{
	return le32_to_cpu(*line->vsc);
}

static inline int qblk_ppa_to_line(struct ppa_addr p)
{
	return p.g.blk;
}

static inline struct ch_info *qblk_ppa_to_chi(struct qblk *qblk, struct ppa_addr p)
{
	return &qblk->ch[p.g.ch];
}

static inline struct qblk_line *qblk_ppa_to_structline(struct qblk *qblk, struct ppa_addr p)
{
	return &(qblk->ch[p.g.ch].lines[qblk_ppa_to_line(p)]);
}

#if 0
static inline int qblk_ppa_to_pos(struct nvm_geo *geo,
					struct ppa_addr p)
{
	return p.g.lun * geo->nr_chnls + p.g.ch;
}
#endif

static inline int qblk_ppa_to_posinsidechnl(struct nvm_geo *geo,
				struct ppa_addr p)
{
	return p.g.lun;
}

static inline u32 qblk_calc_emeta_crc(struct qblk *qblk,
				      struct chnl_emeta *emeta)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	u32 crc = ~(u32)0;

	crc = crc32_le(crc, (unsigned char *)emeta +
				sizeof(struct line_header) + sizeof(crc),
				meta->emeta_len[0] -
				sizeof(struct line_header) - sizeof(crc));

	return crc;
}

static inline struct ppa_addr offset_in_line_to_gen_ppa(struct qblk *qblk,
					u64 offset_in_line, int ch_idx,
					u64 line_id)
{
	struct ppa_addr ppa;

	ppa.ppa = 0;
	ppa.g.blk = line_id;
	ppa.g.ch = ch_idx;
	ppa.g.sec = (offset_in_line & qblk->ppaf.sec_mask) >> qblk->ppaf.sec_offset;
	ppa.g.pl = (offset_in_line & qblk->ppaf.pln_mask) >> qblk->ppaf.pln_offset;
	ppa.g.lun = (offset_in_line & qblk->ppaf.lun_mask_inchnl) >> qblk->ppaf.lun_offset_inchnl;
	ppa.g.pg = (offset_in_line & qblk->ppaf.pg_mask_inchnl) >> qblk->ppaf.pg_offset_inchnl;
	return ppa;
}


static inline u64 gen_ppa_to_offset_in_line(struct qblk *qblk,
						struct ppa_addr ppa)
{
	u64 ret;

	ret = (ppa.g.sec) | (ppa.g.pl << qblk->ppaf.pln_offset)
					| (ppa.g.lun << qblk->ppaf.lun_offset_inchnl)
					| (ppa.g.pg << qblk->ppaf.pg_offset_inchnl);
	return ret;
}

static inline struct ppa_addr gen_ppa_add_one_inside_chnl(struct qblk *qblk,
						struct ppa_addr ppa)
{
	int mid;
	struct nvm_geo *geo = &qblk->dev->geo;

	mid = ppa.g.sec+1;
	if (mid == geo->sec_per_pg) {
		ppa.g.sec = 0;
		mid = ppa.g.pl+1;
		if (mid == geo->nr_planes) {
			ppa.g.pl = 0;
			mid = ppa.g.lun+1;
			if (mid == geo->nr_luns) {
				ppa.g.lun = 0;
				mid = ppa.g.pg+1;
				if (mid == geo->sec_per_chk /
							geo->sec_per_pg /
								geo->nr_planes) {
					ppa.g.pg = 0;
					mid = ppa.g.blk+1;
					if (mid == geo->nr_chks) {
						ppa.g.blk = 0;
						return ppa;
					}
					ppa.g.blk = mid;
				} else {
					ppa.g.pg = mid;
				}
			} else {
				ppa.g.lun = mid;
			}
		} else {
			ppa.g.pl = mid;
		}
	} else {
		ppa.g.sec = mid;
	}
	return ppa;
}


/*
 * When ppa_addr is in cache, we divide ppa32 into 1:11:20 bits where
 * 1 stands for is cached
 * 11 stands for ringBuffer index
 * 20 stands for cache line entry index
 * so, if we use ppa32, the maximum number of ringBuffer is 2048
 */
static inline struct ppa_addr qblk_ppa32_to_ppa64(struct qblk *qblk,
						u32 ppa32)
{
	struct ppa_addr ppa64;

	ppa64.ppa = 0;

	if (ppa32 == -1) {
		ppa64.ppa = ADDR_EMPTY;
	} else if (ppa32 & (1U << 31)) {
		//ppa64.c.line = ppa32 & ((~0U) >> 1);
		ppa64.c.line = ppa32 & ((~0U) >> 12);
		ppa64.c.q_idx = (ppa32 & ((~0U) >> 1)) >> 20;
		ppa64.c.is_cached = 1;
	} else {
		ppa64.g.blk = (ppa32 & qblk->ppaf.blk_mask) >>
							qblk->ppaf.blk_offset;
		ppa64.g.pg = (ppa32 & qblk->ppaf.pg_mask) >>
							qblk->ppaf.pg_offset;
		ppa64.g.lun = (ppa32 & qblk->ppaf.lun_mask) >>
							qblk->ppaf.lun_offset;
		ppa64.g.ch = (ppa32 & qblk->ppaf.ch_mask) >>
							qblk->ppaf.ch_offset;
		ppa64.g.pl = (ppa32 & qblk->ppaf.pln_mask) >>
							qblk->ppaf.pln_offset;
		ppa64.g.sec = (ppa32 & qblk->ppaf.sec_mask) >>
							qblk->ppaf.sec_offset;
	}

	return ppa64;
}

//see comments of qblk_ppa32_to_ppa64
static inline u32 qblk_ppa64_to_ppa32(struct qblk *qblk,
					struct ppa_addr ppa64)
{
	u32 ppa32 = 0;

	if (ppa64.ppa == ADDR_EMPTY) {
		ppa32 = ~0U;
	} else if (ppa64.c.is_cached) {
		ppa32 |= ppa64.c.line;
		ppa32 |= ppa64.c.q_idx << 20;
		ppa32 |= 1U << 31;
	} else {
		ppa32 |= ppa64.g.blk << qblk->ppaf.blk_offset;
		ppa32 |= ppa64.g.pg << qblk->ppaf.pg_offset;
		ppa32 |= ppa64.g.lun << qblk->ppaf.lun_offset;
		ppa32 |= ppa64.g.ch << qblk->ppaf.ch_offset;
		ppa32 |= ppa64.g.pl << qblk->ppaf.pln_offset;
		ppa32 |= ppa64.g.sec << qblk->ppaf.sec_offset;
	}

	return ppa32;
}
#ifdef QBLK_TRANSMAP_LOCK
static inline struct ppa_addr qblk_trans_map_get(struct qblk *qblk,
								sector_t lba)
{
	if (qblk->ppaf_bitsize < 32) {
		u32 *map = (u32 *)qblk->trans_map;

		return qblk_ppa32_to_ppa64(qblk, map[lba]);
	} else {
		struct ppa_addr *map = (struct ppa_addr *)qblk->trans_map;

		return map[lba];
	}
}

static inline void qblk_trans_map_set(struct qblk *qblk,
			sector_t lba, struct ppa_addr ppa)
{
	if (qblk->ppaf_bitsize < 32) {
		u32 *map = (u32 *)qblk->trans_map;

		map[lba] = qblk_ppa64_to_ppa32(qblk, ppa);
	} else {
		struct ppa_addr *map = (struct ppa_addr *)qblk->trans_map;

		map[lba] = ppa;
	}
}
#else
static inline struct ppa_addr qblk_trans_map_atomic_get(struct qblk *qblk,
								sector_t lba)
{
	if (qblk->ppaf_bitsize < 32) {
		u32 *map = (u32 *)qblk->trans_map;

		return qblk_ppa32_to_ppa64(qblk,
					atomic_read((atomic_t *)&map[lba]));
	} else {
		struct ppa_addr ppa;
		struct ppa_addr *map = (struct ppa_addr *)qblk->trans_map;

		ppa.ppa = atomic64_read(&map[lba].ppa_atomic);
		return ppa;
	}
}


static inline void qblk_trans_map_atomic_set(struct qblk *qblk,
			sector_t lba, struct ppa_addr ppa)
{
	if (qblk->ppaf_bitsize < 32) {
		u32 *map = (u32 *)qblk->trans_map;

		atomic_set((atomic_t *)&map[lba],
						qblk_ppa64_to_ppa32(qblk, ppa));
	} else {
		struct ppa_addr *map = (struct ppa_addr *)qblk->trans_map;

		atomic64_set(&map[lba].ppa_atomic, ppa.ppa);
	}
}

static inline struct ppa_addr qblk_trans_map_atomic_get_and_set(struct qblk *qblk,
				sector_t lba, struct ppa_addr ppa)
{
	struct ppa_addr oldppa;

	if (qblk->ppaf_bitsize < 32) {
		u32 *map = (u32 *)qblk->trans_map;

		oldppa = qblk_ppa32_to_ppa64(qblk,
					atomic_xchg((atomic_t *)&map[lba],
					qblk_ppa64_to_ppa32(qblk, ppa)));
	} else {
		struct ppa_addr *map = (struct ppa_addr *)qblk->trans_map;

		oldppa.ppa = atomic64_xchg(&map[lba].ppa_atomic, ppa.ppa);
	}

	return oldppa;
}

/*
 * Return 0 if xchg succeeded.
 */
static inline int qblk_trans_map_tomic_cmp_and_xchg(struct qblk *qblk,
				sector_t lba, struct ppa_addr oldppa,
				struct ppa_addr newppa)
{
	struct ppa_addr cur_ppa;

	if (qblk->ppaf_bitsize < 32) {
		u32 *map = (u32 *)qblk->trans_map;

		cur_ppa = qblk_ppa32_to_ppa64(qblk, atomic_cmpxchg((atomic_t *)&map[lba],
						qblk_ppa64_to_ppa32(qblk, oldppa),
						qblk_ppa64_to_ppa32(qblk, newppa)));
	} else {
		struct ppa_addr *map = (struct ppa_addr *)qblk->trans_map;

		cur_ppa.ppa = atomic64_cmpxchg(&map[lba].ppa_atomic, oldppa.ppa, newppa.ppa);
	}
	//pr_notice("%s,cur_ppa%s=oldppa,cur=0x%llx,old=0x%llx,new=0x%llx\n",
	//			__FUNCTION__,(cur_ppa.ppa != oldppa.ppa)?" !":" =",cur_ppa.ppa,oldppa.ppa,newppa.ppa);

	return (cur_ppa.ppa != oldppa.ppa);

}
#endif
static inline int qblk_ppa_empty(struct ppa_addr ppa_addr)
{
	return (ppa_addr.ppa == ADDR_EMPTY);
}


static inline void qblk_ppa_set_empty(struct ppa_addr *ppa_addr)
{
	ppa_addr->ppa = ADDR_EMPTY;
}

static inline int qblk_addr_in_cache(struct ppa_addr ppa)
{
	return (ppa.ppa != ADDR_EMPTY && ppa.c.is_cached);
}

static inline bool qblk_ppa_comp(struct ppa_addr lppa, struct ppa_addr rppa)
{
	return (lppa.ppa == rppa.ppa);
}



static inline int qblk_addr_to_cacheline(struct ppa_addr ppa)
{
	return ppa.c.line;
}

static inline struct ppa_addr qblk_cacheline_to_addr(unsigned int queueIndex, int addr)
{
	struct ppa_addr p;

	p.c.line = addr;
	p.c.q_idx = queueIndex;
	p.c.is_cached = 1;

	return p;
}

static inline sector_t qblk_get_rq_lba(struct request *req)
{
	return blk_rq_pos(req) >> QBLK_LBA_SHIFT;
}

static inline unsigned int qblk_get_rq_secs(struct request *req)
{
	return blk_rq_sectors(req) >> (QBLK_EXPOSED_PAGE_SHIFT-QBLK_SECTOR_SHIFT);
}

static inline int qblk_boundary_paddr_checks(struct qblk *qblk, u64 paddr)
{
	struct qblk_metainfo *meta = &qblk->metainfo;

	if (paddr > meta->sec_per_chline)
		return 1;

	return 0;
}

static inline sector_t qblk_get_lba(struct bio *bio)
{
	return bio->bi_iter.bi_sector / NR_PHY_IN_LOG;
}

static inline unsigned int qblk_get_secs(struct bio *bio)
{
	return  bio->bi_iter.bi_size / QBLK_EXPOSED_PAGE_SIZE;
}

static inline unsigned int qblk_get_secs_rq(struct request *rq)
{
	return blk_rq_sectors(rq) >> QBLK_EXPOSED_PAGE_SHIFT;
}

static inline void qblk_setup_uuid(struct qblk *qblk)
{
	uuid_le uuid;

	uuid_le_gen(&uuid);
	memcpy(qblk->instance_uuid, uuid.b, 16);
}

static inline int qblk_set_read_mode(struct qblk *qblk, int type)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int flags;


	flags = NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
	if (type == QBLK_READ_SEQUENTIAL)
		flags |= geo->plane_mode >> 1;

	return flags;
}

static inline int qblk_set_progr_mode(struct qblk *qblk, int type)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int flags;

	flags = geo->plane_mode >> 1;

	if (type == QBLK_WRITE)
		flags |= NVM_IO_SCRAMBLE_ENABLE;

	return flags;
}

static inline int qblk_io_aligned(struct qblk *qblk, int nr_secs)
{
	return !(nr_secs % qblk->min_write_pgs);
}


//return the index number of qblk->luns[]
static inline int qblk_chlun_to_lunidx(struct nvm_geo *geo, int ch_idx, int lun_in_ch)
{
	return lun_in_ch*geo->nr_chnls + ch_idx;
}

#ifdef CONFIG_NVM_DEBUG
static inline void print_ppa(struct ppa_addr *p, char *msg, int error)
{
	if (p->c.is_cached) {
		pr_err("ppa: (%s: %x) cache line: %llu\n",
				msg, error, (u64)p->c.line);
	} else {
		pr_err("ppa: (%s: %x):ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
			msg, error,
			p->g.ch, p->g.lun, p->g.blk,
			p->g.pg, p->g.pl, p->g.sec);
	}
}

static inline void qblk_print_failed_rqd(struct qblk *qblk, struct nvm_rq *rqd,
					 int error)
{
	int bit = -1;

	if (rqd->nr_ppas ==  1) {
		print_ppa(&rqd->ppa_addr, "rqd", error);
		return;
	}

	while ((bit = find_next_bit((void *)&rqd->ppa_status, rqd->nr_ppas,
						bit + 1)) < rqd->nr_ppas) {
		print_ppa(&rqd->ppa_list[bit], "rqd", error);
	}

	pr_err("%s, error:%d, ppa_status:%llx\n",
			__func__, error, rqd->ppa_status);
}
#endif

/* qblk-rb.c */
extern unsigned int qblk_rb_sync_init(struct qblk_rb *rb,
					unsigned long *flags);
extern void qblk_rb_sync_end(struct qblk_rb *rb,
					unsigned long *flags);
extern unsigned int qblk_rb_sync_advance(struct qblk_rb *rb,
					unsigned int nr_entries);
extern unsigned int qblk_rb_sync_count(struct qblk_rb *rb);
extern unsigned int qblk_rb_read_count(struct qblk_rb *rb);
extern unsigned int qblk_rb_read_commit(struct qblk_rb *rb,
				unsigned int nr_entries);
extern struct qblk_w_ctx *qblk_rb_w_ctx(struct qblk_rb *rb, unsigned int pos);
extern unsigned int qblk_rb_flush_point_count(struct qblk_rb *rb);
extern void qblk_rb_sync_all_l2p(struct qblk *qblk);
extern blk_status_t qblk_rb_may_write_user(struct qblk *qblk,
			unsigned int rbid,
			struct qblk_rb *rb, struct bio *bio,
			unsigned int nr_entries,
			unsigned int *pos);
extern void qblk_rb_write_entry_user(struct qblk *qblk,
			struct qblk_rb *rb, void *data,
			struct qblk_w_ctx w_ctx, unsigned int ring_pos);
extern void qblk_rb_data_free(struct qblk_rb *rb);
extern int qblk_rb_init(struct qblk *pblk,
			struct qblk_rb *rb, unsigned int rbIndex,
			struct qblk_rb_entry *rb_entry_base,
			unsigned int power_size,
			unsigned int power_seg_sz);
extern unsigned int qblk_rb_calculate_size(unsigned int nr_entries);
extern void *qblk_rb_entries_ref(struct qblk_rb *rb);
extern int qblk_rb_tear_down_check(struct qblk_rb *rb);
extern int qblk_rb_pos_oob(struct qblk_rb *rb, u64 pos);
extern void printRbStatus(struct qblk_rb *ringBuffer,
				unsigned int rbIndex);
extern blk_status_t qblk_rq_write_to_cache(struct qblk *qblk,
				struct qblk_queue *pq,
				struct request *req,
				unsigned long flags);
extern unsigned int qblk_rb_wrap_pos(struct qblk_rb *rb, unsigned int pos);
extern unsigned int qblk_rb_read_to_bio(struct qblk *qblk,
				struct qblk_rb *rb, struct nvm_rq *rqd,
				unsigned int pos, unsigned int nr_entries,
				unsigned int count);
extern int qblk_write_gc_to_cache(struct qblk *qblk, struct qblk_gc_rq *gc_rq);
/*
 * qblk gc
 */
#define QBLK_GC_MAX_READERS (8)	/* Max number of outstanding GC reader jobs */
#define QBLK_GC_RQ_QD (128)	/* Queue depth for inflight GC requests */
#define QBLK_GC_L_QD (4)	/* Queue depth for inflight GC lines */
#define QBLK_GC_RSV_LINE (3)	/* Reserved lines for GC */
#define QBLK_GC_THRES_INTERVAL (1)	/* NR lines of interval between thresholds to diminish fluctuations */

/* qblk-init.c */
extern void qblk_stop_writers(struct qblk *qblk, unsigned int nr_writers);

/* qblk-rl.c */
extern void qblk_rl_free_lines_inc(struct qblk_per_chnl_rl *rl, struct qblk_line *line);
extern void qblk_rl_free_lines_dec(struct qblk_per_chnl_rl *rl, struct qblk_line *line,
			    bool used);
extern int qblk_rl_high_thrs(struct qblk_per_chnl_rl *rl);
extern unsigned long qblk_rl_nr_free_blks(struct qblk_per_chnl_rl *rl);
extern void qblk_rl_inserted(struct qblk_rl *rl, int nr_entries);
extern void qblk_rl_user_in(struct qblk_rl *rl, int nr_entries);
extern void qblk_rl_gc_in(struct qblk_rl *rl, int nr_entries);
extern void qblk_rl_out(struct qblk_rl *rl,
					int nr_user, int nr_gc);
extern int qblk_rl_gc_maynot_insert(struct qblk_rl *rl,
					struct qblk_per_chnl_rl *pch_rl, int nr_entries);
extern blk_status_t qblk_rl_user_may_insert(struct qblk *qblk, int nr_entries);
extern unsigned long qblk_rl_nr_user_free_blks(struct qblk_per_chnl_rl *rl);
extern void qblk_rl_update_rates(struct qblk_per_chnl_rl *rl);
extern void qblk_rl_free(struct qblk_rl *rl);
extern int qblk_rl_init(struct qblk_rl *rl, int budget);
extern void qblk_per_chnl_rl_free(struct qblk_per_chnl_rl *rl);
extern void qblk_per_chnl_rl_init(struct qblk *qblk,
			struct ch_info *chi, struct qblk_per_chnl_rl *rl,
			int nr_free_blks);
extern int qblk_channel_may_writeback(struct qblk *qblk,
					struct ch_info *chi,
					unsigned int nr_sec_required);

/* qblk-core.c */
extern int qblk_line_read_emeta(struct qblk *qblk, struct qblk_line *line,
			 void *emeta_buf);
extern struct bio *qblk_bio_map_addr(struct qblk *qblk,
			void *data, unsigned int nr_secs,
			unsigned int len, int alloc_type,
			gfp_t gfp_mask);
extern void qblk_line_close_ws(struct work_struct *work);
extern void qblk_gen_run_ws(struct qblk *qblk,
			struct qblk_line *line, void *priv,
		    void (*work)(struct work_struct *),
		    gfp_t gfp_mask,
		    struct workqueue_struct *wq);
extern void __qblk_map_invalidate(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line *line,
			u64 paddr);
extern void qblk_map_invalidate(struct qblk *qblk, struct ppa_addr ppa);
extern void qblk_map_invalidate(struct qblk *qblk, struct ppa_addr ppa);
extern struct list_head *qblk_line_gc_list(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line *line);
extern int qblk_calc_secs(struct qblk *qblk, unsigned long secs_avail,
		   unsigned long secs_to_flush);
extern struct qblk_line *qblk_line_get_data(struct ch_info *chi);
extern struct qblk_line *qblk_line_get_erase(struct ch_info *chi);
extern int qblk_blk_erase_sync(struct qblk *qblk, struct ppa_addr ppa);
extern int qblk_blk_erase_async(struct qblk *qblk, struct ppa_addr ppa);
extern u64 qblk_lookup_page(struct qblk *qblk, struct qblk_line *line);
extern void qblk_line_put(struct kref *ref);
extern void qblk_line_put_wq(struct kref *ref);
extern int qblk_line_erase(struct qblk *qblk,
			int ch_idx, struct qblk_line *line);
extern struct qblk_line *qblk_line_replace_data(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line *cur,
			struct qblk_line *newline);
extern void qblk_log_write_err(struct qblk *qblk, struct nvm_rq *rqd);
extern void qblk_set_sec_per_write(struct qblk *qblk,
			int sec_per_write);
extern void qblk_dealloc_page(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line *line,
			int nr_secs);
extern struct ppa_addr qblk_alloc_page(struct qblk *qblk,
			struct ch_info *chi, struct qblk_line **pline,
			int nr_secs);
extern struct ppa_addr __qblk_alloc_page(struct qblk *qblk,
			struct qblk_line *line, int nr_secs);
extern void qblk_line_close(struct qblk *qblk,
			struct qblk_line *line);
extern void qblk_line_close_meta(struct qblk *qblk,
			struct ch_info *chi,
			struct qblk_line *line);
extern void qblk_rq_get_semaphores(struct qblk *qblk,
			struct ch_info *chi,
			unsigned long *lun_bitmap);
extern void qblk_mark_rq_luns(struct qblk *qblk,
			struct ppa_addr *ppa_list, int nr_ppas,
			unsigned long *lun_bitmap);
extern void qblk_up_rq(struct qblk *qblk,
			struct ppa_addr *ppa_list, int nr_ppas,
			unsigned long *lun_bitmap);
extern void qblk_discard_req(struct qblk *qblk, struct request *req);
extern int qblk_update_map_gc(struct qblk *qblk, struct qblk_rb *rb,
				sector_t lba, struct ppa_addr ppa_new,
		       struct qblk_line *gc_line, u64 paddr_gc);
extern void qblk_update_map_dev(struct qblk *qblk, sector_t lba,
			 struct ppa_addr ppa_mapped, struct ppa_addr ppa_cache);
extern void qblk_update_map(struct qblk *qblk, sector_t lba,
			struct ppa_addr ppa);
extern void qblk_update_map_cache(struct qblk *qblk,
			struct qblk_rb *rb, sector_t lba,
			struct ppa_addr ppa);
extern struct nvm_rq *qblk_alloc_rqd_nowait(struct qblk *qblk, int type);
extern void qblk_free_rqd(struct qblk *qblk, struct nvm_rq *rqd, int type);
extern int qblk_submit_io(struct qblk *qblk, struct nvm_rq *rqd);
extern int qblk_submit_io_sync(struct qblk *qblk, struct nvm_rq *rqd);
extern void qblk_log_read_err(struct qblk *qblk, struct nvm_rq *rqd);
extern int qblk_bio_add_pages(struct qblk *qblk, struct bio *bio, gfp_t flags,
		       int nr_pages);
extern void qblk_bio_free_pages(struct qblk *qblk, struct bio *bio, int off,
			 int nr_pages);
extern u64 qblk_line_smeta_start(struct qblk *qblk, struct qblk_line *line);

extern int qblk_line_read_smeta(struct qblk *qblk, struct qblk_line *line);
extern void qblk_line_free(struct qblk *qblk, struct qblk_line *line);
extern struct qblk_line *qblk_line_get(struct qblk *qblk, struct ch_info *chi);
extern int qblk_line_get_first_data(struct qblk *qblk);
extern void qblk_write_should_kick(struct qblk *qblk, int index);

#ifdef QBLK_TRANSMAP_LOCK
extern struct ppa_addr qblk_lookup_l2p(struct qblk *qblk,
			 sector_t blba);
#endif

/* qblk-read.c */
extern void __qblk_end_req_io_read(struct qblk *qblk,
			struct request *req,
			unsigned long startTime);
extern blk_status_t qblk_read_req_nowait(struct request_queue *q,
				struct qblk *qblk, struct request *req);
extern int qblk_submit_read_gc(struct qblk_gc *gc, struct qblk_gc_rq *gc_rq);


/* qblk-write.c */
extern int qblk_alloc_w_rq(struct qblk *qblk, struct nvm_rq *rqd,
				unsigned int nr_secs,
				nvm_end_io_fn(*end_io));
extern int qblk_submit_meta_io(struct qblk *qblk,
		struct qblk_line *meta_line,
		struct ch_info *chi);
extern int qblk_writer_thread_fn(void *data);
extern void qblk_write_kick(struct qblk *qblk, unsigned int writer_index);
extern void qblk_timer_fn(struct timer_list *t);
extern void qblk_writeback_timer_fn(struct timer_list *t);


/* qblk-map.c */
extern void qblk_map_rq(struct qblk *qblk, struct ch_info *chi,
				struct nvm_rq *rqd, unsigned int sentry,
				unsigned long *lun_bitmap,
				unsigned int valid_secs,
				unsigned int off, unsigned int rb_count);
extern void qblk_map_erase_rq(struct qblk *qblk,
		struct ch_info *chi, struct nvm_rq *rqd,
		unsigned int sentry, unsigned long *lun_bitmap,
		unsigned int valid_secs,
		struct ppa_addr *erase_ppa,	unsigned int rb_count);

/* qblk-recovery.c */
extern int qblk_recov_check_emeta(struct qblk *qblk, struct chnl_emeta *emeta_buf);
extern int qblk_recov_l2p(struct qblk *qblk);

/* qblk-debug.c */
extern void printRqdStatus(struct nvm_rq *rqd);
extern void printBufSample(void *data);
extern void print_gcrq_status(struct qblk_gc_rq *gc_rq);	
extern void qblk_debug_complete_time(struct qblk *qblk, int index, int chnl);
extern void qblk_debug_complete_time3(struct qblk *qblk, int index, int chnl);
extern void qblk_debug_time_irqsave(struct qblk *qblk, int *pindex,
				int chnl, struct qblk_debug_entry entry);
extern void qblk_debug_time(struct qblk *qblk, int *pindex,
				int chnl, struct qblk_debug_entry entry);
extern void qblk_debug_init(struct qblk *qblk);
extern void qblk_debug_exit(void);

/* qblk-gc.c */
extern int qblk_gc_is_activated(struct qblk *qblk);
extern int qblk_gc_is_stopped(struct qblk *qblk);
extern void qblk_gc_free_full_lines(struct qblk_gc *gc, struct ch_info *chi);
extern void qblk_gc_kick(struct qblk_gc *gc);
void qblk_gc_should_start(struct qblk_per_chnl_rl *rl);
extern void qblk_gc_should_stop(struct qblk_per_chnl_rl *rl);
extern void qblk_gc_should_kick(struct qblk *qblk);
extern int qblk_gc_init(struct qblk *qblk);
extern void qblk_gc_exit(struct qblk *qblk);
#endif

