/*
 * (C) Copyright 2002-2007
 * Detlev Zundel, DENX Software Engineering, dzu@denx.de.
 *
 * Code used from linux/kernel/printk.c
 * Copyright (C) 1991, 1992  Linus Torvalds
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 * Comments:
 *
 * After relocating the code, the environment variable "loglevel" is
 * copied to console_loglevel.  The functionality is similar to the
 * handling in the Linux kernel, i.e. messages logged with a priority
 * less than console_loglevel are also output to stdout.
 *
 * If you want messages with the default level (e.g. POST messages) to
 * appear on stdout also, make sure the environment variable
 * "loglevel" is set at boot time to a number higher than
 * default_message_loglevel below.
 */

/*
 * Logbuffer handling routines
 */

#include <common.h>
#include <command.h>
#include <stdio_dev.h>
#include <post.h>
#include <logbuff.h>

#define LOGBUFF_MAGIC	0xc0de4ced	/* Forced by code, eh!	*/
#define LOGBUFF_LEN	(16384)	/* Must be 16k right now */
#define LOGBUFF_MASK	(LOGBUFF_LEN-1)
#define LOGBUFF_CB_PADDED_LENGTH (1024) /* Logbuffer control block with padding */

/* The mapping used here has to be the same as in setup_ext_logbuff ()
   in linux/kernel/printk */

typedef struct {
	union {
		struct {
			unsigned long	tag;
			unsigned long	start;
			unsigned long	con;
			unsigned long	end;
			unsigned long	chars;
		} v2;
		struct {
			unsigned long	dummy;
			unsigned long	tag;
			unsigned long	start;
			unsigned long	size;
			unsigned long	chars;
		} v1;
	};
	unsigned char	buf[0];
} logbuff_t;

/* v3 log is based on structure in Linux kernel (kernel/printk/printk.c) */
typedef struct {
	u32 log_magic;		/* sanity check number */
	u64 ts_nsec;		/* timestamp in nanoseconds */
	u16 len;		/* length of entire record */
	u16 text_len;		/* length of text buffer */
	u16 dict_len;		/* length of dictionary buffer */
	u8 facility;		/* syslog facility */
	u8 flags:5;		/* internal record flags */
	u8 level:3;		/* syslog level */
} log_hdr_t;

/*
 * When enabled via CONFIG_LOGBUFFER, this control block collects tracking
 * offsets for the log into a single place.  It also facilitates pointing
 * the log to another location, and, when combined with the CONFIG_LOGBUFFER
 * feature, it allows log sharing between the bootloader and the kernel.
 *
 * NOTE:
 *   By convention, the control block and the log buffer are contiguous.
 *   This requirement can be relaxed, if desired.
 */
typedef struct {
	/* Pointer to log buffer space and length of space */
	char *log_buf;
	u32 log_buf_len;

	/* index and sequence number of the first record stored in the buffer */
	u64 log_first_seq;
	u32 log_first_idx;

	/* index and sequence number of the next record to store in the buffer */
	u64 log_next_seq;
	u32 log_next_idx;

	/* the next printk record to read by syslog(READ) or /proc/kmsg */
	u64 syslog_seq;
	u32 syslog_idx;
	u32 syslog_prev;  /* NOTE: this is an enum in printk.c */
	size_t syslog_partial;

	/* the next printk record to write to the console */
	u64 console_seq;
	u32 console_idx;
	u32 console_prev;  /* NOTE: this is an enum in printk.c */

	/* the next printk record to read after the last 'clear' command */
	u64 clear_seq;
	u32 clear_idx;

	u32 log_version;
	u32 lcb_padded_len;
	u32 lcb_size;
	u32 log_hdr_size;
	u32 log_phys_addr;
	u32 lcb_magic;
} lcb_t;

DECLARE_GLOBAL_DATA_PTR;

/* Local prototypes */
static void logbuff_putc(struct stdio_dev *dev, const char c);
static void logbuff_puts(struct stdio_dev *dev, const char *s);
static int logbuff_printk(const char *line);

static void log_append_v3(int argc, char *const argv[]);
static void log_printk_v3(const unsigned level, const char *msg);
static void log_info_v3(void);
static void log_show_v3(void);
static void log_printk_v3_write(const log_hdr_t * hdr, const char *msg);

#ifdef CONFIG_LOGBUFFER_EARLY
static void early_log_printk_v3(const unsigned level, const char *msg);
#endif

#ifndef CONFIG_EARLY_LOGBUFF_ADDR
#define CONFIG_EARLY_LOGBUFF_ADDR 0x20000000
#endif
#ifndef CONFIG_EARLY_LOGBUFF_SZ
#define CONFIG_EARLY_LOGBUFF_SZ (8 << 20)
#endif

static char buf[1024];
static char buf2[1024];

#define LOG_ALIGN 4

/* This combination will not print messages with the default loglevel */
static unsigned console_loglevel = 3;
static unsigned default_message_loglevel = 4;
#ifdef CONFIG_ALT_LB_ADDR
static volatile logbuff_t *log;
static volatile lcb_t *lcb;
#else
static logbuff_t *log;
static lcb_t *lcb;
#endif
static char *lbuf;

unsigned long __get_lcb_base(void)
{
	unsigned long lcb_base = 0;
	char *s;

	/* Check for a value set in the environment */
	if ((s = getenv("lcbbase")) != NULL)
		lcb_base = (unsigned long)simple_strtoul(s, NULL, 10);

	/* Validate the value */
	if (lcb_base == 0)
	{
		/* Default to the top of available RAM */
		lcb_base = CONFIG_SYS_SDRAM_BASE + get_effective_memsize();
		lcb_base -= (get_lcb_padded_len() + get_log_buf_len());
	}

	return (lcb_base);
}
unsigned long get_lcb_base(void)
__attribute__((weak, alias("__get_lcb_base")));

unsigned long __get_log_base(void)
{
	unsigned long log_base = 0;
	char *s;

	/* Check for a value set in the environment */
	if ((s = getenv("logbase")) != NULL)
		log_base = (unsigned long)simple_strtoul(s, NULL, 10);

	/* Validate the value */
	if (0 == log_base)
		log_base = get_lcb_base() + get_lcb_padded_len();

	return (log_base);
}
unsigned long get_log_base(void)
__attribute__((weak, alias("__get_log_base")));

u32 __get_log_version(void)
{
	unsigned long log_version = 1;
	char *s;

	/* If set in the environment, overide the default log size */
	if ((s = getenv("logversion")) != NULL)
		log_version = (unsigned long)simple_strtoul(s, NULL, 10);

	/* Validate the value */
	if (0 == log_version || 3 < log_version)
		log_version = 1;

	return (log_version);
}

u32 get_log_version(void)
    __attribute__ ((weak, alias("__get_log_version")));

unsigned long __get_log_buf_len(void)
{
	unsigned long log_length = LOGBUFF_LEN;
	char *s;

	/* If set in the environment, overide the default log size */
	if ((s = getenv("logsize")) != NULL)
		log_length = (unsigned long)simple_strtoul(s, NULL, 10);

	/* Validate the value */
	if (0 == log_length)
		log_length = LOGBUFF_LEN;

	return (log_length);
}

unsigned long get_log_buf_len(void)
    __attribute__ ((weak, alias("__get_log_buf_len")));

unsigned long __get_lcb_padded_len(void)
{
	unsigned long lcb_padded_len = LOGBUFF_CB_PADDED_LENGTH;
	char *s;

	/* If set in the environment, overide the default log overhead_size */
	if ((s = getenv("lcb_padded_len")) != NULL)
		lcb_padded_len = (unsigned long)simple_strtoul(s, NULL, 10);

	/* Validate the value */
	if (0 == lcb_padded_len)
		lcb_padded_len = LOGBUFF_CB_PADDED_LENGTH;

	return (lcb_padded_len);
}

unsigned long get_lcb_padded_len(void)
    __attribute__ ((weak, alias("__get_lcb_padded_len")));

#ifdef CONFIG_LOGBUFFER_EARLY
void logbuff_copy_early_buffer(void)
{
	char *p = (char *)CONFIG_EARLY_LOGBUFF_ADDR;

	if (get_log_version() != 3)
		return;

	while (p < (char *)CONFIG_EARLY_LOGBUFF_ADDR + gd->early_logbuff_idx) {
		log_printk_v3_write((log_hdr_t *) p, (p + lcb->log_hdr_size));
		p += ((log_hdr_t *) p)->len;
	}
}
#endif

void logbuff_init_ptrs(void)
{
	unsigned long tag;
	char *s;
	unsigned long log_version;

#ifdef CONFIG_ALT_LB_ADDR
	log = (logbuff_t *)CONFIG_ALT_LH_ADDR;
	lbuf = (char *)CONFIG_ALT_LB_ADDR;
#else
	log = (logbuff_t *)(get_log_base()) - 1;
	lbuf = (char *)log->buf;
#endif

	/* Read log version from the environment */
	log_version = get_log_version();

	gd->logbuff_suppress_printk = 0;

	if (log_version == 3) {
		/*
		 * Locate the v3 log control block at the top of the log overhead area
		 * see common/image.c for lmb_reserve() call that matches this
		 * NOTE:
		 *   When this function runs, stored environment variables haven't loaded.
		 *   Instead it uses the hardcoded defaults, or ones set in the default config,
		 *   but not ones saved in the environment.
		 */
		lcb = (lcb_t *)get_lcb_base();

		/* Check to ensure that CB values match compiled constants, if not reset */
		if (lcb->log_version != log_version ||
		    lcb->log_buf_len != get_log_buf_len() ||
		    lcb->lcb_padded_len != get_lcb_padded_len() ||
		    lcb->lcb_size != sizeof(lcb_t) ||
		    lcb->log_hdr_size != sizeof(log_hdr_t) ||
		    lcb->log_phys_addr != get_log_base() ||
		    lcb->lcb_magic != LOGBUFF_MAGIC) {
			logbuff_reset();
		}

		gd->flags |= GD_FLG_LOGINIT;

#ifdef CONFIG_LOGBUFFER_EARLY
		/* Copy early messages to the logbuff */
		logbuff_copy_early_buffer();
#endif

		return;
	}
	if (log_version == 2)
		tag = log->v2.tag;
	else
		tag = log->v1.tag;
#ifdef CONFIG_POST
	/* The post routines have setup the word so we can simply test it */
	if (tag != LOGBUFF_MAGIC || (post_word_load() & POST_COLDBOOT))
		logbuff_reset();
#else
	/* No post routines, so we do our own checking                    */
	if (tag != LOGBUFF_MAGIC) {
		logbuff_reset();
	}
#endif
	if (log_version == 2 && (long)log->v2.start > (long)log->v2.con)
		log->v2.start = log->v2.con;

	/* Initialize default loglevel if present */
	if ((s = getenv ("loglevel")) != NULL)
		console_loglevel = (int)simple_strtoul(s, NULL, 10);

	gd->flags |= GD_FLG_LOGINIT;
}

#ifdef CONFIG_LOGBUFFER_EARLY
int early_logbuff_init_ptrs(void)
{
	char *s;
	unsigned long log_version;

	/* Read log version from the environment */
	log_version = get_log_version();

	if ((s = getenv("loglevel")) != NULL)
		console_loglevel = (int)simple_strtoul(s, NULL, 10);

	gd->early_logbuff_idx = 0;
	gd->logbuff_suppress_printk = 0;
	return 0;
}
#endif

void logbuff_reset(void)
{
	unsigned long log_version;

	/* Read log version from the environment */
	log_version = get_log_version();

	if (log_version == 3) {
		printf("Resetting the log with v3 settings\n");

		/*
		 * Re-assign the log control block
		 * see common/image.c for lmb_reserve() call that matches this
		 * NOTE:
		 *   When called by logbuff_init_ptrs(), stored env vars are not loaded.
		 *   Instead it uses the hardcoded defaults, or ones set in the default config,
		 *   but not ones saved in the environment.
		 *   Subsequent runs will take into account stored vars.
		 */
		lcb = (lcb_t *)get_lcb_base();

		/* Initialize the control block */
		memset(lcb, 0, sizeof(lcb_t));
		lcb->log_version = log_version;
		lcb->log_buf_len = get_log_buf_len();
		lcb->lcb_padded_len = get_lcb_padded_len();
		lcb->lcb_size = sizeof(lcb_t);
		lcb->log_hdr_size = sizeof(log_hdr_t);
		lcb->log_phys_addr = get_log_base();

		/* Initialize the first entry and mark it "valid" with a magic value */
		log_hdr_t *first = (log_hdr_t *) lcb->log_phys_addr;
		memset(first, 0, sizeof(log_hdr_t));
		first->log_magic = LOGBUFF_MAGIC;

		/* Last step, write the magic value into the control block to mark it valid */
		lcb->lcb_magic = LOGBUFF_MAGIC;
		return;
	}
#ifndef CONFIG_ALT_LB_ADDR
	memset(log, 0, sizeof(logbuff_t));
#endif
	if (log_version == 2) {
		log->v2.tag = LOGBUFF_MAGIC;
#ifdef CONFIG_ALT_LB_ADDR
		log->v2.start = 0;
		log->v2.con = 0;
		log->v2.end = 0;
		log->v2.chars = 0;
#endif
	} else {
		log->v1.tag = LOGBUFF_MAGIC;
#ifdef CONFIG_ALT_LB_ADDR
		log->v1.dummy = 0;
		log->v1.start = 0;
		log->v1.size = 0;
		log->v1.chars = 0;
#endif
	}
}

int drv_logbuff_init(void)
{
	struct stdio_dev logdev;
	int rc;

	/* Device initialization */
	memset (&logdev, 0, sizeof (logdev));

	strcpy (logdev.name, "logbuff");
	logdev.ext   = 0;			/* No extensions */
	logdev.flags = DEV_FLAGS_OUTPUT;	/* Output only */
	logdev.putc  = logbuff_putc;		/* 'putc' function */
	logdev.puts  = logbuff_puts;		/* 'puts' function */

	rc = stdio_register(&logdev);

	return (rc == 0) ? 1 : rc;
}

static void logbuff_putc(struct stdio_dev *dev, const char c)
{
	char buf[2];
	buf[0] = c;
	buf[1] = '\0';
	logbuff_printk(buf);
}

static void logbuff_puts(struct stdio_dev *dev, const char *s)
{
	logbuff_printk (s);
}

void logbuff_log(char *msg)
{
	if ((gd->flags & GD_FLG_LOGINIT)) {
		logbuff_printk(msg);
	} else {
		/*
		 * Can happen only for pre-relocated errors as logging
		 * at that stage should be disabled
		 */
		puts (msg);
	}
}

/*
 * Subroutine:  do_log
 *
 * Description: Handler for 'log' command..
 *
 * Inputs:	argv[1] contains the subcommand
 *
 * Return:      None
 *
 */
int do_log(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	struct stdio_dev *sdev = NULL;
	char *s;
	unsigned long i, start, size;
	unsigned long log_version;

	/* Read log version from the environment */
	log_version = get_log_version();

	if (strcmp(argv[1], "append") == 0) {
		/* Log concatenation of all arguments separated by spaces */
		if (log_version == 3) {
			log_append_v3(argc, argv);
			return 0;
		}
		for (i = 2; i < argc; i++) {
			logbuff_printk(argv[i]);
			logbuff_putc(sdev, (i < argc - 1) ? ' ' : '\n');
		}
		return 0;
	}

	switch (argc) {

	case 2:
		if (strcmp(argv[1], "show") == 0) {
			gd->logbuff_suppress_printk = 1;
			if (log_version == 3) {
				log_show_v3();
				gd->logbuff_suppress_printk = 0;
				return 0;
			}
			if (log_version == 2) {
				start = log->v2.start;
				size = log->v2.end - log->v2.start;
			} else {
				start = log->v1.start;
				size = log->v1.size;
			}
			if (size > LOGBUFF_LEN)
				size = LOGBUFF_LEN;
			for (i = 0; i < size; i++) {
				s = lbuf + ((start + i) & LOGBUFF_MASK);
				putc(*s);
			}
			gd->logbuff_suppress_printk = 0;
			return 0;
		} else if (strcmp(argv[1], "reset") == 0) {
			logbuff_reset();
			return 0;
		} else if (strcmp(argv[1], "info") == 0) {
			if (log_version == 3) {
				log_info_v3();
				return 0;
			}
			printf("Logbuffer   at  %08lx\n", (unsigned long)lbuf);
			if (log_version == 2) {
				printf("log_start    =  %08lx\n",
					log->v2.start);
				printf("log_end      =  %08lx\n", log->v2.end);
				printf("log_con      =  %08lx\n", log->v2.con);
				printf("logged_chars =  %08lx\n",
					log->v2.chars);
			}
			else {
				printf("log_start    =  %08lx\n",
					log->v1.start);
				printf("log_size     =  %08lx\n",
					log->v1.size);
				printf("logged_chars =  %08lx\n",
					log->v1.chars);
			}
			return 0;
		}
		return CMD_RET_USAGE;

	default:
		return CMD_RET_USAGE;
	}
}

U_BOOT_CMD(
	log,     255,	1,	do_log,
	"manipulate logbuffer",
	"info   - show pointer details\n"
	"log reset  - clear contents\n"
	"log show   - show contents\n"
	"log append <msg> - append <msg> to the logbuffer"
);

static int logbuff_printk(const char *line)
{
	int i;
	char *msg, *p, *buf_end;
	int line_feed;
	static signed char msg_level = -1;
	unsigned long log_version;

	if (gd->logbuff_suppress_printk)
		return 0;

	/* Read log version from the environment */
	log_version = get_log_version();

	strcpy(buf + 3, line);
	i = strlen(line);
	buf_end = buf + 3 + i;
	for (p = buf + 3; p < buf_end; p++) {
		msg = p;
		if (msg_level < 0) {
			if (
				p[0] != '<' ||
				p[1] < '0' ||
				p[1] > '7' ||
				p[2] != '>'
			) {
				p -= 3;
				p[0] = '<';
				p[1] = default_message_loglevel + '0';
				p[2] = '>';
			} else {
				msg += 3;
			}
			msg_level = p[1] - '0';
		}
		if (log_version == 3) {
			if ((gd->flags & GD_FLG_LOGINIT))
				log_printk_v3(msg_level, msg);
			else
#ifdef CONFIG_LOGBUFFER_EARLY
				early_log_printk_v3(msg_level, msg);
#else
				return 0;
#endif

			if (msg_level < console_loglevel)
				printf("%s\n", msg);

			msg_level = -1;
			break;
		}
		if (!(gd->flags & GD_FLG_LOGINIT))
			return 0;
		line_feed = 0;
		for (; p < buf_end; p++) {
			if (log_version == 2) {
				lbuf[log->v2.end & LOGBUFF_MASK] = *p;
				log->v2.end++;
				if (log->v2.end - log->v2.start > LOGBUFF_LEN)
					log->v2.start++;
				log->v2.chars++;
			} else {
				lbuf[(log->v1.start + log->v1.size) &
					 LOGBUFF_MASK] = *p;
				if (log->v1.size < LOGBUFF_LEN)
					log->v1.size++;
				else
					log->v1.start++;
				log->v1.chars++;
			}
			if (*p == '\n') {
				line_feed = 1;
				break;
			}
		}
		if (msg_level < console_loglevel) {
			printf("%s", msg);
		}
		if (line_feed)
			msg_level = -1;
	}
	return i;
}

void logbuff_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf2, sizeof(buf2), fmt, args);
	va_end(args);
	logbuff_printk(buf2);
}

 /*
    get next record; idx must point to a valid entry
    NOTE: code from linux kernel printk.c::log_next()
  */
static u32 log_next(const lcb_t * const cb, const u32 idx)
{
	log_hdr_t *hdr = (log_hdr_t *) (cb->log_phys_addr + idx);

	/* length == 0 indicates the end of the buffer; wrap */
	/*
	 * A length == 0 record is the end of buffer marker. Wrap around and
	 * read the message at the start of the buffer as *this* one, and
	 * return the one after that.
	 */
	if (!hdr->len) {
		hdr = (log_hdr_t *) cb->log_phys_addr;
		return hdr->len;
	}
	return idx + hdr->len;
}

#ifdef CONFIG_LOGBUFFER_EARLY
static void early_log_printk_v3(const unsigned level, const char *msg)
{
	char *buffer;
	u16 text_length;
	u32 size, pad_len;
	unsigned long log_version;

	/* Only supports v3 */
	if (get_log_version() != 3)
		return;

	buffer = (char *)CONFIG_EARLY_LOGBUFF_ADDR + gd->early_logbuff_idx;
	text_length = strlen(msg);
	size = sizeof(log_hdr_t) + text_length;
	pad_len = (-size) & (LOG_ALIGN - 1);
	size += pad_len;

	/* Check for available space */
	if ((gd->early_logbuff_idx + size) >= CONFIG_EARLY_LOGBUFF_SZ)
		return;

	log_hdr_t *next =
	    (log_hdr_t *) buffer;

	memset(next, 0, size);

	/* Fill the log entry contents */
	next->ts_nsec = (u64) timer_get_us() * 1000;
	next->text_len = text_length;
	next->len = size;
	next->level = level;
	memcpy(((void *)next) + sizeof(log_hdr_t),
	       msg, text_length);
	next->log_magic = LOGBUFF_MAGIC;

	gd->early_logbuff_idx += size;
}
#endif

static void log_printk_v3_write(const log_hdr_t * hdr, const char *msg)
{
	while (lcb->log_first_seq < lcb->log_next_seq) {
		u32 free;

		if (lcb->log_next_idx > lcb->log_first_idx)
			free = max(lcb->log_buf_len -
				   lcb->log_next_idx, lcb->log_first_idx);
		else
			free = lcb->log_first_idx - lcb->log_next_idx;

		if (free > hdr->len + lcb->log_hdr_size)
			break;

		/* drop old messages until we have enough contiuous space */
		lcb->log_first_idx = log_next(lcb, lcb->log_first_idx);
		lcb->log_first_seq++;
	}

	/* Pointer to next message to write */
	log_hdr_t *next = (log_hdr_t *) (lcb->log_phys_addr + lcb->log_next_idx);

	if (lcb->log_next_idx + hdr->len + lcb->log_hdr_size >= lcb->log_buf_len) {
		/*
		 * This message + an additional empty header does not fit
		 * at the end of the buffer. Add an empty header with len == 0
		 * to signify a wrap around.
		 */
		memset(next, 0, lcb->log_hdr_size);
		lcb->log_next_idx = 0;
		next = (log_hdr_t *) lcb->log_phys_addr;
	}

	/* Initialize the log entry */
	memset(next, 0, hdr->len);

	/* Fill the log entry contents */
	memcpy(next, hdr, lcb->log_hdr_size);
	memcpy(((void *)next) + lcb->log_hdr_size, msg, hdr->text_len);

	/* Increment the message count & update the next index. */
	lcb->log_next_idx += next->len;
	lcb->log_next_seq++;
}

/*
  * Write a log entry with the new kernel log structure
 * NOTE: code from linux kernel printk.c::log_store()
  */
static void log_printk_v3(const unsigned level, const const char *msg)
{
	u32 size, pad_len;
	const u16 text_length = strlen(msg);
	log_hdr_t hdr;

	/* Calculate the total message record length with padding */
	size = sizeof(log_hdr_t) + text_length;
	pad_len = (-size) & (LOG_ALIGN - 1);
	size += pad_len;

	memset(&hdr, 0, lcb->log_hdr_size);

	/* Fill the log entry contents */
	hdr.ts_nsec = (u64) timer_get_us() * 1000;
	hdr.text_len = text_length;
	hdr.len = size;
	hdr.level = level;
	hdr.log_magic = LOGBUFF_MAGIC;

	log_printk_v3_write(&hdr, msg);
}

static void log_show_v3(void)
{
	log_hdr_t *cur;
	u64 cur_seq;
	int i;

	/* Validate the log pointers */
	if (!lcb ||
	    !lcb->log_phys_addr ||
	    lcb->log_first_idx > lcb->log_buf_len ||
	    lcb->log_next_idx > lcb->log_buf_len ||
	    lcb->syslog_idx > lcb->log_buf_len ||
	    lcb->console_idx > lcb->log_buf_len ||
	    lcb->clear_idx > lcb->log_buf_len) {
		printf("Error: log pointers are invalid.  Resetting the log\n");
		printf ("lcb = %p\n", lcb);
		if (lcb) {
			printf ("lcb->log_phys_addr = %lu\n", lcb->log_phys_addr);
			printf ("lcb->log_buf_len = %lu\n", lcb->log_buf_len);
			printf ("lcb->log_first_idx = %lu\n", lcb->log_first_idx );
			printf ("lcb->log_next_idx = %lu\n", lcb->log_next_idx );
			printf ("lcb->syslog_idx = %lu\n", lcb->syslog_idx );
			printf ("lcb->console_idx = %lu\n", lcb->console_idx );
			printf ("lcb->clear_idx = %lu\n", lcb->clear_idx );
		}
		logbuff_reset();
		return;
	}

	/* Determine if this is the initial log entry */
	cur = (log_hdr_t *) (lcb->log_phys_addr + lcb->log_first_idx);

	if (lcb->log_first_idx == lcb->log_next_idx &&
	    cur->len == 0 && cur->log_magic == LOGBUFF_MAGIC)
		return;

	for (cur_seq = lcb->log_first_seq; cur_seq < lcb->log_next_seq; cur_seq++) {
		/* Validate the current record. */
		if ((cur->log_magic != LOGBUFF_MAGIC && cur->log_magic != 0) ||
		    (cur->log_magic == LOGBUFF_MAGIC && cur->len == 0)) {
			printf
			    ("Error: Invalid entry detected in the log.  Resetting the log\n");
			printf("Error: Dumping invalid entry : \n"
			       "%p : 0x%x : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x\n",
			       cur, cur->log_magic, cur->ts_nsec, cur->len,
			       cur->text_len, cur->facility, cur->level);
			logbuff_reset();
			return;
		}
		/* Check for a continuation record */
		if (cur->log_magic == 0 && cur->len == 0) {
			printf
			    ("%p : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x : Continuation Record\n",
			     cur, cur->ts_nsec, cur->len, cur->text_len,
			     cur->facility, cur->level);

			cur = (log_hdr_t *) (lcb->log_phys_addr);
			continue;
		}

		printf ("%p : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x : ",
			cur, cur->ts_nsec, cur->len, cur->text_len, cur->facility, cur->level);
		for (i = 0; i < cur->text_len; i++) {
			char *this = (char *)cur;
			putc(this[lcb->log_hdr_size + i]);
		}

		/* Add a newline. */
		putc('\n');

		/* Advance to the next record. */
		cur = ((void *)cur) + cur->len;
	}
}

static void log_append_v3(int argc, char *const argv[])
{
	static const int buf_size = sizeof(buf2);
	unsigned long i, size, count;

	count = size = 0;

	/* Re-build the passed in string to append */
	for (i = 2; i < argc; i++) {
		if (count + strlen(argv[i]) + 1 <= buf_size) {
			/* Add a space to the end of each arg or a null for the last one. */
			size = sprintf(&buf2[count], "%s%c", argv[i], ((i < argc - 1) ? ' ' : 0));
			if (size > 0)
				count += size;
			else
				count = 0;
		} else
			count = 0;
		if (0 == count)
			break;
	}

	/* Output non empty strings */
	if (count)
		logbuff_printk(buf2);
}

static void log_info_v3(void)
{
	log_hdr_t *first, *next;

	if (!lcb ||
	    !lcb->log_phys_addr ||
	    lcb->log_first_idx > lcb->log_buf_len ||
	    lcb->log_next_idx > lcb->log_buf_len ||
	    lcb->syslog_idx > lcb->log_buf_len ||
	    lcb->console_idx > lcb->log_buf_len ||
	    lcb->clear_idx > lcb->log_buf_len) {
		printf("Error: Invalid address detected in the log control "
		       "block.  Resetting the log\n");
		logbuff_reset();
		return;
	}

	first = (log_hdr_t *) (lcb->log_phys_addr + lcb->log_first_idx);
	next = (log_hdr_t *) (lcb->log_phys_addr + lcb->log_next_idx);

	printf("Log levels: console = %d  :  default = %d\n",
	       console_loglevel, default_message_loglevel);
	printf("Log version (calculated/stored) = %d/%d\n",
	       get_log_version(), lcb->log_version);
	printf("lcb base address (calculated/stored) = %08lx/%p\n",
	       get_lcb_base(), (void *)lcb);
	printf("Log base address (calculated/stored) = %08lx/%p\n",
	       get_log_base(), (void *)lcb->log_phys_addr);
	printf("Log size (calculated/stored) = %ld/%d\n",
	       get_log_buf_len(), lcb->log_buf_len);
	printf("Log overhead size (calculated/stored) = %ld/%d\n",
	       get_lcb_padded_len(), lcb->lcb_padded_len);
	printf("Log control block size (calculated/stored) = %lu/%u\n",
	       sizeof(lcb_t), lcb->lcb_size);
	printf("Log entry header size (calculated/stored) = %lu/%u\n",
	       sizeof(log_hdr_t), lcb->log_hdr_size);
	printf("Log control block magic (calculated/stored) = %08x/%08x\n",
	       lcb->lcb_magic, LOGBUFF_MAGIC);
	printf("Log sequence numbers: first/next/syslog/console/clear = "
	       "%lld/%lld/%lld/%lld/%lld\n",
	       lcb->log_first_seq, lcb->log_next_seq,
	       lcb->syslog_seq, lcb->console_seq, lcb->clear_seq);
	printf("Log indices : first/next/syslog/console/clear = "
	       "%u/%u/%u/%u/%u\n",
	       lcb->log_first_idx, lcb->log_next_idx,
	       lcb->syslog_idx, lcb->console_idx, lcb->clear_idx);
	printf("Log first entry magic/length = %08x/%d\n",
	       first->log_magic, first->len);
	printf("Log next entry magic/length = %08x/%d\n",
	       next->log_magic, next->len);
}
