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

DECLARE_GLOBAL_DATA_PTR;

/* Local prototypes */
static void logbuff_putc(struct stdio_dev *dev, const char c);
static void logbuff_puts(struct stdio_dev *dev, const char *s);
static int logbuff_printk(const char *line);

static void logbuff_append_v3(int argc, char *const argv[]);
static void logbuff_printk_v3(const unsigned level, const char *msg);
static void logbuff_info_v3(void);
static void logbuff_show_v3(void);

static char buf[1024];
static char buf2[1024];

#define LOG_ALIGN 4

/* This combination will not print messages with the default loglevel */
static unsigned console_loglevel = 3;
static unsigned default_message_loglevel = 4;
static unsigned log_version = 1;
#ifdef CONFIG_ALT_LB_ADDR
static volatile logbuff_t *log;
static volatile log_cb_t *log_cb;
#else
static logbuff_t *log;
static log_cb_t *log_cb;
#endif
static char *lbuf;

unsigned long __logbuffer_base(void)
{
	unsigned long log_base;
	char *s;

	/* Default to the top of available RAM */
	log_base =
	    CONFIG_SYS_SDRAM_BASE + get_effective_memsize() - LOGBUFF_LEN;

	/* If set in the environment, overide the default log base */
	if ((s = getenv("logbase")) != NULL)
		log_base = (unsigned long)simple_strtoul(s, NULL, 10);

	return (log_base);
}
unsigned long logbuffer_base(void)
__attribute__((weak, alias("__logbuffer_base")));

unsigned long __logbuffer_size(void)
{
	unsigned long log_size = LOGBUFF_LEN;
	char *s;

	/* If set in the environment, overide the default log size */
	if ((s = getenv("logsize")) != NULL)
		log_size = (unsigned long)simple_strtoul(s, NULL, 10);

	return (log_size);
}

unsigned long logbuffer_size(void)
    __attribute__ ((weak, alias("__logbuffer_size")));

unsigned long __logbuffer_overhead_size(void)
{
	unsigned long log_overhead_size = LOGBUFF_OVERHEAD;
	char *s;

	/* If set in the environment, overide the default log overhead_size */
	if ((s = getenv("logoverheadsize")) != NULL)
		log_overhead_size = (unsigned long)simple_strtoul(s, NULL, 10);

	return (log_overhead_size);
}

unsigned long logbuffer_overhead_size(void)
    __attribute__ ((weak, alias("__logbuffer_overhead_size")));

void logbuff_init_ptrs(void)
{
	unsigned long tag;
	char *s;

#ifdef CONFIG_ALT_LB_ADDR
	log = (logbuff_t *)CONFIG_ALT_LH_ADDR;
	lbuf = (char *)CONFIG_ALT_LB_ADDR;
#else
	log = (logbuff_t *)(logbuffer_base()) - 1;
	lbuf = (char *)log->buf;
#endif

	/* Set up log version */
	if ((s = getenv ("logversion")) != NULL)
		log_version = (int)simple_strtoul(s, NULL, 10);

	if (log_version == 3) {
		/*
		 * Locate the v3 log control block at the top of the log overhead area
		 * see common/image.c for lmb_reserve() call that matches this
		 * NOTE:
		 *   When this function runs, stored environment variables haven't loaded.
		 *   Instead it uses the hardcoded defaults, or ones set in the default config,
		 *   but not ones saved in the environment.
		 */
		log_cb =
		    (log_cb_t *) (logbuffer_base() - logbuffer_overhead_size());

		/* Check to ensure that CB values match compiled constants, if not reset */
		if (log_cb->log_version != log_version ||
		    log_cb->log_length != logbuffer_size() ||
		    log_cb->log_overhead_length != logbuffer_overhead_size() ||
		    log_cb->stored_cb_size != sizeof(log_cb_t) ||
		    log_cb->stored_log_entry_header_size !=
		    sizeof(logbuff_v3_log_entry_header_t)
		    || log_cb->log_physical_address != logbuffer_base()
		    || log_cb->magic != LOGBUFF_MAGIC) {
			logbuff_reset();
		}

		gd->flags |= GD_FLG_LOGINIT;
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

void logbuff_reset(void)
{
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
		log_cb =
		    (log_cb_t *) (logbuffer_base() - logbuffer_overhead_size());

		/* Initialize the control block */
		memset(log_cb, 0, sizeof(log_cb_t));
		log_cb->log_version = log_version;
		log_cb->log_length = logbuffer_size();
		log_cb->log_overhead_length = logbuffer_overhead_size();
		log_cb->stored_cb_size = sizeof(log_cb_t);
		log_cb->stored_log_entry_header_size =
		    sizeof(logbuff_v3_log_entry_header_t);
		log_cb->log_physical_address = logbuffer_base();

		/* Initialize the first entry and mark it "valid" with a magic value */
		logbuff_v3_log_entry_header_t *first =
		    (logbuff_v3_log_entry_header_t *)
		    log_cb->log_physical_address;
		memset(first, 0, sizeof(logbuff_v3_log_entry_header_t));
		first->magic = LOGBUFF_MAGIC;

		/* Last step, write the magic value into the control block to mark it valid */
		log_cb->magic = LOGBUFF_MAGIC;
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

	if (strcmp(argv[1], "append") == 0) {
		/* Log concatenation of all arguments separated by spaces */
		if (log_version == 3) {
			logbuff_append_v3(argc, argv);
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
			if (log_version == 3) {
				logbuff_show_v3();
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
			return 0;
		} else if (strcmp(argv[1], "reset") == 0) {
			logbuff_reset();
			return 0;
		} else if (strcmp(argv[1], "info") == 0) {
			if (log_version == 3) {
				logbuff_info_v3();
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
			logbuff_printk_v3(msg_level, msg);

			if (msg_level < console_loglevel)
				printf("%s\n", msg);

			msg_level = -1;
			break;
		}
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
    get next record; idx must point to valid msg
    NOTE: code from linux kernel printk.c::log_next()
  */
static u32 log_next(const log_cb_t * const cb, const u32 idx)
{
	logbuff_v3_log_entry_header_t *msg = (logbuff_v3_log_entry_header_t *)
	    (cb->log_physical_address + idx);

	/* length == 0 indicates the end of the buffer; wrap */
	/*
	 * A length == 0 record is the end of buffer marker. Wrap around and
	 * read the message at the start of the buffer as *this* one, and
	 * return the one after that.
	 */
	if (!msg->len) {
		msg =
		    (logbuff_v3_log_entry_header_t *) cb->log_physical_address;
		return msg->len;
	}
	return idx + msg->len;
}

/*
  * Write a log entry with the new kernel log structure
 * NOTE: code from linux kernel printk.c::log_store()
  */
static void logbuff_printk_v3(const unsigned level, const const char *msg)
{
	u32 size, pad_len;
	const u16 text_length = strlen(msg);

	/* Calculate the total message record length with padding */
	size = sizeof(logbuff_v3_log_entry_header_t) + text_length;
	pad_len = (-size) & (LOG_ALIGN - 1);
	size += pad_len;

	while (log_cb->log_first_seq < log_cb->log_next_seq) {
		u32 free;

		if (log_cb->log_next_idx > log_cb->log_first_idx)
			free = max(log_cb->log_length -
				   log_cb->log_next_idx, log_cb->log_first_idx);
		else
			free = log_cb->log_first_idx - log_cb->log_next_idx;

		if (free > size + log_cb->stored_log_entry_header_size)
			break;

		/* drop old messages until we have enough contiuous space */
		log_cb->log_first_idx = log_next(log_cb, log_cb->log_first_idx);
		log_cb->log_first_seq++;
	}

	/* Pointer to next message to write */
	logbuff_v3_log_entry_header_t *next = (logbuff_v3_log_entry_header_t *)
	    (log_cb->log_physical_address + log_cb->log_next_idx);

	if (log_cb->log_next_idx +
	    size + log_cb->stored_log_entry_header_size >= log_cb->log_length) {
		/*
		 * This message + an additional empty header does not fit
		 * at the end of the buffer. Add an empty header with len == 0
		 * to signify a wrap around.
		 */
		memset(next, 0, log_cb->stored_log_entry_header_size);
		log_cb->log_next_idx = 0;
		next = (logbuff_v3_log_entry_header_t *)
		    (log_cb->log_physical_address);
	}
	/* Initialize the log entry */
	memset(next, 0, size);

	/* Fill the log entry contents */
	next->ts_nsec = get_timer_masked() * 1000;
	next->text_len = text_length;
	next->len = size;
	next->level = level;
	memcpy(((void *)next) + log_cb->stored_log_entry_header_size,
	       msg, text_length);
	next->magic = LOGBUFF_MAGIC;

	/* Increment the message count & update the next index. */
	log_cb->log_next_idx += next->len;
	log_cb->log_next_seq++;
}

static void logbuff_show_v3(void)
{
	logbuff_v3_log_entry_header_t *cur;
	u64 cur_seq;
	int i;

	/* Validate the log pointers */
	if (!log_cb ||
	    !log_cb->log_physical_address ||
	    log_cb->log_first_idx > log_cb->log_length ||
	    log_cb->log_next_idx > log_cb->log_length ||
	    log_cb->syslog_idx > log_cb->log_length ||
	    log_cb->console_idx > log_cb->log_length ||
	    log_cb->clear_idx > log_cb->log_length) {
		printf("Error: log pointers are invalid.  Resetting the log\n");
		logbuff_reset();
		return;
	}

	/* Determine if this is the initial log entry */
	cur = (logbuff_v3_log_entry_header_t *)
	    (log_cb->log_physical_address + log_cb->log_first_idx);

	if (log_cb->log_first_idx == log_cb->log_next_idx &&
	    cur->len == 0 && cur->magic == LOGBUFF_MAGIC)
		return;

	for (cur_seq = log_cb->log_first_seq;
	     cur_seq < log_cb->log_next_seq; cur_seq++) {
		/* Validate the current record. */
		if ((cur->magic != LOGBUFF_MAGIC && cur->magic != 0) ||
		    (cur->magic == LOGBUFF_MAGIC && cur->len == 0)) {
			printf
			    ("Error: Invalid entry detected in the log.  Resetting the log\n");
			printf("Error: Dumping invalid entry : \n"
			       "%p : 0x%x : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x\n",
			       cur, cur->magic, cur->ts_nsec, cur->len,
			       cur->text_len, cur->facility, cur->level);
			logbuff_reset();
			return;
		}
		/* Check for a continuation record */
		if (cur->magic == 0 && cur->len == 0) {
			printf
			    ("%p : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x : Continuation Record\n",
			     cur, cur->ts_nsec, cur->len, cur->text_len,
			     cur->facility, cur->level);

			cur = (logbuff_v3_log_entry_header_t *)
			    (log_cb->log_physical_address);
			continue;
		}

		printf
		    ("%p : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x : ",
		     cur, cur->ts_nsec, cur->len, cur->text_len, cur->facility,
		     cur->level);
		for (i = 0; i < cur->text_len; i++) {
			char *this = (char *)cur;
			putc(this[log_cb->stored_log_entry_header_size + i]);
		}

		/* Add a newline. */
		putc('\n');

		/* Advance to the next record. */
		cur = ((void *)cur) + cur->len;
	}
}

static void logbuff_append_v3(int argc, char *const argv[])
{
	static const int buf_size = sizeof(buf2);
	unsigned long i, size, count;

	count = size = 0;

	/* Re-build the passed in string to append */
	for (i = 2; i < argc; i++) {
		if (count + strlen(argv[i]) + 1 <= buf_size) {
			/* Add a space to the end of each arg or a null for the last one. */
			size =
			    sprintf(&buf2[count], "%s%c", argv[i],
				    ((i < argc - 1) ? ' ' : 0));
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

static void logbuff_info_v3(void)
{
	logbuff_v3_log_entry_header_t *first, *next;

	if (!log_cb ||
	    !log_cb->log_physical_address ||
	    log_cb->log_first_idx > log_cb->log_length ||
	    log_cb->log_next_idx > log_cb->log_length ||
	    log_cb->syslog_idx > log_cb->log_length ||
	    log_cb->console_idx > log_cb->log_length ||
	    log_cb->clear_idx > log_cb->log_length) {
		printf("Error: log pointers are invalid.  Resetting the log\n");
		logbuff_reset();
		return;
	}

	first =
	    (logbuff_v3_log_entry_header_t *) (log_cb->log_physical_address +
					       log_cb->log_first_idx);
	next =
	    (logbuff_v3_log_entry_header_t *) (log_cb->log_physical_address +
					       log_cb->log_next_idx);

	printf("Log levels: console = %d  :  default = %d\n",
	       console_loglevel, default_message_loglevel);
	printf("Log version (calculated/stored) = %d/%d\n",
	       log_version, log_cb->log_version);
	printf("Log base address (calculated/stored) = %08lx/%p\n",
	       logbuffer_base(), (void *)log_cb->log_physical_address);
	printf("Log size (calculated/stored) = %ld/%d\n",
	       logbuffer_size(), log_cb->log_length);
	printf("Log overhead size (calculated/stored) = %ld/%d\n",
	       logbuffer_overhead_size(), log_cb->log_overhead_length);
	printf("Log control block size (calculated/stored) = %d/%d\n",
	       sizeof(log_cb_t), log_cb->stored_cb_size);
	printf("Log entry header size (calculated/stored) = %d/%d\n",
	       sizeof(logbuff_v3_log_entry_header_t),
	       log_cb->stored_log_entry_header_size);
	printf("Log control block magic (calculated/stored) = %08x/%08x\n",
	       log_cb->magic, LOGBUFF_MAGIC);
	printf("Log sequence numbers: first/next/syslog/console/clear = "
	       "%lld/%lld/%lld/%lld/%lld\n",
	       log_cb->log_first_seq, log_cb->log_next_seq,
	       log_cb->syslog_seq, log_cb->console_seq, log_cb->clear_seq);
	printf("Log indices : first/next/syslog/console/clear = "
	       "%u/%u/%u/%u/%u\n",
	       log_cb->log_first_idx, log_cb->log_next_idx,
	       log_cb->syslog_idx, log_cb->console_idx, log_cb->clear_idx);
	printf("Log first entry magic/length = %08x/%d\n",
	       first->magic, first->len);
	printf("Log next entry magic/length = %08x/%d\n",
	       next->magic, next->len);
}
