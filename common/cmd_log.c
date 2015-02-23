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
static void logbuff_putc(const char c);
static void logbuff_puts(const char *s);
static int logbuff_printk(const char *line);

static void logbuff_append_v3 ( int argc, char * const argv[] );
static void logbuff_printk_v3(const unsigned level, const char *msg);
static void logbuff_info_v3 ( void );
static void logbuff_show_v3( void );

static char buf[1024];
static char buf2[1024];

#define LOG_ALIGN 4

/* This combination will not print messages with the default loglevel */
static unsigned console_loglevel = 3;
static unsigned default_message_loglevel = 4;
static unsigned log_version = 1;
#ifdef CONFIG_ALT_LB_ADDR
static volatile logbuff_t *log;
static volatile logbuff_v3_cb_t *log_cb;
#else
static logbuff_t *log;
static logbuff_v3_cb_t *log_cb;
#endif
static char *lbuf;

unsigned long __logbuffer_base(void)
{
	unsigned long log_base;
	char *s;

	// Default to the top of available RAM
	log_base = CONFIG_SYS_SDRAM_BASE + get_effective_memsize() - LOGBUFF_LEN;

	/* If set in the environment, overide the default log base */
	if ((s = getenv ("logbase")) != NULL)
		log_base = (int)simple_strtoul(s, NULL, 10);

	return ( log_base );
}
unsigned long logbuffer_base(void)
__attribute__((weak, alias("__logbuffer_base")));

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

	if (log_version == 3)
	{
		// Locate the v3 log control block at the top of the log overhead area
		// see common/image.c for lmb_reserve() call that matches this
		log_cb = (logbuff_v3_cb_t *) (logbuffer_base() - LOGBUFF_OVERHEAD);
		
		// Check to ensure that CB values match compiled constants, if not reset
		if ( log_cb->log_version != log_version ||
				log_cb->log_length != LOGBUFF_LEN ||
				log_cb->log_overhead_length != LOGBUFF_OVERHEAD ||
				log_cb->stored_cb_size != sizeof(logbuff_v3_cb_t) ||
				log_cb->stored_log_entry_header_size != sizeof(logbuff_v3_log_entry_header_t) ||
				log_cb->min_log_addr != (logbuff_v3_log_entry_header_t*) (logbuffer_base()) ||
				log_cb->max_log_addr != ( log_cb->min_log_addr + log_cb->log_length - 1 ) ||
				log_cb->magic != LOGBUFF_MAGIC )
		{
			logbuff_reset ();
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
		logbuff_reset ();
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
	if (log_version == 3)
	{
		printf("Resetting the log with v3 settings\n");

		// Initialize the control block
		log_cb->log_version = log_version;
		log_cb->log_length = LOGBUFF_LEN;
		log_cb->log_overhead_length = LOGBUFF_OVERHEAD;
		log_cb->stored_cb_size = sizeof(logbuff_v3_cb_t);
		log_cb->stored_log_entry_header_size = sizeof(logbuff_v3_log_entry_header_t);
		log_cb->min_log_addr = (void*) (logbuffer_base());
		log_cb->max_log_addr = ( log_cb->min_log_addr + LOGBUFF_LEN - 1 );
		log_cb->head = log_cb->min_log_addr;
		log_cb->tail = log_cb->head;

		// Initialize the first entry and mark it "valid" with a magic value
		memset ( log_cb->head, 0, sizeof(logbuff_v3_log_entry_header_t));
		log_cb->head->magic = LOGBUFF_MAGIC;

		// Last step, write the magic value into the control block to mark it valid
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

static void logbuff_putc(const char c)
{
	char buf[2];
	buf[0] = c;
	buf[1] = '\0';
	logbuff_printk(buf);
}

static void logbuff_puts(const char *s)
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
			logbuff_putc((i < argc - 1) ? ' ' : '\n');
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

/*
 * Write a log entry with the new kernel log structure
 */
static void logbuff_printk_v3(const unsigned level, const const char *msg)
{
	const u16 text_length = strlen ( msg );
	u32 freespace = 0;
	u16 msg_length = 0;
	u8 firstpass;

	// Calculate the total message record length with padding
	msg_length =
		( log_cb->stored_log_entry_header_size + text_length + LOG_ALIGN - 1 ) & ~(LOG_ALIGN - 1);

	// Determine if this is the initial log entry
	firstpass = ( log_cb->head == log_cb->tail &&
			log_cb->head->len == 0 &&
			log_cb->head->magic == LOGBUFF_MAGIC );

	// Ignore this processing for the first pass
	if ( ! firstpass )
	{
		// Check the relative position of the head and tail
		if ( log_cb->tail > log_cb->head )
		{
			// How much space between the current tail and the end of the buffer?
			freespace = log_cb->max_log_addr - (void*) log_cb->tail - 1;

			if ( freespace > LOGBUFF_LEN )
			{
				printf( "ERROR: " __FILE__ "[%d] freespace is out of range = %d\n", __LINE__, freespace );
				return;
			}

			// Check if the tail has to wrap because the new record is too long
			// Note: we keep room for at least one entry header as a continuation marker
			if ( freespace < msg_length + log_cb->stored_log_entry_header_size )
			{
				// Write a continuation header
				memset ( log_cb->tail, 0, log_cb->stored_log_entry_header_size );

				// Move tail to the top and reset freespace
				// This means that the head (at the top) will have to move
				log_cb->tail = log_cb->min_log_addr;
				freespace = 0;
			}
		}
		else if ( log_cb->tail < log_cb->head )
		{
			// Check if there is already enough space between tail and head
			freespace = (void*)log_cb->head - (void*)log_cb->tail - 1;

			if ( freespace > LOGBUFF_LEN )
			{
				printf( "ERROR: " __FILE__ "[%d] freespace is out of range = %d\n", __LINE__, freespace );
				return;
			}
		}

		// If there isn't enough space for the entry at this point, then the
		// head has to move.  Walk entries until there is room and wrap, as needed.
		while ( freespace < msg_length )
		{
			// Is the head pointing to a continuation record?
			if ( log_cb->head->magic != LOGBUFF_MAGIC && log_cb->head->len == 0 )
			{
				// The head has to wrap, move it to the top.
				log_cb->head = log_cb->min_log_addr;

				// Consider all buffer space to the end free.
				freespace = log_cb->max_log_addr - (void*) log_cb->tail;

				// Is there enough space now?
				if ( freespace < msg_length + log_cb->stored_log_entry_header_size )
				{
					// There isn't enough space even moving the head pointer,
					// so write a continuation record and wrap to the top.
					memset ( log_cb->tail, 0, log_cb->stored_log_entry_header_size );

					// Move tail to the top and reset freespace
					// This means that the head (at the top) will have to move
					log_cb->tail = log_cb->min_log_addr;
					freespace = 0;
				}
			}

			// Add the current head's space to the freespace and increment the head
			freespace += log_cb->head->len;
			log_cb->head = (void*)log_cb->head + log_cb->head->len;
		}
	}

	// Ensure the new message will *not* overrun our buffer
	if ( ((void*)log_cb->tail) + msg_length > log_cb->max_log_addr )
	{
		printf ("ERROR: Attempting to write past the end of the log buffer\n");
	}
	else
	{
		// Initialize the log entry header
		memset ( log_cb->tail, 0, log_cb->stored_log_entry_header_size );

		// Fill the log entry contents
		log_cb->tail->magic = LOGBUFF_MAGIC;
		log_cb->tail->ts_nsec = 0;
		log_cb->tail->text_len = text_length;
		log_cb->tail->len = msg_length;
		log_cb->tail->level = level;
		memcpy ( ((void*)log_cb->tail) + log_cb->stored_log_entry_header_size, msg, log_cb->tail->text_len );

		// Move the tail to the next location.
		log_cb->tail = ((void*)log_cb->tail) + log_cb->tail->len;
	}
}

static void logbuff_show_v3( void )
{
	logbuff_v3_log_entry_header_t * cur;
	int i;

	// Determine if this is the initial log entry
	if ( log_cb->head == log_cb->tail && log_cb->head->len == 0 && log_cb->head->magic == LOGBUFF_MAGIC )
		return;

	cur = log_cb->head;
	do
	{
		// Check for a continuation record
		if ( cur->magic != LOGBUFF_MAGIC && cur->len == 0 )
		{
			printf ("%p : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x : Continuation Record\n",
					cur, cur->ts_nsec, cur->len, cur->text_len, cur->facility, cur->level);

			cur = log_cb->min_log_addr;
			continue;
		}

		printf ("%p : 0x%16.16llx : 0x%4.4x : 0x%4.4x : 0x%2.2x : 0x%1.1x : ",
				cur, cur->ts_nsec, cur->len, cur->text_len, cur->facility, cur->level);
		for ( i = 0; i < cur->text_len; i++ )
		{
			char * this = (char *) cur;
			putc(this[log_cb->stored_log_entry_header_size  + i]);
		}

		// Add a newline.
		putc ('\n');

		// Advance to the next record.
		cur = ( (void*) cur ) + cur->len;
	}
	while ( cur != log_cb->tail );
}

static void logbuff_append_v3 ( int argc, char * const argv[] )
{
	static const int buf_size = sizeof ( buf2 );
	unsigned long i, size, count;

	count = size = 0;

	// Re-build the passed in string to append
	for ( i = 2; i < argc; i++ )
	{
		if ( count + strlen (argv[i]) + 1 <= buf_size )
		{
			// Add a space to the end of each arg or a null for the last one.
			size = sprintf (&buf2[count], "%s%c", argv[i], ((i < argc - 1) ? ' ' : 0));
			if ( size > 0 )
				count += size;
			else
				count = 0;
		}
		else
			count = 0;
		if ( 0 == count )
			break;
	}

	// Output non empty strings
	if ( count )
		logbuff_printk(buf2);
}

void logbuff_printf ( const char *fmt, ... )
{
	va_list	args;

	va_start(args, fmt);
	vsnprintf(buf2, sizeof(buf2), fmt, args);
	va_end(args);
	logbuff_printk(buf2);
}

static void logbuff_info_v3 ( void )
{
	printf("console_loglevel = %d\n", console_loglevel );
	printf("default_message_loglevel = %d\n", default_message_loglevel );
	printf("Calculated log_base = %08lx\n", CONFIG_SYS_SDRAM_BASE + get_effective_memsize() - LOGBUFF_LEN);
	printf("logbuffer_base() = %08lx\n", logbuffer_base() );
	printf("log_cb = %p\n", log_cb);
	printf("log_cb->log_version = %d\n", log_cb->log_version );
	printf("log_cb->log_length = %d\n", log_cb->log_length );
	printf("LOGBUFF_LEN = %d\n", LOGBUFF_LEN);
	printf("log_cb->log_overhead_length = %d\n", log_cb->log_overhead_length );
	printf("LOGBUFF_OVERHEAD = %d\n", LOGBUFF_OVERHEAD);
	printf("log_cb->stored_cb_size = %d\n", log_cb->stored_cb_size );
	printf("sizeof(logbuff_v3_cb_t) = %d\n", sizeof(logbuff_v3_cb_t) );
	printf("log_cb->stored_log_entry_header_size = %d\n", log_cb->stored_log_entry_header_size );
	printf("sizeof(logbuff_v3_log_entry_header_t) = %d\n", sizeof(logbuff_v3_log_entry_header_t) );
	printf("log_cb->min_log_addr = %08lx\n", log_cb->min_log_addr );
	printf("log_cb->max_log_addr  = %08lx\n", log_cb->max_log_addr );
	printf("LOGBUFF_MAGIC = %08lx\n", LOGBUFF_MAGIC);
	printf("log_cb->magic = %08lx\n", log_cb->magic);
	printf("log_cb->head->magic = %08lx\n", log_cb->head->magic);
	printf("log_cb->head = %p\n", log_cb->head);
	printf("log_cb->tail = %p\n", log_cb->tail);
}
