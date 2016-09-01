/*
 * (C) Copyright 2002-2007
 * Detlev Zundel, dzu@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef _LOGBUFF_H
#define _LOGBUFF_H

#ifdef CONFIG_LOGBUFFER

#define LOGBUFF_MAGIC	0xc0de4ced	/* Forced by code, eh!	*/
#define LOGBUFF_LEN	(16384)	/* Must be 16k right now */
#define LOGBUFF_MASK	(LOGBUFF_LEN-1)
#define LOGBUFF_CB_PADDED_LENGTH (1024) /* Logbuffer control block with padding */
#define LOGBUFF_RESERVE (LOGBUFF_LEN+LOGBUFF_CB_PADDED_LENGTH)

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
} log_header_t;

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
	u32 lcb_len_with_pad;
	u32 lcb_size;
	u32 log_hdr_size;
	u32 log_phys_addr;
	u32 lcb_magic;
} log_cb_t;

int drv_logbuff_init (void);
void logbuff_init_ptrs (void);
int early_logbuff_init_ptrs(void);
void logbuff_log(char *msg);
void logbuff_reset (void);
unsigned long logbuffer_base (void);
void logbuff_printf(const char *fmt, ...);

#endif /* CONFIG_LOGBUFFER */

#endif /* _LOGBUFF_H */
