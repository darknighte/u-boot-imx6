/*
 * (C) Copyright 2002-2007
 * Detlev Zundel, dzu@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef _LOGBUFF_H
#define _LOGBUFF_H

#ifdef CONFIG_LOGBUFFER

int drv_logbuff_init (void);
void logbuff_init_ptrs (void);
int early_logbuff_init_ptrs(void);
void logbuff_log(char *msg);
void logbuff_reset (void);
unsigned long get_lcb_base (void);
unsigned long get_lcb_padded_len (void);
unsigned long get_log_base (void);
unsigned long get_log_buf_len (void);
void logbuff_printf(const char *fmt, ...);

#endif /* CONFIG_LOGBUFFER */

#endif /* _LOGBUFF_H */
