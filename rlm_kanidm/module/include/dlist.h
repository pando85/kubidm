/*
 * Minimal stub for freeradius/dlist.h
 *
 * This file is a workaround for openSUSE Tumbleweed's freeradius-server-devel
 * package which includes radiusd.h that references dlist.h, but doesn't provide it.
 *
 * The actual dlist.h from FreeRADIUS provides doubly-linked list macros, but
 * this module doesn't use them. We only need to define the fr_dlist_t type
 * which is used in radiusd.h.
 */

#ifndef _FR_DLIST_H
#define _FR_DLIST_H

/**
 * Doubly-linked list entry.
 *
 * This is a minimal definition sufficient for radiusd.h which uses fr_dlist_t
 * as a struct member. The full FreeRADIUS implementation includes additional
 * macros and functions, but they are not needed by this module.
 */
typedef struct fr_dlist_s {
	struct fr_dlist_s *next;
	struct fr_dlist_s *prev;
} fr_dlist_t;

#endif /* _FR_DLIST_H */
