/*
 * Minimal stub for freeradius/dlist.h
 *
 * This file is a workaround for openSUSE Tumbleweed's freeradius-server-devel
 * package which includes radiusd.h that references dlist.h, but doesn't provide it.
 *
 * The actual dlist.h from FreeRADIUS provides doubly-linked list macros, but
 * this module doesn't use them, so a minimal stub suffices.
 */

#ifndef _FR_DLIST_H
#define _FR_DLIST_H

/* Stub file - doubly-linked list macros not used by this module */

#endif /* _FR_DLIST_H */
