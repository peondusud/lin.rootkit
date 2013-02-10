#ifndef _EXTERN_SYMBOLS_H__
#define _EXTERN_SYMBOLS_H__

#include <linux/kernel.h>
#include <linux/module.h>

/* thx to Int27h :-). */
void * get_sysenter_entry( void );

#endif /* _EXTERN_SYMBOLS_H__ */
