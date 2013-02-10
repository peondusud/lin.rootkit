#ifndef _LOWLEVEL_H__
#define _LOWLEVEL_H__

#include <linux/string.h>

#define PUSH_OPCODE 0x68
#define RET_OPCODE  0xC3
#define CLI_OPCODE  0xFA

#define JNB_OPCODE_1 0x0F 
#define JNB_OPCODE_2 0x83

#define CALL_OPCODE_1 0xFF 
#define CALL_OPCODE_2 0x14 
#define CALL_OPCODE_3 0x85

#define DISTANCE_FROM_DIRE_CALL_TO_SYSCALL_TABLE  3
#define DISTANCE_FROM_SYSCALL_TABLE_TO_AFTER_CALL 4

#define SIZE_OPCODE_CMP 0x03
#define DISTANCE_FROM_CMP_NR_SYSCALL_TO_JNB                               \
    (                                                                     \
        sizeof( JNB_OPCODE_1 ) + sizeof( JNB_OPCODE_2 ) + SIZE_OPCODE_CMP \
    )

#pragma pack( 1 )

typedef struct push_ret_s
{
    char          opcode_push;
    unsigned long address_to_push;
    char          opcode_ret;

} push_ret_t;


typedef struct call_s
{
    char          opcode_call[3];
    unsigned long address_to_call;

} call_t;

typedef struct jnb_s
{
    char          opcode_jnb[2];
    unsigned long address_to_jump;

} jnb_t;

void create_push_ret( push_ret_t *, unsigned long );
void write_push_ret( void *, push_ret_t * );

void write_cli( void * );

void create_call( call_t *, unsigned long );
void write_call( void *, call_t * );

void create_jnb( jnb_t *, unsigned long );
void write_jnb( void *, jnb_t * );

int is_call_opcode( unsigned char * );
int is_jnb_opcode( unsigned char * );

#endif /* _LOWLEVEL_H__ */
