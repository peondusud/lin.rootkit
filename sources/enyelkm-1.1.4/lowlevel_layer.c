#include "lowlevel_layer.h"


void create_push_ret( push_ret_t * push_ret, unsigned long address )
{
    push_ret->opcode_push     = PUSH_OPCODE ;
    push_ret->address_to_push = address     ;
    push_ret->opcode_ret      = RET_OPCODE  ;
}

void write_push_ret( void * address, push_ret_t * push_ret )
{
    memcpy( address, push_ret, sizeof( push_ret_t ) );    
}

void write_cli( void * address )
{
    * ( ( char * ) address ) = CLI_OPCODE;
}

void create_call( call_t * call, unsigned long address )
{
    int i = 0;

    call->opcode_call[i++] = CALL_OPCODE_1;
    call->opcode_call[i++] = CALL_OPCODE_2;
    call->opcode_call[i]   = CALL_OPCODE_3;
   
    call->address_to_call = address;
}

void write_call( void * address, call_t * call )
{
    memcpy( address, call, sizeof( call_t ) );
}

void create_jnb( jnb_t * jnb, unsigned long address )
{
    int i = 0;

    jnb->opcode_jnb[i++] = JNB_OPCODE_1;
    jnb->opcode_jnb[i]   = JNB_OPCODE_2;

    jnb->address_to_jump = address;
}

void write_jnb( void * address, jnb_t * jnb )
{
    memcpy( address, jnb, sizeof( jnb_t ) );
}

int is_call_opcode( unsigned char * opcode )
{
   if 
   ( 
        ( opcode[0] == CALL_OPCODE_1 ) 
        && 
        ( opcode[1] == CALL_OPCODE_2 ) 
        && 
        ( opcode[2] == CALL_OPCODE_3 ) 
    )
       return 1;

   return 0;
}

int is_jnb_opcode( unsigned char * opcode )
{
    if 
    ( 
        ( opcode[0] == JNB_OPCODE_1 ) 
        && 
        ( opcode[1] == JNB_OPCODE_2 ) 
    )
        return 1;

    return 0;
}
