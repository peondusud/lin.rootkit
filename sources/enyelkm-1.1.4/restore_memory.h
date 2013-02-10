#ifndef _RESTORE_MEMORY_H__
#define _RESTORE_MEMORY_H__

#include <linux/string.h>
#include "lowlevel_layer.h"

#define NUMBER_OF_JMP 3 

#pragma pack( 1 )

typedef struct block_backup_memory_s
{
    push_ret_t    data;
    unsigned long ptr_to_data_in_memory;

} block_backup_memory_t;

typedef struct backup_memory_s
{
    block_backup_memory_t jmp[NUMBER_OF_JMP];
    int                   next_jmp;

} backup_memory_t;


void init_backup_memory( backup_memory_t * );

int save_memory( unsigned long, backup_memory_t * );
 
void restore_memory( backup_memory_t * );

#endif /* _RESTORE_MEMORY_H__ */
