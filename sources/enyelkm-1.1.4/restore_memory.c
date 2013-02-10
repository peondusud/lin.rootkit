#include "restore_memory.h"

void init_backup_memory( backup_memory_t * backup_memory )
{
    backup_memory->next_jmp = 0;
}

int save_memory( unsigned long ptr_to_memory, backup_memory_t * backup_memory )
{
    int actual_jmp = backup_memory->next_jmp;

    if ( actual_jmp >= NUMBER_OF_JMP )
        return -1;

    memcpy( (void *) & backup_memory->jmp[actual_jmp].data, (void *) ptr_to_memory, sizeof( push_ret_t ) );

    backup_memory->jmp[actual_jmp].ptr_to_data_in_memory = ptr_to_memory;

    backup_memory->next_jmp++;

    return 0;
}

/* BUCLE DE MENOS A MAS OBLIGATORIAMENTE, POR CUESTION DE LA ESTRUCTURA DE entry.S en 386 */
void restore_memory( backup_memory_t * backup_memory )
{
    int i;
    int number_of_jmp;

    number_of_jmp = backup_memory->next_jmp;

    for ( i = number_of_jmp - 1; i >= 0; i-- )
        memcpy(  (void *) backup_memory->jmp[i].ptr_to_data_in_memory, (void *)  & backup_memory->jmp[i].data, sizeof( push_ret_t ) );
}
