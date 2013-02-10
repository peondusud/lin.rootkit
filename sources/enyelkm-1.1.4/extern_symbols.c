#include "extern_symbols.h"

/* thx to Int27h :-). */
void * get_sysenter_entry( void ) 
{
    void          * psysenter_entry = NULL ;
    unsigned long   v2                     ;
    
    if ( boot_cpu_has( X86_FEATURE_SEP ) )
        rdmsr( MSR_IA32_SYSENTER_EIP, psysenter_entry, v2 );
    else
        return NULL;

    return psysenter_entry;
}
