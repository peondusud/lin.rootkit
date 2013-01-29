#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x68d372d2, "module_layout" },
	{ 0xab84d9aa, "dev_add_pack" },
	{ 0xb9533aa5, "__dev_remove_pack" },
	{ 0x268cc6a2, "sys_close" },
	{ 0x8235805b, "memmove" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x6b76b4, "find_module" },
	{ 0xc5734835, "current_task" },
	{ 0x50eedeb8, "printk" },
	{ 0x2e5dc57e, "kfree_skb" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "7D3B96C97F0A1610CB79C4E");
