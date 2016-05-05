#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/string.h>
#include <linux/rtc.h>
// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

#define MAX_EVENTS 10
#define BUF_SIZE 128

static char msg[128];
static int len = 0;
static int len_check = 1;

/* monitoring flags */
int exec_monitoring = 0;
int exec_blocking = 0;
int script_monitoring = 0;
int script_blocking = 0;

/*MAX_EVENTS stands for the maximum number of elements Queue can hold.
  num_of_events stands for the current size of the Queue.
  events is the array of elements. 
 */
int num_of_events = 0;
char events[MAX_EVENTS][BUF_SIZE];

unsigned long **find_sys_call_table(void);
void **syscall_table;

long(* original_execve_call)(const char *filename, const char *const argv[], const char *const envp[]);

struct rtc_time tm;
struct timeval time;
unsigned long local_time;

void get_time(void)
{
	do_gettimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);
}

void dequeue(void)
{
    int i;
    char empty_string[128] = {'\0'};
    if(num_of_events == 0)
    {
	    return;
    }
    else
    {
    	for(i = 1 ; i < MAX_EVENTS ; ++i)
    	{
    		strcpy(events[i-1], events[i]);
    	}
	    num_of_events--;
    	strcpy(events[num_of_events], empty_string);
    }
}

void enqueue(char *event)
{
    if(num_of_events == MAX_EVENTS)
    {
		dequeue();
    }
    strcpy(events[num_of_events], event);
    num_of_events++;
}

int my_sys_execve(const char *filename, const char *const argv[], const char *const envp[])
{
	printk(KERN_INFO "filename is %s\n", filename);
	return original_execve_call(filename, argv, envp);
}

int fops_open(struct inode * sp_inode, struct file *sp_file)
{
	// printk(KERN_INFO "proc called open\n");
	return 0;
}

int fops_release(struct inode *sp_indoe, struct file *sp_file)
{
	// printk(KERN_INFO "proc called release\n");
	return 0;
}

void print_events(void)
{
	int i = 0;
	for(; i < num_of_events ; ++i)
	{
		printk(KERN_INFO "%s", events[i]);
	}
}

void print_conf(void)
{
	if(exec_monitoring)
		printk(KERN_INFO "Executables Monitoring - Enabled\n");
	else
		printk(KERN_INFO "Executables Monitoring - Disabled\n");
	if(script_monitoring)
		printk(KERN_INFO "Script Monitoring - Enabled\n");
	else
		printk(KERN_INFO "Script Monitoring - Disabled\n");
	if(exec_blocking)
		printk(KERN_INFO "Executables Blocking - Enabled\n");
	else
		printk(KERN_INFO "Executables Blocking - Disabled\n");
	if(script_blocking)
		printk(KERN_INFO "Script Blocking - Enabled\n");
	else
		printk(KERN_INFO "Script Blocking - Disabled\n");
}

void print_hashes_execs(void)
{

}

void print_hashes_scripts(void)
{

}

ssize_t fops_read(struct file *sp_file,char __user *buf, size_t size, loff_t *offset)
{
	if (len_check)
	 len_check = 0;
	else 
	{
	 	len_check = 1;
	 	return 0;
	}

	copy_to_user(buf,msg,len);
	printk(KERN_INFO "KBlocker - Last Events:\n");
	print_events();
	printk(KERN_INFO "KBlocker Current Configuration:\n");
	print_conf();
	printk(KERN_INFO "SHA256 hashes to block (Executables)\n");
	print_hashes_execs();
	printk(KERN_INFO "SHA256 hashes to block (Python Scripts)\n");
	print_hashes_scripts();
	return len;
}

/* write controling: parsing user preferences and LKM definition*/
ssize_t fops_write(struct file *sp_file,const char __user *buf, size_t size, loff_t *offset)
{
	printk(KERN_INFO "proc called write %d\n",(int)size);
	if(size > 14)
	{
	    printk(KERN_DEBUG "Error: cannot parse string. Too many characters.\n");
	    return -1;
	}
	len = size;
	copy_from_user(msg,buf,len);
	switch(*msg)
	{	
	    case 'E':
			if(*(msg + 4) == 'M')
			{
				if(*(msg + 8) == '1')
					exec_monitoring = 1;
				else if(*(msg + 8) == '0')
					exec_monitoring = 0;
				else 
					printk(KERN_DEBUG "Error: cannot parse string.\n");
			}
			else if(*(msg + 4) == 'B')
			{
			    if(*(msg + 9) == '1')
					exec_blocking = 1;
				else if(*(msg + 9) == '0')
					exec_blocking = 0;
				else 
					printk(KERN_DEBUG "Error: cannot parse string.\n");
			}
			else
			{
			    printk(KERN_DEBUG "Error: cannot parse string.\n");
			}
			break;
	    case 'S':
			if(*(msg + 6) == 'M')
			{
				if(*(msg + 10) == '1')
					script_monitoring = 1;
				else if(*(msg + 10) == '0')
					script_monitoring = 0;
				else 
					printk(KERN_DEBUG "Error: cannot parse string.\n");
			}
			else if(*(msg + 6) == 'B')
			{
			    if(*(msg + 12) == '1')
					exec_blocking = 1;
				else if(*(msg + 12) == '0')
					exec_blocking = 0;
				else 
					printk(KERN_DEBUG "Error: cannot parse string.\n");
			}
			else
			{
			    printk(KERN_DEBUG "Error: cannot parse string.\n");
			}
			break;
	    case 'A':
	    	printk(KERN_INFO "'A' case in writing\n");
	    	break;
	    case 'D':
	    	printk(KERN_INFO "'D' case in writing\n");
			break;
	    default:
		printk(KERN_DEBUG "Error: cannot parse string.\n");
	}
    return len;
}

struct file_operations fops = 
{
.open = fops_open,
.read = fops_read,
.write = fops_write,
.release = fops_release
};

unsigned long **find_sys_call_table(void)
{
    unsigned long ptr;
    unsigned long *p;
    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
        p = (unsigned long *) ptr;
        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    return NULL;
}

static int __init init_kblocker (void)
{
  unsigned long cr0;	
  printk(KERN_INFO "init KBlockerfs\n");
  
  syscall_table = (void **) find_sys_call_table();

	if (! proc_create("KBlocker",0666,NULL,&fops)) 
	{
		printk(KERN_INFO "ERROR! proc_create\n");
		remove_proc_entry("KBlocker",NULL);
		return -1;
	}
	
    if (! syscall_table) 
    {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    // original_execve_call = syscall_table[__NR_execve];
    // syscall_table[__NR_execve] = my_sys_execve;

    write_cr0(cr0);
    return 0;	
}

static void __exit exit_kblocker(void)
{
    unsigned long cr0;
    remove_proc_entry("KBlocker",NULL);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    // syscall_table[__NR_execve] = original_execve_call;

    printk(KERN_DEBUG "Everything is back to normal\n");
    write_cr0(cr0);
    printk(KERN_INFO "exit KBlockerfs\n");
}

module_init(init_kblocker);
module_exit(exit_kblocker);
MODULE_AUTHOR("Oshrat Bar and Orian Zinger");
MODULE_LICENSE("GPL v3");
MODULE_DESCRIPTION("Ass2");