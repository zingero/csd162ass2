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

// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

#define MAX_EVENTS 10
#define BUF_SIZE 128

static char msg[128];
static int len = 0;
static int len_check = 1;


/* monitoring flags */
int file_monitoring = 1;
int net_monitoring = 0;
int mount_monitoring = 0;

/*MAX_EVENTS stands for the maximum number of elements Queue can hold.
  num_of_events stands for the current size of the Queue.
  events is the array of elements. 
 */
int num_of_events = 0;
char events[MAX_EVENTS][BUF_SIZE];

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

/*
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
		printk(KERN_INFO "%s\n", events[i]);
	}
}


void print_conf(void)
{
	if(file_monitoring)
		printk(KERN_INFO "File Monitoring - Enabled\n");
	else
		printk(KERN_INFO "File Monitoring - Disabled\n");
	if(net_monitoring)
		printk(KERN_INFO "Net Monitoring - Enabled\n");
	else
		printk(KERN_INFO "Net Monitoring - Disabled\n");
	if(mount_monitoring)
		printk(KERN_INFO "Mount Monitoring - Enabled\n");
	else
		printk(KERN_INFO "Mount Monitoring - Disabled\n");
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
	printk(KERN_INFO "KMonitor - Last Events:\n");
	print_events();
	printk(KERN_INFO "KMonitor Current Configuration:\n");
	print_conf();
	return len;
}
*/
/* write controling: parsing user preferences and LKM definition*/
/*ssize_t fops_write(struct file *sp_file,const char __user *buf, size_t size, loff_t *offset)
{
	printk(KERN_INFO "proc called write %d\n",(int)size);
	if(size > 11)
	{
	    printk(KERN_DEBUG "Error: cannot parse string. Too many characters.\n");
	    return -1;
	}
	len = size;
	copy_from_user(msg,buf,len);
	switch(*msg)
	{	
	    case 'F':
		if(*(msg + 8) == '1')
		{
		  file_monitoring = 1;
		}
		else if(*(msg + 8) == '0')
		{
		    file_monitoring = 0;
		}
		else
		{
		    printk(KERN_DEBUG "Error: cannot parse string.\n");
		}
		break;
	    case 'N':
		if(*(msg + 7) == '1')
		{
		    net_monitoring = 1; 
		}
		else if(*(msg + 7) == '0')
		{
		    net_monitoring = 0;
		}
		else
		{
		    printk(KERN_DEBUG "Error: cannot parse string.\n");
		}
		break;
	    case 'M':
		if(*(msg + 9) == '1')
		{
		    mount_monitoring = 1; 
		}
		else if(*(msg + 9) == '0')
		{
		    mount_monitoring = 0;
		}
		else
		{
		    printk(KERN_DEBUG "Error: cannot parse string.\n");
		}
		break;
	    default:
		printk(KERN_DEBUG "Error: cannot parse string.\n");
	}
    return len;
}
*/
struct file_operations fops = 
{
.open = fops_open,
.read = fops_read,
.write = fops_write,
.release = fops_release
};

unsigned long **find_sys_call_table()
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

static int __init init_simpleproc (void)
{
  unsigned long cr0;	
  printk(KERN_INFO "init KMonitorfs\n");
  
  syscall_table = (void **) find_sys_call_table();

	if (! proc_create("KMonitor",0666,NULL,&fops)) 
	{
		printk(KERN_INFO "ERROR! proc_create\n");
		remove_proc_entry("KMonitor",NULL);
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

    original_open_call = syscall_table[__NR_open];
    original_read_call = syscall_table[__NR_read];
    original_write_call = syscall_table[__NR_write];
    original_listen_call = syscall_table[__NR_listen];
    original_accept_call = syscall_table[__NR_accept];	
    original_mount_call = syscall_table[__NR_mount];
    syscall_table[__NR_open] = my_sys_open;
    syscall_table[__NR_read] = my_sys_read;
    syscall_table[__NR_write] = my_sys_write;
    syscall_table[__NR_listen] = my_sys_listen;
    syscall_table[__NR_accept] = my_sys_accept;
    syscall_table[__NR_mount] = my_sys_mount;

    write_cr0(cr0);
    return 0;	
}

static void __exit exit_simpleproc(void)
{
    unsigned long cr0;
    remove_proc_entry("KMonitor",NULL);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    syscall_table[__NR_open] = original_open_call;
    syscall_table[__NR_read] = original_read_call;
    syscall_table[__NR_write] = original_write_call;
    syscall_table[__NR_listen] = original_listen_call;
    syscall_table[__NR_accept] = original_accept_call;
    syscall_table[__NR_mount] = original_mount_call;

    printk(KERN_DEBUG "Everything is back to normal\n");
    write_cr0(cr0);
    printk(KERN_INFO "exit KMonitorfs\n");
}

module_init(init_simpleproc);
module_exit(exit_simpleproc);
MODULE_AUTHOR("Oshrat Bar and Orian Zinger");
MODULE_LICENSE("GPL v3");
MODULE_DESCRIPTION("Ass2");