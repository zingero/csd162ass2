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
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/rtc.h>
#include <net/sock.h> 
#include <linux/netlink.h>
#include <linux/skbuff.h> 
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/list.h>

#define NETLINK_USER 31
// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

#define MAX_EVENTS 10
#define BUF_SIZE 128

int ans = 0;

static char msg[128];
static int len = 0;
static int len_check = 1;

struct sock *nl_sk = NULL;

// monitoring flags. we init with 1 because we want to monitor and block everything that the user runs at first
int exec_monitoring = 1;
int exec_blocking = 1;
int script_monitoring = 1;
int script_blocking = 1;

int first_time = 1;
int keep_working = 1;
int blocked_program = 0;

/*MAX_EVENTS stands for the maximum number of elements Queue can hold.
  num_of_events stands for the current size of the Queue.
  events is the array of elements. 
 */
int num_of_events = 0;
char events[MAX_EVENTS][BUF_SIZE];

/* -------------------------------------- linked list BEGINS ---------------------------------------------------- */
// typedef struct Link
// {
// 	char* value;
// 	struct Link* next;
// } Link;

// typedef struct List
// {
// 	Link* head;
// 	int counter;
// } List; 
// Link* findPrevious(List* list, Link* curr);
// int isExists(char* str);
// Link* search(char* str);
// void addLink(char* str);
// void addToTail(Link *new);
// void init_sha_list(void);
// void free_list(List *log);
// void free_link(Link *link);
// void deleteLink(Link *link);

//List *exec_hashes;
//List *scripts_hashes;
// List *sha_list;

typedef struct Link
{
    char *value;
    struct list_head list; /* kernel's list structure */
} Link;

 struct Link sha_list_head;


void print_hashes(void);
/* -------------------------------------- linked list ENDS ---------------------------------------------------- */

unsigned long **find_sys_call_table(void);
void **syscall_table;
long(* original_execve_call)(const char *filename, const char *const argv[], const char *const envp[]);

struct rtc_time tm;
struct timeval time;
unsigned long local_time;

struct nlmsghdr *nlh;
int portid;
struct sk_buff *skb_out;
struct semaphore *sem;

int isELF = 0;
char formatted_sha[65];
char *sha = NULL;

void netlink_output(char * filename)
{
    if(first_time || !strcmp(filename, "./netlink_user")) // we want to get the portid of the user program, so in the first time we doesn't want to send anything.
    {
    	first_time = 0;
    	return;
    }
    skb_out = nlmsg_new(strlen(filename), 0);
    if (!skb_out) 
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, strlen(filename), 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), filename, strlen(filename));
    printk(KERN_INFO "SENDING TO USER: filename = %s\n", filename);
    if (nlmsg_unicast(nl_sk, skb_out, portid) < 0)
        printk(KERN_INFO "Error while sending to user\n");
}

// Link* search(char* str)
// {
//   	Link *temp;
//   	Link *ans = NULL;
//   	int i = 0;
//   	char test[70];
//   	if(sha_list == NULL || str == NULL)
// 	{
// 		printk(KERN_INFO "search: sha_list is null or the str is null\n");
// 		return NULL;
// 	}
// 	for(; i < 70 ; ++i)
// 		test[i] = '\0';
// 	i = 0;
// 	temp = sha_list->head;
// 	if(temp != 0 && (temp->value) != 0)
// 	{
// 		if(strlen(temp->value) < 70)
// 			strcpy(test, temp->value);
// 		else
// 			printk(KERN_INFO "search: %d is greater then 70\n", (int)strlen(temp->value));
// 		(temp->value)[64] = '\0';
// 		formatted_sha[64] = '\0';
// 		test[64] = '\0';
// 		printk(KERN_INFO "search: the head is not null. temp->value = %s. str = %s. lengths: %d\t%d\n", temp->value, str, (int)strlen(temp->value), (int)strlen(str));
// 		while(temp != 0 && strcmp(test, str) != 0 && temp->next != 0)
// 		{
// 			++i;
// 			temp = temp->next;
// 			printk(KERN_INFO "Searching: %d. temp->value = %s. str = %s\n", i, temp->value, str);
// 		}
// 		if(strcmp(test, str) == 0)
// 		{
// 			printk(KERN_INFO "search: in if\n");
// 			ans = temp;
// 		}
// 	}
// 	else
// 	{
// 		printk(KERN_INFO "search: the head is null\n");
// 	}
// 	// if(ans == NULL)
// 	// {
// 	// 	printk(KERN_INFO "search: ans is null\n");
// 	// 	blocked_program = 0;
// 	// }
// 	// else
// 	// {
// 	// 	printk(KERN_INFO "search: ans is not null\n");
// 	// 	blocked_program = 1;
// 	// }
// 	// return NULL;
// 	// return temp;
// 	return ans;
// }

int isExists(char* str)
{
	Link *link = NULL;
	if(str == NULL)
	{
		printk(KERN_INFO "isExists: the string is null\n");
		return -1;
	}
	list_for_each_entry(link, &sha_list_head.list, list) 
    {
    	(link->value)[64] = '\0';
    	// printk(KERN_INFO "isExists: str = %s. link->value = %s. length: %d\t%d\n", str, link->value, (int)strlen(str), (int)strlen(link->value));
        if(strcmp(str, link->value) == 0)
        	return 1;
    }
    return 0;
}

// int isExists(char* str)
// {
// 	if(sha_list == NULL || str == NULL)
// 	{
// 		printk(KERN_INFO "isExists: the list or the string is null\n");
// 		return -1;
// 	}
// 	printk(KERN_INFO "isExist: %d\n", (search(str) != NULL));
// 	return (search(str) != NULL);
// 	// if(search(str) != NULL)
// 	// {
// 	// 	return 1;
// 	// }
// 	// return blocked_program;
// }

void isBlockedProgram(void)
{
	// List * list = sha_list;
	// if(sha_list == NULL || sha == NULL)
		// return;
	/*if(isELF)
		list = exec_hashes;
	else
		list = scripts_hashes;*/
	if(isExists(formatted_sha))
	{
		printk(KERN_INFO "isBlockedProgram: yes, we want to block %s\n", formatted_sha);
		blocked_program = 1;
	}
	else
	{
		printk(KERN_INFO "isBlockedProgram: no, we don't want to block %s\n", formatted_sha);
		blocked_program = 0;
	}
}

static void netlink_input(struct sk_buff *skb)
{
	// int i = 0;
    nlh = (struct nlmsghdr *)skb->data;
    sha = (char *)nlmsg_data(nlh);
	if(sha != NULL)
		strcpy(formatted_sha, sha);
    isBlockedProgram();
    // for(i = 0 ; i < 65 ; i++)
    // {
    //     formatted_sha[i] = 0;
    // }

    if(nlh->nlmsg_pid != 0)
    	portid = nlh->nlmsg_pid; //portid of sending process
    printk(KERN_INFO "KERNEL GOT:%s. length = %d\n", sha, (int)strlen(sha));
    // up(sem);
}

void get_time(void)
{
	do_gettimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);
}

// Link* findPrevious(List* list, Link* curr)
// {
//   Link* temp = 0;
//   if(curr != (list->head))
//   {
//     while(((list->head)->next)-> value != curr->value )
//     {
//       list->head = (list->head)->next;
//     }
//     if(((list->head)->next)-> value == curr->value)
//     {
//       temp = list->head;
//     }
//   }
//   return temp;
// }

/*
Link* search(List *list)
{
	Link *temp;
	Link *ans = NULL;
	if(list == NULL)
		return NULL;
	temp = list->head;
	if(temp != 0)
	{
		while(strcmp(temp->name, sha) != 0 && temp->next != 0)
		{
			temp = temp->next;
		}
		if(strncmp(temp->name, sha, strlen(temp->name)) == 0)
		{
			ans = temp;
		}
	}
	return ans;
}
*/

void addLink(char * str)
{
	Link * new_link = kmalloc(sizeof(Link), GFP_KERNEL);
    new_link->value = kmalloc(strlen(str), GFP_KERNEL);
    strcpy(new_link->value, str);
    INIT_LIST_HEAD(&new_link->list);
    /* add the new node to mylist */
    list_add_tail(&new_link->list, &(sha_list_head.list));
}

// void addLink(char* str)
// {
// 	Link *new = NULL;
// 	if(!isExists(str))
// 	{
// 		new = kmalloc(sizeof(Link), GFP_KERNEL);
// 		new->value = kmalloc(strlen(str), GFP_KERNEL);
// 		strcpy(new->value, str);
// 		new->next = NULL;
// 		if(!sha_list->head)
// 		{
// 			printk(KERN_INFO "add link: new head! new->value = %s. str = %s. length = %d\t%d\n", new->value, str, (int)strlen(new->value), (int)strlen(str));
// 			sha_list->head = new;
// 			sha_list->counter = 1;
// 		}
// 		else
// 		{
// 			printk(KERN_INFO "add link: add to tail\n");
// 			addToTail(new);
// 	    	sha_list->counter++;
// 		}
// 	}
// 	print_hashes();
// }

// void addToTail(Link *new)
// {
// 	Link *temp;
// 	if(sha_list == NULL)
// 		return;
// 	temp = sha_list->head;
// 	while(temp->next != NULL)
// 	{
// 		temp = temp->next;
// 	}
// 	temp->next = new;
// }

// void init_sha_list(void)
// {
// 	sha_list = kmalloc(sizeof(List), GFP_KERNEL);
// 	sha_list->counter = 0;
//   	sha_list->head = NULL;
// }

// void free_list(List * log) 
// {
// 	Link* curr;
// 	Link* tmp;
// 	if(log == NULL)
// 		return;
// 	curr = log->head;
// 	while (curr != 0) 
//     {
// 	  tmp = curr;
// 	  curr = curr->next;
// 	  free_link(tmp);
// 	}
// 	kfree(log); 
// }

// void free_link(Link *link) 
// {
// 	if(link == NULL)
// 		return;
// 	kfree(link->value);
// 	kfree(link);
// }

// void deleteLink(Link *link)
// {
//     Link *previous = findPrevious(sha_list, link);
// 	if(previous != NULL)
// 	{
// 	    previous->next = link->next;
//     }
//     free_link(link);
// }

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

int type_check(char * type_of_elf, const char * filename, const char *first_argv)
{
	char elf_type[] = {0x7f, 0x45, 0x4c, 0x46, 0x00};
    char script_type[] = {0x23, 0x21, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x70, 0x79, 0x74, 0x68, 0x6f, 0x6e, 0x00}; //#!/usr/bin/python
	char file_type[18];
	struct file *file;
	mm_segment_t fs;
    int i;
    file = filp_open(filename, O_RDONLY, 0);
	if(!file)
    {
    	printk(KERN_ALERT "ERROR: Can not open file\n");
    	return -1;
    }
    for(i = 0 ; i < 18 ; i++)
    {
        file_type[i] = 0;
    }
    for(i = 0 ; i < 15 ; i++)
    {
        type_of_elf[i] = 0;
    }
    fs = get_fs(); // Get current segment descriptor
    set_fs(get_ds()); // Set segment descriptor associated to kernel space
    file->f_op->read(file, file_type, 18, &file->f_pos); // Read the file    // TODO: what if there is not 4 bytes to read?
    // file->f_op->read(file, file_type, 4, &file->f_pos); // Read the file    // TODO: what if there is not 4 bytes to read?
    set_fs(fs); // Restore segment descriptor
    filp_close(file, NULL); // See what we read from file
    if(strcmp(first_argv, "python") == 0)
	{
		strcpy(type_of_elf, "PYTHON SCRIPT");
		return 0; 
	}
	else if(strncmp(file_type, elf_type, strlen(elf_type)) == 0)
	{
		strcpy(type_of_elf, "EXECUTABLE");
		return 2;
	}
	else if(strncmp(file_type, script_type, strlen(script_type) - 1) == 0)
	{
		strcpy(type_of_elf, "PYTHON SCRIPT");
		return 1;
	}
	else
	{
		strcpy(type_of_elf, "SOMETHING ELSE");
		return 3;
	}
}

int my_sys_execve(const char *filename, const char *const argv[], const char *const envp[])
{
	// down(sem);
	char entry[128];
	char message[128];
	char type_of_elf[15];
    int i;
    int file_type; // 0 = "python <file>", 1 = "#!/usr/bin/python", 2 = ELF, 3 = something else
    char *full_path = NULL;
	char pwd[4];
    int path_size;
    int delete_path = 0;
	if(filename == 0)
	{
		printk(KERN_INFO "ERROR: Filename is null\n");
		return original_execve_call(filename, argv, envp);
	}
	blocked_program = 0;
	file_type = type_check(type_of_elf, filename, argv[0]);

	if(file_type == 0)
	{
		if(!script_monitoring)
			return original_execve_call(filename, argv, envp);
		strcpy(message, argv[1]);
	}
	else if(file_type == 1)
	{
		if(!script_monitoring)
			return original_execve_call(filename, argv, envp);
		strcpy(message, filename);
	}
	else if(file_type == 2)
	{
		if(!exec_monitoring)
			return original_execve_call(filename, argv, envp);
		strcpy(message, filename);
	}
	else
	{
		strcpy(message, filename);
		netlink_output(message);
	}
	if(*message == '/')
	{
		// full path
		// printk(KERN_INFO "FULL PATH. no need to change\n");
		full_path = message;
	}
	else
	{
		// printk(KERN_INFO "RELATIVE PATH. We need to change\n");
		for(i = 0 ; envp[i] != 0; i++)
	    {
	        strncpy(pwd, envp[i], 4);
	    	// printk(KERN_INFO "envp[%d] = %s. pwd = %s\n", i, envp[i], pwd);
	        // pwd[3] = '\0';
	        if(strncmp(pwd, "PWD", 3) == 0)
	        {
	        	// printk(KERN_INFO "IN PWD\n");
	        	path_size = (strlen(envp[i]) - 4) + strlen(filename) + 1;
	        	full_path =	kmalloc(path_size, GFP_KERNEL);
	        	delete_path = 1;
	        	strcpy(full_path, envp[i] + 4);
	        	strcat(full_path, "/");
	        	strcat(full_path, filename);
	        	break;
	        }
	    }
	}
	// printk(KERN_ALERT "full path: %s\n", full_path);		

	get_time();
	if(keep_working)
	{
		if((*type_of_elf == 'P' && script_blocking) || (*type_of_elf == 'E' && exec_blocking))
		{
			netlink_output(full_path);
			// netlink_output(message);
		}
	}
	if(strcmp(filename, "./unload.sh") == 0)
	{
		keep_working = 0;
		for(i = 0 ; i < strlen(formatted_sha) ; ++i)
			formatted_sha[i] = 0;
	}
	msleep(100); // we want the user to have enough time to send the sha // TODO: CHANGE TO SEMAPHORE
	if(blocked_program)
	{
    	sprintf(entry, "%04d.%02d.%02d %02d:%02d:%02d, %s: %s was not loaded due to configuration (%s)\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, type_of_elf, full_path, formatted_sha);
		return -1;
	}
    sprintf(entry, "%04d.%02d.%02d %02d:%02d:%02d, %s: %s was loaded with pid %d (%s)\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, type_of_elf, full_path, current->pid, formatted_sha);
    printk(KERN_INFO "%s", entry);
    enqueue(entry);
    if(delete_path)
    {
    	kfree(full_path);
    }
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
		printk(KERN_INFO "-------------- %d ---------------- %s", i, events[i]);
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

void print_hashes(void)
{
  	Link *curr;
	list_for_each_entry(curr, &sha_list_head.list, list) 
    {
        printk(KERN_INFO "Hash: %s", curr->value);
    }
}
/*
void print_hashes_execs(void)
{
  	Link *curr = exec_hashes->head;
	while (curr != 0) 
    {
		printk(KERN_INFO "%s", curr->value);
		curr = curr->next;
	}
}

void print_hashes_scripts(void)
{
	Link *curr = scripts_hashes->head;
	while (curr != 0) 
    {
		printk(KERN_INFO "%s", curr->value);
		curr = curr->next;
	}
}
*/
ssize_t fops_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
	if (len_check)
	 len_check = 0;
	else 
	{
	 	len_check = 1;
	 	return 0;
	}

	copy_to_user(buf,msg,len);
	printk(KERN_INFO "\nKBlocker - Last Events:\n");
	print_events();
	printk(KERN_INFO "\nKBlocker Current Configuration:\n");
	print_conf();
	/*printk(KERN_INFO "SHA256 hashes to block (Executables)\n");
	print_hashes_execs();
	printk(KERN_INFO "SHA256 hashes to block (Python Scripts)\n");
	print_hashes_scripts();*/
	printk(KERN_INFO "\nSHA256 hashes to block:\n");
	print_hashes();
	printk(KERN_INFO "\n");
	return len;
}

/* write controling: parsing user preferences and LKM definition*/
ssize_t fops_write(struct file *sp_file,const char __user *buf, size_t size, loff_t *offset)
{
	char new_sha[70];
	int i = 0;
	for(; i < 70 ; ++i)
	{
		new_sha[i] = 0;
	}
	// printk(KERN_INFO "proc called write %d\n",(int)size);
	if(size > 73)
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
	    case 'A': //add
	    	// printk(KERN_INFO "'A' case in writing\n");
	    	strcpy(new_sha, msg + 8);
	    	addLink(new_sha);
	    	break;
	    case 'D':
	    	// printk(KERN_INFO "'D' case in writing\n");
	    	strcpy(new_sha, msg + 8);
	    	// deleteLink(search(new_sha));
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
  	char *ptr = NULL;
  
    struct netlink_kernel_cfg cfg = 
    {
        .input = netlink_input,
    };
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
    
	// sema_init(sem, 1); // this initials the semaphore with 1 keys.

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    ptr = memchr(syscall_table[__NR_execve], 0xE8, 200);
    if(!ptr)
    {
    	printk(KERN_INFO "ERROR: Cannot find the execve call in init\n");
    	return -1;
    }
    ++ptr;
    original_execve_call = (void *)ptr + *(int32_t *)ptr + 4;	
     *(int32_t*)ptr = (char*) my_sys_execve - ptr - 4;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if(!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    // init_list(exec_hashes);
	//init_list(scripts_hashes);
	// init_sha_list();
    INIT_LIST_HEAD(&sha_list_head.list);


    write_cr0(cr0);
    return 0;	
}

static void __exit exit_kblocker(void)
{
    char *ptr = 0;
	struct Link *aPerson, *tmp;
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

	ptr = memchr(syscall_table[__NR_execve], 0xE8, 200);
	if(!ptr++)
	{
		printk(KERN_INFO "ERROR: Cannot find the execve call in exit\n");
	}
	*(int32_t *)ptr = (char *) original_execve_call - ptr - 4;
    remove_proc_entry("KBlocker",NULL);

    netlink_kernel_release(nl_sk);

	//free_list(exec_hashes);
	//free_list(scripts_hashes);
	// free_list(sha_list);
    list_for_each_entry_safe(aPerson, tmp, &sha_list_head.list, list)
    {
         list_del(&aPerson->list);
         kfree(aPerson->value);
         kfree(aPerson);
    }

    write_cr0(cr0);
    printk(KERN_INFO "exit KBlockerfs\n");
}

module_init(init_kblocker);
module_exit(exit_kblocker);
MODULE_AUTHOR("Oshrat Bar and Orian Zinger");
MODULE_LICENSE("GPL v3");
MODULE_DESCRIPTION("Ass2");