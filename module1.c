#include <linux/module.h>  // Needed by all modules
#include <linux/kernel.h>  // Needed for KERN_INFO
#include <linux/fs.h>      // Needed by filp
#include <asm/uaccess.h>   // Needed by segment descriptors


static int __init init_module1 (void)
{
	char entry[128];
	char message[128];
	char type_of_elf[14];
	struct file *file;
	char buf[128];
    mm_segment_t fs;
    int i;
    int isELF;

   
    for(i=0;i<128;i++){
        buf[i] = 0;
    }
	
	//char ELF_start[4];
	//char Python_start[17];
	//fread(ELF_start, 1, 4, filename);
	//fread(Python_start, 1, 17, filename);
	file = filp_open("a", O_RDONLY, 0);
	if(!file)
        printk(KERN_ALERT "filp_open error!\n");
    else{
        // Get current segment descriptor
        fs = get_fs();
        // Set segment descriptor associated to kernel space
        set_fs(get_ds());
        // Read the file
        file->f_op->read(file, buf, 4, &file->f_pos);

		if(strcmp(buf, "0x7F454C46") == 0){
			printk("!!!\n");
				isELF = 1;
			}


        // Restore segment descriptor
        set_fs(fs);
        // See what we read from file
        printk(KERN_INFO "buf:%s\n",buf);
    }
    filp_close(file,NULL);
    return 0;
}



static void __exit exit_module1(void)
{
    printk(KERN_INFO "exit module\n");
}
module_init(init_module1);
module_exit(exit_module1);
MODULE_LICENSE("GPL v3");