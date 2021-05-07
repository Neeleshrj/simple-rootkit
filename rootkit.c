#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h> //debug messages
#include <linux/moduleparam.h>
#include <linux/stat.h>


#define DRIVER_AUTHOR "Neelesh Ranjan Jha"
#define DRIVER_DESCRIPTION "Simple Rootkit"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);

static char *MyString = ""; //should not contain spaces when passing parameters

module_param(MyString, charp, 0000);  //(parameter, type-here charachter pointer, permissions)
MODULE_PARM_DESC(MyString, "Test argument in the kernel module");



static int HelloInit(void)
{
  printk(KERN_INFO "EXAMPLE-HELLO %s \n",MyString);
  return 0;
}

static void HelloExit(void)
{
  printk(KERN_INFO "EXAMPLE-BYE\n");
}

module_init(HelloInit);
module_exit(HelloExit);
