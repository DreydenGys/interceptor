#include "asm-generic/errno-base.h"
#include <linux/ftrace.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DreydenGys");
MODULE_DESCRIPTION("A Linux Syscall interceptor");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
/* modify syscall name */
#define SYSCALL_NAME(name) ("__x64_" name)
/* use ptregs calling convention */
#define PTREGS_SYSCALL_STUBS 1
#else
#define SYSCALL_NAME(name) (name)
#endif

/* Define all the information necessary for a hooks */
struct ftrace_hook {
  const char *name;
  void *function;
  void *original;

  unsigned long address;
  struct ftrace_ops ops;
};

/* Make defining a hook easier */
#define HOOK(_name, _hook, _orig)                                              \
  { .name = SYSCALL_NAME(_name), .function = (_hook), .original = (_orig), }

/* kallsyms_lookup_name struct */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t klookup = NULL;

/* Find the function "kallsyms_lookup_name" */
int find_lookup_name(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
  static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

  printk("  [+] Starting resarch with kprobe...\n");
  if (register_kprobe(&kp) < 0)
    return 1;

  klookup = (kallsyms_lookup_name_t)kp.addr;
  unregister_kprobe(&kp);
  return 0;
#else
  printk("  [+] kallsyms_lookup_name is exported\n");
  klookup = &kallsyms_lookup_name;
  return 0;
#endif
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

asmlinkage int hook_mkdir(const struct pt_regs *regs) {
  char __user *pathname = (char *)regs->di;
  char dir_name[NAME_MAX] = {0};

  long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

  if (error > 0)
    printk("interceptor: trying to create directory with name: %s\n",
           dir_name);
  if (strcmp(dir_name, "secret") ==0 ) {
    printk("interceptor: secret directory blocked\n");
    return 1;
  }

  orig_mkdir(regs);
  return 0;
}
#else
static asmlinkage long (*orig_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode) {
  char dir_name[NAME_MAX] = {0};

  long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

  if (error > 0)
    printk("interceptor: trying to create directory with name %s\n",
           dir_name);

  orig_mkdir(pathname, mode);
  return 0;
}
#endif

/* Callback function called by strace */
static void notrace callback(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct pt_regs *regs) {

  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

  /* Custom recursion detection */
  if (!within_module(parent_ip, THIS_MODULE))
    regs->ip = (unsigned long)hook->function;
}

/* Register a given hook */
int register_hook(struct ftrace_hook *hook) {
  int err;

  hook->address = klookup(hook->name);
  *((unsigned long *) hook->original) = hook->address;
  printk("  [+] registering %s at 0x%lx\n", hook->name, hook->address);

  if (!hook->address)
    return 1;

  hook->ops.func = callback;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE |
                    FTRACE_OPS_FL_IPMODIFY;

  if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0))) {
    printk("    [+] ftrace_set_filter_ip() failed: %d\n", err);
    return err;
  }

  if ((err = register_ftrace_function(&hook->ops))) {
    printk("    [+]register_ftrace_function() failed: %d\n", err);
    return err;
  }

  printk("  [+] %s registered \n", hook->name);
  return 0;
}

/* Unregister a given hook */
void unregister_hook(struct ftrace_hook *hook) {
  int err;

  printk("  [+] unregistering %s", hook->name);
  err = unregister_ftrace_function(&hook->ops);
  if(err)
    printk("    [+] unregister_ftrace_function() failed: %d\n", err);

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
  if(err)
    printk("    [+] ftrace_set_filter_ip() failed: %d\n", err);

  printk("  [+] %s unregistered", hook->name);
}

/* Register size hooks in the array ftrace_hook */
int register_hooks(struct ftrace_hook *hooks, size_t size) {
  size_t i;
  int err;

  printk("[+] Starting registering hooks\n");
  for (i = 0; i < size; i++) {
    err = register_hook(&hooks[i]);
    if (err)
      goto error;
  }
  return 0;

error:
  for (; i + 1 != 0; i--) {
    unregister_hook(&hooks[i]);
  }

  return err;
}


/* Unregister size hooks in the array ftrace_hook */
void unregister_hooks(struct ftrace_hook *hooks, size_t size) {
  size_t i;

  printk("[+] Starting unregistering hooks\n");
  for (i = 0; i < size; i++) {
    unregister_hook(&hooks[i]);
  }

}


/* Struct containing all the hooks */
static struct ftrace_hook hooks[] = {
HOOK("sys_mkdir", &hook_mkdir, &orig_mkdir),
};

/* Module Init function */
static int __init ModuleInit(void) {
  int res = 0;

  printk("= = Starting interceptor = =\n");
  printk("[+] Kernel version %hhu.%hhu.%hhu\n",
         (unsigned char)(LINUX_VERSION_CODE >> 16),
         (unsigned char)(LINUX_VERSION_CODE >> 8),
         (unsigned char)LINUX_VERSION_CODE);
  printk("[+] Finding kallsyms_lookup_name...\n");
  res = find_lookup_name();
  if (res)
    printk("  [+] kallsyms_lookup_name not found\n");
  else
    printk("  [+] kallsyms_lookup_name found at 0x%p\n", klookup);

   res  = register_hooks(hooks, ARRAY_SIZE(hooks));
  return res;
}

/* Module Exit function */
static void __exit ModuleExit(void) {
  unregister_hooks(hooks, ARRAY_SIZE(hooks));
  printk("= = Exiting interceptor = = \n");
}

module_init(ModuleInit);
module_exit(ModuleExit);
