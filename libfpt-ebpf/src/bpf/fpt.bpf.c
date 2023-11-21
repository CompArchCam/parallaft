#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define FPT_EXCLUDE_NONWRITABLE_VMAS 1

const volatile int flags = FPT_EXCLUDE_NONWRITABLE_VMAS;
const volatile int page_size = 4096;

long dropped = 0;

struct ringbuf_map
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024 /* 16MB */);
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 32);
	__type(key, pid_t);
	__array(values, struct ringbuf_map);
} pid_map SEC(".maps");

static long find_vma_callback_fn(struct task_struct *task, struct vm_area_struct *vma, void *callback_ctx)
{
	bool *vma_is_writable = (bool *)callback_ctx;
	*vma_is_writable = vma->vm_flags & 0x2 /* VM_WRITE */;
	return 0;
}

static __always_inline int trace_enqueue(struct trace_event_raw_x86_exceptions *ctx)
{
	void *rb;
	unsigned long *next_address;
	struct task_struct *current;
	pid_t pid;
	bool vma_is_writable = false;

	current = bpf_get_current_task_btf();

	if (!current)
	{
#ifdef DEBUG
		bpf_printk("failed to get current task btf");
#endif
		return 1;
	}

	pid = current->pid;
	rb = bpf_map_lookup_elem(&pid_map, &pid);

	if (!rb)
	{
		return 1;
	}

#ifdef DEBUG
	bpf_printk("pid is interesting\n");
#endif

	if (flags & FPT_EXCLUDE_NONWRITABLE_VMAS)
	{
		if (bpf_find_vma(current, ctx->address, find_vma_callback_fn, &vma_is_writable, 0))
		{
#ifdef DEBUG
			bpf_printk("cannot find vma\n");
#endif
			return 1;
		}

		if (!vma_is_writable)
		{
#ifdef DEBUG
			bpf_printk("vma is non-writable\n");
#endif
			return 1;
		}
	}

#ifdef DEBUG
	bpf_printk("page-fault at %px.\n", ctx->address);
#endif

	next_address = bpf_ringbuf_reserve(rb, sizeof(unsigned long), 0);

	if (!next_address)
	{
		dropped++;
		return 1;
	}

	*next_address = (ctx->address & ~(page_size - 1)) | (ctx->error_code & (page_size - 1));

	bpf_ringbuf_submit(next_address, 0);

	return 0;
}

SEC("tp/exceptions/page_fault_user")
int page_fault_user(struct trace_event_raw_x86_exceptions *ctx)
{
	return trace_enqueue(ctx);
}

SEC("tp/exceptions/page_fault_kernel")
int page_fault_kernel(struct trace_event_raw_x86_exceptions *ctx)
{
	return trace_enqueue(ctx);
}

char LICENSE[] SEC("license") = "GPL";
