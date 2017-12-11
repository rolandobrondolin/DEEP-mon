from bcc import BPF
BPF(text='''
	int kprobe__sys_clone(void *ctx) { 
		bpf_trace_printk("%llu\\n", bpf_get_smp_processor_id()); 
		return 0; 
	}''').trace_print()

