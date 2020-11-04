#include <linux/kconfig.h>
#include <linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <partial_x509.h>

struct sourcerts_event_t {
	u32 pid;
	char str[80];
} __attribute__((packed));

BPF_PERF_OUTPUT(sourcerts_events);

int get_return_value(struct pt_regs *ctx) {
	struct sourcerts_event_t event = {};
	u32 pid;
	X509 *certptr;
	X509 cert;
	X509_VAL validity;
	ASN1_TIME *asn1_timeptr;
	ASN1_TIME asn1_time;
	if (!PT_REGS_RC(ctx))
		return 0;
	bpf_trace_printk("HELLO\\n");
	pid = bpf_get_current_pid_tgid();
	event.pid = pid;
	bpf_probe_read(&cert, sizeof(cert), (void *)PT_REGS_RC(ctx));
	validity = cert.cert_info.validity;
	asn1_timeptr = validity.notAfter;
	bpf_probe_read(&asn1_time, sizeof(asn1_time), (void *)asn1_timeptr);
	bpf_probe_read_str(&event.str, 80, (void *)asn1_time.data);
	sourcerts_events.perf_submit(ctx, &event, sizeof(event));
	return 0;
}
