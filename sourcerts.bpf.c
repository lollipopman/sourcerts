#include "sc_openssl/stack.h"
#include "sc_openssl/x509.h"
#include <linux/types.h>
#include <uapi/linux/ptrace.h>

#define X509_NAME_SIZE 512
#define ASN1_STR_PRINT_SIZE 64
#define ASN1_STR_SIZE ASN1_STR_PRINT_SIZE - 7

struct sourcerts_event_t {
  u32 pid;
  /* asn1_time, e.g. 201020180834Z */
  char not_before[14];
  char not_after[14];
  char subject[X509_NAME_SIZE];
  char issuer[X509_NAME_SIZE];
} __attribute__((packed));

static __always_inline void *sc_sk_value(const struct stack_st *stptr, int i) {
  struct stack_st st;
  bpf_probe_read(&st, sizeof(struct stack_st), (void *)stptr);
  if (i < 0 || i >= st.num)
    return NULL;
  void *ptr;
  bpf_probe_read(&ptr, sizeof(void *), (void *)(st.data + i));
  return ptr;
}

static __always_inline int sc_x509_name(char *output, int output_len,
                                        X509_NAME *nameptr) {
  X509_NAME name;
  bpf_probe_read(&name, sizeof(name), (void *)nameptr);
  OPENSSL_STACK *name_stackptr;
  name_stackptr = (OPENSSL_STACK *)name.entries;
  unsigned int i = 0;
  struct stack_st st;
  bpf_probe_read(&st, sizeof(struct stack_st), (void *)name_stackptr);
  struct X509_name_entry_st *name_tmp_ptr = NULL, name_tmp;
  ASN1_STRING *asn1_str_tmp_ptr = NULL, asn1_str_tmp;
  unsigned int pos = 0;
  unsigned int asn1_str_len;
  unsigned int st_len;
  for (i = 0; i < (X509_NAME_SIZE / ASN1_STR_PRINT_SIZE) && i < st.num; i++) {
    if (i != 0) {
      if (pos < output_len) {
        output[pos] = ',';
      }
      pos++;
      if (pos < output_len) {
        output[pos] = ' ';
      }
      pos++;
    }
    name_tmp_ptr = sc_sk_value(name_stackptr, i);
    if (!name_tmp_ptr)
      return 0;
    bpf_probe_read(&name_tmp, sizeof(struct X509_name_entry_st),
                   (void *)name_tmp_ptr);
    bpf_probe_read(&asn1_str_tmp, sizeof(ASN1_STRING), (void *)name_tmp.value);
    if ((unsigned int)asn1_str_tmp.length < ASN1_STR_SIZE) {
      asn1_str_len = (unsigned int)asn1_str_tmp.length;
    } else {
      bpf_trace_printk("ASN string length too long '%d'\n",
                       (unsigned int)asn1_str_tmp.length);
      return 0;
    }
    if (pos < (output_len - ASN1_STR_SIZE)) {
      bpf_probe_read(output + pos, asn1_str_len, (void *)asn1_str_tmp.data);
      pos += asn1_str_len;
    } else {
      bpf_trace_printk("X509_NAME_SIZE too short to fit asn1 str: '%d'\n",
                       (unsigned int)asn1_str_tmp.length);
      return 0;
    }
  }
  if (pos < output_len) {
    output[pos] = '\0';
  }
  return 1;
}

BPF_PERF_OUTPUT(sourcerts_events);
BPF_PERCPU_ARRAY(sourcerts_struct, struct sourcerts_event_t, 1);

int get_return_value(struct pt_regs *ctx) {
  u32 map_id;
  if (!PT_REGS_RC(ctx))
    return 0;

  map_id = 0;
  struct sourcerts_event_t *event = sourcerts_struct.lookup(&map_id);
  if (!event)
    return 0;

  event->pid = bpf_get_current_pid_tgid();

  X509 *certptr, cert;
  bpf_probe_read(&cert, sizeof(cert), (void *)PT_REGS_RC(ctx));

  X509_VAL validity;
  ASN1_TIME *asn1_timeptr, asn1_time;
  X509_NAME *nameptr, name;
  validity = cert.cert_info.validity;

  bpf_probe_read(&asn1_time, sizeof(asn1_time), validity.notBefore);
  bpf_probe_read(&event->not_before, sizeof(event->not_before), asn1_time.data);
  event->not_before[sizeof(event->not_before) - 1] = '\0';

  bpf_probe_read(&asn1_time, sizeof(asn1_time), validity.notAfter);
  bpf_probe_read(&event->not_after, sizeof(event->not_before), asn1_time.data);
  event->not_before[sizeof(event->not_after) - 1] = '\0';

  if (!sc_x509_name(event->subject, sizeof(event->subject),
                    cert.cert_info.subject)) {
    bpf_trace_printk("Error returned from sc_x509_name with subject\n");
  }
  if (!sc_x509_name(event->issuer, sizeof(event->issuer),
                    cert.cert_info.issuer)) {
    bpf_trace_printk("Error returned from sc_x509_name with issuer\n");
  }

  sourcerts_events.perf_submit(ctx, event, sizeof(*event));
  return 0;
}
