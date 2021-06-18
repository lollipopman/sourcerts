#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sc_openssl/stack.h"
#include "sc_openssl/x509.h"
/* #include <openssl/pem.h> */

#define X509_NAME_SIZE 512
#define ASN1_STR_PRINT_SIZE 64
#define ASN1_STR_SIZE ASN1_STR_PRINT_SIZE - 7

struct sourcerts_event_t {
  uint32_t pid;
  /* asn1_time, e.g. 201020180834Z */
  char not_before[14];
  char not_after[14];
  char subject[X509_NAME_SIZE];
  char issuer[X509_NAME_SIZE];
} __attribute__((packed));

static __always_inline void perf_submit(struct sourcerts_event_t *, size_t);

static __always_inline void *sc_sk_value(const struct stack_st *stptr, int i) {
  struct stack_st st;
  memcpy(&st, (void *)stptr, sizeof(struct stack_st));
  if (i < 0 || i >= st.num)
    return NULL;
  void *ptr;
  memcpy(&ptr, (void *)(st.data + i), sizeof(void *));
  return ptr;
}

static __always_inline int sc_x509_name(char *output, int output_len,
                                        X509_NAME *nameptr) {
  X509_NAME name;
  memcpy(&name, (void *)nameptr, sizeof(name));
  OPENSSL_STACK *name_stackptr;
  name_stackptr = (OPENSSL_STACK *)name.entries;
  unsigned int i = 0;
  struct stack_st st;
  memcpy(&st, (void *)name_stackptr, sizeof(struct stack_st));
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
    memcpy(&name_tmp, (void *)name_tmp_ptr, sizeof(struct X509_name_entry_st));
    memcpy(&asn1_str_tmp, (void *)name_tmp.value, sizeof(ASN1_STRING));
    if ((unsigned int)asn1_str_tmp.length < ASN1_STR_SIZE) {
      asn1_str_len = (unsigned int)asn1_str_tmp.length;
    } else {
      printf("ASN string length too long '%d'\n",
             (unsigned int)asn1_str_tmp.length);
      return 0;
    }
    if (pos < (output_len - ASN1_STR_SIZE)) {
      memcpy(output + pos, (void *)asn1_str_tmp.data, asn1_str_len);
      pos += asn1_str_len;
    } else {
      printf("X509_NAME_SIZE too short to fit asn1 str: '%d'\n",
             (unsigned int)asn1_str_tmp.length);
      return 0;
    }
  }
  if (pos < output_len) {
    output[pos] = '\0';
  }
  return 1;
}

int get_return_value(X509 *certptr, struct sourcerts_event_t *event) {
  X509 cert;
  memcpy(&cert, (void *)certptr, sizeof(cert));
  X509_VAL validity;
  ASN1_TIME *asn1_timeptr, asn1_time;
  X509_NAME *nameptr, name;
  validity = cert.cert_info.validity;

  memcpy(&asn1_time, validity.notBefore, sizeof(asn1_time));
  memcpy(&event->not_before, asn1_time.data, sizeof(event->not_before));
  event->not_before[sizeof(event->not_before) - 1] = '\0';

  memcpy(&asn1_time, validity.notAfter, sizeof(asn1_time));
  memcpy(&event->not_after, asn1_time.data, sizeof(event->not_before));
  event->not_before[sizeof(event->not_after) - 1] = '\0';

  if (!sc_x509_name(event->subject, sizeof(event->subject),
                    cert.cert_info.subject)) {
    printf("Error returned from sc_x509_name with subject\n");
  }
  if (!sc_x509_name(event->issuer, sizeof(event->issuer),
                    cert.cert_info.issuer)) {
    printf("Error returned from sc_x509_name with issuer\n");
  }

  perf_submit(event, sizeof(&event));
  return 0;
}

static __always_inline void perf_submit(struct sourcerts_event_t *eventptr,
                                        size_t event_size) {
  struct sourcerts_event_t event = {};
  memcpy(&event, (void *)eventptr, sizeof(event));
  printf("notBefore: %s\n", event.not_before);
  printf("notAfter: %s\n", event.not_after);
  printf("Subject: %s\n", event.subject);
  printf("Subject: %s\n", event.issuer);
}

int main() {
  char *path;
  path = "google.pem";
  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "unable to open: %s\n", path);
    return EXIT_FAILURE;
  }
  X509 *certptr;
  certptr = PEM_read_X509(fp, NULL, NULL, NULL);
  if (!certptr) {
    fprintf(stderr, "unable to parse certificate in: %s\n", path);
    fclose(fp);
    return EXIT_FAILURE;
  }
  struct sourcerts_event_t event = {};
  get_return_value(certptr, &event);
  X509_free(certptr);
  fclose(fp);
}
