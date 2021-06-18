#include <crypto/x509.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct stack_st {
  int num;
  const void **data;
  int sorted;
  int num_alloc;
  OPENSSL_sk_compfunc comp;
};

static __always_inline void *sc_sk_value(const struct stack_st *stptr, int i) {
  struct stack_st st;
  memcpy(&st, (void *)stptr, sizeof(struct stack_st));
  if (i < 0 || i >= st.num)
    return NULL;
  return (void *)st.data[i];
}

static __always_inline int sc_x509_name(char *output, int output_len,
                                        X509_NAME *nameptr) {
  X509_NAME name;
  memcpy(&name, (void *)nameptr, sizeof(name));
  STACK_OF(X509_NAME_ENTRY) * name_stackptr;
  name_stackptr = name.entries;
  int num = sk_X509_NAME_ENTRY_num(name_stackptr);
  int i = 0;
  struct stack_st st;
  memcpy(&st, (void *)name_stackptr, sizeof(struct stack_st));
  X509_NAME_ENTRY *name_tmp_ptr = NULL, name_tmp;
  ASN1_STRING *asn1_str_tmp_ptr = NULL, asn1_str_tmp;
  int pos = 0;
  for (i = 0; i < st.num; i++) {
    name_tmp_ptr = sc_sk_value((const struct stack_st *)name_stackptr, i);
    memcpy(&name_tmp, (void *)name_tmp_ptr, sizeof(struct X509_name_entry_st));
    memcpy(&asn1_str_tmp, (void *)name_tmp.value, sizeof(ASN1_STRING));
    memcpy(output + pos, (void *)asn1_str_tmp.data, asn1_str_tmp.length);
    pos += asn1_str_tmp.length;
    if ((i + 1) < st.num) {
      output[pos] = ',';
      pos++;
      output[pos] = ' ';
      pos++;
    }
    output[pos] = '\0';
  }
  return 0;
}

int main() {
  char *path;
  path = "google.pem";
  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "unable to open: %s\n", path);
    return EXIT_FAILURE;
  }
  X509 *certptr, cert;
  X509_VAL validity;
  ASN1_TIME *asn1_timeptr, asn1_time;
  X509_NAME *nameptr, name;
  certptr = PEM_read_X509(fp, NULL, NULL, NULL);
  if (!certptr) {
    fprintf(stderr, "unable to parse certificate in: %s\n", path);
    fclose(fp);
    return EXIT_FAILURE;
  }
  memcpy(&cert, (void *)certptr, sizeof(cert));
  validity = cert.cert_info.validity;

  asn1_timeptr = validity.notBefore;
  memcpy(&asn1_time, (void *)asn1_timeptr, sizeof(asn1_time));
  printf("Not Before: '%s'\n", asn1_time.data);

  asn1_timeptr = validity.notAfter;
  memcpy(&asn1_time, (void *)asn1_timeptr, sizeof(asn1_time));
  printf("Not After: '%s'\n", asn1_time.data);

  nameptr = cert.cert_info.subject;
  int subject_len = 200;
  char subject[subject_len];
  sc_x509_name(subject, subject_len, nameptr);
  printf("subject: '%s'\n", subject);

  nameptr = cert.cert_info.issuer;
  int issuer_len = 200;
  char issuer[issuer_len];
  sc_x509_name(issuer, issuer_len, nameptr);
  printf("issuer: '%s'\n", issuer);

  X509_free(certptr);
  fclose(fp);
}
