#include <crypto/x509.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  char *path;
  path = "google.pem";
  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "unable to open: %s\n", path);
    return EXIT_FAILURE;
  }
  X509 *certptr;
  X509 cert;
  X509_VAL validity;
  ASN1_TIME *asn1_timeptr;
  ASN1_TIME asn1_time;
  X509_NAME *nameptr;
  X509_NAME name;
  STACK_OF(X509_NAME_ENTRY) * name_stackptr;
  certptr = PEM_read_X509(fp, NULL, NULL, NULL);
  if (!certptr) {
    fprintf(stderr, "unable to parse certificate in: %s\n", path);
    fclose(fp);
    return EXIT_FAILURE;
  }
  memcpy(&cert, (void *)certptr, sizeof(cert));
  validity = cert.cert_info.validity;
  asn1_timeptr = validity.notAfter;
  memcpy(&asn1_time, (void *)asn1_timeptr, sizeof(asn1_time));
  printf("ASN1 %s\n", asn1_time.data);
  nameptr = cert.cert_info.subject;
  memcpy(&name, (void *)nameptr, sizeof(name));
  name_stackptr = name.entries;
  int num = sk_X509_NAME_ENTRY_num(name_stackptr);
  printf("NUM %d\n", num);
  int i = 0;
  X509_NAME_ENTRY *name_tmp = NULL;
  for (i = 0; i < sk_X509_NAME_ENTRY_num(name_stackptr); i++) {
    name_tmp = sk_X509_NAME_ENTRY_value(name_stackptr, i);
    printf("XXX = '%s'\n", name_tmp->value->data);
  }
  X509_free(certptr);
  fclose(fp);
}
