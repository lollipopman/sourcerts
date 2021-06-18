#include "sc_openssl/stack.h"

typedef struct ASN1_VALUE_st ASN1_VALUE;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_name_st X509_NAME;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_type_st ASN1_TYPE;
typedef struct x509_cinf_st X509_CINF;
typedef struct x509_st X509;
typedef int ASN1_BOOLEAN;

struct X509_algor_st {
  ASN1_OBJECT *algorithm;
  ASN1_TYPE *parameter;
} /* X509_ALGOR */;

struct asn1_type_st {
  int type;
  union {
    char *ptr;
    ASN1_BOOLEAN boolean;
    ASN1_STRING *asn1_string;
    ASN1_OBJECT *object;
    ASN1_INTEGER *integer;
    ASN1_ENUMERATED *enumerated;
    ASN1_BIT_STRING *bit_string;
    ASN1_OCTET_STRING *octet_string;
    ASN1_PRINTABLESTRING *printablestring;
    ASN1_T61STRING *t61string;
    ASN1_IA5STRING *ia5string;
    ASN1_GENERALSTRING *generalstring;
    ASN1_BMPSTRING *bmpstring;
    ASN1_UNIVERSALSTRING *universalstring;
    ASN1_UTCTIME *utctime;
    ASN1_GENERALIZEDTIME *generalizedtime;
    ASN1_VISIBLESTRING *visiblestring;
    ASN1_UTF8STRING *utf8string;
    /*
     * set and sequence are left complete and still contain the set or
     * sequence bytes
     */
    ASN1_STRING *set;
    ASN1_STRING *sequence;
    void *asn1_value;
  } value;
};

struct asn1_object_st {
  const char *sn, *ln;
  int nid;
  int length;
  const unsigned char *data; /* data remains const after init */
  int flags;                 /* Should we free this one */
};

struct asn1_string_st {
  int length;
  int type;
  unsigned char *data;
  /*
   * The value of the following field depends on the type being held.  It
   * is mostly being used for BIT_STRING so if the input data has a
   * non-zero 'unused bits' value, it will be handled correctly
   */
  long flags;
};

typedef struct X509_val_st {
  ASN1_TIME *notBefore;
  ASN1_TIME *notAfter;
} X509_VAL;

struct x509_cinf_st {
  ASN1_INTEGER *version; /* [ 0 ] default of v1 */
  ASN1_INTEGER serialNumber;
  X509_ALGOR signature;
  // X509_NAME *issuer;
  void *issuer;
  X509_VAL validity;
  // X509_NAME *subject;
  void *subject;
};

struct x509_st {
  X509_CINF cert_info;
};

struct X509_name_entry_st {
  ASN1_OBJECT *object; /* AttributeType */
  ASN1_STRING *value;  /* AttributeValue */
  int set;             /* index of RDNSequence for this entry */
  int size;            /* temp variable */
};

/* Name from RFC 5280. */
typedef struct buf_mem_st BUF_MEM;

struct buf_mem_st {
  size_t length;
  char *data;
  size_t max;
  unsigned long flags;
};

struct X509_name_st {
  OPENSSL_STACK *entries; /* DN components */
  int modified;           /* true if 'bytes' needs to be built */
  BUF_MEM *bytes;         /* cached encoding: cannot be NULL */
  /* canonical encoding used for rapid Name comparison */
  unsigned char *canon_enc;
  int canon_enclen;
} /* X509_NAME */;

struct stack_st {
  int num;
  const void **data;
  int sorted;
  int num_alloc;
  OPENSSL_sk_compfunc comp;
};
