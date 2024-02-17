/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdlib.h>

#include "yaml-common.h"

#include "util/aux_util.h"

    static struct {
        TPM2_ALG_ID id;
        const char *value;
    } alg_table[] = {
        { TPM2_ALG_RSA,            "rsa"           },
        { TPM2_ALG_TDES,           "tdes"          },
        { TPM2_ALG_SHA,            "sha1"          },
        { TPM2_ALG_SHA1,           "sha1"          },
        { TPM2_ALG_HMAC,           "hmac"          },
        { TPM2_ALG_AES,            "aes"           },
        { TPM2_ALG_MGF1,           "mfg1"          },
        { TPM2_ALG_KEYEDHASH,      "keyedhash"     },
        { TPM2_ALG_XOR,            "xor"           },
        { TPM2_ALG_SHA256,         "sha256"        },
        { TPM2_ALG_SHA384,         "sha384"        },
        { TPM2_ALG_SHA512,         "sha512"        },
        { TPM2_ALG_NULL,           "null"          },
        { TPM2_ALG_SM3_256,        "sha256"        },
        { TPM2_ALG_SM4,            "sm4"           },
        { TPM2_ALG_RSASSA,         "rsassa"        },
        { TPM2_ALG_RSAES,          "rsaes"         },
        { TPM2_ALG_RSAPSS,         "rsapss"        },
        { TPM2_ALG_OAEP,           "oaep"          },
        { TPM2_ALG_ECDSA,          "ecdsa"         },
        { TPM2_ALG_ECDH,           "ecdh"          },
        { TPM2_ALG_ECDAA,          "ecdaa"         },
        { TPM2_ALG_SM2,            "sm2"           },
        { TPM2_ALG_ECSCHNORR,      "ecschnorr"     },
        { TPM2_ALG_ECMQV,          "ecmqv"         },
        { TPM2_ALG_KDF1_SP800_56A, "kdf1_sp800_561"},
        { TPM2_ALG_KDF2,           "kdf2"          },
        { TPM2_ALG_KDF1_SP800_108, "kdf1_sp800_108"},
        { TPM2_ALG_ECC,            "ecc"           },
        { TPM2_ALG_SYMCIPHER,      "symcipher"     },
        { TPM2_ALG_CAMELLIA,       "camellia"      },
        { TPM2_ALG_CMAC,           "cmac"          },
        { TPM2_ALG_CTR,            "ctr"           },
        { TPM2_ALG_SHA3_256,       "sha3_256"      },
        { TPM2_ALG_SHA3_384,       "sha3_384"      },
        { TPM2_ALG_SHA3_512,       "sha3_512"      },
        { TPM2_ALG_OFB,            "ofb"           },
        { TPM2_ALG_CBC,            "cbc"           },
        { TPM2_ALG_CFB,            "cfb"           },
        { TPM2_ALG_ECB,            "ecb"           },
    };

static TSS2_RC TPM2_ALG_ID_tostring(uint64_t id, char **str) {

    size_t i;
    for (i=0; i < ARRAY_LEN(alg_table); i++) {
        if (alg_table[i].id == id) {
            char *s = strdup(alg_table[i].value);
            if (!s) {
                return TSS2_MU_RC_MEMORY;
            }
            *str = s;
            return TSS2_RC_SUCCESS;
        }
    }

    return TSS2_MU_RC_BAD_VALUE;
}

static TSS2_RC TPM2_ALG_ID_fromstring(char *alg, TPM2_ALG_ID *d) {

    size_t i;
    for (i=0; i < ARRAY_LEN(alg_table); i++) {
        if (alg_table[i].value == alg) {
            *d = alg_table[i].id;
            return TSS2_RC_SUCCESS;
        }
    }

    return TSS2_MU_RC_BAD_VALUE;
}

static TSS2_RC TPMA_ALGORITHM_fromstring(char *str, TPMA_ALGORITHM *d) {

    char *saveptr;
    char *token = strtok_r(str, ",", &saveptr);

    while (token != NULL) {

        if (!strcmp(token, "asymmetric")) {
            *d |= TPMA_ALGORITHM_ASYMMETRIC;
        } else if (!strcmp(token, "symmetric")) {
            *d |= TPMA_ALGORITHM_SYMMETRIC;
        } else if (!strcmp(token, "hash")) {
            *d |= TPMA_ALGORITHM_HASH;
        } else if (!strcmp(token, "object")) {
            *d |= TPMA_ALGORITHM_OBJECT;
        } else if (!strcmp(token, "signing")) {
            *d |= TPMA_ALGORITHM_SIGNING;
        } else if (!strcmp(token, "encrypting")) {
            *d |= TPMA_ALGORITHM_ENCRYPTING;
        } else if (!strcmp(token, "method")) {
            *d |= TPMA_ALGORITHM_METHOD;
        } else {
            return TSS2_MU_RC_BAD_VALUE;
        }

        token = strtok_r(NULL, ",", &saveptr);
    }

    return TSS2_RC_SUCCESS;
}

static TSS2_RC TPMA_ALGORITHM_tostring(uint64_t details, char **str) {

    char buf[256] = { 0 };
    char *p = buf;
    if (details & TPMA_ALGORITHM_ASYMMETRIC) {
        strcat(p, "symmetric");
    }

    if (details & TPMA_ALGORITHM_SYMMETRIC) {
        strcat(p, ",symmetric");
    }

    if (details & TPMA_ALGORITHM_HASH) {
        strcat(p, ",hash");
    }

    if (details & TPMA_ALGORITHM_OBJECT) {
        strcat(p, ",object");
    }

    if (details & TPMA_ALGORITHM_SIGNING) {
        strcat(p, ",signing");
    }

    if (details & TPMA_ALGORITHM_ENCRYPTING) {
        strcat(p, ",encrypting");
    }

    if (details & TPMA_ALGORITHM_METHOD) {
        strcat(p, ",method");
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *str = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_MU_YAML_TPMS_ALG_PROPERTY_Marshal(
    TPMS_ALG_PROPERTY const *src,
    char            **output)
{
    TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE;
    yaml_document_t doc = { 0 };

    return_if_null(src, "src is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(output, "output is NULL", TSS2_MU_RC_BAD_REFERENCE);

    rc = doc_init(&doc);
    return_if_error(rc, "Could not initialize document");

    int root = yaml_document_add_mapping(&doc, NULL, YAML_ANY_MAPPING_STYLE);
    if (!root) {
        yaml_document_delete(&doc);
        return TSS2_MU_RC_GENERAL_FAILURE;
    }

    struct key_value kvs[2] = {
        KVP_ADD_UINT_TOSTRING("alg", src->alg, TPM2_ALG_ID_tostring),
        KVP_ADD_UINT_TOSTRING("algProperties", src->algProperties, TPMA_ALGORITHM_tostring)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ALG_PROPERTY_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPMS_ALG_PROPERTY   *dest) {

    return TSS2_RC_SUCCESS + 1;
}
