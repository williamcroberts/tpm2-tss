/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "util/aux_util.h"
#include "util/tpm2b.h"
#include "util/tss2_endian.h"

#include "yaml-common.h"

#define LOGMODULE yaml_marshal
#include "util/log.h"

/* when a string is null print this don't rely on %s as it's a gnu extension */
#define NULL_STR "(null)"

TSS2_RC doc_init(yaml_document_t *doc) {
    return yaml_to_tss2_rc(yaml_document_initialize( \
            doc,
            NULL, /* version */
            NULL, /* start */
            NULL, /* end */
            1,    /* implicit start */
            1     /* implicit end */
        ));
}

/*
 * IMPORTANT All base add functions for types MUST set the written flag
 * or output will be an empty document of {}.
 */
static int yaml_add_str(yaml_document_t *doc, const char *str) {
    return yaml_document_add_scalar(doc, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)str ? str : NULL_STR, -1, YAML_ANY_SCALAR_STYLE);
}

/* an 64 bit is 20 chars max in base 10 PLUS a sign plus a nul, this is plenty big */
#define MAX_CHARS 32

#define IMPLEMENT_SCALAR_MARSHAL(type, fmt) \
    TSS2_RC yaml_common_scalar_##type##_marshal(type in, char **out) \
    { \
        assert(out); \
        \
        char *x = calloc(1, MAX_CHARS); \
        return_if_null(x, "Out of memory.", TSS2_MU_RC_MEMORY); \
        snprintf(x, MAX_CHARS, "%"fmt, in); \
        *out = x; \
        return TSS2_RC_SUCCESS; \
    }

IMPLEMENT_SCALAR_MARSHAL(int8_t, PRId8)
IMPLEMENT_SCALAR_MARSHAL(uint8_t, PRIu8)
IMPLEMENT_SCALAR_MARSHAL(int16_t, PRId16)
IMPLEMENT_SCALAR_MARSHAL(uint16_t, PRIu16)
IMPLEMENT_SCALAR_MARSHAL(int32_t, PRId32)
IMPLEMENT_SCALAR_MARSHAL(uint32_t, PRIu32)
IMPLEMENT_SCALAR_MARSHAL(int64_t, PRId64)
IMPLEMENT_SCALAR_MARSHAL(uint64_t, PRIu64)

#define _SCALAR_UNMARSHAL_LINE unsigned long long result = strtoull(in, &endptr, 10)
#define IMPLEMENT_SCALAR_UNMARSHAL(type) \
    TSS2_RC yaml_common_scalar_##type##_unmarshal(const char *in, size_t len, type *out) \
    { \
        assert(in); \
        assert(out); \
        \
        char *endptr = NULL; \
        errno = 0;  \
        _SCALAR_UNMARSHAL_LINE; \
        \
        if ((errno == ERANGE && (result == ULLONG_MAX || result == 0)) || (errno != 0 && result == 0)) { \
            LOG_ERROR("Could not convert: \"%s\" to integer", in); \
            return TSS2_MU_RC_BAD_VALUE; \
        } \
        if (endptr == in) { \
            LOG_ERROR("No digits were found.\n"); \
            return TSS2_MU_RC_BAD_VALUE; \
        } \
        /* force truncation */ \
        type tmp = (type)result; \
        if (tmp != result) { \
            LOG_ERROR("Truncation detected, got \"%s\""); \
            return TSS2_MU_RC_BAD_VALUE; \
        } \
        \
        *out = tmp; \
        \
        return TSS2_RC_SUCCESS; \
    }

IMPLEMENT_SCALAR_UNMARSHAL(uint8_t)
IMPLEMENT_SCALAR_UNMARSHAL(uint16_t)
IMPLEMENT_SCALAR_UNMARSHAL(uint32_t)
IMPLEMENT_SCALAR_UNMARSHAL(uint64_t)
#undef _SCALAR_UNMARSHAL_LINE

#define _SCALAR_UNMARSHAL_LINE long long result = strtoll(in, &endptr, 10)
IMPLEMENT_SCALAR_UNMARSHAL(int8_t)
IMPLEMENT_SCALAR_UNMARSHAL(int16_t)
IMPLEMENT_SCALAR_UNMARSHAL(int32_t)
IMPLEMENT_SCALAR_UNMARSHAL(int64_t)
#undef _SCALAR_UNMARSHAL_LINE

TSS2_RC yaml_common_generic_marshal(const datum *data, char **out) {

    char *hex_string = malloc(data->size * 2 + 1);
    return_if_null(hex_string, "Out of memory.", TSS2_MU_RC_MEMORY);
    char *buffer = (char *)data;
    size_t i, off;
    for (i = 0, off = 0; i < data->size; i++, off += 2) {
        sprintf(&hex_string[off], "%02x", buffer[i]);
    }

    hex_string[data->size * 2] = '\0';
    *out = hex_string;

    return TSS2_RC_SUCCESS;
}

TSS2_RC tpm2b_simple_generic_marshal(const datum *in, char **out) {

    assert(in);
    assert(out);

    TPM2B *tpm2b = (TPM2B *)in->data;

    if (tpm2b->size == 0) {
        // TODO zero len ok?
        return TSS2_RC_SUCCESS;
    }

    /*
     * on TPM2B simples, datum->size is the tpm2b->size are the same, but
     * we have to drop the data pointer down to an array of bytes, or the
     * buffer field.
     */
    datum tmp = {
        .size = tpm2b->size,
        .data = tpm2b->buffer
    };

    return yaml_common_generic_marshal(&tmp, out);
}

static TSS2_RC hex_to_nibble(char c, unsigned *val) {

    if (c >= '0' && c <= '9') {
            *val = c - '0';
    } else if (c >= 'a' && c <= 'f') {
            *val = 10 + c - 'a';
    } else if (c >= 'A' && c <= 'F') {
            *val = 10 + c - 'A';
    } else {
        LOG_ERROR("Invalid hex char found, got: %c", c);
        return TSS2_MU_RC_BAD_VALUE;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_common_generic_unmarshal(const char *in, size_t len, datum *out) {
    assert(in);
    assert(out);
    // TODO use?
    UNUSED(len);

    char *buffer = (char *)out->data;
    char c = in[0];
    UINT16 i, offset;
    unsigned val;
    TSS2_RC rc;
    for(i=0, offset=0; c != '\0'; i++, c = in[i]) {
        if (offset > out->size) {
            LOG_ERROR("Out of bounds for data type");
            return TSS2_MU_RC_BAD_VALUE;
        }

        /* convert one char to a nibble */
        rc = hex_to_nibble(c, &val);
        if (rc != TSS2_RC_SUCCESS) {
            return rc;
        }

        /* odd means low nibble */
        if (i & 0x1) {
            buffer[offset] |= val;
            /* done with this byte of processing */
            offset++;
        } else {
            /* even means high nibble */
            buffer[offset] = val << 4;
        }
    };

    if (i & 0x1) {
        LOG_ERROR("Hex strings must be even");
        return TSS2_MU_RC_BAD_VALUE;
    }

    out->size = offset;

    return TSS2_RC_SUCCESS;
}


TSS2_RC tpm2b_simple_generic_unmarshal(const char *hex, size_t len, datum *d) {
    assert(d);
    assert(hex);
    // TODO use?
    UNUSED(len);

    TPM2B *tpm2b = (TPM2B *)d->data;

    /* fill up a TPM2B based on this max size */
    datum tmp = {
        .size = d->size,
        .data = tpm2b->buffer
    };

    /* populate data and reset size to what it is */
    TSS2_RC rc = yaml_common_generic_unmarshal(hex,  d->size, &tmp);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /* the tpm2b buffer field was populated directly, but populate the size field */
    tpm2b->size = tmp.size;

    return TSS2_RC_SUCCESS;
}

static int add_datum(yaml_document_t *doc, const datum *d) {

    char *yaml = NULL;
    TSS2_RC rc = d->marshal(d, &yaml);
    if (rc != TSS2_RC_SUCCESS) {
        return 0;
    }

    int node = yaml_document_add_scalar(doc, (yaml_char_t *)YAML_STR_TAG,
            yaml, -1, YAML_ANY_SCALAR_STYLE);
    free(yaml);

    return node;
}

TSS2_RC add_kvp(yaml_document_t *doc, int root, const key_value *k) {

    // TODO WHAT TO DO WITH EMPTY TPM2Bs
    if (k->value.size == 0) {
        return TSS2_RC_SUCCESS;
    }

    /*
     * skip handling things that are not being marshalled/unmarshalled like
     * selectors for TPMUs.
     */
    if (!k->value.data) {
        return TSS2_RC_SUCCESS;
    }

    int key = yaml_document_add_scalar(doc, YAML_STR_TAG, \
                (yaml_char_t *)k->key, -1, YAML_ANY_SCALAR_STYLE);
    return_yaml_rc(key);

    int value = add_datum(doc, &k->value);
    return_yaml_rc(value);

    /* append to node */
    return yaml_to_tss2_rc(yaml_document_append_mapping_pair(doc, root, key, value));
}

TSS2_RC add_kvp_list(yaml_document_t *doc, int root, const key_value *kvs, size_t len) {

    size_t i;
    for(i=0; i < len; i++) {
        const key_value *k = &kvs[i];
        TSS2_RC rc = add_kvp(doc, root, k);
        return_if_error(rc, "Could not add KVP");
    }

    // TODO EMPTY LISTS?
    return TSS2_RC_SUCCESS;
}

static TSS2_RC add_lst(yaml_document_t *doc, int root, const datum *d) {

    // TODO WHAT TO DO WITH EMPTY THINGS
    if (d->size == 0) {
        return TSS2_RC_SUCCESS;
    }

    int value = add_datum(doc, d);
    return_yaml_rc(value);

    return yaml_to_tss2_rc(yaml_document_append_sequence_item(doc, root, value));
}

// TODO USED
TSS2_RC add_sequence_root_with_items(yaml_document_t *doc, int root,
        const char *mapkey, const datum *lst, size_t len) {

    int sub_root = yaml_document_add_sequence(doc,
            YAML_SEQ_TAG, YAML_ANY_SEQUENCE_STYLE);
    return_yaml_rc(yaml_to_tss2_rc(sub_root));

    size_t i;
    for(i=0; i < len; i++) {
        const datum *x = &lst[i];
        TSS2_RC rc = add_lst(doc, sub_root, x);
        return_if_error(rc, "Could not add list item");
    }

    int sub_root_key = yaml_add_str(doc, mapkey);
    return_yaml_rc(sub_root_key);

    return yaml_to_tss2_rc(yaml_document_append_mapping_pair(doc, root, sub_root_key, sub_root));
}

// TODO USED
TSS2_RC add_mapping_root_with_items(yaml_document_t *doc, int root,
        const char *mapkey, const key_value *kvs, size_t len) {

    int sub_root = yaml_document_add_mapping(doc,
            NULL, YAML_ANY_MAPPING_STYLE);
    return_yaml_rc(sub_root);

    int sub_root_key = yaml_add_str(doc, mapkey);
    return_yaml_rc(sub_root_key);

    TSS2_RC rc = add_kvp_list(doc, sub_root, kvs, len);
    return_if_error(rc, "Could not add KVP List")

    return yaml_to_tss2_rc(yaml_document_append_mapping_pair(doc, root, sub_root_key, sub_root));
}

static int write_handler(void *data, unsigned char *buffer, size_t size) {

    write_data *wd = (write_data *)data;
    assert(wd);

    /* do we need to grow the string ? */
    size_t free_space = wd->cur_size - wd->cur_offset;
    if (size > free_space) {
        size_t grow_size = 0;
        if (__builtin_mul_overflow(size, 2, &grow_size)) {
            LOG_ERROR("Overflow detected");
            return 0;
        }

        size_t new_size = 0;
        if (__builtin_add_overflow(wd->cur_size, grow_size, &new_size)) {
            LOG_ERROR("Overflow detected");
            return 0;
        }

        char *new_buffer = realloc(wd->buffer, new_size);
        if (!new_buffer) {
            LOG_ERROR("oom");
            return 0;
        }

        wd->cur_size = new_size;
        wd->buffer = new_buffer;

    }

    /* add to the string */
    memcpy(&wd->buffer[wd->cur_offset], buffer, size);

    /* update the offset */
    wd->cur_offset += size;

    /* success is 1 in libyaml */
    return 1;
}

TSS2_RC yaml_dump(yaml_document_t *doc, char **output) {
    assert(doc);
    assert(output);

    write_data wd = { 0 };
    TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE;

    yaml_emitter_t emitter = { 0 };
    int r = yaml_emitter_initialize(&emitter);
    return_yaml_rc(r);

    // TODO Canonical support?
    //yaml_emitter_set_canonical(&emitter, 1);

    yaml_emitter_set_output(&emitter, write_handler, &wd);

    r = yaml_emitter_dump(&emitter, doc);
    if (!r) {
        LOG_ERROR("Could not dump YAML");
        goto out;
    }

    /* caller takes ownership */
    *output = wd.buffer;
    wd.buffer = NULL;
    rc = TSS2_RC_SUCCESS;

out:
    yaml_emitter_close(&emitter);
    yaml_emitter_delete(&emitter);
    free(wd.buffer);

    return rc;
}

static TSS2_RC handle_mapping_scalar_key(const char *key, key_value *dest, size_t dest_len, parser_state *state);

static TSS2_RC handle_mapping_scalar_value(const char *value, key_value *dest, size_t dest_len, parser_state *state) {

    assert(state->cur);

    /* We shouldn't hit keys for selectors on UNIONS, as public API doesn't include them */
    if (state->cur->value.unmarshal) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    // TODO plumb len in
    TSS2_RC rc = state->cur->value.unmarshal(value, strlen(value), &state->cur->value);
    if (rc != TSS2_RC_SUCCESS) {
            return TSS2_MU_RC_BAD_VALUE;
    }

    // TODO STILL NEEDED?
    /* keep track of many of the kvps we have processed, we should never fall short */
    if (rc == TSS2_RC_SUCCESS) {
        state->handled++;
        state->handler = NULL;
    }

    state->cur = NULL;
    state->handler = handle_mapping_scalar_key;

    return rc;
}

static TSS2_RC handle_mapping_scalar_key(const char *key, key_value *dest, size_t dest_len, parser_state *state) {

    /* current should only be set if we're processing a kvp entry */
    assert(!state->cur);

    size_t i = 0;
    for (i=0; i < dest_len; i++) {
        key_value *c = &dest[i];
        if (strcmp(key, c->key)) {
            /* no match loop up */
            continue;
        }

        /* match update cur and state */
        state->cur = c;
        break;
    }

    if (!state->cur) {
        LOG_ERROR("Could not match: %s", key);
        return TSS2_MU_RC_BAD_VALUE;
    }

    /* transition to handling values */
    state->handler = handle_mapping_scalar_value;
    assert(state->cur);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
yaml_handle_event(const yaml_event_t *e, key_value *dest, size_t dest_len, parser_state *state)
{
    assert(dest);
    assert(e);
    assert(state);

    switch(e->type) {
        case YAML_NO_EVENT:
        case YAML_STREAM_START_EVENT:
        case YAML_STREAM_END_EVENT:
        case YAML_DOCUMENT_START_EVENT:
        case YAML_DOCUMENT_END_EVENT:
            return TSS2_RC_SUCCESS;
        case YAML_MAPPING_START_EVENT:
            /* Nested mappings shouldn't be OK */
            if (state->handler != NULL) {
                return TSS2_MU_RC_GENERAL_FAILURE;
            }
            /* start looking for the key */
            state->handler = handle_mapping_scalar_key;
            return TSS2_RC_SUCCESS;
        case YAML_MAPPING_END_EVENT:
            return TSS2_RC_SUCCESS;

        /* Data, could be a key or value */
        case YAML_SCALAR_EVENT:
            return state->handler(e->data.scalar.value, dest, dest_len, state);
        default:
            LOG_ERROR("Unhandled YAML event type: %u\n", e->type);
        }

        return TSS2_MU_RC_GENERAL_FAILURE;
}

TSS2_RC yaml_parse(const char *yaml, size_t size, key_value *dest, size_t dest_len) {

    TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE;

    yaml_parser_t parser;
    int r = yaml_parser_initialize(&parser);
    if(!r) {
        return false;
    }

    yaml_parser_set_input_string(&parser, yaml, size);

    parser_state state = { 0 };

    yaml_event_t event;
    do {
        r = yaml_parser_parse(&parser, &event);
        if (!r) {
            LOG_ERROR("Parser error %d", parser.error);
            goto error;
        }

        /* handle events */
        TSS2_RC rcx = yaml_handle_event(&event, dest, dest_len, &state);
        if (rcx != TSS2_RC_SUCCESS) {
            LOG_ERROR("Parser error %d", rcx);
            rc = rcx;
            goto error;
        }

        if(event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }

    } while(event.type != YAML_STREAM_END_EVENT);

    if (state.handled != dest_len) {
        LOG_ERROR("Did not find all of expected data fields, got: %zu expected %zu",
                state.handled, dest_len);
        rc = TSS2_MU_RC_BAD_VALUE;
        goto error;
    }

    rc = TSS2_RC_SUCCESS;

error:
        yaml_event_delete(&event);
        yaml_parser_delete(&parser);

        return rc;
}

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

TSS2_RC yaml_common_generic_scalar_unmarshal(const char *data, size_t len, datum *result) {

    TSS2_RC rc = TSS2_MU_RC_BAD_VALUE;
    /* zero length data is interpreted as NUL terminated C string */
    char *tmp = NULL;
    const char *nul_term = NULL;
    if (!len) {
        nul_term = data;
    } else {
        tmp = calloc(1, len + 1);
        if (!tmp) {
            return TSS2_MU_RC_MEMORY;
        }
        memcpy(tmp, data, len);
        nul_term = tmp;
    }

    char *endptr = NULL;
    errno = 0;
    unsigned long long r = strtoull(nul_term, &endptr, 0);
    if (errno ||  endptr == nul_term) {
        LOG_ERROR("Could not convert value to scalar, got: \"%s\"", data);
        goto out;
    }

    /* enforce we're not truncating the type */
    if ((~(0ULL) << (result->size * 8)) & r) {
        LOG_ERROR("Scalar size is too big, expected %zu bytes", result->size);
        goto out;
    }

    memcpy(result->data, &r, result->size);
    rc = TSS2_RC_SUCCESS;

out:
    free(tmp);
    return rc;
}

TSS2_RC yaml_common_generic_scalar_marshal(uint64_t data, char **result) {

    int size = snprintf(NULL, 0, "0x%" PRIx64, data);
    size++;
    char *s = calloc(1, size);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    snprintf(s, size, "0x%" PRIx64, data);

    *result = s;

    return TSS2_RC_SUCCESS;
}

void yaml_common_to_lower(char *s)
{
    while(*s) {
        *s = tolower(*s);
        s++;
    }
}

/* TODO REMOVE HACKY McHACKERSON CODE */
TSS2_RC Tss2_MU_YAML_TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPML_PCR_SELECTION_Unmarshal(const char *yaml, size_t yaml_len, TPML_PCR_SELECTION *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_ASYM_SCHEME_Marshal(TPMT_ASYM_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_ASYM_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMT_ASYM_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_ECC_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMT_ECC_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_HA_Marshal(TPMT_HA const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_HA_Unmarshal(const char *yaml, size_t yaml_len, TPMT_HA *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_KDF_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMT_KDF_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_KEYEDHASH_SCHEME_Marshal(TPMT_KEYEDHASH_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_KEYEDHASH_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMT_KEYEDHASH_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_RSA_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMT_RSA_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMT_SYM_DEF_OBJECT_Unmarshal(const char *yaml, size_t yaml_len, TPMT_SYM_DEF_OBJECT *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_ASYM_SCHEME_Marshal(TPMU_ASYM_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_ASYM_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMU_ASYM_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_ATTEST_Marshal(TPMU_ATTEST const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_ATTEST_Unmarshal(const char *yaml, size_t yaml_len, TPMU_ATTEST *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_CAPABILITIES_Marshal(TPMU_CAPABILITIES const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_CAPABILITIES_Unmarshal(const char *yaml, size_t yaml_len, TPMU_CAPABILITIES *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_HA_Marshal(TPMU_HA const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_HA_Unmarshal(const char *yaml, size_t yaml_len, TPMU_HA *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_KDF_SCHEME_Marshal(TPMU_KDF_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_KDF_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMU_KDF_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_PUBLIC_ID_Marshal(TPMU_PUBLIC_ID const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_PUBLIC_ID_Unmarshal(const char *yaml, size_t yaml_len, TPMU_PUBLIC_ID *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_PUBLIC_PARMS_Marshal(TPMU_PUBLIC_PARMS const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_PUBLIC_PARMS_Unmarshal(const char *yaml, size_t yaml_len, TPMU_PUBLIC_PARMS *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SCHEME_KEYEDHASH_Marshal(TPMU_SCHEME_KEYEDHASH const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SCHEME_KEYEDHASH_Unmarshal(const char *yaml, size_t yaml_len, TPMU_SCHEME_KEYEDHASH *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SENSITIVE_COMPOSITE_Marshal(TPMU_SENSITIVE_COMPOSITE const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SENSITIVE_COMPOSITE_Unmarshal(const char *yaml, size_t yaml_len, TPMU_SENSITIVE_COMPOSITE *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SIGNATURE_Marshal(TPMU_SIGNATURE const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SIGNATURE_Unmarshal(const char *yaml, size_t yaml_len, TPMU_SIGNATURE *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SIG_SCHEME_Marshal(TPMU_SIG_SCHEME const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SIG_SCHEME_Unmarshal(const char *yaml, size_t yaml_len, TPMU_SIG_SCHEME *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SYM_KEY_BITS_Marshal(TPMU_SYM_KEY_BITS const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SYM_KEY_BITS_Unmarshal(const char *yaml, size_t yaml_len, TPMU_SYM_KEY_BITS *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SYM_MODE_Marshal(TPMU_SYM_MODE const *src, char **yaml) { (void)src; (void)yaml; return TSS2_RC_SUCCESS; }
TSS2_RC Tss2_MU_YAML_TPMU_SYM_MODE_Unmarshal(const char *yaml, size_t yaml_len, TPMU_SYM_MODE *dest) { (void)yaml; (void)yaml_len; (void)dest; return TSS2_RC_SUCCESS; }


