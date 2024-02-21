/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "util/aux_util.h"

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

static int yaml_add_yaml_64(yaml_document_t *doc, const yaml_64 *data) {

    /*
     * 8 bytes for 64 bit nums, times two for 2 chars per byte in hex,
     * and a nul byte and extra bytes for the fmt string
     */
    char buf[128] = { 0 };

    const char *fmt = NULL;
    switch(data->base) {
    case 10:
        fmt = data->sign ? "%"PRIi64 : "%"PRIu64;
        break;
    case 16:
        fmt = "0x%"PRIx64;
        break;
    default:
        LOG_ERROR("Cannot handle integer base: %u", data->base);
        return 0;
    }

    snprintf(buf, sizeof(buf), fmt, data->u);

    /* prevents something like !!int always being tagged on ints unless canonical is set */
    // TODO: DO WE WANT CANNONICAL SUPPORT? yaml_char_t *tag = doc->canonical ? YAML_INT_TAG : YAML_STR_TAG;
    return yaml_document_add_scalar(doc, (yaml_char_t *)YAML_STR_TAG, \
                        (yaml_char_t *)buf, -1, YAML_ANY_SCALAR_STYLE);
}

static char *bin2hex(const uint8_t *buffer, size_t size) {
    char *hex_string = malloc((size) * 2 + 1);
    return_if_null(hex_string, "Out of memory.", NULL);

    if (size > 0) {
        size_t i, off;
        for (i = 0, off = 0; i < size; i++, off += 2)
            sprintf(&hex_string[off], "%02x", buffer[i]);
    }
    hex_string[(size) * 2] = '\0';

    return hex_string;
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

static TSS2_RC hex2bin(const char *hex, uint8_t *buffer, UINT16 *size) {
    assert(size);
    assert(hex);
    UINT16 max = *size;

    if (*size == 0 ) {
        return TSS2_RC_SUCCESS;
    }

    char c = hex[0];
    UINT16 i, offset;
    unsigned val;
    TSS2_RC rc;
    for(i=0, offset=0; c != '\0'; i++, c = hex[i]) {
        if (offset > max) {
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

    *size = offset;

    return TSS2_RC_SUCCESS;
}


static int yaml_add_tpm2b(yaml_document_t *doc, const TPM2B *data) {

    char *h = bin2hex(data->buffer, data->size);
    if (!h) {
        return TSS2_MU_RC_MEMORY;
    }

    int node = yaml_document_add_scalar(doc, (yaml_char_t *)YAML_STR_TAG,
            h, -1, YAML_ANY_SCALAR_STYLE);
    free(h);

    return node;
}

static int add_datum(yaml_document_t *doc, const datum *d) {
    int value = 0;
    switch (d->type) {
    case data_type_ep_tpm2b:
        value = yaml_add_tpm2b(doc, d->as.ep_tpm2b);
        break;
    case data_type_str:
        value = yaml_add_str(doc, d->as.str);
        break;
    case data_type_e_y64:
        if (d->as.e_y64.tostring) {
            assert (d->as.e_y64.sign == 0);
            char *s = NULL;
            TSS2_RC rc = d->as.e_y64.tostring(d->as.e_y64.u, &s);
            if (rc == TSS2_MU_RC_BAD_VALUE) {
                value = yaml_add_yaml_64(doc, &d->as.e_y64);
            } else if (rc != TSS2_RC_SUCCESS) {
                return 0;
            } else {
                value = yaml_add_str(doc, s);
                free(s);
            }
        } else {
            value = yaml_add_yaml_64(doc, &d->as.e_y64);
        }
        break;
    default:
        LOG_ERROR("Unknown type: %u", d->type);
        return 0;
    }

    return value;
}

TSS2_RC add_kvp(yaml_document_t *doc, int root, const key_value *k) {

    // TODO WHAT TO DO WITH EMPTY TPM2Bs
    if (k->value.type == data_type_ep_tpm2b && k->value.as.ep_tpm2b->size == 0) {
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

    // TODO WHAT TO DO WITH EMPTY TPM2Bs
    if (d->type == data_type_ep_tpm2b && d->as.ep_tpm2b->size == 0) {
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

static TSS2_RC handle_scalar(const yaml_event_t *e, key_value *dest, size_t dest_len, parser_state *state) {

    if (!(state->state == parser_state_key ||
            state->state == parser_state_value)) {
        return TSS2_MU_RC_GENERAL_FAILURE;
    }

    /* need a key */
    if (state->state == parser_state_key) {
        /* current should only be set if we're processing a kvp entry */
        assert(!state->cur);

        size_t i = 0;
        for (i=0; i < dest_len; i++) {
            key_value *c = &dest[i];
            if (strcmp(e->data.scalar.value, c->key)) {
                /* no match loop up */
                continue;
            }

            /* match update cur and state */
            state->cur = c;
            state->state = parser_state_value;
            break;
        }

        if (!state->cur) {
            LOG_ERROR("Could not match: %s", e->data.scalar.value);
            return TSS2_MU_RC_BAD_VALUE;
        }

        /* assert we transitioned the state machine */
        assert(state->cur);
        assert(state->state == parser_state_value);
        return TSS2_RC_SUCCESS;
    }

    /* handling the value */
    if (state->state == parser_state_value) {
        assert(state->cur);

        TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE;

        switch(state->cur->value.type) {
            case data_type_ep_tpm2b:
                rc = hex2bin(e->data.scalar.value,
                        state->cur->value.as.ep_tpm2b->buffer,
                        &state->cur->value.as.ep_tpm2b->size);
                break;
            default:
                LOG_ERROR("Cannot handle type: %d", state->cur->value.type);
                return TSS2_MU_RC_BAD_VALUE;
        }

        /* keep track of many of the kvps we have processed, we should never fall short */
        if (rc == TSS2_RC_SUCCESS) {
            state->handled++;
        }

        /* after we get a key value for a mapping we transition to mapping end */
        state->state = parser_state_mapping_end;
        state->cur = NULL; /* this is cleared as we're done processing this kvp map */

        return rc;
    }

    /* unknown state */
    LOG_ERROR("Unknown parser state: %d", state->state);
    return TSS2_MU_RC_GENERAL_FAILURE;
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
            /* if we're looking for a key, we shouldn't hit another mapping */
            if (state->state != parser_state_initial) {
                return TSS2_MU_RC_GENERAL_FAILURE;
            }
            /* start looking for the key */
            state->state = parser_state_key;
            return TSS2_RC_SUCCESS;
        case YAML_MAPPING_END_EVENT:
            /*
             * We better end a mapping event after getting the value OR
             * the mapping better be empty
             */
            if (!(state->state == parser_state_mapping_end ||
                    state->state == parser_state_key)) {
                return TSS2_MU_RC_GENERAL_FAILURE;
            }
            /* back to handling anything */
            state->state = parser_state_initial;
            return TSS2_RC_SUCCESS;

        /* Data, could be a key or value */
        case YAML_SCALAR_EVENT:
            return handle_scalar(e, dest, dest_len, state);
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

TSS2_RC TPM2_ALG_ID_tostring(uint64_t id, char **str) {

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

TSS2_RC TPM2_ALG_ID_fromstring(char *alg, datum *value) {

    assert(value->type == data_type_p_y16);
    TPM2_ALG_ID *d = value->as.p_y16.u;

    size_t i;
    for (i=0; i < ARRAY_LEN(alg_table); i++) {
        if (alg_table[i].value == alg) {
            *d = alg_table[i].id;
            return TSS2_RC_SUCCESS;
        }
    }

    return TSS2_MU_RC_BAD_VALUE;
}

TSS2_RC TPMA_ALGORITHM_tostring(uint64_t details, char **str) {

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

TSS2_RC TPMA_ALGORITHM_fromstring(char *str, datum *value) {

    char *saveptr;
    char *token = strtok_r(str, ",", &saveptr);

    assert(value->type == data_type_p_y32);
    TPMA_ALGORITHM *d = value->as.p_y32.u;

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
