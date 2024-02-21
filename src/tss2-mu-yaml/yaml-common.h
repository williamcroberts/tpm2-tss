/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_TSS2_MU_YAML_YAML_COMMON_H_
#define SRC_TSS2_MU_YAML_YAML_COMMON_H_

#include <yaml.h>

#include "util/tpm2b.h"

#include "yaml-common.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE yaml_marshal
#include "util/log.h"

typedef enum data_type data_type;
enum data_type {
    data_type_none = 0,
    data_type_str, // TODO unused thusfar
    /* _p_ types are pointers to yaml types for parsing */
    data_type_p_y8,
    data_type_p_y16,
    data_type_p_y32,
    data_type_p_y64,
    /* _e_ are for emitting scalar types, allows for a u8 to be promoted, which is always safe */
    data_type_e_y64,
    /* _ep_ work as emitting or parsing types */
    data_type_ep_tpm2b,
    data_type_error
};

typedef struct key_value key_value;
typedef struct datum datum;

typedef TSS2_RC (*yaml_fromstring)(const char *data, datum *value);
typedef TSS2_RC (*yaml_tostring)(uint64_t data, char **value);

typedef struct yaml_p8 yaml_p8;
struct yaml_p8 {
    int sign;
    union {
        uint8_t *u;
        int8_t *s;
    };
};

typedef struct yaml_p16 yaml_p16;
struct yaml_p16 {
    int sign;
    union {
        uint16_t *u;
        int16_t *s;
    };
};

typedef struct yaml_p32 yaml_p32;
struct yaml_p32 {
    int sign;
    union {
        uint32_t *u;
        int32_t *s;
    };
};

typedef struct yaml_p64 yaml_p64;
struct yaml_p64 {
    int sign;
    union {
        uint64_t *u;
        int64_t *s;
    };
};

typedef struct yaml_64 yaml_64;
struct yaml_64 {
    int sign;
    unsigned base;
    yaml_tostring tostring;
    union {
        uint64_t u;
        int64_t s;
    };
};

struct datum {
    data_type type;
    yaml_fromstring fromstring;
    union {
        char *str; // TODO used
        TPM2B *ep_tpm2b; /* Suitable for emitting or parsing */
        yaml_p8 p_y8;  /* Suitable for parsing ONLY */
        yaml_p16 p_y16; /* Suitable for parsing ONLY */
        yaml_p32 p_y32; /* Suitable for parsing ONLY */
        yaml_p64 p_y64; /* Suitable for parsing ONLY */
        yaml_64 e_y64;  /* Suitable for emitting ONLY */
    } as;
};

struct key_value {
    const char *key;
    datum value;
};

typedef struct write_data write_data;
struct write_data {
    char *buffer;
    size_t cur_size;
    size_t cur_offset;
};

typedef struct parser_state parser_state;

typedef TSS2_RC(*parser_handler)(const char *data, key_value *dest, size_t dest_len, parser_state *state);

struct parser_state {
    parser_handler handler;
    key_value *cur;
    size_t offset;
    size_t handled;
};

// TODO USED?
//#define KVP_ADD_STR(k, v)   {.key = k, .value = { .type = data_type_str,   .as = { .str = v}}}

/* Adding key values to the list for emitting (generating YAML) */
#define KVP_ADD_SINT(k, v)  {.key = k, .value = { .type = data_type_e_y64,.as = { .e_y64 = { .sign = 1, .s = v, .base = 10 )}}}
#define KVP_ADD_UINT(k, v)  {.key = k, .value = { .type = data_type_e_y64, .as = { .e_y64 = { .sign = 0, .u = v, .base = 10 }}}}
#define KVP_ADD_UINT_TOSTRING(k, v, s)  {.key = k, .value = { .type = data_type_e_y64,   .as = { .e_y64 = { .tostring = s, .sign = 0, .u = v, .base = 16 }}}}

/* Adding key values to the list for parsing (consuming YAML) */
#define KVP_ADD_PARSER_SCALAR_U16(k, v, h) {.key = k, .value = { .type = data_type_p_y16, .fromstring = h, .as = { .p_y16 = { .sign = 0, .u = v }}}}
#define KVP_ADD_PARSER_SCALAR_U32(k, v, h) {.key = k, .value = { .type = data_type_p_y32, .fromstring = h, .as = { .p_y32 = { .sign = 0, .u = v }}}}

/* Adding key values to the list for parsing or emitting */
#define KVP_ADD_TPM2B(k, v) {.key = k, .value = { .type = data_type_ep_tpm2b, .as = { .ep_tpm2b = (TPM2B *)v}}}

#define return_yaml_rc(rc) do { if (!rc) { return yaml_to_tss2_rc(rc); } } while (0)

#define MAX_LEN_STATIC_INIT(var, field)  { .size = sizeof(var.field) };

static inline TSS2_RC yaml_to_tss2_rc(int x) {
    return x ? TSS2_RC_SUCCESS : TSS2_MU_RC_GENERAL_FAILURE;
}

TSS2_RC doc_init(yaml_document_t *doc);

//TSS2_RC add_mapping_root_with_items(yaml_document_t *doc, int root,
//        const char *mapkey, const key_value *kvs, size_t len);
//
//TSS2_RC add_sequence_root_with_items(yaml_document_t *doc, int root,
//        const char *mapkey, const datum *lst, size_t len);

TSS2_RC add_kvp(yaml_document_t *doc, int root, const key_value *k);
TSS2_RC add_kvp_list(yaml_document_t *doc, int root, const key_value *kvs, size_t len);

TSS2_RC yaml_dump(yaml_document_t *doc, char **output);

TSS2_RC yaml_parse(const char *yaml, size_t size, key_value *dest, size_t dest_len);

TSS2_RC TPM2_ALG_ID_tostring(uint64_t id, char **str);
TSS2_RC TPM2_ALG_ID_fromstring(const char *alg, datum *value);

TSS2_RC TPMA_ALGORITHM_tostring(uint64_t details, char **str);
TSS2_RC TPMA_ALGORITHM_fromstring(const char *str, datum *value);

#endif /* SRC_TSS2_MU_YAML_YAML_COMMON_H_ */
