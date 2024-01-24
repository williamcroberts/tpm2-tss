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
    data_type_str,
    data_type_y64,
    data_type_tpm2b,
    data_type_error
};

typedef struct yaml_64 yaml_64;
struct yaml_64 {
    int sign;
    unsigned base;
    union {
        uint64_t u;
        int64_t s;
    };
};

typedef struct datum datum;
struct datum {
    data_type type;
    union {
        char *str;
        TPM2B *tpm2b;
        yaml_64 y64;
    } as;
};

typedef struct key_value key_value;
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

typedef enum p_state p_state;
enum p_state {
    parser_state_initial = 0,
    parser_state_key,
    parser_state_value,
    parser_state_mapping_start,
    parser_state_mapping_end,
    parser_state_sequence_start,
    parser_state_sequence_end,
};

typedef struct parser_state parser_state;
struct parser_state {
    p_state state;
    key_value *cur;
    size_t offset;
    size_t handled;
};

#define KVP_ADD_STR(k, v)   {.key = k, .value = { .type = data_type_str,   .as = { str = v}}}
#define KVP_ADD_SINT(k, v)  {.key = k, .value = { .type = data_type_y64,   .as = { .y64 = { .sign = 1, .s = v, .base = 10 )}}}
#define KVP_ADD_UINT(k, v)  {.key = k, .value = { .type = data_type_y64,   .as = { .y64 = { .sign = 0, .u = v, .base = 10 }}}}
#define KVP_ADD_TPM2B(k, v) {.key = k, .value = { .type = data_type_tpm2b, .as = { .tpm2b = (TPM2B *)v}}}

#define return_yaml_rc(rc) do { if (!rc) { return yaml_to_tss2_rc(rc); } } while (0)

#define MAX_LEN_STATIC_INIT(var, field)  { .size = sizeof(var.field) };

static inline TSS2_RC yaml_to_tss2_rc(int x) {
    return x ? TSS2_RC_SUCCESS : TSS2_MU_RC_GENERAL_FAILURE;
}

TSS2_RC doc_init(yaml_document_t *doc);

TSS2_RC add_mapping_root_with_items(yaml_document_t *doc, int root,
        const char *mapkey, const key_value *kvs, size_t len);

TSS2_RC add_sequence_root_with_items(yaml_document_t *doc, int root,
        const char *mapkey, const datum *lst, size_t len);

TSS2_RC add_kvp(yaml_document_t *doc, int root, const key_value *k);

TSS2_RC yaml_dump(yaml_document_t *doc, char **output);

TSS2_RC yaml_parse(const char *yaml, size_t size, key_value *dest, size_t dest_len);

#endif /* SRC_TSS2_MU_YAML_YAML_COMMON_H_ */
