/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef SRC_TSS2_MU_YAML_YAML_COMMON_H_
#define SRC_TSS2_MU_YAML_YAML_COMMON_H_

#include <yaml.h>

#include "yaml-common.h"
#include "tss2_tpm2_types.h"

#include "yaml-internal.h"

#define LOGMODULE yaml_marshal
#include "util/log.h"

typedef struct key_value key_value;
typedef struct datum datum;

typedef TSS2_RC (*generic_marshal)(const datum *from, char **to);
typedef TSS2_RC (*generic_unmarshal)(const char *from, size_t yaml_len, datum *to);

struct datum {
    void *data;
    size_t size;
    generic_marshal marshal;
    generic_unmarshal unmarshal;
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

#define FIELD_SIZE(type, field) sizeof(((type *)NULL)->field)
#define FIELD_TYPE(type, field) typeof(((type *)NULL)->field)

/* Adding key values to the list for emitting (generating YAML) */
#define KVP_ADD_MARSHAL(k, s, v, m)    {.key = k, .value = { .data = (void *)v, .size = s, .marshal = m }}
#define KVP_ADD_UNMARSHAL(k, s, v, u)  {.key = k, .value = { .data = (void *)v, .size = s, .unmarshal = u }}

#define return_yaml_rc(rc) do { if (!rc) { return yaml_to_tss2_rc(rc); } } while (0)

static inline TSS2_RC yaml_to_tss2_rc(int x) {
    return x ? TSS2_RC_SUCCESS : TSS2_MU_RC_GENERAL_FAILURE;
}

TSS2_RC doc_init(yaml_document_t *doc);


TSS2_RC add_kvp(yaml_document_t *doc, int root, const key_value *k);

TSS2_RC add_kvp_list(yaml_document_t *doc, int root, const key_value *kvs, size_t len);

TSS2_RC yaml_dump(yaml_document_t *doc, char **output);

TSS2_RC yaml_parse(const char *yaml, size_t size, key_value *dest, size_t dest_len);

TSS2_RC tpm2b_simple_generic_marshal(const datum *in, char **out);
TSS2_RC tpm2b_simple_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_common_generic_marshal(const datum *data, char **out);
TSS2_RC yaml_common_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_common_scalar_int8_t_marshal(int8_t in, char **out);
TSS2_RC yaml_common_scalar_uint8_t_marshal(uint8_t in, char **out);
TSS2_RC yaml_common_scalar_int16_t_marshal(int16_t in, char **out);
TSS2_RC yaml_common_scalar_uint16_t_marshal(uint16_t in, char **out);
TSS2_RC yaml_common_scalar_int32_t_marshal(int32_t in, char **out);
TSS2_RC yaml_common_scalar_uint32_t_marshal(uint32_t in, char **out);
TSS2_RC yaml_common_scalar_int64_t_marshal(int64_t in, char **out);
TSS2_RC yaml_common_scalar_uint64_t_marshal(uint64_t in, char **out);

TSS2_RC yaml_common_scalar_int8_t_unmarshal(const char *in, size_t len, int8_t *out);
TSS2_RC yaml_common_scalar_uint8_t_unmarshal(const char *in, size_t len, uint8_t *out);
TSS2_RC yaml_common_scalar_int16_t_unmarshal(const char *in, size_t len, int16_t *out);
TSS2_RC yaml_common_scalar_uint16_t_unmarshal(const char *in, size_t len, uint16_t *out);
TSS2_RC yaml_common_scalar_int32_t_unmarshal(const char *in, size_t len, int32_t *out);
TSS2_RC yaml_common_scalar_uint32_t_unmarshal(const char *in, size_t len, uint32_t *out);
TSS2_RC yaml_common_scalar_int64_t_unmarshal(const char *in, size_t len, int64_t *out);
TSS2_RC yaml_common_scalar_uint64_t_unmarshal(const char *in, size_t len, uint64_t *out);

TSS2_RC TPM2_ALG_ID_generic_marshal(const datum *in, char **out);
TSS2_RC TPM2_ALG_ID_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC TPMA_ALGORITHM_generic_marshal(const datum *in, char **out);
TSS2_RC TPMA_ALGORITHM_generic_unmarshal(const char *in, size_t len, datum *out);

#endif /* SRC_TSS2_MU_YAML_YAML_COMMON_H_ */
