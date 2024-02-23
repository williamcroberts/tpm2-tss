
/* SPDX-License-Identifier: BSD-2-Clause */
/* AUTOGENRATED CODE DO NOT MODIFY */

#include <stdlib.h>

#include "yaml-common.h"

#include "util/aux_util.h"
#include "util/tpm2b.h"

#define SIMPLE_TPM2B_MARSHAL(type, field) \
    TSS2_RC Tss2_MU_YAML_##type##_Marshal( \
            type const *src, \
            char ** yaml \
    ) \
    { \
        TSS2_RC rc = TSS2_MU_RC_GENERAL_FAILURE; \
        yaml_document_t doc = { 0 }; \
        \
        return_if_null(src, "src is NULL", TSS2_MU_RC_BAD_REFERENCE); \
        return_if_null(yaml, "output is NULL", TSS2_MU_RC_BAD_REFERENCE); \
        \
        if (src->size == 0) { \
            return TSS2_MU_RC_BAD_VALUE; \
        } \
        rc = doc_init(&doc); \
        return_if_error(rc, "Could not initialize document"); \
        \
        int root = yaml_document_add_mapping(&doc, NULL, YAML_ANY_MAPPING_STYLE); \
        if (!root) { \
            yaml_document_delete(&doc); \
            return TSS2_MU_RC_GENERAL_FAILURE; \
        } \
        \
        struct key_value kv = KVP_ADD_MARSHAL(#field, src->size, src, tpm2b_simple_generic_marshal); \
        rc = add_kvp(&doc, root, &kv); \
        return_if_error(rc, "Could not add KVP"); \
        \
        return yaml_dump(&doc, yaml); \
    }

#define SIMPLE_TPM2B_UNMARSHAL(type, field) \
        TSS2_RC Tss2_MU_YAML_##type##_Unmarshal( \
            const char  *yaml, \
            size_t       yaml_len, \
            type        *dest) { \
            \
            return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE); \
            return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE); \
            \
            if (yaml_len == 0) { \
                yaml_len = strlen(yaml); \
            } \
            \
            if (yaml_len == 0) { \
                return TSS2_MU_RC_BAD_VALUE; \
            } \
            type tmp_dest = { 0 }; \
            key_value parsed_data = KVP_ADD_UNMARSHAL(#field, FIELD_SIZE(type, field), &tmp_dest, tpm2b_simple_generic_unmarshal); \
            \
            TSS2_RC rc = yaml_parse(yaml, yaml_len, &parsed_data, 1); \
            if (rc == TSS2_RC_SUCCESS) { \
                *dest = tmp_dest; \
            } \
            \
            return rc; \
        }

SIMPLE_TPM2B_MARSHAL(TPM2B_ATTEST, attestationData)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_ATTEST, attestationData)
SIMPLE_TPM2B_MARSHAL(TPM2B_CONTEXT_DATA, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_CONTEXT_DATA, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_CONTEXT_SENSITIVE, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_CONTEXT_SENSITIVE, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_CREATION_DATA, creationData)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_CREATION_DATA, creationData)
SIMPLE_TPM2B_MARSHAL(TPM2B_DATA, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_DATA, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_DERIVE, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_DERIVE, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_DIGEST, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_DIGEST, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_ECC_PARAMETER, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_ECC_PARAMETER, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_ECC_POINT, point)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_ECC_POINT, point)
SIMPLE_TPM2B_MARSHAL(TPM2B_ENCRYPTED_SECRET, secret)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_ENCRYPTED_SECRET, secret)
SIMPLE_TPM2B_MARSHAL(TPM2B_EVENT, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_EVENT, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_ID_OBJECT, credential)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_ID_OBJECT, credential)
SIMPLE_TPM2B_MARSHAL(TPM2B_IV, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_IV, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_LABEL, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_LABEL, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_MAX_BUFFER, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_MAX_BUFFER, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_MAX_CAP_BUFFER, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_MAX_CAP_BUFFER, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_MAX_NV_BUFFER, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_MAX_NV_BUFFER, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_NAME, name)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_NAME, name)
SIMPLE_TPM2B_MARSHAL(TPM2B_NV_PUBLIC, nvPublic)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_NV_PUBLIC, nvPublic)
SIMPLE_TPM2B_MARSHAL(TPM2B_PRIVATE, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_PRIVATE, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_PRIVATE_KEY_RSA, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_PRIVATE_KEY_RSA, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_PRIVATE_VENDOR_SPECIFIC, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_PRIVATE_VENDOR_SPECIFIC, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_PUBLIC, publicArea)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_PUBLIC, publicArea)
SIMPLE_TPM2B_MARSHAL(TPM2B_PUBLIC_KEY_RSA, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_PUBLIC_KEY_RSA, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_SENSITIVE, sensitiveArea)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_SENSITIVE, sensitiveArea)
SIMPLE_TPM2B_MARSHAL(TPM2B_SENSITIVE_CREATE, sensitive)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_SENSITIVE_CREATE, sensitive)
SIMPLE_TPM2B_MARSHAL(TPM2B_SENSITIVE_DATA, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_SENSITIVE_DATA, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_SYM_KEY, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_SYM_KEY, buffer)
SIMPLE_TPM2B_MARSHAL(TPM2B_TEMPLATE, buffer)
SIMPLE_TPM2B_UNMARSHAL(TPM2B_TEMPLATE, buffer)
