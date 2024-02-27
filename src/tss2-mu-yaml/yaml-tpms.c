/* SPDX-License-Identifier: BSD-2-Clause */
/* AUTOGENRATED CODE DO NOT MODIFY */

#include <stdlib.h>

#include "yaml-common.h"



TSS2_RC
Tss2_MU_YAML_TPMS_EMPTY_Marshal(
    TPMS_EMPTY const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("empty", sizeof(src->empty), &src->empty, yaml_scalar_UINT8_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_EMPTY_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_EMPTY   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_EMPTY tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("empty", sizeof(tmp_dest.empty), &tmp_dest.empty, yaml_scalar_UINT8_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_PCR_SELECT_Marshal(
    TPMS_PCR_SELECT const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("sizeofSelect", sizeof(src->sizeofSelect), &src->sizeofSelect, yaml_scalar_UINT8_generic_marshal),
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_scalar_BYTE_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_PCR_SELECT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_PCR_SELECT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_PCR_SELECT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("sizeofSelect", sizeof(tmp_dest.sizeofSelect), &tmp_dest.sizeofSelect, yaml_scalar_UINT8_generic_unmarshal),
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_scalar_BYTE_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_PCR_SELECTION_Marshal(
    TPMS_PCR_SELECTION const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("sizeofSelect", sizeof(src->sizeofSelect), &src->sizeofSelect, yaml_scalar_UINT8_generic_marshal),
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_scalar_BYTE_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_PCR_SELECTION_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_PCR_SELECTION   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_PCR_SELECTION tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sizeofSelect", sizeof(tmp_dest.sizeofSelect), &tmp_dest.sizeofSelect, yaml_scalar_UINT8_generic_unmarshal),
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_scalar_BYTE_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("alg", sizeof(src->alg), &src->alg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("algProperties", sizeof(src->algProperties), &src->algProperties, yaml_scalar_TPMA_ALGORITHM_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ALG_PROPERTY_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ALG_PROPERTY   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ALG_PROPERTY tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("alg", sizeof(tmp_dest.alg), &tmp_dest.alg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("algProperties", sizeof(tmp_dest.algProperties), &tmp_dest.algProperties, yaml_scalar_TPMA_ALGORITHM_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_TAGGED_PROPERTY_Marshal(
    TPMS_TAGGED_PROPERTY const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("property", sizeof(src->property), &src->property, yaml_scalar_TPM2_PT_generic_marshal),
        KVP_ADD_MARSHAL("value", sizeof(src->value), &src->value, yaml_scalar_UINT32_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_TAGGED_PROPERTY_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_TAGGED_PROPERTY   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_TAGGED_PROPERTY tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("property", sizeof(tmp_dest.property), &tmp_dest.property, yaml_scalar_TPM2_PT_generic_unmarshal),
        KVP_ADD_UNMARSHAL("value", sizeof(tmp_dest.value), &tmp_dest.value, yaml_scalar_UINT32_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_TAGGED_PCR_SELECT_Marshal(
    TPMS_TAGGED_PCR_SELECT const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_scalar_TPM2_PT_PCR_generic_marshal),
        KVP_ADD_MARSHAL("sizeofSelect", sizeof(src->sizeofSelect), &src->sizeofSelect, yaml_scalar_UINT8_generic_marshal),
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_scalar_BYTE_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_TAGGED_PCR_SELECT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_TAGGED_PCR_SELECT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_TAGGED_PCR_SELECT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_scalar_TPM2_PT_PCR_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sizeofSelect", sizeof(tmp_dest.sizeofSelect), &tmp_dest.sizeofSelect, yaml_scalar_UINT8_generic_unmarshal),
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_scalar_BYTE_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_TAGGED_POLICY_Marshal(
    TPMS_TAGGED_POLICY const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("handle", sizeof(src->handle), &src->handle, yaml_scalar_TPM2_HANDLE_generic_marshal),
        KVP_ADD_MARSHAL("policyHash", sizeof(src->policyHash), &src->policyHash, yaml_scalar_TPMT_HA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_TAGGED_POLICY_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_TAGGED_POLICY   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_TAGGED_POLICY tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("handle", sizeof(tmp_dest.handle), &tmp_dest.handle, yaml_scalar_TPM2_HANDLE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("policyHash", sizeof(tmp_dest.policyHash), &tmp_dest.policyHash, yaml_scalar_TPMT_HA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ACT_DATA_Marshal(
    TPMS_ACT_DATA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("handle", sizeof(src->handle), &src->handle, yaml_scalar_TPM2_HANDLE_generic_marshal),
        KVP_ADD_MARSHAL("timeout", sizeof(src->timeout), &src->timeout, yaml_scalar_UINT32_generic_marshal),
        KVP_ADD_MARSHAL("attributes", sizeof(src->attributes), &src->attributes, yaml_scalar_TPMA_ACT_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ACT_DATA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ACT_DATA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ACT_DATA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("handle", sizeof(tmp_dest.handle), &tmp_dest.handle, yaml_scalar_TPM2_HANDLE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("timeout", sizeof(tmp_dest.timeout), &tmp_dest.timeout, yaml_scalar_UINT32_generic_unmarshal),
        KVP_ADD_UNMARSHAL("attributes", sizeof(tmp_dest.attributes), &tmp_dest.attributes, yaml_scalar_TPMA_ACT_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CAPABILITY_DATA_Marshal(
    TPMS_CAPABILITY_DATA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("capability", sizeof(src->capability), &src->capability, yaml_scalar_TPM2_CAP_generic_marshal),
        KVP_ADD_MARSHAL("data", sizeof(src->data), &src->data, yaml_scalar_TPMU_CAPABILITIES_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CAPABILITY_DATA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CAPABILITY_DATA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CAPABILITY_DATA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("capability", sizeof(tmp_dest.capability), &tmp_dest.capability, yaml_scalar_TPM2_CAP_generic_unmarshal),
        KVP_ADD_UNMARSHAL("data", sizeof(tmp_dest.data), &tmp_dest.data, yaml_scalar_TPMU_CAPABILITIES_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CLOCK_INFO_Marshal(
    TPMS_CLOCK_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("clock", sizeof(src->clock), &src->clock, yaml_scalar_UINT64_generic_marshal),
        KVP_ADD_MARSHAL("resetCount", sizeof(src->resetCount), &src->resetCount, yaml_scalar_UINT32_generic_marshal),
        KVP_ADD_MARSHAL("restartCount", sizeof(src->restartCount), &src->restartCount, yaml_scalar_UINT32_generic_marshal),
        KVP_ADD_MARSHAL("safe", sizeof(src->safe), &src->safe, yaml_scalar_TPMI_YES_NO_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CLOCK_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CLOCK_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CLOCK_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("clock", sizeof(tmp_dest.clock), &tmp_dest.clock, yaml_scalar_UINT64_generic_unmarshal),
        KVP_ADD_UNMARSHAL("resetCount", sizeof(tmp_dest.resetCount), &tmp_dest.resetCount, yaml_scalar_UINT32_generic_unmarshal),
        KVP_ADD_UNMARSHAL("restartCount", sizeof(tmp_dest.restartCount), &tmp_dest.restartCount, yaml_scalar_UINT32_generic_unmarshal),
        KVP_ADD_UNMARSHAL("safe", sizeof(tmp_dest.safe), &tmp_dest.safe, yaml_scalar_TPMI_YES_NO_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_TIME_INFO_Marshal(
    TPMS_TIME_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("time", sizeof(src->time), &src->time, yaml_scalar_UINT64_generic_marshal),
        KVP_ADD_MARSHAL("clockInfo", sizeof(src->clockInfo), &src->clockInfo, yaml_scalar_TPMS_CLOCK_INFO_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_TIME_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_TIME_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_TIME_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("time", sizeof(tmp_dest.time), &tmp_dest.time, yaml_scalar_UINT64_generic_unmarshal),
        KVP_ADD_UNMARSHAL("clockInfo", sizeof(tmp_dest.clockInfo), &tmp_dest.clockInfo, yaml_scalar_TPMS_CLOCK_INFO_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_TIME_ATTEST_INFO_Marshal(
    TPMS_TIME_ATTEST_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("time", sizeof(src->time), &src->time, yaml_scalar_TPMS_TIME_INFO_generic_marshal),
        KVP_ADD_MARSHAL("firmwareVersion", sizeof(src->firmwareVersion), &src->firmwareVersion, yaml_scalar_UINT64_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_TIME_ATTEST_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_TIME_ATTEST_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_TIME_ATTEST_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("time", sizeof(tmp_dest.time), &tmp_dest.time, yaml_scalar_TPMS_TIME_INFO_generic_unmarshal),
        KVP_ADD_UNMARSHAL("firmwareVersion", sizeof(tmp_dest.firmwareVersion), &tmp_dest.firmwareVersion, yaml_scalar_UINT64_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CERTIFY_INFO_Marshal(
    TPMS_CERTIFY_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("name", sizeof(src->name), &src->name, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("qualifiedName", sizeof(src->qualifiedName), &src->qualifiedName, yaml_scalar_TPM2B_NAME_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CERTIFY_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CERTIFY_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CERTIFY_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("name", sizeof(tmp_dest.name), &tmp_dest.name, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("qualifiedName", sizeof(tmp_dest.qualifiedName), &tmp_dest.qualifiedName, yaml_scalar_TPM2B_NAME_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_QUOTE_INFO_Marshal(
    TPMS_QUOTE_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_scalar_TPML_PCR_SELECTION_generic_marshal),
        KVP_ADD_MARSHAL("pcrDigest", sizeof(src->pcrDigest), &src->pcrDigest, yaml_scalar_TPM2B_DIGEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_QUOTE_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_QUOTE_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_QUOTE_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_scalar_TPML_PCR_SELECTION_generic_unmarshal),
        KVP_ADD_UNMARSHAL("pcrDigest", sizeof(tmp_dest.pcrDigest), &tmp_dest.pcrDigest, yaml_scalar_TPM2B_DIGEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_COMMAND_AUDIT_INFO_Marshal(
    TPMS_COMMAND_AUDIT_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("auditCounter", sizeof(src->auditCounter), &src->auditCounter, yaml_scalar_UINT64_generic_marshal),
        KVP_ADD_MARSHAL("digestAlg", sizeof(src->digestAlg), &src->digestAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("auditDigest", sizeof(src->auditDigest), &src->auditDigest, yaml_scalar_TPM2B_DIGEST_generic_marshal),
        KVP_ADD_MARSHAL("commandDigest", sizeof(src->commandDigest), &src->commandDigest, yaml_scalar_TPM2B_DIGEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_COMMAND_AUDIT_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_COMMAND_AUDIT_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_COMMAND_AUDIT_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("auditCounter", sizeof(tmp_dest.auditCounter), &tmp_dest.auditCounter, yaml_scalar_UINT64_generic_unmarshal),
        KVP_ADD_UNMARSHAL("digestAlg", sizeof(tmp_dest.digestAlg), &tmp_dest.digestAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("auditDigest", sizeof(tmp_dest.auditDigest), &tmp_dest.auditDigest, yaml_scalar_TPM2B_DIGEST_generic_unmarshal),
        KVP_ADD_UNMARSHAL("commandDigest", sizeof(tmp_dest.commandDigest), &tmp_dest.commandDigest, yaml_scalar_TPM2B_DIGEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SESSION_AUDIT_INFO_Marshal(
    TPMS_SESSION_AUDIT_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("exclusiveSession", sizeof(src->exclusiveSession), &src->exclusiveSession, yaml_scalar_TPMI_YES_NO_generic_marshal),
        KVP_ADD_MARSHAL("sessionDigest", sizeof(src->sessionDigest), &src->sessionDigest, yaml_scalar_TPM2B_DIGEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SESSION_AUDIT_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SESSION_AUDIT_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SESSION_AUDIT_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("exclusiveSession", sizeof(tmp_dest.exclusiveSession), &tmp_dest.exclusiveSession, yaml_scalar_TPMI_YES_NO_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sessionDigest", sizeof(tmp_dest.sessionDigest), &tmp_dest.sessionDigest, yaml_scalar_TPM2B_DIGEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CREATION_INFO_Marshal(
    TPMS_CREATION_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("objectName", sizeof(src->objectName), &src->objectName, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("creationHash", sizeof(src->creationHash), &src->creationHash, yaml_scalar_TPM2B_DIGEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CREATION_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CREATION_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CREATION_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("objectName", sizeof(tmp_dest.objectName), &tmp_dest.objectName, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("creationHash", sizeof(tmp_dest.creationHash), &tmp_dest.creationHash, yaml_scalar_TPM2B_DIGEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_NV_CERTIFY_INFO_Marshal(
    TPMS_NV_CERTIFY_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("indexName", sizeof(src->indexName), &src->indexName, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("offset", sizeof(src->offset), &src->offset, yaml_scalar_UINT16_generic_marshal),
        KVP_ADD_MARSHAL("nvContents", sizeof(src->nvContents), &src->nvContents, yaml_scalar_TPM2B_MAX_NV_BUFFER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_NV_CERTIFY_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_NV_CERTIFY_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_NV_CERTIFY_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("indexName", sizeof(tmp_dest.indexName), &tmp_dest.indexName, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("offset", sizeof(tmp_dest.offset), &tmp_dest.offset, yaml_scalar_UINT16_generic_unmarshal),
        KVP_ADD_UNMARSHAL("nvContents", sizeof(tmp_dest.nvContents), &tmp_dest.nvContents, yaml_scalar_TPM2B_MAX_NV_BUFFER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_NV_DIGEST_CERTIFY_INFO_Marshal(
    TPMS_NV_DIGEST_CERTIFY_INFO const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("indexName", sizeof(src->indexName), &src->indexName, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("nvDigest", sizeof(src->nvDigest), &src->nvDigest, yaml_scalar_TPM2B_DIGEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_NV_DIGEST_CERTIFY_INFO_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_NV_DIGEST_CERTIFY_INFO   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_NV_DIGEST_CERTIFY_INFO tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("indexName", sizeof(tmp_dest.indexName), &tmp_dest.indexName, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("nvDigest", sizeof(tmp_dest.nvDigest), &tmp_dest.nvDigest, yaml_scalar_TPM2B_DIGEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ATTEST_Marshal(
    TPMS_ATTEST const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("magic", sizeof(src->magic), &src->magic, yaml_scalar_TPM2_GENERATED_generic_marshal),
        KVP_ADD_MARSHAL("type", sizeof(src->type), &src->type, yaml_scalar_TPM2_ST_generic_marshal),
        KVP_ADD_MARSHAL("qualifiedSigner", sizeof(src->qualifiedSigner), &src->qualifiedSigner, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("extraData", sizeof(src->extraData), &src->extraData, yaml_scalar_TPM2B_DATA_generic_marshal),
        KVP_ADD_MARSHAL("clockInfo", sizeof(src->clockInfo), &src->clockInfo, yaml_scalar_TPMS_CLOCK_INFO_generic_marshal),
        KVP_ADD_MARSHAL("firmwareVersion", sizeof(src->firmwareVersion), &src->firmwareVersion, yaml_scalar_UINT64_generic_marshal),
        KVP_ADD_MARSHAL("attested", sizeof(src->attested), &src->attested, yaml_scalar_TPMU_ATTEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ATTEST_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ATTEST   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ATTEST tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("magic", sizeof(tmp_dest.magic), &tmp_dest.magic, yaml_scalar_TPM2_GENERATED_generic_unmarshal),
        KVP_ADD_UNMARSHAL("type", sizeof(tmp_dest.type), &tmp_dest.type, yaml_scalar_TPM2_ST_generic_unmarshal),
        KVP_ADD_UNMARSHAL("qualifiedSigner", sizeof(tmp_dest.qualifiedSigner), &tmp_dest.qualifiedSigner, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("extraData", sizeof(tmp_dest.extraData), &tmp_dest.extraData, yaml_scalar_TPM2B_DATA_generic_unmarshal),
        KVP_ADD_UNMARSHAL("clockInfo", sizeof(tmp_dest.clockInfo), &tmp_dest.clockInfo, yaml_scalar_TPMS_CLOCK_INFO_generic_unmarshal),
        KVP_ADD_UNMARSHAL("firmwareVersion", sizeof(tmp_dest.firmwareVersion), &tmp_dest.firmwareVersion, yaml_scalar_UINT64_generic_unmarshal),
        KVP_ADD_UNMARSHAL("attested", sizeof(tmp_dest.attested), &tmp_dest.attested, yaml_scalar_TPMU_ATTEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_AUTH_COMMAND_Marshal(
    TPMS_AUTH_COMMAND const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("sessionHandle", sizeof(src->sessionHandle), &src->sessionHandle, yaml_scalar_TPM2_HANDLE_generic_marshal),
        KVP_ADD_MARSHAL("nonce", sizeof(src->nonce), &src->nonce, yaml_scalar_TPM2B_NONCE_generic_marshal),
        KVP_ADD_MARSHAL("sessionAttributes", sizeof(src->sessionAttributes), &src->sessionAttributes, yaml_scalar_TPMA_SESSION_generic_marshal),
        KVP_ADD_MARSHAL("hmac", sizeof(src->hmac), &src->hmac, yaml_scalar_TPM2B_AUTH_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_AUTH_COMMAND_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_AUTH_COMMAND   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_AUTH_COMMAND tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("sessionHandle", sizeof(tmp_dest.sessionHandle), &tmp_dest.sessionHandle, yaml_scalar_TPM2_HANDLE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("nonce", sizeof(tmp_dest.nonce), &tmp_dest.nonce, yaml_scalar_TPM2B_NONCE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sessionAttributes", sizeof(tmp_dest.sessionAttributes), &tmp_dest.sessionAttributes, yaml_scalar_TPMA_SESSION_generic_unmarshal),
        KVP_ADD_UNMARSHAL("hmac", sizeof(tmp_dest.hmac), &tmp_dest.hmac, yaml_scalar_TPM2B_AUTH_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_AUTH_RESPONSE_Marshal(
    TPMS_AUTH_RESPONSE const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("nonce", sizeof(src->nonce), &src->nonce, yaml_scalar_TPM2B_NONCE_generic_marshal),
        KVP_ADD_MARSHAL("sessionAttributes", sizeof(src->sessionAttributes), &src->sessionAttributes, yaml_scalar_TPMA_SESSION_generic_marshal),
        KVP_ADD_MARSHAL("hmac", sizeof(src->hmac), &src->hmac, yaml_scalar_TPM2B_AUTH_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_AUTH_RESPONSE_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_AUTH_RESPONSE   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_AUTH_RESPONSE tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("nonce", sizeof(tmp_dest.nonce), &tmp_dest.nonce, yaml_scalar_TPM2B_NONCE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sessionAttributes", sizeof(tmp_dest.sessionAttributes), &tmp_dest.sessionAttributes, yaml_scalar_TPMA_SESSION_generic_unmarshal),
        KVP_ADD_UNMARSHAL("hmac", sizeof(tmp_dest.hmac), &tmp_dest.hmac, yaml_scalar_TPM2B_AUTH_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SYMCIPHER_PARMS_Marshal(
    TPMS_SYMCIPHER_PARMS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("sym", sizeof(src->sym), &src->sym, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SYMCIPHER_PARMS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SYMCIPHER_PARMS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SYMCIPHER_PARMS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("sym", sizeof(tmp_dest.sym), &tmp_dest.sym, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_DERIVE_Marshal(
    TPMS_DERIVE const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("label", sizeof(src->label), &src->label, yaml_scalar_TPM2B_LABEL_generic_marshal),
        KVP_ADD_MARSHAL("context", sizeof(src->context), &src->context, yaml_scalar_TPM2B_LABEL_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_DERIVE_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_DERIVE   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_DERIVE tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("label", sizeof(tmp_dest.label), &tmp_dest.label, yaml_scalar_TPM2B_LABEL_generic_unmarshal),
        KVP_ADD_UNMARSHAL("context", sizeof(tmp_dest.context), &tmp_dest.context, yaml_scalar_TPM2B_LABEL_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SENSITIVE_CREATE_Marshal(
    TPMS_SENSITIVE_CREATE const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("userAuth", sizeof(src->userAuth), &src->userAuth, yaml_scalar_TPM2B_AUTH_generic_marshal),
        KVP_ADD_MARSHAL("data", sizeof(src->data), &src->data, yaml_scalar_TPM2B_SENSITIVE_DATA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SENSITIVE_CREATE_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SENSITIVE_CREATE   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SENSITIVE_CREATE tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("userAuth", sizeof(tmp_dest.userAuth), &tmp_dest.userAuth, yaml_scalar_TPM2B_AUTH_generic_unmarshal),
        KVP_ADD_UNMARSHAL("data", sizeof(tmp_dest.data), &tmp_dest.data, yaml_scalar_TPM2B_SENSITIVE_DATA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_HASH_Marshal(
    TPMS_SCHEME_HASH const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_HASH_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_HASH   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_HASH tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_ECDAA_Marshal(
    TPMS_SCHEME_ECDAA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("count", sizeof(src->count), &src->count, yaml_scalar_UINT16_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_ECDAA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_ECDAA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_ECDAA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("count", sizeof(tmp_dest.count), &tmp_dest.count, yaml_scalar_UINT16_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_HMAC_Marshal(
    TPMS_SCHEME_HMAC const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_HMAC_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_HMAC   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_HMAC tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_XOR_Marshal(
    TPMS_SCHEME_XOR const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("kdf", sizeof(src->kdf), &src->kdf, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_XOR_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_XOR   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_XOR tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("kdf", sizeof(tmp_dest.kdf), &tmp_dest.kdf, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_RSASSA_Marshal(
    TPMS_SIG_SCHEME_RSASSA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_RSASSA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIG_SCHEME_RSASSA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIG_SCHEME_RSASSA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_RSAPSS_Marshal(
    TPMS_SIG_SCHEME_RSAPSS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_RSAPSS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIG_SCHEME_RSAPSS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIG_SCHEME_RSAPSS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_ECDSA_Marshal(
    TPMS_SIG_SCHEME_ECDSA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_ECDSA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIG_SCHEME_ECDSA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIG_SCHEME_ECDSA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_SM2_Marshal(
    TPMS_SIG_SCHEME_SM2 const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_SM2_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIG_SCHEME_SM2   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIG_SCHEME_SM2 tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(
    TPMS_SIG_SCHEME_ECSCHNORR const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIG_SCHEME_ECSCHNORR   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIG_SCHEME_ECSCHNORR tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_ECDAA_Marshal(
    TPMS_SIG_SCHEME_ECDAA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("count", sizeof(src->count), &src->count, yaml_scalar_UINT16_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIG_SCHEME_ECDAA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIG_SCHEME_ECDAA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIG_SCHEME_ECDAA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("count", sizeof(tmp_dest.count), &tmp_dest.count, yaml_scalar_UINT16_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ENC_SCHEME_OAEP_Marshal(
    TPMS_ENC_SCHEME_OAEP const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ENC_SCHEME_OAEP_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ENC_SCHEME_OAEP   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ENC_SCHEME_OAEP tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ENC_SCHEME_RSAES_Marshal(
    TPMS_ENC_SCHEME_RSAES const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("empty", sizeof(src->empty), &src->empty, yaml_scalar_UINT8_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ENC_SCHEME_RSAES_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ENC_SCHEME_RSAES   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ENC_SCHEME_RSAES tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("empty", sizeof(tmp_dest.empty), &tmp_dest.empty, yaml_scalar_UINT8_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_KEY_SCHEME_ECDH_Marshal(
    TPMS_KEY_SCHEME_ECDH const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_KEY_SCHEME_ECDH_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_KEY_SCHEME_ECDH   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_KEY_SCHEME_ECDH tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_KEY_SCHEME_ECMQV_Marshal(
    TPMS_KEY_SCHEME_ECMQV const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_KEY_SCHEME_ECMQV_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_KEY_SCHEME_ECMQV   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_KEY_SCHEME_ECMQV tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_MGF1_Marshal(
    TPMS_SCHEME_MGF1 const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_MGF1_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_MGF1   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_MGF1 tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_KDF1_SP800_56A_Marshal(
    TPMS_SCHEME_KDF1_SP800_56A const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_KDF1_SP800_56A_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_KDF1_SP800_56A   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_KDF1_SP800_56A tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_KDF2_Marshal(
    TPMS_SCHEME_KDF2 const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_KDF2_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_KDF2   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_KDF2 tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_KDF1_SP800_108_Marshal(
    TPMS_SCHEME_KDF1_SP800_108 const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hashAlg", sizeof(src->hashAlg), &src->hashAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SCHEME_KDF1_SP800_108_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SCHEME_KDF1_SP800_108   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SCHEME_KDF1_SP800_108 tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", sizeof(tmp_dest.hashAlg), &tmp_dest.hashAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ECC_POINT_Marshal(
    TPMS_ECC_POINT const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("x", sizeof(src->x), &src->x, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("y", sizeof(src->y), &src->y, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ECC_POINT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ECC_POINT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ECC_POINT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("x", sizeof(tmp_dest.x), &tmp_dest.x, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("y", sizeof(tmp_dest.y), &tmp_dest.y, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ALGORITHM_DETAIL_ECC_Marshal(
    TPMS_ALGORITHM_DETAIL_ECC const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("curveID", sizeof(src->curveID), &src->curveID, yaml_scalar_TPM2_ECC_CURVE_generic_marshal),
        KVP_ADD_MARSHAL("keySize", sizeof(src->keySize), &src->keySize, yaml_scalar_UINT16_generic_marshal),
        KVP_ADD_MARSHAL("kdf", sizeof(src->kdf), &src->kdf, yaml_scalar_TPMT_KDF_SCHEME_generic_marshal),
        KVP_ADD_MARSHAL("sign", sizeof(src->sign), &src->sign, yaml_scalar_TPMT_ECC_SCHEME_generic_marshal),
        KVP_ADD_MARSHAL("p", sizeof(src->p), &src->p, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("a", sizeof(src->a), &src->a, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("b", sizeof(src->b), &src->b, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("gX", sizeof(src->gX), &src->gX, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("gY", sizeof(src->gY), &src->gY, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("n", sizeof(src->n), &src->n, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("h", sizeof(src->h), &src->h, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ALGORITHM_DETAIL_ECC_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ALGORITHM_DETAIL_ECC   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ALGORITHM_DETAIL_ECC tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("curveID", sizeof(tmp_dest.curveID), &tmp_dest.curveID, yaml_scalar_TPM2_ECC_CURVE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("keySize", sizeof(tmp_dest.keySize), &tmp_dest.keySize, yaml_scalar_UINT16_generic_unmarshal),
        KVP_ADD_UNMARSHAL("kdf", sizeof(tmp_dest.kdf), &tmp_dest.kdf, yaml_scalar_TPMT_KDF_SCHEME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sign", sizeof(tmp_dest.sign), &tmp_dest.sign, yaml_scalar_TPMT_ECC_SCHEME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("p", sizeof(tmp_dest.p), &tmp_dest.p, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("a", sizeof(tmp_dest.a), &tmp_dest.a, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("b", sizeof(tmp_dest.b), &tmp_dest.b, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("gX", sizeof(tmp_dest.gX), &tmp_dest.gX, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("gY", sizeof(tmp_dest.gY), &tmp_dest.gY, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("n", sizeof(tmp_dest.n), &tmp_dest.n, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("h", sizeof(tmp_dest.h), &tmp_dest.h, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_RSA_Marshal(
    TPMS_SIGNATURE_RSA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("sig", sizeof(src->sig), &src->sig, yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_RSA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_RSA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_RSA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sig", sizeof(tmp_dest.sig), &tmp_dest.sig, yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_RSASSA_Marshal(
    TPMS_SIGNATURE_RSASSA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("sig", sizeof(src->sig), &src->sig, yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_RSASSA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_RSASSA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_RSASSA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sig", sizeof(tmp_dest.sig), &tmp_dest.sig, yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_RSAPSS_Marshal(
    TPMS_SIGNATURE_RSAPSS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("sig", sizeof(src->sig), &src->sig, yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_RSAPSS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_RSAPSS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_RSAPSS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("sig", sizeof(tmp_dest.sig), &tmp_dest.sig, yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECC_Marshal(
    TPMS_SIGNATURE_ECC const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("signatureR", sizeof(src->signatureR), &src->signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("signatureS", sizeof(src->signatureS), &src->signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECC_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_ECC   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_ECC tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureR", sizeof(tmp_dest.signatureR), &tmp_dest.signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureS", sizeof(tmp_dest.signatureS), &tmp_dest.signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECDSA_Marshal(
    TPMS_SIGNATURE_ECDSA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("signatureR", sizeof(src->signatureR), &src->signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("signatureS", sizeof(src->signatureS), &src->signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECDSA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_ECDSA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_ECDSA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureR", sizeof(tmp_dest.signatureR), &tmp_dest.signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureS", sizeof(tmp_dest.signatureS), &tmp_dest.signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECDAA_Marshal(
    TPMS_SIGNATURE_ECDAA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("signatureR", sizeof(src->signatureR), &src->signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("signatureS", sizeof(src->signatureS), &src->signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECDAA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_ECDAA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_ECDAA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureR", sizeof(tmp_dest.signatureR), &tmp_dest.signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureS", sizeof(tmp_dest.signatureS), &tmp_dest.signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_SM2_Marshal(
    TPMS_SIGNATURE_SM2 const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("signatureR", sizeof(src->signatureR), &src->signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("signatureS", sizeof(src->signatureS), &src->signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_SM2_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_SM2   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_SM2 tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureR", sizeof(tmp_dest.signatureR), &tmp_dest.signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureS", sizeof(tmp_dest.signatureS), &tmp_dest.signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECSCHNORR_Marshal(
    TPMS_SIGNATURE_ECSCHNORR const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("signatureR", sizeof(src->signatureR), &src->signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal),
        KVP_ADD_MARSHAL("signatureS", sizeof(src->signatureS), &src->signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_SIGNATURE_ECSCHNORR_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_SIGNATURE_ECSCHNORR   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_SIGNATURE_ECSCHNORR tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureR", sizeof(tmp_dest.signatureR), &tmp_dest.signatureR, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal),
        KVP_ADD_UNMARSHAL("signatureS", sizeof(tmp_dest.signatureS), &tmp_dest.signatureS, yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_KEYEDHASH_PARMS_Marshal(
    TPMS_KEYEDHASH_PARMS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("scheme", sizeof(src->scheme), &src->scheme, yaml_scalar_TPMT_KEYEDHASH_SCHEME_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_KEYEDHASH_PARMS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_KEYEDHASH_PARMS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_KEYEDHASH_PARMS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", sizeof(tmp_dest.scheme), &tmp_dest.scheme, yaml_scalar_TPMT_KEYEDHASH_SCHEME_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ASYM_PARMS_Marshal(
    TPMS_ASYM_PARMS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("symmetric", sizeof(src->symmetric), &src->symmetric, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_marshal),
        KVP_ADD_MARSHAL("scheme", sizeof(src->scheme), &src->scheme, yaml_scalar_TPMT_ASYM_SCHEME_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ASYM_PARMS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ASYM_PARMS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ASYM_PARMS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("symmetric", sizeof(tmp_dest.symmetric), &tmp_dest.symmetric, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_unmarshal),
        KVP_ADD_UNMARSHAL("scheme", sizeof(tmp_dest.scheme), &tmp_dest.scheme, yaml_scalar_TPMT_ASYM_SCHEME_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_RSA_PARMS_Marshal(
    TPMS_RSA_PARMS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("symmetric", sizeof(src->symmetric), &src->symmetric, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_marshal),
        KVP_ADD_MARSHAL("scheme", sizeof(src->scheme), &src->scheme, yaml_scalar_TPMT_RSA_SCHEME_generic_marshal),
        KVP_ADD_MARSHAL("keyBits", sizeof(src->keyBits), &src->keyBits, yaml_scalar_TPM2_KEY_BITS_generic_marshal),
        KVP_ADD_MARSHAL("exponent", sizeof(src->exponent), &src->exponent, yaml_scalar_UINT32_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_RSA_PARMS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_RSA_PARMS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_RSA_PARMS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("symmetric", sizeof(tmp_dest.symmetric), &tmp_dest.symmetric, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_unmarshal),
        KVP_ADD_UNMARSHAL("scheme", sizeof(tmp_dest.scheme), &tmp_dest.scheme, yaml_scalar_TPMT_RSA_SCHEME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("keyBits", sizeof(tmp_dest.keyBits), &tmp_dest.keyBits, yaml_scalar_TPM2_KEY_BITS_generic_unmarshal),
        KVP_ADD_UNMARSHAL("exponent", sizeof(tmp_dest.exponent), &tmp_dest.exponent, yaml_scalar_UINT32_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ECC_PARMS_Marshal(
    TPMS_ECC_PARMS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("symmetric", sizeof(src->symmetric), &src->symmetric, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_marshal),
        KVP_ADD_MARSHAL("scheme", sizeof(src->scheme), &src->scheme, yaml_scalar_TPMT_ECC_SCHEME_generic_marshal),
        KVP_ADD_MARSHAL("curveID", sizeof(src->curveID), &src->curveID, yaml_scalar_TPM2_ECC_CURVE_generic_marshal),
        KVP_ADD_MARSHAL("kdf", sizeof(src->kdf), &src->kdf, yaml_scalar_TPMT_KDF_SCHEME_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ECC_PARMS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ECC_PARMS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ECC_PARMS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("symmetric", sizeof(tmp_dest.symmetric), &tmp_dest.symmetric, yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_unmarshal),
        KVP_ADD_UNMARSHAL("scheme", sizeof(tmp_dest.scheme), &tmp_dest.scheme, yaml_scalar_TPMT_ECC_SCHEME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("curveID", sizeof(tmp_dest.curveID), &tmp_dest.curveID, yaml_scalar_TPM2_ECC_CURVE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("kdf", sizeof(tmp_dest.kdf), &tmp_dest.kdf, yaml_scalar_TPMT_KDF_SCHEME_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_ID_OBJECT_Marshal(
    TPMS_ID_OBJECT const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("integrityHMAC", sizeof(src->integrityHMAC), &src->integrityHMAC, yaml_scalar_TPM2B_DIGEST_generic_marshal),
        KVP_ADD_MARSHAL("encIdentity", sizeof(src->encIdentity), &src->encIdentity, yaml_scalar_TPM2B_DIGEST_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_ID_OBJECT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ID_OBJECT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ID_OBJECT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("integrityHMAC", sizeof(tmp_dest.integrityHMAC), &tmp_dest.integrityHMAC, yaml_scalar_TPM2B_DIGEST_generic_unmarshal),
        KVP_ADD_UNMARSHAL("encIdentity", sizeof(tmp_dest.encIdentity), &tmp_dest.encIdentity, yaml_scalar_TPM2B_DIGEST_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_NV_PIN_COUNTER_PARAMETERS_Marshal(
    TPMS_NV_PIN_COUNTER_PARAMETERS const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("pinCount", sizeof(src->pinCount), &src->pinCount, yaml_scalar_UINT32_generic_marshal),
        KVP_ADD_MARSHAL("pinLimit", sizeof(src->pinLimit), &src->pinLimit, yaml_scalar_UINT32_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_NV_PIN_COUNTER_PARAMETERS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_NV_PIN_COUNTER_PARAMETERS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_NV_PIN_COUNTER_PARAMETERS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("pinCount", sizeof(tmp_dest.pinCount), &tmp_dest.pinCount, yaml_scalar_UINT32_generic_unmarshal),
        KVP_ADD_UNMARSHAL("pinLimit", sizeof(tmp_dest.pinLimit), &tmp_dest.pinLimit, yaml_scalar_UINT32_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_NV_PUBLIC_Marshal(
    TPMS_NV_PUBLIC const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("nvIndex", sizeof(src->nvIndex), &src->nvIndex, yaml_scalar_TPM2_HANDLE_generic_marshal),
        KVP_ADD_MARSHAL("nameAlg", sizeof(src->nameAlg), &src->nameAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("attributes", sizeof(src->attributes), &src->attributes, yaml_scalar_TPMA_NV_generic_marshal),
        KVP_ADD_MARSHAL("authPolicy", sizeof(src->authPolicy), &src->authPolicy, yaml_scalar_TPM2B_DIGEST_generic_marshal),
        KVP_ADD_MARSHAL("dataSize", sizeof(src->dataSize), &src->dataSize, yaml_scalar_UINT16_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_NV_PUBLIC_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_NV_PUBLIC   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_NV_PUBLIC tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("nvIndex", sizeof(tmp_dest.nvIndex), &tmp_dest.nvIndex, yaml_scalar_TPM2_HANDLE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("nameAlg", sizeof(tmp_dest.nameAlg), &tmp_dest.nameAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("attributes", sizeof(tmp_dest.attributes), &tmp_dest.attributes, yaml_scalar_TPMA_NV_generic_unmarshal),
        KVP_ADD_UNMARSHAL("authPolicy", sizeof(tmp_dest.authPolicy), &tmp_dest.authPolicy, yaml_scalar_TPM2B_DIGEST_generic_unmarshal),
        KVP_ADD_UNMARSHAL("dataSize", sizeof(tmp_dest.dataSize), &tmp_dest.dataSize, yaml_scalar_UINT16_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CONTEXT_DATA_Marshal(
    TPMS_CONTEXT_DATA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("integrity", sizeof(src->integrity), &src->integrity, yaml_scalar_TPM2B_DIGEST_generic_marshal),
        KVP_ADD_MARSHAL("encrypted", sizeof(src->encrypted), &src->encrypted, yaml_scalar_TPM2B_CONTEXT_SENSITIVE_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CONTEXT_DATA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CONTEXT_DATA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CONTEXT_DATA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("integrity", sizeof(tmp_dest.integrity), &tmp_dest.integrity, yaml_scalar_TPM2B_DIGEST_generic_unmarshal),
        KVP_ADD_UNMARSHAL("encrypted", sizeof(tmp_dest.encrypted), &tmp_dest.encrypted, yaml_scalar_TPM2B_CONTEXT_SENSITIVE_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CONTEXT_Marshal(
    TPMS_CONTEXT const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("sequence", sizeof(src->sequence), &src->sequence, yaml_scalar_UINT64_generic_marshal),
        KVP_ADD_MARSHAL("savedHandle", sizeof(src->savedHandle), &src->savedHandle, yaml_scalar_TPM2_HANDLE_generic_marshal),
        KVP_ADD_MARSHAL("hierarchy", sizeof(src->hierarchy), &src->hierarchy, yaml_scalar_TPM2_HANDLE_generic_marshal),
        KVP_ADD_MARSHAL("contextBlob", sizeof(src->contextBlob), &src->contextBlob, yaml_scalar_TPM2B_CONTEXT_DATA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CONTEXT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CONTEXT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CONTEXT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("sequence", sizeof(tmp_dest.sequence), &tmp_dest.sequence, yaml_scalar_UINT64_generic_unmarshal),
        KVP_ADD_UNMARSHAL("savedHandle", sizeof(tmp_dest.savedHandle), &tmp_dest.savedHandle, yaml_scalar_TPM2_HANDLE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("hierarchy", sizeof(tmp_dest.hierarchy), &tmp_dest.hierarchy, yaml_scalar_TPM2_HANDLE_generic_unmarshal),
        KVP_ADD_UNMARSHAL("contextBlob", sizeof(tmp_dest.contextBlob), &tmp_dest.contextBlob, yaml_scalar_TPM2B_CONTEXT_DATA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_CREATION_DATA_Marshal(
    TPMS_CREATION_DATA const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_scalar_TPML_PCR_SELECTION_generic_marshal),
        KVP_ADD_MARSHAL("pcrDigest", sizeof(src->pcrDigest), &src->pcrDigest, yaml_scalar_TPM2B_DIGEST_generic_marshal),
        KVP_ADD_MARSHAL("locality", sizeof(src->locality), &src->locality, yaml_scalar_TPMA_LOCALITY_generic_marshal),
        KVP_ADD_MARSHAL("parentNameAlg", sizeof(src->parentNameAlg), &src->parentNameAlg, yaml_scalar_TPM2_ALG_ID_generic_marshal),
        KVP_ADD_MARSHAL("parentName", sizeof(src->parentName), &src->parentName, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("parentQualifiedName", sizeof(src->parentQualifiedName), &src->parentQualifiedName, yaml_scalar_TPM2B_NAME_generic_marshal),
        KVP_ADD_MARSHAL("outsideInfo", sizeof(src->outsideInfo), &src->outsideInfo, yaml_scalar_TPM2B_DATA_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_CREATION_DATA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_CREATION_DATA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_CREATION_DATA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_scalar_TPML_PCR_SELECTION_generic_unmarshal),
        KVP_ADD_UNMARSHAL("pcrDigest", sizeof(tmp_dest.pcrDigest), &tmp_dest.pcrDigest, yaml_scalar_TPM2B_DIGEST_generic_unmarshal),
        KVP_ADD_UNMARSHAL("locality", sizeof(tmp_dest.locality), &tmp_dest.locality, yaml_scalar_TPMA_LOCALITY_generic_unmarshal),
        KVP_ADD_UNMARSHAL("parentNameAlg", sizeof(tmp_dest.parentNameAlg), &tmp_dest.parentNameAlg, yaml_scalar_TPM2_ALG_ID_generic_unmarshal),
        KVP_ADD_UNMARSHAL("parentName", sizeof(tmp_dest.parentName), &tmp_dest.parentName, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("parentQualifiedName", sizeof(tmp_dest.parentQualifiedName), &tmp_dest.parentQualifiedName, yaml_scalar_TPM2B_NAME_generic_unmarshal),
        KVP_ADD_UNMARSHAL("outsideInfo", sizeof(tmp_dest.outsideInfo), &tmp_dest.outsideInfo, yaml_scalar_TPM2B_DATA_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMS_AC_OUTPUT_Marshal(
    TPMS_AC_OUTPUT const *src,
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

    struct key_value kvs[] = {
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_scalar_TPM_AT_generic_marshal),
        KVP_ADD_MARSHAL("data", sizeof(src->data), &src->data, yaml_scalar_UINT32_generic_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMS_AC_OUTPUT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMS_AC_OUTPUT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_AC_OUTPUT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_scalar_TPM_AT_generic_unmarshal),
        KVP_ADD_UNMARSHAL("data", sizeof(tmp_dest.data), &tmp_dest.data, yaml_scalar_UINT32_generic_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}
