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
        KVP_ADD_MARSHAL("empty", sizeof(src->empty), &src->empty, yaml_common_generic_marshal)
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
        KVP_ADD_UNMARSHAL("empty", sizeof(tmp_dest.empty), &tmp_dest.empty, yaml_common_generic_unmarshal)
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
        KVP_ADD_MARSHAL("sizeofSelect", sizeof(src->sizeofSelect), &src->sizeofSelect, yaml_internal_uint8_t_scalar_marshal),
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_common_generic_marshal)
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
        KVP_ADD_UNMARSHAL("sizeofSelect", sizeof(tmp_dest.sizeofSelect), &tmp_dest.sizeofSelect, yaml_internal_uint8_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_common_generic_unmarshal)
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
        KVP_ADD_MARSHAL("hash", sizeof(src->hash), &src->hash, yaml_internal_uint16_t_scalar_marshal),
        KVP_ADD_MARSHAL("sizeofSelect", sizeof(src->sizeofSelect), &src->sizeofSelect, yaml_internal_uint8_t_scalar_marshal),
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_common_generic_marshal)
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
        KVP_ADD_UNMARSHAL("hash", sizeof(tmp_dest.hash), &tmp_dest.hash, yaml_internal_uint16_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("sizeofSelect", sizeof(tmp_dest.sizeofSelect), &tmp_dest.sizeofSelect, yaml_internal_uint8_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_common_generic_unmarshal)
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
        KVP_ADD_MARSHAL("alg", sizeof(src->alg), &src->alg, yaml_internal_uint16_t_scalar_marshal),
        KVP_ADD_MARSHAL("algProperties", sizeof(src->algProperties), &src->algProperties, yaml_internal_uint32_t_scalar_marshal)
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
        KVP_ADD_UNMARSHAL("alg", sizeof(tmp_dest.alg), &tmp_dest.alg, yaml_internal_uint16_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("algProperties", sizeof(tmp_dest.algProperties), &tmp_dest.algProperties, yaml_internal_uint32_t_scalar_unmarshal)
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
        KVP_ADD_MARSHAL("property", sizeof(src->property), &src->property, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("value", sizeof(src->value), &src->value, yaml_internal_uint32_t_scalar_marshal)
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
        KVP_ADD_UNMARSHAL("property", sizeof(tmp_dest.property), &tmp_dest.property, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("value", sizeof(tmp_dest.value), &tmp_dest.value, yaml_internal_uint32_t_scalar_unmarshal)
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
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("sizeofSelect", sizeof(src->sizeofSelect), &src->sizeofSelect, yaml_internal_uint8_t_scalar_marshal),
        KVP_ADD_MARSHAL("pcrSelect", sizeof(src->pcrSelect), &src->pcrSelect, yaml_common_generic_marshal)
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
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("sizeofSelect", sizeof(tmp_dest.sizeofSelect), &tmp_dest.sizeofSelect, yaml_internal_uint8_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("pcrSelect", sizeof(tmp_dest.pcrSelect), &tmp_dest.pcrSelect, yaml_common_generic_unmarshal)
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
        KVP_ADD_MARSHAL("handle", sizeof(src->handle), &src->handle, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("policyHash", sizeof(src->policyHash), &src->policyHash, yaml_internal_TPMT_HA_marshal)
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
        KVP_ADD_UNMARSHAL("handle", sizeof(tmp_dest.handle), &tmp_dest.handle, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("policyHash", sizeof(tmp_dest.policyHash), &tmp_dest.policyHash, yaml_internal_TPMT_HA_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}
