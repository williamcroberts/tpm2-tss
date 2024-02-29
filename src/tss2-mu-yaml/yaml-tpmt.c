/* SPDX-License-Identifier: BSD-2-Clause */
/* AUTOGENRATED CODE DO NOT MODIFY */

#include <stdlib.h>

#include "yaml-common.h"



TSS2_RC
Tss2_MU_YAML_TPMT_HA_Marshal(
    TPMT_HA const *src,
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
        KVP_ADD_MARSHAL("hashAlg", 0, NULL, NULL),
        KVP_ADD_MARSHAL("digest", sizeof(src->digest), &src->digest, yaml_internal_TPMU_HA_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_HA_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_HA   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_HA tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("hashAlg", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("digest", sizeof(tmp_dest.digest), &tmp_dest.digest, yaml_internal_TPMU_HA_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_TK_CREATION_Marshal(
    TPMT_TK_CREATION const *src,
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
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_internal_uint16_t_scalar_marshal),
        KVP_ADD_MARSHAL("hierarchy", sizeof(src->hierarchy), &src->hierarchy, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("digest", sizeof(src->digest), &src->digest, yaml_internal_TPM2B_DIGEST_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_TK_CREATION_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_TK_CREATION   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_TK_CREATION tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_internal_uint16_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("hierarchy", sizeof(tmp_dest.hierarchy), &tmp_dest.hierarchy, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("digest", sizeof(tmp_dest.digest), &tmp_dest.digest, yaml_internal_TPM2B_DIGEST_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_TK_VERIFIED_Marshal(
    TPMT_TK_VERIFIED const *src,
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
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_internal_uint16_t_scalar_marshal),
        KVP_ADD_MARSHAL("hierarchy", sizeof(src->hierarchy), &src->hierarchy, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("digest", sizeof(src->digest), &src->digest, yaml_internal_TPM2B_DIGEST_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_TK_VERIFIED_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_TK_VERIFIED   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_TK_VERIFIED tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_internal_uint16_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("hierarchy", sizeof(tmp_dest.hierarchy), &tmp_dest.hierarchy, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("digest", sizeof(tmp_dest.digest), &tmp_dest.digest, yaml_internal_TPM2B_DIGEST_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_TK_AUTH_Marshal(
    TPMT_TK_AUTH const *src,
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
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_internal_uint16_t_scalar_marshal),
        KVP_ADD_MARSHAL("hierarchy", sizeof(src->hierarchy), &src->hierarchy, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("digest", sizeof(src->digest), &src->digest, yaml_internal_TPM2B_DIGEST_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_TK_AUTH_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_TK_AUTH   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_TK_AUTH tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_internal_uint16_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("hierarchy", sizeof(tmp_dest.hierarchy), &tmp_dest.hierarchy, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("digest", sizeof(tmp_dest.digest), &tmp_dest.digest, yaml_internal_TPM2B_DIGEST_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_TK_HASHCHECK_Marshal(
    TPMT_TK_HASHCHECK const *src,
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
        KVP_ADD_MARSHAL("tag", sizeof(src->tag), &src->tag, yaml_internal_uint16_t_scalar_marshal),
        KVP_ADD_MARSHAL("hierarchy", sizeof(src->hierarchy), &src->hierarchy, yaml_internal_uint32_t_scalar_marshal),
        KVP_ADD_MARSHAL("digest", sizeof(src->digest), &src->digest, yaml_internal_TPM2B_DIGEST_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_TK_HASHCHECK_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_TK_HASHCHECK   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_TK_HASHCHECK tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("tag", sizeof(tmp_dest.tag), &tmp_dest.tag, yaml_internal_uint16_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("hierarchy", sizeof(tmp_dest.hierarchy), &tmp_dest.hierarchy, yaml_internal_uint32_t_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("digest", sizeof(tmp_dest.digest), &tmp_dest.digest, yaml_internal_TPM2B_DIGEST_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_SYM_DEF_Marshal(
    TPMT_SYM_DEF const *src,
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
        KVP_ADD_MARSHAL("algorithm", 0, NULL, NULL),
        KVP_ADD_MARSHAL("keyBits", sizeof(src->keyBits), &src->keyBits, yaml_internal_TPMU_SYM_KEY_BITS_marshal),
        KVP_ADD_MARSHAL("mode", sizeof(src->mode), &src->mode, yaml_internal_TPMU_SYM_MODE_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_SYM_DEF_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_SYM_DEF   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_SYM_DEF tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("algorithm", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("keyBits", sizeof(tmp_dest.keyBits), &tmp_dest.keyBits, yaml_internal_TPMU_SYM_KEY_BITS_unmarshal),
        KVP_ADD_UNMARSHAL("mode", sizeof(tmp_dest.mode), &tmp_dest.mode, yaml_internal_TPMU_SYM_MODE_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_SYM_DEF_OBJECT_Marshal(
    TPMT_SYM_DEF_OBJECT const *src,
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
        KVP_ADD_MARSHAL("algorithm", 0, NULL, NULL),
        KVP_ADD_MARSHAL("keyBits", sizeof(src->keyBits), &src->keyBits, yaml_internal_TPMU_SYM_KEY_BITS_marshal),
        KVP_ADD_MARSHAL("mode", sizeof(src->mode), &src->mode, yaml_internal_TPMU_SYM_MODE_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_SYM_DEF_OBJECT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_SYM_DEF_OBJECT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_SYM_DEF_OBJECT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("algorithm", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("keyBits", sizeof(tmp_dest.keyBits), &tmp_dest.keyBits, yaml_internal_TPMU_SYM_KEY_BITS_unmarshal),
        KVP_ADD_UNMARSHAL("mode", sizeof(tmp_dest.mode), &tmp_dest.mode, yaml_internal_TPMU_SYM_MODE_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_KEYEDHASH_SCHEME_Marshal(
    TPMT_KEYEDHASH_SCHEME const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_SCHEME_KEYEDHASH_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_KEYEDHASH_SCHEME_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_KEYEDHASH_SCHEME   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_KEYEDHASH_SCHEME tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_SCHEME_KEYEDHASH_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_SIG_SCHEME_Marshal(
    TPMT_SIG_SCHEME const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_SIG_SCHEME_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_SIG_SCHEME_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_SIG_SCHEME   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_SIG_SCHEME tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_SIG_SCHEME_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_KDF_SCHEME_Marshal(
    TPMT_KDF_SCHEME const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_KDF_SCHEME_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_KDF_SCHEME_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_KDF_SCHEME   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_KDF_SCHEME tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_KDF_SCHEME_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_ASYM_SCHEME_Marshal(
    TPMT_ASYM_SCHEME const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_ASYM_SCHEME_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_ASYM_SCHEME_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_ASYM_SCHEME   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_ASYM_SCHEME tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_ASYM_SCHEME_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_RSA_SCHEME_Marshal(
    TPMT_RSA_SCHEME const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_ASYM_SCHEME_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_RSA_SCHEME_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_RSA_SCHEME   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_RSA_SCHEME tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_ASYM_SCHEME_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_RSA_DECRYPT_Marshal(
    TPMT_RSA_DECRYPT const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_ASYM_SCHEME_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_RSA_DECRYPT_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_RSA_DECRYPT   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_RSA_DECRYPT tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_ASYM_SCHEME_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_ECC_SCHEME_Marshal(
    TPMT_ECC_SCHEME const *src,
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
        KVP_ADD_MARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_MARSHAL("details", sizeof(src->details), &src->details, yaml_internal_TPMU_ASYM_SCHEME_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_ECC_SCHEME_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_ECC_SCHEME   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_ECC_SCHEME tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("scheme", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("details", sizeof(tmp_dest.details), &tmp_dest.details, yaml_internal_TPMU_ASYM_SCHEME_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_SIGNATURE_Marshal(
    TPMT_SIGNATURE const *src,
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
        KVP_ADD_MARSHAL("sigAlg", 0, NULL, NULL),
        KVP_ADD_MARSHAL("signature", sizeof(src->signature), &src->signature, yaml_internal_TPMU_SIGNATURE_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_SIGNATURE_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_SIGNATURE   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_SIGNATURE tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("sigAlg", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("signature", sizeof(tmp_dest.signature), &tmp_dest.signature, yaml_internal_TPMU_SIGNATURE_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_PUBLIC_PARMS_Marshal(
    TPMT_PUBLIC_PARMS const *src,
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
        KVP_ADD_MARSHAL("type", 0, NULL, NULL),
        KVP_ADD_MARSHAL("parameters", sizeof(src->parameters), &src->parameters, yaml_internal_TPMU_PUBLIC_PARMS_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_PUBLIC_PARMS_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_PUBLIC_PARMS   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_PUBLIC_PARMS tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("type", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("parameters", sizeof(tmp_dest.parameters), &tmp_dest.parameters, yaml_internal_TPMU_PUBLIC_PARMS_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_PUBLIC_Marshal(
    TPMT_PUBLIC const *src,
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
        KVP_ADD_MARSHAL("type", sizeof(src->type), &src->type, yaml_internal_TPM2_ALG_ID_scalar_marshal),
        KVP_ADD_MARSHAL("nameAlg", sizeof(src->nameAlg), &src->nameAlg, yaml_internal_TPM2_ALG_ID_scalar_marshal),
        KVP_ADD_MARSHAL("objectAttributes", sizeof(src->objectAttributes), &src->objectAttributes, yaml_internal_TPMA_OBJECT_scalar_marshal),
        KVP_ADD_MARSHAL("authPolicy", sizeof(src->authPolicy), &src->authPolicy, yaml_internal_TPM2B_DIGEST_marshal),
        KVP_ADD_MARSHAL("parameters", sizeof(src->parameters), &src->parameters, yaml_internal_TPMU_PUBLIC_PARMS_marshal),
        KVP_ADD_MARSHAL("unique", sizeof(src->unique), &src->unique, yaml_internal_TPMU_PUBLIC_ID_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_PUBLIC_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_PUBLIC   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_PUBLIC tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("type", sizeof(tmp_dest.type), &tmp_dest.type, yaml_internal_TPM2_ALG_ID_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("nameAlg", sizeof(tmp_dest.nameAlg), &tmp_dest.nameAlg, yaml_internal_TPM2_ALG_ID_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("objectAttributes", sizeof(tmp_dest.objectAttributes), &tmp_dest.objectAttributes, yaml_internal_TPMA_OBJECT_scalar_unmarshal),
        KVP_ADD_UNMARSHAL("authPolicy", sizeof(tmp_dest.authPolicy), &tmp_dest.authPolicy, yaml_internal_TPM2B_DIGEST_unmarshal),
        KVP_ADD_UNMARSHAL("parameters", sizeof(tmp_dest.parameters), &tmp_dest.parameters, yaml_internal_TPMU_PUBLIC_PARMS_unmarshal),
        KVP_ADD_UNMARSHAL("unique", sizeof(tmp_dest.unique), &tmp_dest.unique, yaml_internal_TPMU_PUBLIC_ID_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}


TSS2_RC
Tss2_MU_YAML_TPMT_SENSITIVE_Marshal(
    TPMT_SENSITIVE const *src,
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
        KVP_ADD_MARSHAL("sensitiveType", 0, NULL, NULL),
        KVP_ADD_MARSHAL("authValue", sizeof(src->authValue), &src->authValue, yaml_internal_TPM2B_AUTH_marshal),
        KVP_ADD_MARSHAL("seedValue", sizeof(src->seedValue), &src->seedValue, yaml_internal_TPM2B_DIGEST_marshal),
        KVP_ADD_MARSHAL("sensitive", sizeof(src->sensitive), &src->sensitive, yaml_internal_TPMU_SENSITIVE_COMPOSITE_marshal)
    };
    rc = add_kvp_list(&doc, root, kvs, ARRAY_LEN(kvs));
    return_if_error(rc, "Could not add KVPs");

    return yaml_dump(&doc, output);
}

TSS2_RC
Tss2_MU_YAML_TPMT_SENSITIVE_Unmarshal(
    const char          *yaml,
    size_t               yaml_len,
    TPMT_SENSITIVE   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE);
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE);

    if (yaml_len == 0) {
        yaml_len = strlen(yaml);
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMT_SENSITIVE tmp_dest = { 0 };

    key_value parsed_data[] = {
        KVP_ADD_UNMARSHAL("sensitiveType", 0, NULL, NULL),
        KVP_ADD_UNMARSHAL("authValue", sizeof(tmp_dest.authValue), &tmp_dest.authValue, yaml_internal_TPM2B_AUTH_unmarshal),
        KVP_ADD_UNMARSHAL("seedValue", sizeof(tmp_dest.seedValue), &tmp_dest.seedValue, yaml_internal_TPM2B_DIGEST_unmarshal),
        KVP_ADD_UNMARSHAL("sensitive", sizeof(tmp_dest.sensitive), &tmp_dest.sensitive, yaml_internal_TPMU_SENSITIVE_COMPOSITE_unmarshal)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}
