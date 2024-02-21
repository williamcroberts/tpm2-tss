/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdlib.h>

#include "yaml-common.h"

#include "util/aux_util.h"

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
    const char          *yaml,
    size_t               yaml_len,
    TPMS_ALG_PROPERTY   *dest) {

    return_if_null(yaml, "buffer is NULL", TSS2_MU_RC_BAD_REFERENCE); \
    return_if_null(dest, "dest is NULL", TSS2_MU_RC_BAD_REFERENCE); \

    if (yaml_len == 0) { \
        yaml_len = strlen(yaml); \
    }

    if (yaml_len == 0) {
        return TSS2_MU_RC_BAD_VALUE;
    }

    TPMS_ALG_PROPERTY tmp_dest = { 0 };

    key_value parsed_data[] = {
            KVP_ADD_PARSER_SCALAR_U16("alg",          &tmp_dest.alg,            TPM2_ALG_ID_fromstring),
            KVP_ADD_PARSER_SCALAR_U32("algProperties", &tmp_dest.algProperties, TPMA_ALGORITHM_fromstring)
    };

    TSS2_RC rc = yaml_parse(yaml, yaml_len, parsed_data, ARRAY_LEN(parsed_data));
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *dest = tmp_dest;

    return TSS2_RC_SUCCESS;
}
