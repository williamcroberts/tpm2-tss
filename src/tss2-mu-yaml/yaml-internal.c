
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include "tss2_mu_yaml.h"
#include "yaml-common.h"
#include "yaml-internal.h"

TSS2_RC yaml_internal_TPM2_PT_PCR_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPM2_PT_PCR) == in->size);

    const TPM2_PT_PCR *d = (const TPM2_PT_PCR *)in->data;
    TPM2_PT_PCR tmp = *d;

    static struct {
        TPM2_PT_PCR key;
        const char *value;
    } lookup[] = {
        {TPM2_PT_PCR_SAVE, "save"},
    {TPM2_PT_PCR_AUTH, "auth"},
    {TPM2_PT_PCR_COUNT, "count"},
    {TPM2_PT_PS_YEAR, "s_year"},
    {TPM2_PT_PCR_POLICY, "policy"},
    {TPM2_PT_PS_LEVEL, "s_level"},
    {TPM2_PT_PERMANENT, "ermanent"},
    {TPM2_PT_PCR_RESET_L0, "reset_l0"},
    {TPM2_PT_PCR_RESET_L1, "reset_l1"},
    {TPM2_PT_PCR_RESET_L2, "reset_l2"},
    {TPM2_PT_PCR_RESET_L3, "reset_l3"},
    {TPM2_PT_PCR_RESET_L4, "reset_l4"},
    {TPM2_PT_PCR_EXTEND_L0, "extend_l0"},
    {TPM2_PT_PCR_EXTEND_L1, "extend_l1"},
    {TPM2_PT_PCR_EXTEND_L2, "extend_l2"},
    {TPM2_PT_PCR_EXTEND_L3, "extend_l3"},
    {TPM2_PT_PCR_EXTEND_L4, "extend_l4"},
    {TPM2_PT_PCR_SELECT_MIN, "select_min"},
    {TPM2_PT_PS_REVISION, "s_revision"},
    {TPM2_PT_PCR_DRTM_RESET, "drtm_reset"},
    {TPM2_PT_PCR_NO_INCREMENT, "no_increment"},
    {TPM2_PT_PS_DAY_OF_YEAR, "s_day_of_year"},
    {TPM2_PT_PS_YEAR, "tpm2_pt_ps_year"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp == lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int32_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2_PT_PCR_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPM2_PT_PCR));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPM2_PT_PCR tmp = 0;
    TPM2_PT_PCR *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPM2_PT_PCR value;
    } lookup[] = {
        {"tpm2_pt_pcr_count", TPM2_PT_PCR_COUNT},
    {"count", TPM2_PT_PCR_COUNT},
    {"tpm2_pt_pcr_select_min", TPM2_PT_PCR_SELECT_MIN},
    {"select_min", TPM2_PT_PCR_SELECT_MIN},
    {"tpm2_pt_ps_family_indicator", TPM2_PT_PS_FAMILY_INDICATOR},
    {"s_family_indicator", TPM2_PT_PS_FAMILY_INDICATOR},
    {"tpm2_pt_ps_level", TPM2_PT_PS_LEVEL},
    {"s_level", TPM2_PT_PS_LEVEL},
    {"tpm2_pt_ps_revision", TPM2_PT_PS_REVISION},
    {"s_revision", TPM2_PT_PS_REVISION},
    {"tpm2_pt_ps_day_of_year", TPM2_PT_PS_DAY_OF_YEAR},
    {"s_day_of_year", TPM2_PT_PS_DAY_OF_YEAR},
    {"tpm2_pt_ps_year", TPM2_PT_PS_YEAR},
    {"s_year", TPM2_PT_PS_YEAR},
    {"tpm2_pt_permanent", TPM2_PT_PERMANENT},
    {"ermanent", TPM2_PT_PERMANENT},
    {"tpm2_pt_pcr_save", TPM2_PT_PCR_SAVE},
    {"save", TPM2_PT_PCR_SAVE},
    {"tpm2_pt_pcr_extend_l0", TPM2_PT_PCR_EXTEND_L0},
    {"extend_l0", TPM2_PT_PCR_EXTEND_L0},
    {"tpm2_pt_pcr_reset_l0", TPM2_PT_PCR_RESET_L0},
    {"reset_l0", TPM2_PT_PCR_RESET_L0},
    {"tpm2_pt_pcr_extend_l1", TPM2_PT_PCR_EXTEND_L1},
    {"extend_l1", TPM2_PT_PCR_EXTEND_L1},
    {"tpm2_pt_pcr_reset_l1", TPM2_PT_PCR_RESET_L1},
    {"reset_l1", TPM2_PT_PCR_RESET_L1},
    {"tpm2_pt_pcr_extend_l2", TPM2_PT_PCR_EXTEND_L2},
    {"extend_l2", TPM2_PT_PCR_EXTEND_L2},
    {"tpm2_pt_pcr_reset_l2", TPM2_PT_PCR_RESET_L2},
    {"reset_l2", TPM2_PT_PCR_RESET_L2},
    {"tpm2_pt_pcr_extend_l3", TPM2_PT_PCR_EXTEND_L3},
    {"extend_l3", TPM2_PT_PCR_EXTEND_L3},
    {"tpm2_pt_pcr_reset_l3", TPM2_PT_PCR_RESET_L3},
    {"reset_l3", TPM2_PT_PCR_RESET_L3},
    {"tpm2_pt_pcr_extend_l4", TPM2_PT_PCR_EXTEND_L4},
    {"extend_l4", TPM2_PT_PCR_EXTEND_L4},
    {"tpm2_pt_pcr_reset_l4", TPM2_PT_PCR_RESET_L4},
    {"reset_l4", TPM2_PT_PCR_RESET_L4},
    {"tpm2_pt_pcr_no_increment", TPM2_PT_PCR_NO_INCREMENT},
    {"no_increment", TPM2_PT_PCR_NO_INCREMENT},
    {"tpm2_pt_pcr_drtm_reset", TPM2_PT_PCR_DRTM_RESET},
    {"drtm_reset", TPM2_PT_PCR_DRTM_RESET},
    {"tpm2_pt_pcr_policy", TPM2_PT_PCR_POLICY},
    {"policy", TPM2_PT_PCR_POLICY},
    {"tpm2_pt_pcr_auth", TPM2_PT_PCR_AUTH},
    {"auth", TPM2_PT_PCR_AUTH}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int32_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMA_ALGORITHM_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPMA_ALGORITHM) == in->size);

    const TPMA_ALGORITHM *d = (const TPMA_ALGORITHM *)in->data;
    TPMA_ALGORITHM tmp = *d;

    static struct {
        TPMA_ALGORITHM key;
        const char *value;
    } lookup[] = {
        {TPMA_ALGORITHM_HASH, "hash"},
    {TPMA_ALGORITHM_OBJECT, "object"},
    {TPMA_ALGORITHM_METHOD, "method"},
    {TPMA_ALGORITHM_SIGNING, "signing"},
    {TPMA_ALGORITHM_SYMMETRIC, "symmetric"},
    {TPMA_ALGORITHM_ASYMMETRIC, "asymmetric"},
    {TPMA_ALGORITHM_ENCRYPTING, "encrypting"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp & lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int32_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMA_ALGORITHM_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPMA_ALGORITHM));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPMA_ALGORITHM tmp = 0;
    TPMA_ALGORITHM *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPMA_ALGORITHM value;
    } lookup[] = {
        {"tpma_algorithm_asymmetric", TPMA_ALGORITHM_ASYMMETRIC},
    {"asymmetric", TPMA_ALGORITHM_ASYMMETRIC},
    {"tpma_algorithm_symmetric", TPMA_ALGORITHM_SYMMETRIC},
    {"symmetric", TPMA_ALGORITHM_SYMMETRIC},
    {"tpma_algorithm_hash", TPMA_ALGORITHM_HASH},
    {"hash", TPMA_ALGORITHM_HASH},
    {"tpma_algorithm_object", TPMA_ALGORITHM_OBJECT},
    {"object", TPMA_ALGORITHM_OBJECT},
    {"tpma_algorithm_signing", TPMA_ALGORITHM_SIGNING},
    {"signing", TPMA_ALGORITHM_SIGNING},
    {"tpma_algorithm_encrypting", TPMA_ALGORITHM_ENCRYPTING},
    {"encrypting", TPMA_ALGORITHM_ENCRYPTING},
    {"tpma_algorithm_method", TPMA_ALGORITHM_METHOD},
    {"method", TPMA_ALGORITHM_METHOD}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int32_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2B_MAX_NV_BUFFER_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_MAX_NV_BUFFER) == in->size);

    const TPM2B_MAX_NV_BUFFER *x = (const TPM2B_MAX_NV_BUFFER *)in->data;

    return Tss2_MU_YAML_TPM2B_MAX_NV_BUFFER_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_MAX_NV_BUFFER_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_MAX_NV_BUFFER) == out->size);

    TPM2B_MAX_NV_BUFFER *x = (TPM2B_MAX_NV_BUFFER *)out->data;

    return Tss2_MU_YAML_TPM2B_MAX_NV_BUFFER_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMS_TIME_INFO_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMS_TIME_INFO) == in->size);

    const TPMS_TIME_INFO *x = (const TPMS_TIME_INFO *)in->data;

    return Tss2_MU_YAML_TPMS_TIME_INFO_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMS_TIME_INFO_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMS_TIME_INFO) == out->size);

    TPMS_TIME_INFO *x = (TPMS_TIME_INFO *)out->data;

    return Tss2_MU_YAML_TPMS_TIME_INFO_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMT_KDF_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_KDF_SCHEME) == in->size);

    const TPMT_KDF_SCHEME *x = (const TPMT_KDF_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMT_KDF_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_KDF_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_KDF_SCHEME) == out->size);

    TPMT_KDF_SCHEME *x = (TPMT_KDF_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMT_KDF_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_CONTEXT_DATA_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_CONTEXT_DATA) == in->size);

    const TPM2B_CONTEXT_DATA *x = (const TPM2B_CONTEXT_DATA *)in->data;

    return Tss2_MU_YAML_TPM2B_CONTEXT_DATA_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_CONTEXT_DATA_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_CONTEXT_DATA) == out->size);

    TPM2B_CONTEXT_DATA *x = (TPM2B_CONTEXT_DATA *)out->data;

    return Tss2_MU_YAML_TPM2B_CONTEXT_DATA_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_SENSITIVE_COMPOSITE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_SENSITIVE_COMPOSITE) == in->size);

    const TPMU_SENSITIVE_COMPOSITE *x = (const TPMU_SENSITIVE_COMPOSITE *)in->data;

    return Tss2_MU_YAML_TPMU_SENSITIVE_COMPOSITE_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_SENSITIVE_COMPOSITE_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_SENSITIVE_COMPOSITE) == out->size);

    TPMU_SENSITIVE_COMPOSITE *x = (TPMU_SENSITIVE_COMPOSITE *)out->data;

    return Tss2_MU_YAML_TPMU_SENSITIVE_COMPOSITE_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_SIGNATURE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_SIGNATURE) == in->size);

    const TPMU_SIGNATURE *x = (const TPMU_SIGNATURE *)in->data;

    return Tss2_MU_YAML_TPMU_SIGNATURE_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_SIGNATURE_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_SIGNATURE) == out->size);

    TPMU_SIGNATURE *x = (TPMU_SIGNATURE *)out->data;

    return Tss2_MU_YAML_TPMU_SIGNATURE_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_KDF_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_KDF_SCHEME) == in->size);

    const TPMU_KDF_SCHEME *x = (const TPMU_KDF_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMU_KDF_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_KDF_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_KDF_SCHEME) == out->size);

    TPMU_KDF_SCHEME *x = (TPMU_KDF_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMU_KDF_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_SIG_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_SIG_SCHEME) == in->size);

    const TPMU_SIG_SCHEME *x = (const TPMU_SIG_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMU_SIG_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_SIG_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_SIG_SCHEME) == out->size);

    TPMU_SIG_SCHEME *x = (TPMU_SIG_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMU_SIG_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_uint16_t_scalar_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(uint16_t) == in->size);

    const uint16_t *x = (const uint16_t *)in->data;

    return yaml_common_scalar_uint16_t_marshal(*x, out);
}

TSS2_RC yaml_internal_uint16_t_scalar_unmarshal(const char *in, size_t len, datum *out)
{
    assert(in);
    return yaml_common_scalar_uint16_t_unmarshal(in, len, (uint16_t *)out->data);
}

TSS2_RC yaml_internal_TPMU_SCHEME_KEYEDHASH_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_SCHEME_KEYEDHASH) == in->size);

    const TPMU_SCHEME_KEYEDHASH *x = (const TPMU_SCHEME_KEYEDHASH *)in->data;

    return Tss2_MU_YAML_TPMU_SCHEME_KEYEDHASH_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_SCHEME_KEYEDHASH_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_SCHEME_KEYEDHASH) == out->size);

    TPMU_SCHEME_KEYEDHASH *x = (TPMU_SCHEME_KEYEDHASH *)out->data;

    return Tss2_MU_YAML_TPMU_SCHEME_KEYEDHASH_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2_ALG_ID_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ALG_ID) == in->size);

    const TPM2_ALG_ID *d = (const TPM2_ALG_ID *)in->data;
    TPM2_ALG_ID tmp = *d;

    static struct {
        TPM2_ALG_ID key;
        const char *value;
    } lookup[] = {
        {TPM2_ALG_RSA, "rsa"},
    {TPM2_ALG_SHA, "sha"},
    {TPM2_ALG_AES, "aes"},
    {TPM2_ALG_XOR, "xor"},
    {TPM2_ALG_SM4, "sm4"},
    {TPM2_ALG_SM2, "sm2"},
    {TPM2_ALG_ECC, "ecc"},
    {TPM2_ALG_CTR, "ctr"},
    {TPM2_ALG_OFB, "ofb"},
    {TPM2_ALG_CBC, "cbc"},
    {TPM2_ALG_CFB, "cfb"},
    {TPM2_ALG_ECB, "ecb"},
    {TPM2_ALG_TDES, "tdes"},
    {TPM2_ALG_SHA1, "sha1"},
    {TPM2_ALG_HMAC, "hmac"},
    {TPM2_ALG_MGF1, "mgf1"},
    {TPM2_ALG_NULL, "null"},
    {TPM2_ALG_OAEP, "oaep"},
    {TPM2_ALG_ECDH, "ecdh"},
    {TPM2_ALG_KDF2, "kdf2"},
    {TPM2_ALG_CMAC, "cmac"},
    {TPM2_ALG_RSAES, "rsaes"},
    {TPM2_ALG_ECDSA, "ecdsa"},
    {TPM2_ALG_ECDAA, "ecdaa"},
    {TPM2_ALG_ECMQV, "ecmqv"},
    {TPM2_ALG_SHA256, "sha256"},
    {TPM2_ALG_SHA384, "sha384"},
    {TPM2_ALG_SHA512, "sha512"},
    {TPM2_ALG_RSASSA, "rsassa"},
    {TPM2_ALG_RSAPSS, "rsapss"},
    {TPM2_ALG_SM3_256, "sm3_256"},
    {TPM2_ALG_CAMELLIA, "camellia"},
    {TPM2_ALG_SHA3_256, "sha3_256"},
    {TPM2_ALG_SHA3_384, "sha3_384"},
    {TPM2_ALG_SHA3_512, "sha3_512"},
    {TPM2_ALG_KEYEDHASH, "keyedhash"},
    {TPM2_ALG_ECSCHNORR, "ecschnorr"},
    {TPM2_ALG_SYMCIPHER, "symcipher"},
    {TPM2_ALG_RSA, "tpm2_alg_rsa"},
    {TPM2_ALG_SHA, "tpm2_alg_sha"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp & lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int16_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2_ALG_ID_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPM2_ALG_ID));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPM2_ALG_ID tmp = 0;
    TPM2_ALG_ID *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPM2_ALG_ID value;
    } lookup[] = {
        {"tpm2_alg_rsa", TPM2_ALG_RSA},
    {"rsa", TPM2_ALG_RSA},
    {"tpm2_alg_tdes", TPM2_ALG_TDES},
    {"tdes", TPM2_ALG_TDES},
    {"tpm2_alg_sha", TPM2_ALG_SHA},
    {"sha", TPM2_ALG_SHA},
    {"tpm2_alg_sha1", TPM2_ALG_SHA1},
    {"sha1", TPM2_ALG_SHA1},
    {"tpm2_alg_hmac", TPM2_ALG_HMAC},
    {"hmac", TPM2_ALG_HMAC},
    {"tpm2_alg_aes", TPM2_ALG_AES},
    {"aes", TPM2_ALG_AES},
    {"tpm2_alg_mgf1", TPM2_ALG_MGF1},
    {"mgf1", TPM2_ALG_MGF1},
    {"tpm2_alg_keyedhash", TPM2_ALG_KEYEDHASH},
    {"keyedhash", TPM2_ALG_KEYEDHASH},
    {"tpm2_alg_xor", TPM2_ALG_XOR},
    {"xor", TPM2_ALG_XOR},
    {"tpm2_alg_sha256", TPM2_ALG_SHA256},
    {"sha256", TPM2_ALG_SHA256},
    {"tpm2_alg_sha384", TPM2_ALG_SHA384},
    {"sha384", TPM2_ALG_SHA384},
    {"tpm2_alg_sha512", TPM2_ALG_SHA512},
    {"sha512", TPM2_ALG_SHA512},
    {"tpm2_alg_null", TPM2_ALG_NULL},
    {"null", TPM2_ALG_NULL},
    {"tpm2_alg_sm3_256", TPM2_ALG_SM3_256},
    {"sm3_256", TPM2_ALG_SM3_256},
    {"tpm2_alg_sm4", TPM2_ALG_SM4},
    {"sm4", TPM2_ALG_SM4},
    {"tpm2_alg_rsassa", TPM2_ALG_RSASSA},
    {"rsassa", TPM2_ALG_RSASSA},
    {"tpm2_alg_rsaes", TPM2_ALG_RSAES},
    {"rsaes", TPM2_ALG_RSAES},
    {"tpm2_alg_rsapss", TPM2_ALG_RSAPSS},
    {"rsapss", TPM2_ALG_RSAPSS},
    {"tpm2_alg_oaep", TPM2_ALG_OAEP},
    {"oaep", TPM2_ALG_OAEP},
    {"tpm2_alg_ecdsa", TPM2_ALG_ECDSA},
    {"ecdsa", TPM2_ALG_ECDSA},
    {"tpm2_alg_ecdh", TPM2_ALG_ECDH},
    {"ecdh", TPM2_ALG_ECDH},
    {"tpm2_alg_ecdaa", TPM2_ALG_ECDAA},
    {"ecdaa", TPM2_ALG_ECDAA},
    {"tpm2_alg_sm2", TPM2_ALG_SM2},
    {"sm2", TPM2_ALG_SM2},
    {"tpm2_alg_ecschnorr", TPM2_ALG_ECSCHNORR},
    {"ecschnorr", TPM2_ALG_ECSCHNORR},
    {"tpm2_alg_ecmqv", TPM2_ALG_ECMQV},
    {"ecmqv", TPM2_ALG_ECMQV},
    {"tpm2_alg_kdf1_sp800_56a", TPM2_ALG_KDF1_SP800_56A},
    {"kdf1_sp800_56a", TPM2_ALG_KDF1_SP800_56A},
    {"tpm2_alg_kdf2", TPM2_ALG_KDF2},
    {"kdf2", TPM2_ALG_KDF2},
    {"tpm2_alg_kdf1_sp800_108", TPM2_ALG_KDF1_SP800_108},
    {"kdf1_sp800_108", TPM2_ALG_KDF1_SP800_108},
    {"tpm2_alg_ecc", TPM2_ALG_ECC},
    {"ecc", TPM2_ALG_ECC},
    {"tpm2_alg_symcipher", TPM2_ALG_SYMCIPHER},
    {"symcipher", TPM2_ALG_SYMCIPHER},
    {"tpm2_alg_camellia", TPM2_ALG_CAMELLIA},
    {"camellia", TPM2_ALG_CAMELLIA},
    {"tpm2_alg_cmac", TPM2_ALG_CMAC},
    {"cmac", TPM2_ALG_CMAC},
    {"tpm2_alg_ctr", TPM2_ALG_CTR},
    {"ctr", TPM2_ALG_CTR},
    {"tpm2_alg_sha3_256", TPM2_ALG_SHA3_256},
    {"sha3_256", TPM2_ALG_SHA3_256},
    {"tpm2_alg_sha3_384", TPM2_ALG_SHA3_384},
    {"sha3_384", TPM2_ALG_SHA3_384},
    {"tpm2_alg_sha3_512", TPM2_ALG_SHA3_512},
    {"sha3_512", TPM2_ALG_SHA3_512},
    {"tpm2_alg_ofb", TPM2_ALG_OFB},
    {"ofb", TPM2_ALG_OFB},
    {"tpm2_alg_cbc", TPM2_ALG_CBC},
    {"cbc", TPM2_ALG_CBC},
    {"tpm2_alg_cfb", TPM2_ALG_CFB},
    {"cfb", TPM2_ALG_CFB},
    {"tpm2_alg_ecb", TPM2_ALG_ECB},
    {"ecb", TPM2_ALG_ECB}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int16_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2B_DATA_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_DATA) == in->size);

    const TPM2B_DATA *x = (const TPM2B_DATA *)in->data;

    return Tss2_MU_YAML_TPM2B_DATA_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_DATA_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_DATA) == out->size);

    TPM2B_DATA *x = (TPM2B_DATA *)out->data;

    return Tss2_MU_YAML_TPM2B_DATA_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_SYM_MODE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_SYM_MODE) == in->size);

    const TPMU_SYM_MODE *x = (const TPMU_SYM_MODE *)in->data;

    return Tss2_MU_YAML_TPMU_SYM_MODE_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_SYM_MODE_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_SYM_MODE) == out->size);

    TPMU_SYM_MODE *x = (TPMU_SYM_MODE *)out->data;

    return Tss2_MU_YAML_TPMU_SYM_MODE_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_NONCE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_NONCE) == in->size);

    const TPM2B_NONCE *x = (const TPM2B_NONCE *)in->data;

    return Tss2_MU_YAML_TPM2B_NONCE_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_NONCE_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_NONCE) == out->size);

    TPM2B_NONCE *x = (TPM2B_NONCE *)out->data;

    return Tss2_MU_YAML_TPM2B_NONCE_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_AUTH_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_AUTH) == in->size);

    const TPM2B_AUTH *x = (const TPM2B_AUTH *)in->data;

    return Tss2_MU_YAML_TPM2B_AUTH_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_AUTH_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_AUTH) == out->size);

    TPM2B_AUTH *x = (TPM2B_AUTH *)out->data;

    return Tss2_MU_YAML_TPM2B_AUTH_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_CAPABILITIES_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_CAPABILITIES) == in->size);

    const TPMU_CAPABILITIES *x = (const TPMU_CAPABILITIES *)in->data;

    return Tss2_MU_YAML_TPMU_CAPABILITIES_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_CAPABILITIES_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_CAPABILITIES) == out->size);

    TPMU_CAPABILITIES *x = (TPMU_CAPABILITIES *)out->data;

    return Tss2_MU_YAML_TPMU_CAPABILITIES_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_LABEL_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_LABEL) == in->size);

    const TPM2B_LABEL *x = (const TPM2B_LABEL *)in->data;

    return Tss2_MU_YAML_TPM2B_LABEL_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_LABEL_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_LABEL) == out->size);

    TPM2B_LABEL *x = (TPM2B_LABEL *)out->data;

    return Tss2_MU_YAML_TPM2B_LABEL_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_CONTEXT_SENSITIVE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_CONTEXT_SENSITIVE) == in->size);

    const TPM2B_CONTEXT_SENSITIVE *x = (const TPM2B_CONTEXT_SENSITIVE *)in->data;

    return Tss2_MU_YAML_TPM2B_CONTEXT_SENSITIVE_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_CONTEXT_SENSITIVE_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_CONTEXT_SENSITIVE) == out->size);

    TPM2B_CONTEXT_SENSITIVE *x = (TPM2B_CONTEXT_SENSITIVE *)out->data;

    return Tss2_MU_YAML_TPM2B_CONTEXT_SENSITIVE_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_PUBLIC_KEY_RSA_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_PUBLIC_KEY_RSA) == in->size);

    const TPM2B_PUBLIC_KEY_RSA *x = (const TPM2B_PUBLIC_KEY_RSA *)in->data;

    return Tss2_MU_YAML_TPM2B_PUBLIC_KEY_RSA_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_PUBLIC_KEY_RSA_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_PUBLIC_KEY_RSA) == out->size);

    TPM2B_PUBLIC_KEY_RSA *x = (TPM2B_PUBLIC_KEY_RSA *)out->data;

    return Tss2_MU_YAML_TPM2B_PUBLIC_KEY_RSA_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_SENSITIVE_DATA_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_SENSITIVE_DATA) == in->size);

    const TPM2B_SENSITIVE_DATA *x = (const TPM2B_SENSITIVE_DATA *)in->data;

    return Tss2_MU_YAML_TPM2B_SENSITIVE_DATA_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_SENSITIVE_DATA_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_SENSITIVE_DATA) == out->size);

    TPM2B_SENSITIVE_DATA *x = (TPM2B_SENSITIVE_DATA *)out->data;

    return Tss2_MU_YAML_TPM2B_SENSITIVE_DATA_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_NAME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_NAME) == in->size);

    const TPM2B_NAME *x = (const TPM2B_NAME *)in->data;

    return Tss2_MU_YAML_TPM2B_NAME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_NAME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_NAME) == out->size);

    TPM2B_NAME *x = (TPM2B_NAME *)out->data;

    return Tss2_MU_YAML_TPM2B_NAME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMT_ASYM_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_ASYM_SCHEME) == in->size);

    const TPMT_ASYM_SCHEME *x = (const TPMT_ASYM_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMT_ASYM_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_ASYM_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_ASYM_SCHEME) == out->size);

    TPMT_ASYM_SCHEME *x = (TPMT_ASYM_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMT_ASYM_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_PUBLIC_PARMS_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_PUBLIC_PARMS) == in->size);

    const TPMU_PUBLIC_PARMS *x = (const TPMU_PUBLIC_PARMS *)in->data;

    return Tss2_MU_YAML_TPMU_PUBLIC_PARMS_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_PUBLIC_PARMS_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_PUBLIC_PARMS) == out->size);

    TPMU_PUBLIC_PARMS *x = (TPMU_PUBLIC_PARMS *)out->data;

    return Tss2_MU_YAML_TPMU_PUBLIC_PARMS_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_uint8_t_scalar_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(uint8_t) == in->size);

    const uint8_t *x = (const uint8_t *)in->data;

    return yaml_common_scalar_uint8_t_marshal(*x, out);
}

TSS2_RC yaml_internal_uint8_t_scalar_unmarshal(const char *in, size_t len, datum *out)
{
    assert(in);
    return yaml_common_scalar_uint8_t_unmarshal(in, len, (uint8_t *)out->data);
}

TSS2_RC yaml_internal_TPMT_SYM_DEF_OBJECT_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_SYM_DEF_OBJECT) == in->size);

    const TPMT_SYM_DEF_OBJECT *x = (const TPMT_SYM_DEF_OBJECT *)in->data;

    return Tss2_MU_YAML_TPMT_SYM_DEF_OBJECT_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_SYM_DEF_OBJECT_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_SYM_DEF_OBJECT) == out->size);

    TPMT_SYM_DEF_OBJECT *x = (TPMT_SYM_DEF_OBJECT *)out->data;

    return Tss2_MU_YAML_TPMT_SYM_DEF_OBJECT_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMT_HA_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_HA) == in->size);

    const TPMT_HA *x = (const TPMT_HA *)in->data;

    return Tss2_MU_YAML_TPMT_HA_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_HA_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_HA) == out->size);

    TPMT_HA *x = (TPMT_HA *)out->data;

    return Tss2_MU_YAML_TPMT_HA_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMA_OBJECT_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPMA_OBJECT) == in->size);

    const TPMA_OBJECT *d = (const TPMA_OBJECT *)in->data;
    TPMA_OBJECT tmp = *d;

    static struct {
        TPMA_OBJECT key;
        const char *value;
    } lookup[] = {
        {TPMA_OBJECT_NODA, "noda"},
    {TPMA_OBJECT_STCLEAR, "stclear"},
    {TPMA_OBJECT_DECRYPT, "decrypt"},
    {TPMA_OBJECT_FIXEDTPM, "fixedtpm"},
    {TPMA_OBJECT_X509SIGN, "x509sign"},
    {TPMA_OBJECT_SVNLIMITED, "svnlimited"},
    {TPMA_OBJECT_RESTRICTED, "restricted"},
    {TPMA_OBJECT_FIXEDPARENT, "fixedparent"},
    {TPMA_OBJECT_USERWITHAUTH, "userwithauth"},
    {TPMA_OBJECT_SIGN_ENCRYPT, "sign_encrypt"},
    {TPMA_OBJECT_ADMINWITHPOLICY, "adminwithpolicy"},
    {TPMA_OBJECT_FIRMWARELIMITED, "firmwarelimited"},
    {TPMA_OBJECT_NODA, "tpma_object_noda"},
    {TPMA_OBJECT_STCLEAR, "tpma_object_stclear"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp & lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int32_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMA_OBJECT_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPMA_OBJECT));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPMA_OBJECT tmp = 0;
    TPMA_OBJECT *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPMA_OBJECT value;
    } lookup[] = {
        {"tpma_object_fixedtpm", TPMA_OBJECT_FIXEDTPM},
    {"fixedtpm", TPMA_OBJECT_FIXEDTPM},
    {"tpma_object_stclear", TPMA_OBJECT_STCLEAR},
    {"stclear", TPMA_OBJECT_STCLEAR},
    {"tpma_object_fixedparent", TPMA_OBJECT_FIXEDPARENT},
    {"fixedparent", TPMA_OBJECT_FIXEDPARENT},
    {"tpma_object_sensitivedataorigin", TPMA_OBJECT_SENSITIVEDATAORIGIN},
    {"sensitivedataorigin", TPMA_OBJECT_SENSITIVEDATAORIGIN},
    {"tpma_object_userwithauth", TPMA_OBJECT_USERWITHAUTH},
    {"userwithauth", TPMA_OBJECT_USERWITHAUTH},
    {"tpma_object_adminwithpolicy", TPMA_OBJECT_ADMINWITHPOLICY},
    {"adminwithpolicy", TPMA_OBJECT_ADMINWITHPOLICY},
    {"tpma_object_firmwarelimited", TPMA_OBJECT_FIRMWARELIMITED},
    {"firmwarelimited", TPMA_OBJECT_FIRMWARELIMITED},
    {"tpma_object_svnlimited", TPMA_OBJECT_SVNLIMITED},
    {"svnlimited", TPMA_OBJECT_SVNLIMITED},
    {"tpma_object_noda", TPMA_OBJECT_NODA},
    {"noda", TPMA_OBJECT_NODA},
    {"tpma_object_encryptedduplication", TPMA_OBJECT_ENCRYPTEDDUPLICATION},
    {"encryptedduplication", TPMA_OBJECT_ENCRYPTEDDUPLICATION},
    {"tpma_object_restricted", TPMA_OBJECT_RESTRICTED},
    {"restricted", TPMA_OBJECT_RESTRICTED},
    {"tpma_object_decrypt", TPMA_OBJECT_DECRYPT},
    {"decrypt", TPMA_OBJECT_DECRYPT},
    {"tpma_object_sign_encrypt", TPMA_OBJECT_SIGN_ENCRYPT},
    {"sign_encrypt", TPMA_OBJECT_SIGN_ENCRYPT},
    {"tpma_object_x509sign", TPMA_OBJECT_X509SIGN},
    {"x509sign", TPMA_OBJECT_X509SIGN}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int32_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMU_SYM_KEY_BITS_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_SYM_KEY_BITS) == in->size);

    const TPMU_SYM_KEY_BITS *x = (const TPMU_SYM_KEY_BITS *)in->data;

    return Tss2_MU_YAML_TPMU_SYM_KEY_BITS_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_SYM_KEY_BITS_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_SYM_KEY_BITS) == out->size);

    TPMU_SYM_KEY_BITS *x = (TPMU_SYM_KEY_BITS *)out->data;

    return Tss2_MU_YAML_TPMU_SYM_KEY_BITS_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMS_CLOCK_INFO_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMS_CLOCK_INFO) == in->size);

    const TPMS_CLOCK_INFO *x = (const TPMS_CLOCK_INFO *)in->data;

    return Tss2_MU_YAML_TPMS_CLOCK_INFO_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMS_CLOCK_INFO_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMS_CLOCK_INFO) == out->size);

    TPMS_CLOCK_INFO *x = (TPMS_CLOCK_INFO *)out->data;

    return Tss2_MU_YAML_TPMS_CLOCK_INFO_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_uint64_t_scalar_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(uint64_t) == in->size);

    const uint64_t *x = (const uint64_t *)in->data;

    return yaml_common_scalar_uint64_t_marshal(*x, out);
}

TSS2_RC yaml_internal_uint64_t_scalar_unmarshal(const char *in, size_t len, datum *out)
{
    assert(in);
    return yaml_common_scalar_uint64_t_unmarshal(in, len, (uint64_t *)out->data);
}

TSS2_RC yaml_internal_TPMT_ECC_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_ECC_SCHEME) == in->size);

    const TPMT_ECC_SCHEME *x = (const TPMT_ECC_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMT_ECC_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_ECC_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_ECC_SCHEME) == out->size);

    TPMT_ECC_SCHEME *x = (TPMT_ECC_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMT_ECC_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMA_LOCALITY_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPMA_LOCALITY) == in->size);

    const TPMA_LOCALITY *d = (const TPMA_LOCALITY *)in->data;
    TPMA_LOCALITY tmp = *d;

    static struct {
        TPMA_LOCALITY key;
        const char *value;
    } lookup[] = {
        {TPMA_LOCALITY_TPM2_LOC_ONE, "tpm2_loc_one"},
    {TPMA_LOCALITY_TPM2_LOC_TWO, "tpm2_loc_two"},
    {TPMA_LOCALITY_TPM2_LOC_ZERO, "tpm2_loc_zero"},
    {TPMA_LOCALITY_TPM2_LOC_FOUR, "tpm2_loc_four"},
    {TPMA_LOCALITY_TPM2_LOC_THREE, "tpm2_loc_three"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp & lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int8_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMA_LOCALITY_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPMA_LOCALITY));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPMA_LOCALITY tmp = 0;
    TPMA_LOCALITY *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPMA_LOCALITY value;
    } lookup[] = {
        {"tpma_locality_tpm2_loc_zero", TPMA_LOCALITY_TPM2_LOC_ZERO},
    {"tpm2_loc_zero", TPMA_LOCALITY_TPM2_LOC_ZERO},
    {"tpma_locality_tpm2_loc_one", TPMA_LOCALITY_TPM2_LOC_ONE},
    {"tpm2_loc_one", TPMA_LOCALITY_TPM2_LOC_ONE},
    {"tpma_locality_tpm2_loc_two", TPMA_LOCALITY_TPM2_LOC_TWO},
    {"tpm2_loc_two", TPMA_LOCALITY_TPM2_LOC_TWO},
    {"tpma_locality_tpm2_loc_three", TPMA_LOCALITY_TPM2_LOC_THREE},
    {"tpm2_loc_three", TPMA_LOCALITY_TPM2_LOC_THREE},
    {"tpma_locality_tpm2_loc_four", TPMA_LOCALITY_TPM2_LOC_FOUR},
    {"tpm2_loc_four", TPMA_LOCALITY_TPM2_LOC_FOUR}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int8_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2_GENERATED_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPM2_GENERATED) == in->size);

    const TPM2_GENERATED *d = (const TPM2_GENERATED *)in->data;
    TPM2_GENERATED tmp = *d;

    static struct {
        TPM2_GENERATED key;
        const char *value;
    } lookup[] = {
        {TPM2_GENERATED_VALUE, "value"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp == lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int32_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2_GENERATED_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPM2_GENERATED));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPM2_GENERATED tmp = 0;
    TPM2_GENERATED *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPM2_GENERATED value;
    } lookup[] = {
        {"tpm2_generated_value", TPM2_GENERATED_VALUE},
    {"value", TPM2_GENERATED_VALUE}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int32_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPM2B_DIGEST_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_DIGEST) == in->size);

    const TPM2B_DIGEST *x = (const TPM2B_DIGEST *)in->data;

    return Tss2_MU_YAML_TPM2B_DIGEST_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_DIGEST_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_DIGEST) == out->size);

    TPM2B_DIGEST *x = (TPM2B_DIGEST *)out->data;

    return Tss2_MU_YAML_TPM2B_DIGEST_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPML_PCR_SELECTION_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPML_PCR_SELECTION) == in->size);

    const TPML_PCR_SELECTION *x = (const TPML_PCR_SELECTION *)in->data;

    return Tss2_MU_YAML_TPML_PCR_SELECTION_Marshal(x, out);
}

TSS2_RC yaml_internal_TPML_PCR_SELECTION_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPML_PCR_SELECTION) == out->size);

    TPML_PCR_SELECTION *x = (TPML_PCR_SELECTION *)out->data;

    return Tss2_MU_YAML_TPML_PCR_SELECTION_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPM2B_ECC_PARAMETER_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_ECC_PARAMETER) == in->size);

    const TPM2B_ECC_PARAMETER *x = (const TPM2B_ECC_PARAMETER *)in->data;

    return Tss2_MU_YAML_TPM2B_ECC_PARAMETER_Marshal(x, out);
}

TSS2_RC yaml_internal_TPM2B_ECC_PARAMETER_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPM2B_ECC_PARAMETER) == out->size);

    TPM2B_ECC_PARAMETER *x = (TPM2B_ECC_PARAMETER *)out->data;

    return Tss2_MU_YAML_TPM2B_ECC_PARAMETER_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMT_RSA_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_RSA_SCHEME) == in->size);

    const TPMT_RSA_SCHEME *x = (const TPMT_RSA_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMT_RSA_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_RSA_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_RSA_SCHEME) == out->size);

    TPMT_RSA_SCHEME *x = (TPMT_RSA_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMT_RSA_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMA_SESSION_scalar_marshal(const datum *in, char **out) {
    assert(in);
    assert(out);
    assert(sizeof(TPMA_SESSION) == in->size);

    const TPMA_SESSION *d = (const TPMA_SESSION *)in->data;
    TPMA_SESSION tmp = *d;

    static struct {
        TPMA_SESSION key;
        const char *value;
    } lookup[] = {
        {TPMA_SESSION_AUDIT, "audit"},
    {TPMA_SESSION_DECRYPT, "decrypt"},
    {TPMA_SESSION_ENCRYPT, "encrypt"},
    {TPMA_SESSION_AUDITRESET, "auditreset"},
    {TPMA_SESSION_AUDITEXCLUSIVE, "auditexclusive"},
    {TPMA_SESSION_CONTINUESESSION, "continuesession"}
    };

    // TODO more intelligence on size selection?
    char buf[1024] = { 0 };
    char *p = buf;
    while(tmp) {
        unsigned i;
        for (i=0; i < ARRAY_LEN(lookup); i++) {
            if (tmp & lookup[i].key) {
                /* turns down the bit OR sets to 0 to break the loop */
                tmp &= ~lookup[i].key;
                strncat(p, lookup[i].value, sizeof(buf) - 1);
                break;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            return yaml_common_scalar_int8_t_marshal(*d, out);
        }
    }

    if (buf[0] == ',') {
        p++;
    }

    char *s = strdup(p);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    *out = s;
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMA_SESSION_scalar_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(out->size == sizeof(TPMA_SESSION));

    // TODO can we plumb this right?
    UNUSED(len);

    char *s = strdup(in);
    if (!s) {
        return TSS2_MU_RC_MEMORY;
    }

    char *saveptr = NULL;
    char *token = NULL;

    TPMA_SESSION tmp = 0;
    TPMA_SESSION *result = out->data;

    yaml_common_to_lower(s);

    static const struct {
        const char *key;
        TPMA_SESSION value;
    } lookup[] = {
        {"tpma_session_continuesession", TPMA_SESSION_CONTINUESESSION},
    {"continuesession", TPMA_SESSION_CONTINUESESSION},
    {"tpma_session_auditexclusive", TPMA_SESSION_AUDITEXCLUSIVE},
    {"auditexclusive", TPMA_SESSION_AUDITEXCLUSIVE},
    {"tpma_session_auditreset", TPMA_SESSION_AUDITRESET},
    {"auditreset", TPMA_SESSION_AUDITRESET},
    {"tpma_session_decrypt", TPMA_SESSION_DECRYPT},
    {"decrypt", TPMA_SESSION_DECRYPT},
    {"tpma_session_encrypt", TPMA_SESSION_ENCRYPT},
    {"encrypt", TPMA_SESSION_ENCRYPT},
    {"tpma_session_audit", TPMA_SESSION_AUDIT},
    {"audit", TPMA_SESSION_AUDIT}
    };

    char *x = s;
    while ((token = strtok_r(x, ",", &saveptr))) {
        x = NULL;
        size_t i;
        for(i=0; i < ARRAY_LEN(lookup); i++) {
            if (!strcmp(token, lookup[i].key)) {
                tmp |= lookup[i].value;
            }
        }
        if (i >= ARRAY_LEN(lookup)) {
            free(s);
            return yaml_common_scalar_int8_t_unmarshal(in, len, result);
        }
    }

    *result = tmp;
    free(s);
    return TSS2_RC_SUCCESS;
}

TSS2_RC yaml_internal_TPMU_PUBLIC_ID_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_PUBLIC_ID) == in->size);

    const TPMU_PUBLIC_ID *x = (const TPMU_PUBLIC_ID *)in->data;

    return Tss2_MU_YAML_TPMU_PUBLIC_ID_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_PUBLIC_ID_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_PUBLIC_ID) == out->size);

    TPMU_PUBLIC_ID *x = (TPMU_PUBLIC_ID *)out->data;

    return Tss2_MU_YAML_TPMU_PUBLIC_ID_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_uint32_t_scalar_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(uint32_t) == in->size);

    const uint32_t *x = (const uint32_t *)in->data;

    return yaml_common_scalar_uint32_t_marshal(*x, out);
}

TSS2_RC yaml_internal_uint32_t_scalar_unmarshal(const char *in, size_t len, datum *out)
{
    assert(in);
    return yaml_common_scalar_uint32_t_unmarshal(in, len, (uint32_t *)out->data);
}

TSS2_RC yaml_internal_TPMU_ATTEST_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_ATTEST) == in->size);

    const TPMU_ATTEST *x = (const TPMU_ATTEST *)in->data;

    return Tss2_MU_YAML_TPMU_ATTEST_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_ATTEST_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_ATTEST) == out->size);

    TPMU_ATTEST *x = (TPMU_ATTEST *)out->data;

    return Tss2_MU_YAML_TPMU_ATTEST_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_ASYM_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_ASYM_SCHEME) == in->size);

    const TPMU_ASYM_SCHEME *x = (const TPMU_ASYM_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMU_ASYM_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_ASYM_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_ASYM_SCHEME) == out->size);

    TPMU_ASYM_SCHEME *x = (TPMU_ASYM_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMU_ASYM_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMT_KEYEDHASH_SCHEME_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_KEYEDHASH_SCHEME) == in->size);

    const TPMT_KEYEDHASH_SCHEME *x = (const TPMT_KEYEDHASH_SCHEME *)in->data;

    return Tss2_MU_YAML_TPMT_KEYEDHASH_SCHEME_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMT_KEYEDHASH_SCHEME_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMT_KEYEDHASH_SCHEME) == out->size);

    TPMT_KEYEDHASH_SCHEME *x = (TPMT_KEYEDHASH_SCHEME *)out->data;

    return Tss2_MU_YAML_TPMT_KEYEDHASH_SCHEME_Unmarshal(in, len, x);
}

TSS2_RC yaml_internal_TPMU_HA_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_HA) == in->size);

    const TPMU_HA *x = (const TPMU_HA *)in->data;

    return Tss2_MU_YAML_TPMU_HA_Marshal(x, out);
}

TSS2_RC yaml_internal_TPMU_HA_unmarshal(const char *in, size_t len, datum *out) {

    assert(in);
    assert(out);
    assert(sizeof(TPMU_HA) == out->size);

    TPMU_HA *x = (TPMU_HA *)out->data;

    return Tss2_MU_YAML_TPMU_HA_Unmarshal(in, len, x);
}
