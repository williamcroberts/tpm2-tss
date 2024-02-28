
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include "tss2_mu_yaml.h"
#include "yaml-common.h"
#include "yaml-internal.h"

TSS2_RC yaml_internal_TPMI_YES_NO_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMI_YES_NO) == in->size);

    const TPMI_YES_NO *x = (const TPMI_YES_NO *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPMI_YES_NO_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_TPM2_KEY_BITS_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_KEY_BITS) == in->size);

    const TPM2_KEY_BITS *x = (const TPM2_KEY_BITS *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_KEY_BITS_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_UINT64_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT64) == in->size);

    const UINT64 *x = (const UINT64 *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_UINT64_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_TPMA_LOCALITY_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_LOCALITY) == in->size);

    const TPMA_LOCALITY *x = (const TPMA_LOCALITY *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPMA_LOCALITY_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPM2_PT_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_PT) == in->size);

    const TPM2_PT *x = (const TPM2_PT *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_PT_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_UINT16_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT16) == in->size);

    const UINT16 *x = (const UINT16 *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_UINT16_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_UINT32_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT32) == in->size);

    const UINT32 *x = (const UINT32 *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_UINT32_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_TPM_AT_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM_AT) == in->size);

    const TPM_AT *x = (const TPM_AT *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM_AT_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPM2_GENERATED_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_GENERATED) == in->size);

    const TPM2_GENERATED *x = (const TPM2_GENERATED *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_GENERATED_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPMA_SESSION_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_SESSION) == in->size);

    const TPMA_SESSION *x = (const TPMA_SESSION *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPMA_SESSION_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPMA_ALGORITHM_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_ALGORITHM) == in->size);

    const TPMA_ALGORITHM *x = (const TPMA_ALGORITHM *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPMA_ALGORITHM_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_TPM2_HANDLE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_HANDLE) == in->size);

    const TPM2_HANDLE *x = (const TPM2_HANDLE *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_HANDLE_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPM2_ALG_ID_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ALG_ID) == in->size);

    const TPM2_ALG_ID *x = (const TPM2_ALG_ID *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_ALG_ID_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_TPMA_NV_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_NV) == in->size);

    const TPMA_NV *x = (const TPMA_NV *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPMA_NV_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_UINT8_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT8) == in->size);

    const UINT8 *x = (const UINT8 *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_UINT8_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPM2_CAP_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_CAP) == in->size);

    const TPM2_CAP *x = (const TPM2_CAP *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_CAP_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPM2_ST_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ST) == in->size);

    const TPM2_ST *x = (const TPM2_ST *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_ST_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_TPM2_ECC_CURVE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ECC_CURVE) == in->size);

    const TPM2_ECC_CURVE *x = (const TPM2_ECC_CURVE *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_ECC_CURVE_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPM2_PT_PCR_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_PT_PCR) == in->size);

    const TPM2_PT_PCR *x = (const TPM2_PT_PCR *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPM2_PT_PCR_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_internal_TPMA_ACT_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_ACT) == in->size);

    const TPMA_ACT *x = (const TPMA_ACT *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_TPMA_ACT_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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

TSS2_RC yaml_internal_BYTE_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(BYTE) == in->size);

    const BYTE *x = (const BYTE *)in->data;

    return yaml_common_generic_scalar_marshal(*x, out);
}

TSS2_RC yaml_internal_BYTE_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
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
