
/* SPDX-License-Identifier: BSD-2-Clause */
#include "yaml-common.h"
#include "yaml-scalar.h"

TSS2_RC yaml_scalar_UINT8_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT8) == in->size);

    const UINT8 *x = (const UINT8 *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_UINT8_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_BYTE_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(BYTE) == in->size);

    const BYTE *x = (const BYTE *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_BYTE_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_ALG_ID_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ALG_ID) == in->size);

    const TPM2_ALG_ID *x = (const TPM2_ALG_ID *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_ALG_ID_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMA_ALGORITHM_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_ALGORITHM) == in->size);

    const TPMA_ALGORITHM *x = (const TPMA_ALGORITHM *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMA_ALGORITHM_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_PT_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_PT) == in->size);

    const TPM2_PT *x = (const TPM2_PT *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_PT_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_UINT32_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT32) == in->size);

    const UINT32 *x = (const UINT32 *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_UINT32_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_PT_PCR_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_PT_PCR) == in->size);

    const TPM2_PT_PCR *x = (const TPM2_PT_PCR *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_PT_PCR_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_HANDLE_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_HANDLE) == in->size);

    const TPM2_HANDLE *x = (const TPM2_HANDLE *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_HANDLE_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_HA_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_HA) == in->size);

    const TPMT_HA *x = (const TPMT_HA *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_HA_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMA_ACT_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_ACT) == in->size);

    const TPMA_ACT *x = (const TPMA_ACT *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMA_ACT_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_CAP_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_CAP) == in->size);

    const TPM2_CAP *x = (const TPM2_CAP *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_CAP_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMU_CAPABILITIES_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_CAPABILITIES) == in->size);

    const TPMU_CAPABILITIES *x = (const TPMU_CAPABILITIES *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMU_CAPABILITIES_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_UINT64_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT64) == in->size);

    const UINT64 *x = (const UINT64 *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_UINT64_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMI_YES_NO_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMI_YES_NO) == in->size);

    const TPMI_YES_NO *x = (const TPMI_YES_NO *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMI_YES_NO_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMS_CLOCK_INFO_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMS_CLOCK_INFO) == in->size);

    const TPMS_CLOCK_INFO *x = (const TPMS_CLOCK_INFO *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMS_CLOCK_INFO_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMS_TIME_INFO_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMS_TIME_INFO) == in->size);

    const TPMS_TIME_INFO *x = (const TPMS_TIME_INFO *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMS_TIME_INFO_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_NAME_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_NAME) == in->size);

    const TPM2B_NAME *x = (const TPM2B_NAME *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_NAME_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPML_PCR_SELECTION_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPML_PCR_SELECTION) == in->size);

    const TPML_PCR_SELECTION *x = (const TPML_PCR_SELECTION *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPML_PCR_SELECTION_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_DIGEST_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_DIGEST) == in->size);

    const TPM2B_DIGEST *x = (const TPM2B_DIGEST *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_DIGEST_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_UINT16_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(UINT16) == in->size);

    const UINT16 *x = (const UINT16 *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_UINT16_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_MAX_NV_BUFFER_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_MAX_NV_BUFFER) == in->size);

    const TPM2B_MAX_NV_BUFFER *x = (const TPM2B_MAX_NV_BUFFER *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_MAX_NV_BUFFER_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_GENERATED_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_GENERATED) == in->size);

    const TPM2_GENERATED *x = (const TPM2_GENERATED *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_GENERATED_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_ST_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ST) == in->size);

    const TPM2_ST *x = (const TPM2_ST *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_ST_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_DATA_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_DATA) == in->size);

    const TPM2B_DATA *x = (const TPM2B_DATA *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_DATA_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMU_ATTEST_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMU_ATTEST) == in->size);

    const TPMU_ATTEST *x = (const TPMU_ATTEST *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMU_ATTEST_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_NONCE_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_NONCE) == in->size);

    const TPM2B_NONCE *x = (const TPM2B_NONCE *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_NONCE_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMA_SESSION_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_SESSION) == in->size);

    const TPMA_SESSION *x = (const TPMA_SESSION *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMA_SESSION_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_AUTH_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_AUTH) == in->size);

    const TPM2B_AUTH *x = (const TPM2B_AUTH *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_AUTH_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_SYM_DEF_OBJECT) == in->size);

    const TPMT_SYM_DEF_OBJECT *x = (const TPMT_SYM_DEF_OBJECT *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_LABEL_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_LABEL) == in->size);

    const TPM2B_LABEL *x = (const TPM2B_LABEL *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_LABEL_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_SENSITIVE_DATA_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_SENSITIVE_DATA) == in->size);

    const TPM2B_SENSITIVE_DATA *x = (const TPM2B_SENSITIVE_DATA *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_SENSITIVE_DATA_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_ECC_PARAMETER) == in->size);

    const TPM2B_ECC_PARAMETER *x = (const TPM2B_ECC_PARAMETER *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_ECC_CURVE_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_ECC_CURVE) == in->size);

    const TPM2_ECC_CURVE *x = (const TPM2_ECC_CURVE *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_ECC_CURVE_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_KDF_SCHEME_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_KDF_SCHEME) == in->size);

    const TPMT_KDF_SCHEME *x = (const TPMT_KDF_SCHEME *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_KDF_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_ECC_SCHEME_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_ECC_SCHEME) == in->size);

    const TPMT_ECC_SCHEME *x = (const TPMT_ECC_SCHEME *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_ECC_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_PUBLIC_KEY_RSA) == in->size);

    const TPM2B_PUBLIC_KEY_RSA *x = (const TPM2B_PUBLIC_KEY_RSA *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_KEYEDHASH_SCHEME_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_KEYEDHASH_SCHEME) == in->size);

    const TPMT_KEYEDHASH_SCHEME *x = (const TPMT_KEYEDHASH_SCHEME *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_KEYEDHASH_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_ASYM_SCHEME_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_ASYM_SCHEME) == in->size);

    const TPMT_ASYM_SCHEME *x = (const TPMT_ASYM_SCHEME *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_ASYM_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMT_RSA_SCHEME_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMT_RSA_SCHEME) == in->size);

    const TPMT_RSA_SCHEME *x = (const TPMT_RSA_SCHEME *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMT_RSA_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2_KEY_BITS_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2_KEY_BITS) == in->size);

    const TPM2_KEY_BITS *x = (const TPM2_KEY_BITS *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2_KEY_BITS_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMA_NV_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_NV) == in->size);

    const TPMA_NV *x = (const TPMA_NV *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMA_NV_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_CONTEXT_SENSITIVE_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_CONTEXT_SENSITIVE) == in->size);

    const TPM2B_CONTEXT_SENSITIVE *x = (const TPM2B_CONTEXT_SENSITIVE *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_CONTEXT_SENSITIVE_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM2B_CONTEXT_DATA_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM2B_CONTEXT_DATA) == in->size);

    const TPM2B_CONTEXT_DATA *x = (const TPM2B_CONTEXT_DATA *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM2B_CONTEXT_DATA_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPMA_LOCALITY_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPMA_LOCALITY) == in->size);

    const TPMA_LOCALITY *x = (const TPMA_LOCALITY *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPMA_LOCALITY_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}

TSS2_RC yaml_scalar_TPM_AT_generic_marshal(const datum *in, char **out)
{
    assert(in);
    assert(out);
    assert(sizeof(TPM_AT) == in->size);

    const TPM_AT *x = (const TPM_AT *)in->data;

    return yaml_common_generic_scalar_marshal(x, out);
}

TSS2_RC yaml_scalar_TPM_AT_generic_unmarshal(const char *in, size_t len, datum *out) {

    return yaml_common_generic_scalar_unmarshal(in, len, out);
}
