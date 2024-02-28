
/* SPDX-License-Identifier: BSD-2-Clause */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include "tss2_mu_yaml.h"
#include "yaml-common.h"
#include "yaml-internal.h"

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
