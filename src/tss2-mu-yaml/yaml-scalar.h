
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_TSS2_MU_YAML_YAML_SCALAR_H_
#define SRC_TSS2_MU_YAML_YAML_SCALAR_H_

/* forward declare to break cyclic dependency on yaml-common.h */
typedef struct datum datum;

TSS2_RC yaml_scalar_UINT8_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_UINT8_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_BYTE_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_BYTE_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_ALG_ID_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_ALG_ID_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMA_ALGORITHM_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMA_ALGORITHM_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_PT_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_PT_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_UINT32_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_UINT32_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_PT_PCR_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_PT_PCR_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_HANDLE_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_HANDLE_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_HA_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_HA_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMA_ACT_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMA_ACT_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_CAP_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_CAP_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMU_CAPABILITIES_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMU_CAPABILITIES_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_UINT64_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_UINT64_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMI_YES_NO_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMI_YES_NO_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMS_CLOCK_INFO_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMS_CLOCK_INFO_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMS_TIME_INFO_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMS_TIME_INFO_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_NAME_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_NAME_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPML_PCR_SELECTION_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPML_PCR_SELECTION_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_DIGEST_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_DIGEST_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_UINT16_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_UINT16_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_MAX_NV_BUFFER_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_MAX_NV_BUFFER_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_GENERATED_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_GENERATED_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_ST_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_ST_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_DATA_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_DATA_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMU_ATTEST_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMU_ATTEST_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_NONCE_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_NONCE_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMA_SESSION_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMA_SESSION_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_AUTH_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_AUTH_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_SYM_DEF_OBJECT_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_LABEL_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_LABEL_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_SENSITIVE_DATA_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_SENSITIVE_DATA_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_ECC_PARAMETER_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_ECC_PARAMETER_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_ECC_CURVE_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_ECC_CURVE_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_KDF_SCHEME_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_KDF_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_ECC_SCHEME_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_ECC_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_PUBLIC_KEY_RSA_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_KEYEDHASH_SCHEME_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_KEYEDHASH_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_ASYM_SCHEME_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_ASYM_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMT_RSA_SCHEME_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMT_RSA_SCHEME_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2_KEY_BITS_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2_KEY_BITS_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMA_NV_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMA_NV_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_CONTEXT_SENSITIVE_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_CONTEXT_SENSITIVE_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM2B_CONTEXT_DATA_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM2B_CONTEXT_DATA_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPMA_LOCALITY_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPMA_LOCALITY_generic_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_scalar_TPM_AT_generic_marshal(const datum *in, char **out);
TSS2_RC yaml_scalar_TPM_AT_generic_unmarshal(const char *in, size_t len, datum *out);

#endif /* SRC_TSS2_MU_YAML_YAML_SCALAR_H_ */
