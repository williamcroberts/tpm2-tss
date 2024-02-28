
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SRC_TSS2_MU_YAML_YAML_SCALAR_H_
#define SRC_TSS2_MU_YAML_YAML_SCALAR_H_

/* forward declare to break cyclic dependency on yaml-common.h */
typedef struct datum datum;

TSS2_RC yaml_internal_TPM2B_AUTH_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_AUTH_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_CONTEXT_DATA_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_CONTEXT_DATA_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_CONTEXT_SENSITIVE_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_CONTEXT_SENSITIVE_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_ECC_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_ECC_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_CAPABILITIES_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_CAPABILITIES_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_SCHEME_KEYEDHASH_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_SCHEME_KEYEDHASH_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_NONCE_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_NONCE_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_PUBLIC_ID_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_PUBLIC_ID_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_SENSITIVE_COMPOSITE_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_SENSITIVE_COMPOSITE_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_SENSITIVE_DATA_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_SENSITIVE_DATA_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_SYM_DEF_OBJECT_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_SYM_DEF_OBJECT_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_uint8_t_scalar_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_uint8_t_scalar_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_LABEL_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_LABEL_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_KEYEDHASH_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_KEYEDHASH_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_ATTEST_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_ATTEST_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_MAX_NV_BUFFER_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_MAX_NV_BUFFER_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_HA_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_HA_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_NAME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_NAME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_RSA_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_RSA_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_SIGNATURE_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_SIGNATURE_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_uint16_t_scalar_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_uint16_t_scalar_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_HA_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_HA_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_DIGEST_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_DIGEST_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_ASYM_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_ASYM_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_PUBLIC_KEY_RSA_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_PUBLIC_KEY_RSA_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_KDF_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_KDF_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPML_PCR_SELECTION_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPML_PCR_SELECTION_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_PUBLIC_PARMS_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_PUBLIC_PARMS_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_ASYM_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_ASYM_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_SYM_MODE_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_SYM_MODE_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_uint64_t_scalar_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_uint64_t_scalar_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMT_KDF_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMT_KDF_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_uint32_t_scalar_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_uint32_t_scalar_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_SYM_KEY_BITS_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_SYM_KEY_BITS_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMU_SIG_SCHEME_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMU_SIG_SCHEME_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_DATA_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_DATA_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMS_TIME_INFO_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMS_TIME_INFO_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPMS_CLOCK_INFO_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPMS_CLOCK_INFO_unmarshal(const char *in, size_t len, datum *out);

TSS2_RC yaml_internal_TPM2B_ECC_PARAMETER_marshal(const datum *in, char **out);
TSS2_RC yaml_internal_TPM2B_ECC_PARAMETER_unmarshal(const char *in, size_t len, datum *out);

#endif /* SRC_TSS2_MU_YAML_YAML_SCALAR_H_ */
