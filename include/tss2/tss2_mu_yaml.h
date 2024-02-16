/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef INCLUDE_TSS2_TSS2_MU_YAML_H_
#define INCLUDE_TSS2_TSS2_MU_YAML_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "tss2_tpm2_types.h"

TSS2_RC
Tss2_MU_YAML_TPM2B_ATTEST_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_ATTEST_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_AUTH_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_AUTH_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_CONTEXT_DATA_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_CONTEXT_DATA_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_CONTEXT_SENSITIVE_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_CONTEXT_SENSITIVE_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_DATA_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_DATA_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_DIGEST_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_DIGEST_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_ECC_PARAMETER_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_ECC_PARAMETER_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_ENCRYPTED_SECRET_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_ENCRYPTED_SECRET_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_EVENT_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_EVENT_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_ID_OBJECT_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_ID_OBJECT_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_IV_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_IV_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_MAX_BUFFER_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_MAX_BUFFER_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_MAX_NV_BUFFER_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_MAX_NV_BUFFER_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_NAME_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_NAME_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_NONCE_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_NONCE_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_OPERAND_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_OPERAND_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_PRIVATE_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_PRIVATE_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_PRIVATE_KEY_RSA_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_PRIVATE_KEY_RSA_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_PRIVATE_VENDOR_SPECIFIC_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_PRIVATE_VENDOR_SPECIFIC_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_PUBLIC_KEY_RSA_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_PUBLIC_KEY_RSA_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_SENSITIVE_DATA_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_SENSITIVE_DATA_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_SYM_KEY_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_SYM_KEY_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

TSS2_RC
Tss2_MU_YAML_TPM2B_TEMPLATE_Marshal(
    TPM2B_DIGEST const *src,
    char            **output);

TSS2_RC
Tss2_MU_YAML_TPM2B_TEMPLATE_Unmarshal(
    char const      buffer[],
    size_t          buffer_size,
    TPM2B_DIGEST   *dest);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_TSS2_TSS2_MU_YAML_H_ */
