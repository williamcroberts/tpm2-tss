
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
