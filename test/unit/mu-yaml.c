/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tss2_mu_yaml.h"

#define LOGMODULE tests
#include "util/log.h"
#include "util/aux_util.h"

/* AUTOGENERATED ASSISTED CODE using yaml_mu_gen.py. modify with care */

void
test_TPM2B_ATTEST_good(void **state);

void
test_TPM2B_ATTEST_zero(void **state);

void
test_TPM2B_ATTEST_null(void **state);

void
test_TPM2B_AUTH_good(void **state);

void
test_TPM2B_AUTH_zero(void **state);

void
test_TPM2B_AUTH_null(void **state);

void
test_TPM2B_CONTEXT_DATA_good(void **state);

void
test_TPM2B_CONTEXT_DATA_zero(void **state);

void
test_TPM2B_CONTEXT_DATA_null(void **state);

void
test_TPM2B_CONTEXT_SENSITIVE_good(void **state);

void
test_TPM2B_CONTEXT_SENSITIVE_zero(void **state);

void
test_TPM2B_CONTEXT_SENSITIVE_null(void **state);

void
test_TPM2B_DATA_good(void **state);

void
test_TPM2B_DATA_zero(void **state);

void
test_TPM2B_DATA_null(void **state);

void
test_TPM2B_DIGEST_good(void **state);

void
test_TPM2B_DIGEST_zero(void **state);

void
test_TPM2B_DIGEST_null(void **state);

void
test_TPM2B_ECC_PARAMETER_good(void **state);

void
test_TPM2B_ECC_PARAMETER_zero(void **state);

void
test_TPM2B_ECC_PARAMETER_null(void **state);

void
test_TPM2B_ENCRYPTED_SECRET_good(void **state);

void
test_TPM2B_ENCRYPTED_SECRET_zero(void **state);

void
test_TPM2B_ENCRYPTED_SECRET_null(void **state);

void
test_TPM2B_EVENT_good(void **state);

void
test_TPM2B_EVENT_zero(void **state);

void
test_TPM2B_EVENT_null(void **state);

void
test_TPM2B_ID_OBJECT_good(void **state);

void
test_TPM2B_ID_OBJECT_zero(void **state);

void
test_TPM2B_ID_OBJECT_null(void **state);

void
test_TPM2B_IV_good(void **state);

void
test_TPM2B_IV_zero(void **state);

void
test_TPM2B_IV_null(void **state);

void
test_TPM2B_MAX_BUFFER_good(void **state);

void
test_TPM2B_MAX_BUFFER_zero(void **state);

void
test_TPM2B_MAX_BUFFER_null(void **state);

void
test_TPM2B_MAX_NV_BUFFER_good(void **state);

void
test_TPM2B_MAX_NV_BUFFER_zero(void **state);

void
test_TPM2B_MAX_NV_BUFFER_null(void **state);

void
test_TPM2B_NAME_good(void **state);

void
test_TPM2B_NAME_zero(void **state);

void
test_TPM2B_NAME_null(void **state);

void
test_TPM2B_NONCE_good(void **state);

void
test_TPM2B_NONCE_zero(void **state);

void
test_TPM2B_NONCE_null(void **state);

void
test_TPM2B_OPERAND_good(void **state);

void
test_TPM2B_OPERAND_zero(void **state);

void
test_TPM2B_OPERAND_null(void **state);

void
test_TPM2B_PRIVATE_good(void **state);

void
test_TPM2B_PRIVATE_zero(void **state);

void
test_TPM2B_PRIVATE_null(void **state);

void
test_TPM2B_PRIVATE_KEY_RSA_good(void **state);

void
test_TPM2B_PRIVATE_KEY_RSA_zero(void **state);

void
test_TPM2B_PRIVATE_KEY_RSA_null(void **state);

void
test_TPM2B_PRIVATE_VENDOR_SPECIFIC_good(void **state);

void
test_TPM2B_PRIVATE_VENDOR_SPECIFIC_zero(void **state);

void
test_TPM2B_PRIVATE_VENDOR_SPECIFIC_null(void **state);

void
test_TPM2B_PUBLIC_KEY_RSA_good(void **state);

void
test_TPM2B_PUBLIC_KEY_RSA_zero(void **state);

void
test_TPM2B_PUBLIC_KEY_RSA_null(void **state);

void
test_TPM2B_SENSITIVE_DATA_good(void **state);

void
test_TPM2B_SENSITIVE_DATA_zero(void **state);

void
test_TPM2B_SENSITIVE_DATA_null(void **state);

void
test_TPM2B_SYM_KEY_good(void **state);

void
test_TPM2B_SYM_KEY_zero(void **state);

void
test_TPM2B_SYM_KEY_null(void **state);

void
test_TPM2B_TEMPLATE_good(void **state);

void
test_TPM2B_TEMPLATE_zero(void **state);

void
test_TPM2B_TEMPLATE_null(void **state);

// BILL
void test_TPMS_ALG_PROPERTY_good(void **state);
void test_TPMS_ALG_PROPERTY_zero(void **state);
void test_TPMS_ALG_PROPERTY_null(void **state);

int
main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
            /* AUTOGENERATED ASSISTED CODE using yaml_mu_gen.py. modify with care */
            cmocka_unit_test(test_TPM2B_ATTEST_good),
            cmocka_unit_test(test_TPM2B_ATTEST_zero),
            cmocka_unit_test(test_TPM2B_ATTEST_null),
            cmocka_unit_test(test_TPM2B_AUTH_good),
            cmocka_unit_test(test_TPM2B_AUTH_zero),
            cmocka_unit_test(test_TPM2B_AUTH_null),
            cmocka_unit_test(test_TPM2B_CONTEXT_DATA_good),
            cmocka_unit_test(test_TPM2B_CONTEXT_DATA_zero),
            cmocka_unit_test(test_TPM2B_CONTEXT_DATA_null),
            cmocka_unit_test(test_TPM2B_CONTEXT_SENSITIVE_good),
            cmocka_unit_test(test_TPM2B_CONTEXT_SENSITIVE_zero),
            cmocka_unit_test(test_TPM2B_CONTEXT_SENSITIVE_null),
            cmocka_unit_test(test_TPM2B_DATA_good),
            cmocka_unit_test(test_TPM2B_DATA_zero),
            cmocka_unit_test(test_TPM2B_DATA_null),
            cmocka_unit_test(test_TPM2B_DIGEST_good),
            cmocka_unit_test(test_TPM2B_DIGEST_zero),
            cmocka_unit_test(test_TPM2B_DIGEST_null),
            cmocka_unit_test(test_TPM2B_ECC_PARAMETER_good),
            cmocka_unit_test(test_TPM2B_ECC_PARAMETER_zero),
            cmocka_unit_test(test_TPM2B_ECC_PARAMETER_null),
            cmocka_unit_test(test_TPM2B_ENCRYPTED_SECRET_good),
            cmocka_unit_test(test_TPM2B_ENCRYPTED_SECRET_zero),
            cmocka_unit_test(test_TPM2B_ENCRYPTED_SECRET_null),
            cmocka_unit_test(test_TPM2B_EVENT_good),
            cmocka_unit_test(test_TPM2B_EVENT_zero),
            cmocka_unit_test(test_TPM2B_EVENT_null),
            cmocka_unit_test(test_TPM2B_ID_OBJECT_good),
            cmocka_unit_test(test_TPM2B_ID_OBJECT_zero),
            cmocka_unit_test(test_TPM2B_ID_OBJECT_null),
            cmocka_unit_test(test_TPM2B_IV_good),
            cmocka_unit_test(test_TPM2B_IV_zero),
            cmocka_unit_test(test_TPM2B_IV_null),
            cmocka_unit_test(test_TPM2B_MAX_BUFFER_good),
            cmocka_unit_test(test_TPM2B_MAX_BUFFER_zero),
            cmocka_unit_test(test_TPM2B_MAX_BUFFER_null),
            cmocka_unit_test(test_TPM2B_MAX_NV_BUFFER_good),
            cmocka_unit_test(test_TPM2B_MAX_NV_BUFFER_zero),
            cmocka_unit_test(test_TPM2B_MAX_NV_BUFFER_null),
            cmocka_unit_test(test_TPM2B_NAME_good),
            cmocka_unit_test(test_TPM2B_NAME_zero),
            cmocka_unit_test(test_TPM2B_NAME_null),
            cmocka_unit_test(test_TPM2B_NONCE_good),
            cmocka_unit_test(test_TPM2B_NONCE_zero),
            cmocka_unit_test(test_TPM2B_NONCE_null),
            cmocka_unit_test(test_TPM2B_OPERAND_good),
            cmocka_unit_test(test_TPM2B_OPERAND_zero),
            cmocka_unit_test(test_TPM2B_OPERAND_null),
            cmocka_unit_test(test_TPM2B_PRIVATE_good),
            cmocka_unit_test(test_TPM2B_PRIVATE_zero),
            cmocka_unit_test(test_TPM2B_PRIVATE_null),
            cmocka_unit_test(test_TPM2B_PRIVATE_KEY_RSA_good),
            cmocka_unit_test(test_TPM2B_PRIVATE_KEY_RSA_zero),
            cmocka_unit_test(test_TPM2B_PRIVATE_KEY_RSA_null),
            cmocka_unit_test(test_TPM2B_PRIVATE_VENDOR_SPECIFIC_good),
            cmocka_unit_test(test_TPM2B_PRIVATE_VENDOR_SPECIFIC_zero),
            cmocka_unit_test(test_TPM2B_PRIVATE_VENDOR_SPECIFIC_null),
            cmocka_unit_test(test_TPM2B_PUBLIC_KEY_RSA_good),
            cmocka_unit_test(test_TPM2B_PUBLIC_KEY_RSA_zero),
            cmocka_unit_test(test_TPM2B_PUBLIC_KEY_RSA_null),
            cmocka_unit_test(test_TPM2B_SENSITIVE_DATA_good),
            cmocka_unit_test(test_TPM2B_SENSITIVE_DATA_zero),
            cmocka_unit_test(test_TPM2B_SENSITIVE_DATA_null),
            cmocka_unit_test(test_TPM2B_SYM_KEY_good),
            cmocka_unit_test(test_TPM2B_SYM_KEY_zero),
            cmocka_unit_test(test_TPM2B_SYM_KEY_null),
            cmocka_unit_test(test_TPM2B_TEMPLATE_good),
            cmocka_unit_test(test_TPM2B_TEMPLATE_zero),
            cmocka_unit_test(test_TPM2B_TEMPLATE_null),
            /* bill */
            cmocka_unit_test(test_TPMS_ALG_PROPERTY_good),
            cmocka_unit_test(test_TPMS_ALG_PROPERTY_zero),
            cmocka_unit_test(test_TPMS_ALG_PROPERTY_null),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
