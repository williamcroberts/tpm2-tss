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

/* test for "zero length" inputs, like "", "{}\n", etc */
#define TEST_COMMON_ZERO(type) \
    do { \
        static const type golden; \
        type dest = { 0 }; \
        \
        TSS2_RC rc =Tss2_MU_YAML_##type##_Unmarshal( \
                "", \
                0, \
                &dest); \
        assert_int_equal(rc, TSS2_MU_RC_BAD_VALUE); \
        assert_memory_equal(&dest, &golden, sizeof(golden)); \
        \
        rc =Tss2_MU_YAML_##type##_Unmarshal( \
                "notfound: badcafedeadbeefbadccode\n", \
                0, \
                &dest); \
        assert_int_equal(rc, TSS2_MU_RC_BAD_VALUE); \
        assert_memory_equal(&dest, &golden, sizeof(golden)); \
        \
        rc =Tss2_MU_YAML_##type##_Unmarshal( \
                "{}\n", /* empty mapping */ \
                0, \
                &dest); \
        assert_int_equal(rc, TSS2_MU_RC_BAD_VALUE); \
        assert_memory_equal(&dest, &golden, sizeof(golden)); \
    } while(0)

#define TEST_COMMON_NULL(type) \
        do { \
            char *yaml = NULL; \
            type data = { 0 }; \
            TSS2_RC rc = Tss2_MU_YAML_##type##_Marshal(NULL, &yaml); \
            assert_int_equal(rc, TSS2_MU_RC_BAD_REFERENCE); \
            \
            rc = Tss2_MU_YAML_##type##_Marshal(&data, NULL); \
            assert_int_equal(rc, TSS2_MU_RC_BAD_REFERENCE); \
            \
            rc =Tss2_MU_YAML_##type##_Unmarshal( \
                    NULL, \
                    0, \
                    &data); \
            assert_int_equal(rc, TSS2_MU_RC_BAD_REFERENCE); \
            \
            rc =Tss2_MU_YAML_##type##_Unmarshal( \
                    "", \
                    0, \
                    NULL); \
            assert_int_equal(rc, TSS2_MU_RC_BAD_REFERENCE); \
        } while(0)

void test_TPMS_ALG_PROPERTY_good(void **state) {
    UNUSED(state);

    char *yaml = NULL;
    TPMS_ALG_PROPERTY src = {
        .alg = TPM2_ALG_SHA256,
        .algProperties = TPMA_ALGORITHM_HASH
    };

    TSS2_RC rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Marshal(
        &src,
        &yaml);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    TPMS_ALG_PROPERTY dest = { 0 };
    rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Unmarshal(
        yaml,
        0,
        &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(src.alg, dest.alg);
    assert_int_equal(src.algProperties, dest.algProperties);

    /* test multiple */
    memset(&src, 0, sizeof(src));
    src.alg = TPM2_ALG_HMAC;
    src.algProperties = TPMA_ALGORITHM_SYMMETRIC | TPMA_ALGORITHM_SIGNING;
    rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Marshal(
        &src,
        &yaml);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    memset(&dest, 0, sizeof(dest));
    rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Unmarshal(
        yaml,
        0,
        &dest);

    rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Unmarshal(
        yaml,
        0,
        &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    assert_int_equal(src.alg, dest.alg);
    assert_int_equal(src.algProperties, dest.algProperties);

    /* test unknown */
    memset(&src, 0, sizeof(src));
    src.alg = TPM2_ALG_LAST + 1;
    src.algProperties = 0xFF000000;
    rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Marshal(
        &src,
        &yaml);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    memset(&dest, 0, sizeof(dest));
    rc = Tss2_MU_YAML_TPMS_ALG_PROPERTY_Unmarshal(
        yaml,
        0,
        &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    assert_int_equal(src.alg, dest.alg);
    assert_int_equal(src.algProperties, dest.algProperties);
}

void test_TPMS_ALG_PROPERTY_zero(void **state) {
    TEST_COMMON_ZERO(TPMS_ALG_PROPERTY);
}

void test_TPMS_ALG_PROPERTY_null(void **state) {
    TEST_COMMON_NULL(TPMS_ALG_PROPERTY);
}

