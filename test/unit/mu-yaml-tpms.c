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
}
