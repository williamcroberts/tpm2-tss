/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "tss2_tpm2_types.h"
#include "tss2_mu.h"
#include "sysapi_util.h"

#ifdef CONFIGURATOR
#include "configurator.h"
#endif

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_EVICTCONTROL_PREPARE)
TSS2_RC Tss2_Sys_EvictControl_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION auth,
    TPMI_DH_OBJECT objectHandle,
    TPMI_DH_PERSISTENT persistentHandle)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_EvictControl);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(auth, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(objectHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(persistentHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}
#endif

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_EVICTCONTROL_COMPLETE)
TSS2_RC Tss2_Sys_EvictControl_Complete (
    TSS2_SYS_CONTEXT *sysContext)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    return CommonComplete(ctx);
}
#endif

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_EVICTCONTROL)
TSS2_RC Tss2_Sys_EvictControl(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_RH_PROVISION auth,
    TPMI_DH_OBJECT objectHandle,
    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
    TPMI_DH_PERSISTENT persistentHandle,
    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_EvictControl_Prepare(sysContext, auth, objectHandle,
                                         persistentHandle);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_EvictControl_Complete(sysContext);
}
#endif
