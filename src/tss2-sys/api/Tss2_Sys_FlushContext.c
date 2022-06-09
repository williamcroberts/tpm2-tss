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

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_FLUSHCONTEXT_PREPARE)
TSS2_RC Tss2_Sys_FlushContext_Prepare(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT flushHandle)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_FlushContext);
    if (rval)
        return rval;
    rval = Tss2_MU_UINT32_Marshal(flushHandle, ctx->cmdBuffer,
                                  ctx->maxCmdSize,
                                  &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 0;

    return CommonPrepareEpilogue(ctx);
}
#endif

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_FLUSHCONTEXT_COMPLETE)
TSS2_RC Tss2_Sys_FlushContext_Complete (
    TSS2_SYS_CONTEXT *sysContext)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    return CommonComplete(ctx);
}
#endif

#if !defined(CONFIGURATOR) || defined(ENABLE_TSS2_SYS_FLUSHCONTEXT)
TSS2_RC Tss2_Sys_FlushContext(
    TSS2_SYS_CONTEXT *sysContext,
    TPMI_DH_CONTEXT flushHandle)
{
    _TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC rval;

    rval = Tss2_Sys_FlushContext_Prepare(sysContext, flushHandle);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, 0, 0);
    if (rval)
        return rval;

    return Tss2_Sys_FlushContext_Complete(sysContext);
}
#endif
