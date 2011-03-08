/*
 * Copyright (c) 2011, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Context establishment state machine.
 */

#include "gssapiP_eap.h"

static const char *
gssEapStateToString(enum gss_eap_state state)
{
    const char *s;

    switch (state) {
    case GSSEAP_STATE_INITIAL:
        s = "INITIAL";
        break;
    case GSSEAP_STATE_AUTHENTICATE:
        s = "AUTHENTICATE";
        break;
    case GSSEAP_STATE_INITIATOR_EXTS:
        s = "INITIATOR_EXTS";
        break;
    case GSSEAP_STATE_ACCEPTOR_EXTS:
        s = "ACCEPTOR_EXTS";
        break;
    case GSSEAP_STATE_ESTABLISHED:
        s = "ESTABLISHED";
        break;
    default:
        s = "INVALID";
        break;
    }

    return s;
}

static OM_uint32
makeErrorToken(OM_uint32 *minor,
               OM_uint32 majorStatus,
               OM_uint32 minorStatus,
               gss_buffer_set_t *outputToken)
{
    unsigned char errorData[8];
    gss_buffer_desc errorBuffer;

    assert(GSS_ERROR(majorStatus));

    /*
     * Only return error codes that the initiator could have caused,
     * to avoid information leakage.
     */
    if (IS_RADIUS_ERROR(minorStatus)) {
        /* Squash RADIUS error codes */
        minorStatus = GSSEAP_RADIUS_PROT_FAILURE;
    } else if (!IS_WIRE_ERROR(minorStatus)) {
        /* Don't return non-wire error codes */
        return GSS_S_COMPLETE;
    }

    minorStatus -= ERROR_TABLE_BASE_eapg;

    store_uint32_be(majorStatus, &errorData[0]);
    store_uint32_be(minorStatus, &errorData[4]);

    errorBuffer.length = sizeof(errorData);
    errorBuffer.value = errorData;

    return gss_add_buffer_set_member(minor, &errorBuffer, outputToken);
}

OM_uint32
gssEapSmStep(OM_uint32 *minor,
             gss_cred_id_t cred,
             gss_ctx_id_t ctx,
             gss_name_t target,
             gss_OID mech,
             OM_uint32 reqFlags,
             OM_uint32 timeReq,
             gss_channel_bindings_t chanBindings,
             gss_buffer_t inputToken,
             gss_buffer_t outputToken,
             struct gss_eap_sm *sm,
             size_t smCount)
{
    OM_uint32 major, tmpMajor, tmpMinor;
    gss_buffer_desc unwrappedInputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc unwrappedOutputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_set_t innerInputTokens = GSS_C_NO_BUFFER_SET;
    gss_buffer_set_t innerOutputTokens = GSS_C_NO_BUFFER_SET;
    OM_uint32 *inputTokenTypes = NULL, *outputTokenTypes = NULL;
    unsigned int smFlags = 0;
    size_t i, j;
    int initialContextToken = 0;

    assert(smCount > 0);

    *minor = 0;

    outputToken->length = 0;
    outputToken->value = NULL;

    if (inputToken != GSS_C_NO_BUFFER && inputToken->length != 0) {
        enum gss_eap_token_type tokType;

        major = gssEapVerifyToken(minor, ctx, inputToken, &tokType,
                                  &unwrappedInputToken);
        if (GSS_ERROR(major))
            goto cleanup;

        if (tokType != TOK_TYPE_ESTABLISH_CONTEXT) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_WRONG_TOK_ID;
            goto cleanup;
        }
    } else if (!CTX_IS_INITIATOR(ctx) || ctx->state != GSSEAP_STATE_INITIAL) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSEAP_WRONG_SIZE;
        goto cleanup;
    } else {
        initialContextToken = 1;
    }

    if (ctx->state == GSSEAP_STATE_ESTABLISHED) {
        major = GSS_S_BAD_STATUS;
        *minor = GSSEAP_CONTEXT_ESTABLISHED;
        goto cleanup;
    }

    assert(ctx->state < GSSEAP_STATE_ESTABLISHED);

    major = gssEapDecodeInnerTokens(minor, &unwrappedInputToken,
                                    &innerInputTokens, &inputTokenTypes);
    if (GSS_ERROR(major))
        goto cleanup;

    assert(innerInputTokens != GSS_C_NO_BUFFER_SET);

    major = gss_create_empty_buffer_set(minor, &innerOutputTokens);
    if (GSS_ERROR(major))
        goto cleanup;

    assert(innerOutputTokens->count == 0);
    assert(innerOutputTokens->elements == NULL);

    innerOutputTokens->elements = (gss_buffer_desc *)GSSEAP_CALLOC(smCount,
                                                                   sizeof(gss_buffer_desc));
    if (innerOutputTokens->elements == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    outputTokenTypes = (OM_uint32 *)GSSEAP_CALLOC(smCount, sizeof(OM_uint32));
    if (outputTokenTypes == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    /*
     * Process all the tokens that are valid for the current state. If
     * the processToken function returns GSS_S_COMPLETE, the state is
     * advanced until there is a token to send or the ESTABLISHED state
     * is reached.
     */
    do {
        major = GSS_S_COMPLETE;

        for (i = 0; i < smCount; i++) {
            struct gss_eap_sm *smp = &sm[i];
            int processToken = 0;
            gss_buffer_t innerInputToken = GSS_C_NO_BUFFER;
            OM_uint32 *inputTokenType = NULL;
            gss_buffer_desc innerOutputToken = GSS_C_EMPTY_BUFFER;

            if ((smp->validStates & ctx->state) == 0)
                continue;

            if (smp->inputTokenType == ITOK_TYPE_NONE || initialContextToken) {
                processToken = 1;
            } else if ((smFlags & SM_FLAG_TRANSITION) == 0) {
                for (j = 0; j < innerInputTokens->count; j++) {
                    if ((inputTokenTypes[j] & ITOK_TYPE_MASK) == smp->inputTokenType) {
                        processToken = 1;
                        if (innerInputToken != GSS_C_NO_BUFFER) {
                            major = GSS_S_DEFECTIVE_TOKEN;
                            *minor = GSSEAP_DUPLICATE_ITOK;
                            break;
                        }
                    }
                    innerInputToken = &innerInputTokens->elements[j];
                    inputTokenType = &inputTokenTypes[j];
                }
            }

#ifdef GSSEAP_DEBUG
            fprintf(stderr, "GSS-EAP: state %d processToken %d inputTokenType %08x "
                    "innerInputToken %p innerOutputTokensCount %zd\n",
                    ctx->state, processToken, smp->inputTokenType,
                    innerInputToken, innerOutputTokens->count);
#endif

            if (processToken) {
                smFlags = 0;

                major = smp->processToken(minor, cred, ctx, target, mech, reqFlags,
                                         timeReq, chanBindings, innerInputToken,
                                         &innerOutputToken, &smFlags);
                if (GSS_ERROR(major))
                    break;

                if (inputTokenType != NULL)
                    *inputTokenType |= ITOK_FLAG_VERIFIED;

                if (innerOutputToken.value != NULL) {
                    innerOutputTokens->elements[innerOutputTokens->count] = innerOutputToken;
                    assert(smp->outputTokenType != ITOK_TYPE_NONE);
                    outputTokenTypes[innerOutputTokens->count] = smp->outputTokenType;
                    if (smp->itokFlags & SM_ITOK_FLAG_CRITICAL)
                        outputTokenTypes[innerOutputTokens->count] |= ITOK_FLAG_CRITICAL;
                    innerOutputTokens->count++;
                }
                if (smFlags & SM_FLAG_STOP_EVAL)
                    break;
            } else if ((smp->itokFlags & SM_ITOK_FLAG_REQUIRED) &&
                smp->inputTokenType != ITOK_TYPE_NONE) {
                major = GSS_S_DEFECTIVE_TOKEN;
                *minor = GSSEAP_MISSING_REQUIRED_ITOK;
                break;
            }
        }

        if (GSS_ERROR(major) || (smFlags & SM_FLAG_TRANSITION) == 0)
            break;

        assert(ctx->state < GSSEAP_STATE_ESTABLISHED);

#ifdef GSSEAP_DEBUG
        fprintf(stderr, "GSS-EAP: state transition %s->%s\n",
                gssEapStateToString(ctx->state),
                gssEapStateToString(GSSEAP_STATE_NEXT(ctx->state)));
#endif

        ctx->state = GSSEAP_STATE_NEXT(ctx->state);

        if (innerOutputTokens->count != 0 || (smFlags & SM_FLAG_FORCE_SEND_TOKEN)) {
            assert(major == GSS_S_CONTINUE_NEEDED || ctx->state == GSSEAP_STATE_ESTABLISHED);
            break; /* send any tokens if we have them */
        }
    } while (ctx->state != GSSEAP_STATE_ESTABLISHED);

    assert(innerOutputTokens->count <= smCount);

    /* Check we understood all critical tokens */
    if (!GSS_ERROR(major)) {
        for (j = 0; j < innerInputTokens->count; j++) {
            if ((inputTokenTypes[j] & ITOK_FLAG_CRITICAL) &&
                (inputTokenTypes[j] & ITOK_FLAG_VERIFIED) == 0) {
                major = GSS_S_UNAVAILABLE;
                *minor = GSSEAP_CRIT_ITOK_UNAVAILABLE;
                goto cleanup;
            }
        }
    }

    /* Emit an error token if we are the acceptor */
    if (GSS_ERROR(major)) {
        if (CTX_IS_INITIATOR(ctx))
            goto cleanup; /* return error directly to caller */

        /* replace any emitted tokens with error token */
        gss_release_buffer_set(&tmpMinor, &innerOutputTokens);

        tmpMajor = makeErrorToken(&tmpMinor, major, *minor, &innerOutputTokens);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }

        outputTokenTypes[0] = ITOK_TYPE_CONTEXT_ERR | ITOK_FLAG_CRITICAL;
    }

#ifdef GSSEAP_DEBUG
    for (i = 0; i < innerOutputTokens->count; i++) {
        fprintf(stderr, "GSS-EAP: type %08x length %zd value %p\n",
                outputTokenTypes[i],
                innerOutputTokens->elements[i].length,
                innerOutputTokens->elements[i].value);
    }
#endif

    /* Format composite output token */
    if (innerOutputTokens->count != 0 ||            /* inner tokens to send */
        !CTX_IS_INITIATOR(ctx) ||                   /* any leg acceptor */
        ctx->state != GSSEAP_STATE_ESTABLISHED) {   /* non-last leg initiator */
        tmpMajor = gssEapEncodeInnerTokens(&tmpMinor, innerOutputTokens,
                                           outputTokenTypes, &unwrappedOutputToken);
        if (tmpMajor == GSS_S_COMPLETE) {
            tmpMajor = gssEapMakeToken(&tmpMinor, ctx, &unwrappedOutputToken,
                                       TOK_TYPE_ESTABLISH_CONTEXT, outputToken);
            if (GSS_ERROR(tmpMajor)) {
                major = tmpMajor;
                *minor = tmpMinor;
                goto cleanup;
            }
        }
    }

    assert(GSS_ERROR(major) ||
           (major == GSS_S_CONTINUE_NEEDED && (ctx->state > GSSEAP_STATE_INITIAL && ctx->state < GSSEAP_STATE_ESTABLISHED)) ||
           (major == GSS_S_COMPLETE && ctx->state == GSSEAP_STATE_ESTABLISHED));

cleanup:
    gss_release_buffer_set(&tmpMinor, &innerInputTokens);
    gss_release_buffer_set(&tmpMinor, &innerOutputTokens);
    if (inputTokenTypes != NULL)
        GSSEAP_FREE(inputTokenTypes);
    if (outputTokenTypes != NULL)
    gss_release_buffer(&tmpMinor, &unwrappedOutputToken);
        GSSEAP_FREE(outputTokenTypes);

    return major;
}
