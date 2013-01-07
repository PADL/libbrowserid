/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

/*
 * You need to implement this for your platform.
 */

BIDError
_BIDBrowserGetAssertion(
    BIDContext context BID_UNUSED,
    const char *szPackedAudience BID_UNUSED,
    const char *szAudienceOrSpn BID_UNUSED,
    json_t *claims BID_UNUSED,
    const char *szIdentityName BID_UNUSED,
    uint32_t ulReqFlags BID_UNUSED,
    char **pAssertion BID_UNUSED)
{
    return BID_S_INTERACT_UNAVAILABLE;
}
