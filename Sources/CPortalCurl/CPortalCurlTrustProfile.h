#ifndef CPORTALCURL_TRUST_PROFILE_H
#define CPORTALCURL_TRUST_PROFILE_H

#if defined(PVCURL_ENABLE_TEST_TRUST_PROFILE)
#include "CPortalCurlTestTrustProfile.h"
#if !defined(PVCURL_TEST_APPROVED_URL_PREFIX) ||                               \
    !defined(PVCURL_TEST_APPROVED_HOST)
#error "incomplete CPortalCurl test origin profile"
#endif
#define PVCURL_APPROVED_URL_PREFIX PVCURL_TEST_APPROVED_URL_PREFIX
#define PVCURL_APPROVED_HOST PVCURL_TEST_APPROVED_HOST
#else
#define PVCURL_APPROVED_URL_PREFIX "https://166.111.143.19:4443/"
#define PVCURL_APPROVED_HOST "166.111.143.19:4443"
#endif

#endif
