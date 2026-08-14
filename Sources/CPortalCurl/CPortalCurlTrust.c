#include "CPortalCurlInternal.h"

#include <curl/curl.h>

#if defined(PVCURL_ENABLE_TEST_TRUST_PROFILE)
#include "CPortalCurlTestTrustProfile.h"
#if !defined(PVCURL_TEST_APPROVED_LEAF_PEM) ||                                 \
    !defined(PVCURL_TEST_APPROVED_PIN)
#error "incomplete CPortalCurl test trust profile"
#endif
static const uint8_t pvcurl_approved_leaf_pem[] = PVCURL_TEST_APPROVED_LEAF_PEM;
static const char pvcurl_approved_pin[] = PVCURL_TEST_APPROVED_PIN;
#else
static const uint8_t pvcurl_approved_leaf_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICpjCCAg+gAwIBAgIBZDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJDTjEQ\n"
    "MA4GA1UECgwHTGVhZFNlYzEUMBIGA1UECwwLTGVhZFNlYyBWU0cxHDAaBgNVBAMM\n"
    "E09DQSBmb3IgTGVhZFNlYyBWU0cwIBcNMTcwNjE1MDI0NjAwWhgPMjA5OTEyMzEw\n"
    "MjQ2MDBaMEcxCzAJBgNVBAYTAkNOMRAwDgYDVQQKDAdMZWFkU2VjMRQwEgYDVQQL\n"
    "DAtMZWFkU2VjIFZTRzEQMA4GA1UEAwwHR2F0ZVdheTCCASIwDQYJKoZIhvcNAQEB\n"
    "BQADggEPADCCAQoCggEBAMJWnpDTm9oP5oziKqtb+cGQv1Tqa7Q5hyDr3rq6sKT9\n"
    "mg9C+CV8GdV3ziif8u7ARkGwPTWOwjEUljeLvtECqHubLA9+D+TEk1kGlNPWLRlu\n"
    "Kj80tJSvpxOKnCm6jXlF6UWr94MwhbdCJ5oCi8prKhg5g2JAirZaC+o6VzI9jdUb\n"
    "N6Q2Rc+oy+itn/l8gV3uAu+uXoHKqNIR9NZWT99pU7bSNAiG1rroIP7cyZ6RFhbF\n"
    "sbFtXZwXnaChVuMQSwW7HV7yoVyVxOfE9DHNBAKvKLR7UZgkuAZ2fhYwrGZOINaJ\n"
    "elFHHclzYc0dT7KDshjnVgUuiOjoUPMHFD0QxOCRs70CAwEAAaMQMA4wDAYDVR0T\n"
    "AQH/BAIwADANBgkqhkiG9w0BAQsFAAOBgQCWc2ickQhh0HLSyfc8hb1qQKhgayoK\n"
    "ZUnILS3oDjoQbUbJ5QPwqXL2sVpfJsqqp4aWuLcomxlY/mAwQgd2lmcRUOK/nmME\n"
    "pc5vTsvsty7MaDaYFE6w0YFouRqe/7TjshyYQZ/tdOhFEs/iUtTxbHwN4WiNyj0C\n"
    "bqgr6RuG24oacA==\n"
    "-----END CERTIFICATE-----\n";

static const char pvcurl_approved_pin[] =
    "sha256//t9gtW6p01ryORQYkdbVOgevS0sq7bQHgoASWd80Oq1Q=";
#endif

pvcurl_bytes_t pvcurl_approved_leaf_certificate(void) {
  return (pvcurl_bytes_t){
      .pointer = pvcurl_approved_leaf_pem,
      .length = sizeof(pvcurl_approved_leaf_pem) - 1U,
  };
}

const char *pvcurl_approved_pinned_public_key(void) {
  return pvcurl_approved_pin;
}

pvcurl_status_t pvcurl_apply_approved_trust(void *easy_handle) {
  CURL *easy = (CURL *)easy_handle;
  if (easy == NULL) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  struct curl_blob anchor = {
      .data = (void *)pvcurl_approved_leaf_pem,
      .len = sizeof(pvcurl_approved_leaf_pem) - 1U,
      .flags = CURL_BLOB_NOCOPY,
  };

  // The approved leaf has no SAN and its CN is "GateWay", not the fixed IP.
  // Host checking is therefore disabled only inside this adapter. Request
  // creation separately requires the exact IP:port authority; peer-chain
  // validation against this immutable leaf and the immutable SPKI pin remain
  // mandatory on the same connection.
  if (curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &anchor) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_PINNEDPUBLICKEY, pvcurl_approved_pin) !=
          CURLE_OK) {
    return PVCURL_STATUS_UNAVAILABLE;
  }
  return PVCURL_STATUS_OK;
}
