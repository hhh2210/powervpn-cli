#ifndef CPORTALCURL_H
#define CPORTALCURL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const uint8_t *pointer;
  size_t length;
} pvcurl_bytes_t;

typedef enum {
  PVCURL_STATUS_OK = 0,
  PVCURL_STATUS_INVALID_ARGUMENT = 1,
  PVCURL_STATUS_SETUP_FAILED = 2,
  PVCURL_STATUS_TRUST_REJECTED = 3,
  PVCURL_STATUS_REDIRECT_REJECTED = 4,
  PVCURL_STATUS_AUTHENTICATION_REJECTED = 5,
  PVCURL_STATUS_HEADER_FRAMING_REJECTED = 6,
  PVCURL_STATUS_RESPONSE_TOO_LARGE = 7,
  PVCURL_STATUS_CANCELLED = 8,
  PVCURL_STATUS_TIMED_OUT = 9,
  PVCURL_STATUS_UNAVAILABLE = 10
} pvcurl_status_t;

typedef enum {
  PVCURL_SET_COOKIE_SELECTION_UNAVAILABLE = 0,
  PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS = 1
} pvcurl_set_cookie_selection_t;
typedef struct {
  pvcurl_status_t status;
  uint32_t set_cookie_field_count;
  pvcurl_set_cookie_selection_t set_cookie_selection;
  bool duplicate_set_cookie_rejected;
  bool response_headers_observed;
} pvcurl_transfer_diagnostics_t;


typedef enum { PVCURL_METHOD_GET = 0, PVCURL_METHOD_POST = 1 } pvcurl_method_t;

/// Immutable inputs for one allowlisted Portal request. Every text field is
/// ptr+len; an absent body or Content-Type is represented by {NULL, 0}.
/// The body is borrowed without a C-layer copy and must remain alive until
/// pvcurl_request_perform() returns.
typedef struct {
  pvcurl_method_t method;
  bool require_set_cookie;
  pvcurl_bytes_t url;
  pvcurl_bytes_t host_header;
  pvcurl_bytes_t accept_header;
  pvcurl_bytes_t user_agent_header;
  pvcurl_bytes_t content_type_header;
  pvcurl_bytes_t cookie_header;
  pvcurl_bytes_t body;
  uint32_t timeout_milliseconds;
  size_t maximum_response_body_bytes;
  size_t maximum_response_header_bytes;
  size_t maximum_response_header_line_bytes;
  size_t maximum_set_cookie_bytes;
} pvcurl_request_config_t;

typedef struct pvcurl_request pvcurl_request_t;

/// On success, body and set_cookie are owned exact-length allocations.
/// Destroy this value even when a later Swift-layer check fails.
typedef struct {
  uint16_t http_status;
  uint8_t *body;
  size_t body_length;
  uint8_t *set_cookie;
  size_t set_cookie_length;
  uint32_t set_cookie_field_count;
  pvcurl_set_cookie_selection_t set_cookie_selection;
  bool effective_url_exact;
} pvcurl_response_t;

/// Value-free and network-free runtime gate. This initializes libcurl once and
/// checks SecureTransport plus immutable anchor and SPKI-pin support.
pvcurl_status_t pvcurl_runtime_preflight(void);

/// Read-only views of the immutable production trust profile. These values
/// cannot replace or override the profile used by pvcurl_request_perform().
pvcurl_bytes_t pvcurl_approved_leaf_certificate(void);
const char *pvcurl_approved_pinned_public_key(void);

pvcurl_status_t pvcurl_request_create(const pvcurl_request_config_t *config,
    pvcurl_request_t **request_out);

/// A request is one-shot. Calling this twice returns INVALID_ARGUMENT.
pvcurl_status_t pvcurl_request_perform(pvcurl_request_t *request,
    pvcurl_response_t *response_out);
/// Available after pvcurl_request_perform() returns. The result is request-owned,
/// value-free, and remains valid until the request is destroyed.
pvcurl_status_t pvcurl_request_get_diagnostics(pvcurl_request_t *request,
    pvcurl_transfer_diagnostics_t *diagnostics_out);


/// May be called from another thread while perform is running.
void pvcurl_request_cancel(pvcurl_request_t *request);

/// The caller must not destroy a request concurrently with perform/cancel.
void pvcurl_request_destroy(pvcurl_request_t *request);

/// Zeroes every owned byte before release and resets the public fields.
void pvcurl_response_destroy(pvcurl_response_t *response);

#ifdef __cplusplus
}
#endif

#endif
