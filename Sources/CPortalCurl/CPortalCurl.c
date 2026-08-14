#include "CPortalCurlInternal.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
  pvcurl_request_t *request;
  uint8_t *body;
  size_t body_length;
  size_t body_capacity;
  pvcurl_status_t failure;
} pvcurl_transfer_t;
static pthread_once_t pvcurl_once = PTHREAD_ONCE_INIT;
static CURLcode pvcurl_global_status = CURLE_FAILED_INIT;
static void pvcurl_initialize(void) {
  pvcurl_global_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}
static bool pvcurl_has_https(const curl_version_info_data *version) {
  if (version->protocols == NULL) {
    return false;
  }
  for (const char *const *protocol = version->protocols; *protocol != NULL;
       ++protocol) {
    if (strcmp(*protocol, "https") == 0) {
      return true;
    }
  }
  return false;
}
pvcurl_status_t pvcurl_runtime_preflight(void) {
  if (pthread_once(&pvcurl_once, pvcurl_initialize) != 0 ||
      pvcurl_global_status != CURLE_OK) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
  if (version == NULL || version->version_num < 0x075500U ||
      (version->features & CURL_VERSION_SSL) == 0 ||
      version->ssl_version == NULL ||
      strstr(version->ssl_version, "SecureTransport") == NULL ||
      !pvcurl_has_https(version)) {
    return PVCURL_STATUS_UNAVAILABLE;
  }
  CURL *easy = curl_easy_init();
  if (easy == NULL) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  pvcurl_status_t trust_status = pvcurl_apply_approved_trust(easy);
  curl_easy_cleanup(easy);
  return trust_status;
}
static size_t pvcurl_body_callback(char *buffer, size_t size, size_t item_count,
    void *context) {
  pvcurl_transfer_t *transfer = (pvcurl_transfer_t *)context;
  if (transfer == NULL || buffer == NULL ||
      (item_count != 0U && size > SIZE_MAX / item_count)) {
    return 0U;
  }
  size_t length = size * item_count;
  if (atomic_load_explicit(&transfer->request->cancelled,
          memory_order_acquire)) {
    return 0U;
  }
  if (length > transfer->body_capacity - transfer->body_length) {
    transfer->failure = PVCURL_STATUS_RESPONSE_TOO_LARGE;
    return 0U;
  }
  if (length > 0U) {
    memcpy(transfer->body + transfer->body_length, buffer, length);
  }
  transfer->body_length += length;
  return length;
}
static int pvcurl_progress_callback(void *context, curl_off_t download_total,
    curl_off_t download_now,
    curl_off_t upload_total,
    curl_off_t upload_now) {
  (void)download_total;
  (void)download_now;
  (void)upload_total;
  (void)upload_now;
  pvcurl_request_t *request = (pvcurl_request_t *)context;
  return atomic_load_explicit(&request->cancelled, memory_order_acquire) ? 1
                                                                         : 0;
}
static bool pvcurl_trust_error(CURLcode code) {
  switch (code) {
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_ISSUER_ERROR:
  case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
      return true;
    default:
      return false;
  }
}

pvcurl_status_t pvcurl_finalize_status(int curl_code, bool cancelled,
    pvcurl_status_t callback_failure,
    uint16_t http_status,
    bool effective_url_exact) {
  CURLcode code = (CURLcode)curl_code;
  if (callback_failure != PVCURL_STATUS_OK) {
    return callback_failure;
  }
  if (code == CURLE_OPERATION_TIMEDOUT) {
    return PVCURL_STATUS_TIMED_OUT;
  }
  if ((code == CURLE_ABORTED_BY_CALLBACK || code == CURLE_WRITE_ERROR) &&
      cancelled) {
    return PVCURL_STATUS_CANCELLED;
  }
  if (pvcurl_trust_error(code)) {
    return PVCURL_STATUS_TRUST_REJECTED;
  }
  if (code != CURLE_OK) {
    return PVCURL_STATUS_UNAVAILABLE;
  }
  if (http_status >= 300U && http_status <= 399U) {
    return PVCURL_STATUS_REDIRECT_REJECTED;
  }
  if (http_status == 401U || http_status == 407U) {
    return PVCURL_STATUS_AUTHENTICATION_REJECTED;
  }
  if (http_status < 200U || http_status > 599U) {
    return PVCURL_STATUS_HEADER_FRAMING_REJECTED;
  }
  return effective_url_exact ? PVCURL_STATUS_OK
                             : PVCURL_STATUS_REDIRECT_REJECTED;
}

static pvcurl_status_t pvcurl_configure(CURL *curl, pvcurl_request_t *request,
    struct curl_slist *headers,
    pvcurl_header_parser_t *parser,
    pvcurl_transfer_t *transfer) {
#define PVCURL_SET(option, value)                                                \
  do {                                                                           \
    if (curl_easy_setopt(curl, option, value) != CURLE_OK) {                     \
      return PVCURL_STATUS_SETUP_FAILED;                                         \
    }                                                                             \
  } while (0)
  PVCURL_SET(CURLOPT_URL, (const char *)request->url.pointer);
  PVCURL_SET(CURLOPT_PROTOCOLS_STR, "https");
  PVCURL_SET(CURLOPT_REDIR_PROTOCOLS_STR, "https");
  PVCURL_SET(CURLOPT_PROXY, "");
  PVCURL_SET(CURLOPT_NOPROXY, "*");
  PVCURL_SET(CURLOPT_FOLLOWLOCATION, 0L);
  PVCURL_SET(CURLOPT_MAXREDIRS, 0L);
  PVCURL_SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
  pvcurl_status_t trust_status = pvcurl_apply_approved_trust(curl);
  if (trust_status != PVCURL_STATUS_OK) {
    return trust_status;
  }
  PVCURL_SET(CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);
  PVCURL_SET(CURLOPT_NOSIGNAL, 1L);
  PVCURL_SET(CURLOPT_TIMEOUT_MS, (long)request->timeout_milliseconds);
  PVCURL_SET(CURLOPT_CONNECTTIMEOUT_MS, (long)request->timeout_milliseconds);
  PVCURL_SET(CURLOPT_FAILONERROR, 0L);
  if (request->method == PVCURL_METHOD_GET) {
    PVCURL_SET(CURLOPT_HTTPGET, 1L);
  } else {
  PVCURL_SET(CURLOPT_POST, 1L);
    if (request->body_length > 0U) {
  PVCURL_SET(CURLOPT_POSTFIELDS, (void *)request->body);
    }
  PVCURL_SET(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)request->body_length);
  }
  PVCURL_SET(CURLOPT_HTTPHEADER, headers);
  PVCURL_SET(CURLOPT_HEADERFUNCTION, pvcurl_header_callback);
  PVCURL_SET(CURLOPT_HEADERDATA, parser);
  PVCURL_SET(CURLOPT_WRITEFUNCTION, pvcurl_body_callback);
  PVCURL_SET(CURLOPT_WRITEDATA, transfer);
  PVCURL_SET(CURLOPT_NOPROGRESS, 0L);
  PVCURL_SET(CURLOPT_XFERINFOFUNCTION, pvcurl_progress_callback);
  PVCURL_SET(CURLOPT_XFERINFODATA, request);
#undef PVCURL_SET
  return PVCURL_STATUS_OK;
}

pvcurl_status_t pvcurl_request_perform(pvcurl_request_t *request,
    pvcurl_response_t *response_out) {
  if (request == NULL || response_out == NULL) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  memset(response_out, 0, sizeof(*response_out));
  unsigned int expected_state = 0U;
  if (!atomic_compare_exchange_strong_explicit(&request->state, &expected_state,
                                               1U, memory_order_acq_rel,
          memory_order_acquire)) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  pvcurl_status_t result = pvcurl_runtime_preflight();
  if (atomic_load_explicit(&request->cancelled, memory_order_acquire)) {
    result = PVCURL_STATUS_CANCELLED;
  }
  pvcurl_header_parser_t *parser = NULL;
  struct curl_slist *headers = NULL;
  CURL *curl = NULL;
  pvcurl_transfer_t transfer = {.request = request};
  pvcurl_response_t response = {0};
  if (result == PVCURL_STATUS_OK) {
    result =
        pvcurl_header_parser_create(request->maximum_response_header_bytes,
        request->maximum_response_header_line_bytes,
                                    request->maximum_set_cookie_bytes, &parser);
  }
  if (result == PVCURL_STATUS_OK) {
    transfer.body_capacity = request->maximum_response_body_bytes;
    transfer.body = (uint8_t *)calloc(transfer.body_capacity, 1U);
    result =
        transfer.body == NULL ? PVCURL_STATUS_SETUP_FAILED : PVCURL_STATUS_OK;
  }
  if (result == PVCURL_STATUS_OK) {
    result = pvcurl_request_build_headers(request, &headers);
  }
  if (result == PVCURL_STATUS_OK) {
    curl = curl_easy_init();
    result = curl == NULL ? PVCURL_STATUS_SETUP_FAILED : PVCURL_STATUS_OK;
  }
  if (result == PVCURL_STATUS_OK) {
    result = pvcurl_configure(curl, request, headers, parser, &transfer);
  }
  if (result == PVCURL_STATUS_OK) {
    CURLcode code = curl_easy_perform(curl);
    char *effective_url = NULL;
    long curl_status = 0L;
    long http_version = 0L;
    long redirect_count = 0L;
    bool info_valid =
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url) ==
            CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_status) ==
            CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &http_version) ==
            CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count) ==
            CURLE_OK &&
        curl_status >= 0L && curl_status <= 65535L;
    bool wire_metadata_exact =
        http_version == CURL_HTTP_VERSION_1_1 && redirect_count == 0L;
    bool exact =
        info_valid && effective_url != NULL &&
        strlen(effective_url) == request->url.length &&
        memcmp(effective_url, request->url.pointer, request->url.length) == 0;
    pvcurl_status_t callback_failure = transfer.failure;
    if (callback_failure == PVCURL_STATUS_OK) {
      callback_failure = pvcurl_header_parser_failure(parser);
    }
    if (code == CURLE_OK && callback_failure == PVCURL_STATUS_OK) {
      if (info_valid && ((curl_status >= 300L && curl_status <= 399L) ||
           curl_status == 401L || curl_status == 407L)) {
        response.http_status = (uint16_t)curl_status;
      } else {
        callback_failure = pvcurl_header_parser_finish(
            parser, request->require_set_cookie, &response.http_status,
            &response.set_cookie, &response.set_cookie_length);
      }
    }
    if (code == CURLE_OK && (!info_valid || !wire_metadata_exact ||
         (response.http_status != 0U &&
          response.http_status != (uint16_t)curl_status))) {
      callback_failure = PVCURL_STATUS_HEADER_FRAMING_REJECTED;
    }
    response.effective_url_exact = exact;
    result = pvcurl_finalize_status(
        (int)code,
        atomic_load_explicit(&request->cancelled, memory_order_acquire),
        callback_failure, response.http_status, exact);
  }
  request->diagnostics.status = result;
  pvcurl_header_parser_export_diagnostics(parser, &request->diagnostics);
  if (result == PVCURL_STATUS_OK) {
    response.body = transfer.body;
    response.body_length = transfer.body_length;
    response.set_cookie_field_count =
        request->diagnostics.set_cookie_field_count;
    response.set_cookie_selection =
        request->diagnostics.set_cookie_selection;
    transfer.body = NULL;
    *response_out = response;
    memset(&response, 0, sizeof(response));
  }
  pvcurl_response_destroy(&response);
  if (transfer.body != NULL) {
    pvcurl_clear(transfer.body, transfer.body_length);
    free(transfer.body);
  }
  if (curl != NULL) {
    curl_easy_cleanup(curl);
  }
  pvcurl_slist_destroy_secure(headers);
  pvcurl_header_parser_destroy(parser);
  atomic_store_explicit(&request->state, 2U, memory_order_release);
  return result;
}
