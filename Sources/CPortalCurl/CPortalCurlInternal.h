#ifndef CPORTALCURL_INTERNAL_H
#define CPORTALCURL_INTERNAL_H

#include "CPortalCurl.h"

#include <stdatomic.h>

struct curl_slist;

typedef struct {
  uint8_t *pointer;
  size_t length;
} pvcurl_owned_bytes_t;

struct pvcurl_request {
  pvcurl_method_t method;
  bool require_set_cookie;
  pvcurl_owned_bytes_t url;
  pvcurl_owned_bytes_t host_header;
  pvcurl_owned_bytes_t accept_header;
  pvcurl_owned_bytes_t user_agent_header;
  pvcurl_owned_bytes_t content_type_header;
  pvcurl_owned_bytes_t cookie_header;
  const uint8_t *body;
  size_t body_length;
  uint32_t timeout_milliseconds;
  size_t maximum_response_body_bytes;
  size_t maximum_response_header_bytes;
  size_t maximum_response_header_line_bytes;
  size_t maximum_set_cookie_bytes;
  atomic_bool cancelled;
  atomic_uint state;
  pvcurl_transfer_diagnostics_t diagnostics;
};

typedef struct pvcurl_header_parser pvcurl_header_parser_t;

pvcurl_status_t pvcurl_header_parser_create(
    size_t maximum_header_bytes, size_t maximum_line_bytes,
    size_t maximum_set_cookie_bytes, pvcurl_header_parser_t **parser_out);

pvcurl_status_t pvcurl_header_parser_feed(pvcurl_header_parser_t *parser,
                                          const uint8_t *line, size_t length);

pvcurl_status_t pvcurl_header_parser_finish(pvcurl_header_parser_t *parser,
                                            bool require_set_cookie,
    uint16_t *http_status_out,
    uint8_t **set_cookie_out,
    size_t *set_cookie_length_out);
pvcurl_status_t
pvcurl_header_parser_failure(const pvcurl_header_parser_t *parser);
void pvcurl_header_parser_export_diagnostics(
    const pvcurl_header_parser_t *parser,
    pvcurl_transfer_diagnostics_t *diagnostics_out);


size_t pvcurl_header_callback(char *buffer, size_t size, size_t item_count,
    void *context);

void pvcurl_header_parser_destroy(pvcurl_header_parser_t *parser);

pvcurl_status_t pvcurl_request_build_headers(const pvcurl_request_t *request,
    struct curl_slist **headers_out);

void pvcurl_slist_destroy_secure(struct curl_slist *headers);

pvcurl_status_t pvcurl_apply_approved_trust(void *easy_handle);
void pvcurl_clear(void *pointer, size_t length);

pvcurl_status_t pvcurl_finalize_status(int curl_code, bool cancelled,
    pvcurl_status_t callback_failure,
    uint16_t http_status,
    bool effective_url_exact);

#endif
