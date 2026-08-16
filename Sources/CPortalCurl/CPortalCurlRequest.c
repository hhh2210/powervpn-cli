#include "CPortalCurlInternal.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PVCURL_MAX_BODY_BYTES (16U * 1024U * 1024U)
#define PVCURL_MAX_HEADER_BYTES (256U * 1024U)
#define PVCURL_MAX_LINE_BYTES (16U * 1024U)
#define PVCURL_MAX_COOKIE_BYTES (8U * 1024U)

void pvcurl_clear(void *pointer, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)pointer;
  while (pointer != NULL && length > 0U) {
    *bytes++ = 0U;
    --length;
  }
}

static bool pvcurl_valid_bytes(pvcurl_bytes_t value, size_t maximum,
    uint8_t minimum_byte) {
  if (value.pointer == NULL || value.length == 0U || value.length > maximum) {
    return false;
  }
  for (size_t index = 0; index < value.length; ++index) {
    if (value.pointer[index] < minimum_byte || value.pointer[index] > 0x7eU) {
      return false;
    }
  }
  return true;
}

static bool pvcurl_absent(pvcurl_bytes_t value) {
  return value.pointer == NULL && value.length == 0U;
}

static bool pvcurl_url_matches_host(pvcurl_bytes_t url,
    pvcurl_bytes_t host_header) {
  static const uint8_t https_prefix[] = "https://";
  const size_t prefix_length = sizeof(https_prefix) - 1U;
  if (!pvcurl_valid_bytes(host_header, 512U, 0x21U) ||
      url.length <= prefix_length + host_header.length ||
      memcmp(url.pointer, https_prefix, prefix_length) != 0 ||
      memcmp(url.pointer + prefix_length, host_header.pointer,
             host_header.length) != 0 ||
      url.pointer[prefix_length + host_header.length] != '/') {
    return false;
  }
  return true;
}

static bool pvcurl_valid_config(const pvcurl_request_config_t *config) {
  if (config == NULL ||
      (config->method != PVCURL_METHOD_GET &&
       config->method != PVCURL_METHOD_POST) ||
      !pvcurl_valid_bytes(config->url, 4096U, 0x21U) ||
      !pvcurl_url_matches_host(config->url, config->host_header) ||
      !pvcurl_valid_bytes(config->accept_header, 8192U, 0x20U) ||
      !pvcurl_valid_bytes(config->user_agent_header, 8192U, 0x20U) ||
      !pvcurl_valid_bytes(config->cookie_header, PVCURL_MAX_COOKIE_BYTES,
                          0x20U) ||
      config->body.length > PVCURL_MAX_BODY_BYTES ||
      (config->body.pointer == NULL) != (config->body.length == 0U) ||
      (config->content_type_header.pointer == NULL) !=
          (config->content_type_header.length == 0U) ||
      config->timeout_milliseconds == 0U ||
      config->timeout_milliseconds > 60000U ||
      config->maximum_response_body_bytes == 0U ||
      config->maximum_response_body_bytes > PVCURL_MAX_BODY_BYTES ||
      config->maximum_response_header_bytes == 0U ||
      config->maximum_response_header_bytes > PVCURL_MAX_HEADER_BYTES ||
      config->maximum_response_header_line_bytes == 0U ||
      config->maximum_response_header_line_bytes > PVCURL_MAX_LINE_BYTES ||
      config->maximum_response_header_line_bytes >
          config->maximum_response_header_bytes ||
      config->maximum_set_cookie_bytes == 0U ||
      config->maximum_set_cookie_bytes > PVCURL_MAX_COOKIE_BYTES ||
      config->maximum_set_cookie_bytes >
          config->maximum_response_header_line_bytes) {
    return false;
  }
  bool body_absent = pvcurl_absent(config->body);
  bool content_type_absent = pvcurl_absent(config->content_type_header);
  if ((config->method == PVCURL_METHOD_GET &&
       (!body_absent || !content_type_absent)) ||
      (config->method == PVCURL_METHOD_POST &&
       body_absent != content_type_absent) ||
      (!content_type_absent &&
       !pvcurl_valid_bytes(config->content_type_header, 8192U, 0x20U))) {
    return false;
  }
  return memchr(config->url.pointer, '#', config->url.length) == NULL;
}

static pvcurl_status_t pvcurl_copy(pvcurl_bytes_t source,
    pvcurl_owned_bytes_t *destination) {
  if (source.length == SIZE_MAX) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  if (source.length == 0U) {
    destination->pointer = NULL;
    destination->length = 0U;
    return PVCURL_STATUS_OK;
  }
  destination->pointer = (uint8_t *)malloc(source.length + 1U);
  if (destination->pointer == NULL) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  memcpy(destination->pointer, source.pointer, source.length);
  destination->pointer[source.length] = 0U;
  destination->length = source.length;
  return PVCURL_STATUS_OK;
}

static void pvcurl_owned_destroy(pvcurl_owned_bytes_t *value) {
  if (value->pointer != NULL) {
    pvcurl_clear(value->pointer, value->length + 1U);
    free(value->pointer);
  }
  value->pointer = NULL;
  value->length = 0U;
}

pvcurl_status_t pvcurl_request_create(const pvcurl_request_config_t *config,
    pvcurl_request_t **request_out) {
  if (request_out == NULL) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  *request_out = NULL;
  if (!pvcurl_valid_config(config)) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  pvcurl_request_t *request = (pvcurl_request_t *)calloc(1U, sizeof(*request));
  if (request == NULL) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  atomic_init(&request->cancelled, false);
  atomic_init(&request->state, 0U);
  request->method = config->method;
  request->require_set_cookie = config->require_set_cookie;
#define PVCURL_COPY_FIELD(field)                                                \
  do {                                                                          \
    pvcurl_status_t copy_status = pvcurl_copy(config->field, &request->field);  \
    if (copy_status != PVCURL_STATUS_OK) {                                       \
      pvcurl_request_destroy(request);                                           \
      return copy_status;                                                        \
    }                                                                            \
  } while (0)
  PVCURL_COPY_FIELD(url);
  PVCURL_COPY_FIELD(host_header);
  PVCURL_COPY_FIELD(accept_header);
  PVCURL_COPY_FIELD(user_agent_header);
  PVCURL_COPY_FIELD(content_type_header);
  PVCURL_COPY_FIELD(cookie_header);
#undef PVCURL_COPY_FIELD
  request->body = config->body.pointer;
  request->body_length = config->body.length;
  request->timeout_milliseconds = config->timeout_milliseconds;
  request->maximum_response_body_bytes = config->maximum_response_body_bytes;
  request->maximum_response_header_bytes =
      config->maximum_response_header_bytes;
  request->maximum_response_header_line_bytes =
      config->maximum_response_header_line_bytes;
  request->maximum_set_cookie_bytes = config->maximum_set_cookie_bytes;
  *request_out = request;
  return PVCURL_STATUS_OK;
}

static pvcurl_status_t pvcurl_append_header(struct curl_slist **headers,
    const char *name,
    const uint8_t *value,
    size_t value_length) {
  size_t name_length = strlen(name);
  if (value_length > SIZE_MAX - name_length - 3U) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  size_t length = name_length + 2U + value_length;
  char *line = (char *)malloc(length + 1U);
  if (line == NULL) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  memcpy(line, name, name_length);
  memcpy(line + name_length, ": ", 2U);
  if (value_length > 0U) {
    memcpy(line + name_length + 2U, value, value_length);
  }
  line[length] = '\0';
  struct curl_slist *updated = curl_slist_append(*headers, line);
  pvcurl_clear(line, length + 1U);
  free(line);
  if (updated == NULL) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  *headers = updated;
  return PVCURL_STATUS_OK;
}

pvcurl_status_t pvcurl_request_build_headers(const pvcurl_request_t *request,
    struct curl_slist **headers_out) {
  if (request == NULL || headers_out == NULL) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  *headers_out = NULL;
  char content_length[32];
  int rendered = snprintf(content_length, sizeof(content_length), "%zu",
                          request->body_length);
  if (rendered <= 0 || (size_t)rendered >= sizeof(content_length)) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
#define PVCURL_ADD(name, field)                                                 \
  do {                                                                          \
    pvcurl_status_t add_status = pvcurl_append_header(                           \
        headers_out, name, request->field.pointer, request->field.length);       \
    if (add_status != PVCURL_STATUS_OK) {                                        \
      pvcurl_slist_destroy_secure(*headers_out);                                 \
      *headers_out = NULL;                                                       \
      return add_status;                                                         \
    }                                                                            \
  } while (0)
  PVCURL_ADD("Host", host_header);
  PVCURL_ADD("Accept", accept_header);
  PVCURL_ADD("User-Agent", user_agent_header);
  pvcurl_status_t status = PVCURL_STATUS_OK;
  if (request->method == PVCURL_METHOD_POST) {
    if (request->content_type_header.length > 0U) {
  PVCURL_ADD("Content-Type", content_type_header);
    }
    status =
        pvcurl_append_header(headers_out, "Content-Length",
                             (const uint8_t *)content_length, (size_t)rendered);
  if (status == PVCURL_STATUS_OK) {
    struct curl_slist *updated = curl_slist_append(*headers_out, "Expect:");
    status = updated == NULL ? PVCURL_STATUS_SETUP_FAILED : PVCURL_STATUS_OK;
    if (updated != NULL) {
      *headers_out = updated;
    }
  }
  }
  if (status == PVCURL_STATUS_OK) {
    PVCURL_ADD("Cookie", cookie_header);
  }
#undef PVCURL_ADD
  if (status != PVCURL_STATUS_OK) {
    pvcurl_slist_destroy_secure(*headers_out);
    *headers_out = NULL;
  }
  pvcurl_clear(content_length, sizeof(content_length));
  return status;
}

void pvcurl_slist_destroy_secure(struct curl_slist *headers) {
  for (struct curl_slist *item = headers; item != NULL; item = item->next) {
    if (item->data != NULL) {
      pvcurl_clear(item->data, strlen(item->data));
    }
  }
  curl_slist_free_all(headers);
}

pvcurl_status_t pvcurl_request_get_diagnostics(pvcurl_request_t *request,
    pvcurl_transfer_diagnostics_t *diagnostics_out) {
  if (request == NULL || diagnostics_out == NULL)
    return PVCURL_STATUS_INVALID_ARGUMENT;
  memset(diagnostics_out, 0, sizeof(*diagnostics_out));
  if (atomic_load_explicit(&request->state, memory_order_acquire) != 2U) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  *diagnostics_out = request->diagnostics;
  return PVCURL_STATUS_OK;
}

void pvcurl_request_cancel(pvcurl_request_t *request) {
  if (request != NULL) {
    atomic_store_explicit(&request->cancelled, true, memory_order_release);
  }
}

void pvcurl_request_destroy(pvcurl_request_t *request) {
  if (request == NULL) {
    return;
  }
  pvcurl_owned_destroy(&request->url);
  pvcurl_owned_destroy(&request->host_header);
  pvcurl_owned_destroy(&request->accept_header);
  pvcurl_owned_destroy(&request->user_agent_header);
  pvcurl_owned_destroy(&request->content_type_header);
  pvcurl_owned_destroy(&request->cookie_header);
  pvcurl_clear(request, sizeof(*request));
  free(request);
}

void pvcurl_response_destroy(pvcurl_response_t *response) {
  if (response == NULL) {
    return;
  }
  if (response->body != NULL) {
    pvcurl_clear(response->body, response->body_length);
    free(response->body);
  }
  if (response->set_cookie != NULL) {
    pvcurl_clear(response->set_cookie, response->set_cookie_length);
    free(response->set_cookie);
  }
  pvcurl_clear(response, sizeof(*response));
}
