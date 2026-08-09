#include "CPortalCurlInternal.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
  PVCURL_HEADER_EXPECT_STATUS,
  PVCURL_HEADER_EXPECT_FIELDS,
  PVCURL_HEADER_COMPLETE
} pvcurl_header_state_t;

struct pvcurl_header_parser {
  size_t maximum_header_bytes;
  size_t maximum_line_bytes;
  size_t maximum_set_cookie_bytes;
  size_t received_bytes;
  pvcurl_header_state_t state;
  pvcurl_status_t failure;
  uint16_t http_status;
  unsigned int set_cookie_count;
  uint8_t *set_cookie;
  size_t set_cookie_length;
};

static void pvcurl_header_clear(void *pointer, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)pointer;
  while (pointer != NULL && length > 0U) {
    *bytes++ = 0U;
    --length;
  }
}

static pvcurl_status_t pvcurl_reject(
    pvcurl_header_parser_t *parser,
    pvcurl_status_t status) {
  if (parser->failure == PVCURL_STATUS_OK) {
    parser->failure = status;
  }
  return parser->failure;
}

static bool pvcurl_is_token(uint8_t byte) {
  if ((byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
      (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
      (byte >= (uint8_t)'a' && byte <= (uint8_t)'z')) {
    return true;
  }
  return strchr("!#$%&'*+-.^_`|~", (int)byte) != NULL;
}

static bool pvcurl_case_equal(
    const uint8_t *bytes,
    size_t length,
    const char *expected) {
  size_t expected_length = strlen(expected);
  if (length != expected_length) {
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    uint8_t candidate = bytes[index];
    if (candidate >= (uint8_t)'A' && candidate <= (uint8_t)'Z') {
      candidate = (uint8_t)(candidate + ((uint8_t)'a' - (uint8_t)'A'));
    }
    if (candidate != (uint8_t)expected[index]) {
      return false;
    }
  }
  return true;
}

static pvcurl_status_t pvcurl_parse_status(
    pvcurl_header_parser_t *parser,
    const uint8_t *line,
    size_t length) {
  static const uint8_t prefix[] = "HTTP/1.1 ";
  if (length < sizeof(prefix) - 1U + 3U ||
      memcmp(line, prefix, sizeof(prefix) - 1U) != 0) {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  size_t offset = sizeof(prefix) - 1U;
  for (size_t index = 0; index < 3U; ++index) {
    if (line[offset + index] < (uint8_t)'0' ||
        line[offset + index] > (uint8_t)'9') {
      return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
    }
  }
  if (length > offset + 3U && line[offset + 3U] != (uint8_t)' ') {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  unsigned int code =
      (unsigned int)(line[offset] - (uint8_t)'0') * 100U +
      (unsigned int)(line[offset + 1U] - (uint8_t)'0') * 10U +
      (unsigned int)(line[offset + 2U] - (uint8_t)'0');
  if (code < 200U || code > 599U) {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  parser->http_status = (uint16_t)code;
  parser->state = PVCURL_HEADER_EXPECT_FIELDS;
  return PVCURL_STATUS_OK;
}

static pvcurl_status_t pvcurl_capture_field(
    pvcurl_header_parser_t *parser,
    const uint8_t *line,
    size_t length) {
  size_t colon = 0U;
  while (colon < length && line[colon] != (uint8_t)':') {
    if (!pvcurl_is_token(line[colon])) {
      return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
    }
    ++colon;
  }
  if (colon == 0U || colon == length) {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  if (!pvcurl_case_equal(line, colon, "set-cookie")) {
    return PVCURL_STATUS_OK;
  }
  if (parser->set_cookie_count != 0U) {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  size_t start = colon + 1U;
  while (start < length && line[start] == (uint8_t)' ') {
    ++start;
  }
  size_t end = length;
  while (end > start && line[end - 1U] == (uint8_t)' ') {
    --end;
  }
  if (start == end) {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  if (end - start > parser->maximum_set_cookie_bytes) {
    return pvcurl_reject(parser, PVCURL_STATUS_RESPONSE_TOO_LARGE);
  }
  parser->set_cookie = (uint8_t *)malloc(end - start);
  if (parser->set_cookie == NULL) {
    return pvcurl_reject(parser, PVCURL_STATUS_SETUP_FAILED);
  }
  memcpy(parser->set_cookie, line + start, end - start);
  parser->set_cookie_length = end - start;
  parser->set_cookie_count = 1U;
  return PVCURL_STATUS_OK;
}

pvcurl_status_t pvcurl_header_parser_create(
    size_t maximum_header_bytes,
    size_t maximum_line_bytes,
    size_t maximum_set_cookie_bytes,
    pvcurl_header_parser_t **parser_out) {
  if (parser_out == NULL || maximum_header_bytes == 0U ||
      maximum_line_bytes == 0U || maximum_line_bytes > maximum_header_bytes ||
      maximum_set_cookie_bytes == 0U ||
      maximum_set_cookie_bytes > maximum_line_bytes) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  *parser_out = NULL;
  pvcurl_header_parser_t *parser =
      (pvcurl_header_parser_t *)calloc(1U, sizeof(*parser));
  if (parser == NULL) {
    return PVCURL_STATUS_SETUP_FAILED;
  }
  parser->maximum_header_bytes = maximum_header_bytes;
  parser->maximum_line_bytes = maximum_line_bytes;
  parser->maximum_set_cookie_bytes = maximum_set_cookie_bytes;
  parser->state = PVCURL_HEADER_EXPECT_STATUS;
  *parser_out = parser;
  return PVCURL_STATUS_OK;
}

pvcurl_status_t pvcurl_header_parser_feed(
    pvcurl_header_parser_t *parser,
    const uint8_t *line,
    size_t length) {
  if (parser == NULL || line == NULL || length == 0U) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  if (parser->failure != PVCURL_STATUS_OK) {
    return parser->failure;
  }
  if (length > parser->maximum_line_bytes ||
      length > parser->maximum_header_bytes - parser->received_bytes) {
    return pvcurl_reject(parser, PVCURL_STATUS_RESPONSE_TOO_LARGE);
  }
  parser->received_bytes += length;
  if (parser->state == PVCURL_HEADER_COMPLETE || length < 2U ||
      line[length - 2U] != (uint8_t)'\r' ||
      line[length - 1U] != (uint8_t)'\n') {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  size_t content_length = length - 2U;
  for (size_t index = 0; index < content_length; ++index) {
    if (line[index] < 0x20U || line[index] > 0x7eU) {
      return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
    }
  }
  if (parser->state == PVCURL_HEADER_EXPECT_STATUS) {
    return pvcurl_parse_status(parser, line, content_length);
  }
  if (content_length == 0U) {
    parser->state = PVCURL_HEADER_COMPLETE;
    return PVCURL_STATUS_OK;
  }
  return pvcurl_capture_field(parser, line, content_length);
}

pvcurl_status_t pvcurl_header_parser_finish(
    pvcurl_header_parser_t *parser,
    uint16_t *http_status_out,
    uint8_t **set_cookie_out,
    size_t *set_cookie_length_out) {
  if (parser == NULL || http_status_out == NULL || set_cookie_out == NULL ||
      set_cookie_length_out == NULL) {
    return PVCURL_STATUS_INVALID_ARGUMENT;
  }
  *http_status_out = 0U;
  *set_cookie_out = NULL;
  *set_cookie_length_out = 0U;
  if (parser->failure != PVCURL_STATUS_OK) {
    return parser->failure;
  }
  if (parser->state != PVCURL_HEADER_COMPLETE ||
      parser->set_cookie_count != 1U || parser->set_cookie == NULL) {
    return pvcurl_reject(parser, PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  }
  *http_status_out = parser->http_status;
  *set_cookie_out = parser->set_cookie;
  *set_cookie_length_out = parser->set_cookie_length;
  parser->set_cookie = NULL;
  parser->set_cookie_length = 0U;
  return PVCURL_STATUS_OK;
}

pvcurl_status_t pvcurl_header_parser_failure(
    const pvcurl_header_parser_t *parser) {
  return parser == NULL ? PVCURL_STATUS_INVALID_ARGUMENT : parser->failure;
}

size_t pvcurl_header_callback(
    char *buffer,
    size_t size,
    size_t item_count,
    void *context) {
  if (context == NULL || buffer == NULL ||
      (item_count != 0U && size > SIZE_MAX / item_count)) {
    return 0U;
  }
  size_t length = size * item_count;
  pvcurl_status_t status = pvcurl_header_parser_feed(
      (pvcurl_header_parser_t *)context,
      (const uint8_t *)buffer,
      length);
  return status == PVCURL_STATUS_OK ? length : 0U;
}

void pvcurl_header_parser_destroy(pvcurl_header_parser_t *parser) {
  if (parser == NULL) {
    return;
  }
  if (parser->set_cookie != NULL) {
    pvcurl_header_clear(parser->set_cookie, parser->set_cookie_length);
    free(parser->set_cookie);
  }
  pvcurl_header_clear(parser, sizeof(*parser));
  free(parser);
}
