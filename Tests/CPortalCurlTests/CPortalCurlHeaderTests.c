#include "CPortalCurlInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int tests_run = 0U;

static void fail(const char *name, const char *detail) {
  (void)fprintf(stderr, "%s: %s\n", name, detail);
  exit(1);
}

static void expect_status(const char *name, pvcurl_status_t actual,
    pvcurl_status_t expected) {
  if (actual != expected) {
    fail(name, "unexpected status");
  }
}

static pvcurl_header_parser_t *make_parser(const char *name,
    size_t maximum_header_bytes,
    size_t maximum_line_bytes) {
  pvcurl_header_parser_t *parser = NULL;
  expect_status(name,
                pvcurl_header_parser_create(maximum_header_bytes,
          maximum_line_bytes,
                                            maximum_line_bytes, &parser),
      PVCURL_STATUS_OK);
  if (parser == NULL) {
    fail(name, "parser was not created");
  }
  return parser;
}

static pvcurl_status_t feed(pvcurl_header_parser_t *parser, const char *line) {
  return pvcurl_header_parser_feed(parser, (const uint8_t *)line, strlen(line));
}

static void clear_free(uint8_t *bytes, size_t length) {
  volatile uint8_t *cursor = bytes;
  for (size_t index = 0; index < length; ++index) {
    cursor[index] = 0U;
  }
  free(bytes);
}

static void test_single_cookie(void) {
  const char *name = "single_cookie";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Content-Type: text/xml\r\n"),
                PVCURL_STATUS_OK);
  expect_status(
      name, feed(parser, "sEt-CoOkIe:  VSG_SESSIONID=synthetic; Secure  \r\n"),
      PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t cookie_length = 0U;
  expect_status(name,
                pvcurl_header_parser_finish(parser, true, &status, &cookie,
          &cookie_length),
      PVCURL_STATUS_OK);
  const char expected[] = "VSG_SESSIONID=synthetic; Secure";
  if (status != 200U || cookie_length != sizeof(expected) - 1U ||
      memcmp(cookie, expected, cookie_length) != 0) {
    fail(name, "accepted projection differs");
  }
  clear_free(cookie, cookie_length);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_last_cookie_wins(void) {
  const char *name = "last_cookie_wins";
  static const char *cases[][3] = {
      {"unrelated=first", "VSG_SESSIONID=second; Secure", "VSG_SESSIONID=second; Secure"},
      {"VSG_SESSIONID=early", "unrelated=final", "unrelated=final"},
      {"VSG_SESSIONID=first", "VSG_SESSIONID=second", "VSG_SESSIONID=second"},
      {"VSG_SESSIONID=second", "VSG_SESSIONID=first", "VSG_SESSIONID=first"}};
  for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
    expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
    char line[128];
    for (size_t field = 0U; field < 2U; ++field) {
      int written = snprintf(line, sizeof(line), "Set-Cookie: %s\r\n", cases[index][field]);
      if (written < 0 || (size_t)written >= sizeof(line))
        fail(name, "test field overflow");
      expect_status(name, pvcurl_header_parser_feed(
          parser, (const uint8_t *)line, (size_t)written), PVCURL_STATUS_OK);
    }
    expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
    uint16_t status = 0U;
    uint8_t *cookie = NULL;
    size_t length = 0U;
    expect_status(name, pvcurl_header_parser_finish(
        parser, true, &status, &cookie, &length), PVCURL_STATUS_OK);
    pvcurl_transfer_diagnostics_t diagnostics = {0};
    pvcurl_header_parser_export_diagnostics(parser, &diagnostics);
    const char *expected = cases[index][2];
    if (status != 200U || length != strlen(expected) ||
        memcmp(cookie, expected, length) != 0 ||
        diagnostics.set_cookie_field_count != 2U ||
        diagnostics.set_cookie_selection != PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS ||
        diagnostics.duplicate_set_cookie_rejected)
      fail(name, "last-field projection or diagnostics differ");
    clear_free(cookie, length);
    pvcurl_header_parser_destroy(parser);
  }
  ++tests_run;
}

static void test_optional_password_post_without_cookie(void) {
  const char *name = "optional_password_post_without_cookie";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t length = 0U;
  expect_status(
      name,
      pvcurl_header_parser_finish(parser, false, &status, &cookie, &length),
      PVCURL_STATUS_OK);
  if (status != 200U || cookie != NULL || length != 0U) {
    fail(name, "optional empty projection differs");
  }
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_optional_password_post_with_single_cookie(void) {
  const char *name = "optional_password_post_with_single_cookie";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: one=1\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t length = 0U;
  expect_status(
      name,
      pvcurl_header_parser_finish(parser, false, &status, &cookie, &length),
      PVCURL_STATUS_OK);
  static const char expected[] = "one=1";
  if (status != 200U || cookie == NULL || length != sizeof(expected) - 1U ||
      memcmp(cookie, expected, length) != 0) {
    fail(name, "optional single-cookie projection differs");
  }
  clear_free(cookie, length);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_missing_cookie(void) {
  const char *name = "missing_cookie";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t length = 0U;
  expect_status(
      name,
      pvcurl_header_parser_finish(parser, true, &status, &cookie, &length),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_interim_response(void) {
  const char *name = "interim_response";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 100 Continue\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_obs_fold(void) {
  const char *name = "obs_fold";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, " Set-Cookie: folded=1\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_trailer(void) {
  const char *name = "trailer";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: one=1\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "X-Trailer: rejected\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_control_byte(void) {
  const char *name = "control_byte";
  static const uint8_t line[] = {'S', 'e', 't', '-',   'C',  'o',
                                 'o', 'k', 'i', 'e',   ':',  ' ',
      'a', '=', 'b', 0x7fU, '\r', '\n'};
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: VSG_SESSIONID=early\r\n"), PVCURL_STATUS_OK);
  expect_status(name, pvcurl_header_parser_feed(parser, line, sizeof(line)),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t length = 0U;
  expect_status(name, pvcurl_header_parser_finish(
      parser, false, &status, &cookie, &length), PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_transfer_diagnostics_t diagnostics = {0};
  pvcurl_header_parser_export_diagnostics(parser, &diagnostics);
  if (cookie != NULL || length != 0U ||
      diagnostics.set_cookie_field_count != 2U ||
      diagnostics.set_cookie_selection != PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS ||
      diagnostics.duplicate_set_cookie_rejected) {
    fail(name, "invalid final field exposed the prior cookie");
  }
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_line_cap(void) {
  const char *name = "line_cap";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 8U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"),
      PVCURL_STATUS_RESPONSE_TOO_LARGE);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_total_cap(void) {
  const char *name = "total_cap";
  pvcurl_header_parser_t *parser = make_parser(name, 24U, 24U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: one=1\r\n"),
      PVCURL_STATUS_RESPONSE_TOO_LARGE);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_cookie_cap(void) {
  const char *name = "cookie_cap";
  pvcurl_header_parser_t *parser = NULL;
  expect_status(name, pvcurl_header_parser_create(4096U, 1024U, 5U, &parser),
      PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: old=1\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: abcdef\r\n"), PVCURL_STATUS_RESPONSE_TOO_LARGE);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t length = 0U;
  expect_status(name, pvcurl_header_parser_finish(
      parser, false, &status, &cookie, &length), PVCURL_STATUS_RESPONSE_TOO_LARGE);
  if (cookie != NULL || length != 0U) {
    fail(name, "oversized final field exposed the prior cookie");
  }
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_second_response_block(void) {
  const char *name = "second_response_block";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: one=1\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "HTTP/1.1 200 AGAIN\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

int main(void) {
  test_single_cookie();
  test_last_cookie_wins();
  test_missing_cookie();
  test_optional_password_post_without_cookie();
  test_optional_password_post_with_single_cookie();
  test_interim_response();
  test_obs_fold();
  test_trailer();
  test_control_byte();
  test_line_cap();
  test_total_cap();
  test_cookie_cap();
  test_second_response_block();
  (void)printf("CPortalCurlHeaderTests: %u passed\n", tests_run);
  return 0;
}
