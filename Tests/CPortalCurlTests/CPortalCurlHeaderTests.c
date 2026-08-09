#include "CPortalCurlInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int tests_run = 0U;

static void fail(const char *name, const char *detail) {
  (void)fprintf(stderr, "%s: %s\n", name, detail);
  exit(1);
}

static void expect_status(
    const char *name,
    pvcurl_status_t actual,
    pvcurl_status_t expected) {
  if (actual != expected) {
    fail(name, "unexpected status");
  }
}

static pvcurl_header_parser_t *make_parser(
    const char *name,
    size_t maximum_header_bytes,
    size_t maximum_line_bytes) {
  pvcurl_header_parser_t *parser = NULL;
  expect_status(
      name,
      pvcurl_header_parser_create(
          maximum_header_bytes,
          maximum_line_bytes,
          maximum_line_bytes,
          &parser),
      PVCURL_STATUS_OK);
  if (parser == NULL) {
    fail(name, "parser was not created");
  }
  return parser;
}

static pvcurl_status_t feed(
    pvcurl_header_parser_t *parser,
    const char *line) {
  return pvcurl_header_parser_feed(
      parser,
      (const uint8_t *)line,
      strlen(line));
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
  expect_status(name, feed(parser, "Content-Type: text/xml\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      feed(parser, "sEt-CoOkIe:  VSG_SESSIONID=synthetic; Secure  \r\n"),
      PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  uint16_t status = 0U;
  uint8_t *cookie = NULL;
  size_t cookie_length = 0U;
  expect_status(
      name,
      pvcurl_header_parser_finish(
          parser,
          &status,
          &cookie,
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

static void test_duplicate_cookie(void) {
  const char *name = "duplicate_cookie";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: first=1\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      feed(parser, "Set-Cookie: second=2\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
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
      pvcurl_header_parser_finish(parser, &status, &cookie, &length),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_interim_response(void) {
  const char *name = "interim_response";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(
      name,
      feed(parser, "HTTP/1.1 100 Continue\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_obs_fold(void) {
  const char *name = "obs_fold";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      feed(parser, " Set-Cookie: folded=1\r\n"),
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
  expect_status(
      name,
      feed(parser, "X-Trailer: rejected\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_control_byte(void) {
  const char *name = "control_byte";
  static const uint8_t line[] = {
      'S', 'e', 't', '-', 'C', 'o', 'o', 'k', 'i', 'e', ':', ' ',
      'a', '=', 'b', 0x7fU, '\r', '\n'};
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      pvcurl_header_parser_feed(parser, line, sizeof(line)),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_line_cap(void) {
  const char *name = "line_cap";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 8U);
  expect_status(
      name,
      feed(parser, "HTTP/1.1 200 OK\r\n"),
      PVCURL_STATUS_RESPONSE_TOO_LARGE);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_total_cap(void) {
  const char *name = "total_cap";
  pvcurl_header_parser_t *parser = make_parser(name, 24U, 24U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      feed(parser, "Set-Cookie: one=1\r\n"),
      PVCURL_STATUS_RESPONSE_TOO_LARGE);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_cookie_cap(void) {
  const char *name = "cookie_cap";
  pvcurl_header_parser_t *parser = NULL;
  expect_status(
      name,
      pvcurl_header_parser_create(4096U, 1024U, 4U, &parser),
      PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      feed(parser, "Set-Cookie: abcde\r\n"),
      PVCURL_STATUS_RESPONSE_TOO_LARGE);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

static void test_second_response_block(void) {
  const char *name = "second_response_block";
  pvcurl_header_parser_t *parser = make_parser(name, 4096U, 1024U);
  expect_status(name, feed(parser, "HTTP/1.1 200 OK\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "Set-Cookie: one=1\r\n"), PVCURL_STATUS_OK);
  expect_status(name, feed(parser, "\r\n"), PVCURL_STATUS_OK);
  expect_status(
      name,
      feed(parser, "HTTP/1.1 200 AGAIN\r\n"),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  pvcurl_header_parser_destroy(parser);
  ++tests_run;
}

int main(void) {
  test_single_cookie();
  test_duplicate_cookie();
  test_missing_cookie();
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
