#include "CPortalCurlInternal.h"

#include <curl/curl.h>
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

static pvcurl_bytes_t bytes(const char *value) {
  pvcurl_bytes_t result = {
      .pointer = (const uint8_t *)value,
      .length = strlen(value)};
  return result;
}

static pvcurl_password_request_config_t valid_config(void) {
  static const uint8_t body[] = {'a', '=', 'b'};
  pvcurl_password_request_config_t config = {
      .url = bytes("https://portal.example.invalid:4443/password"),
      .host_header = bytes("portal.example.invalid:4443"),
      .accept_header = bytes("*/*"),
      .user_agent_header = bytes("VSG-libCurl/synthetic"),
      .content_type_header = bytes("text/xml"),
      .cookie_header = bytes("VSG_LANGUAGE=zh_CN; "),
      .body = {.pointer = body, .length = sizeof(body)},
      .timeout_milliseconds = 1000U,
      .maximum_response_body_bytes = 4096U,
      .maximum_response_header_bytes = 4096U,
      .maximum_response_header_line_bytes = 1024U,
      .maximum_set_cookie_bytes = 512U};
  return config;
}

static void test_status_mapping(void) {
  const char *name = "status_mapping";
  expect_status(
      name,
      pvcurl_finalize_status(CURLE_OK, false, PVCURL_STATUS_OK, 302U, true),
      PVCURL_STATUS_REDIRECT_REJECTED);
  expect_status(
      name,
      pvcurl_finalize_status(CURLE_OK, false, PVCURL_STATUS_OK, 401U, true),
      PVCURL_STATUS_AUTHENTICATION_REJECTED);
  expect_status(
      name,
      pvcurl_finalize_status(CURLE_OK, false, PVCURL_STATUS_OK, 407U, true),
      PVCURL_STATUS_AUTHENTICATION_REJECTED);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_OPERATION_TIMEDOUT, false, PVCURL_STATUS_OK, 0U, false),
      PVCURL_STATUS_TIMED_OUT);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_ABORTED_BY_CALLBACK, true, PVCURL_STATUS_OK, 0U, false),
      PVCURL_STATUS_CANCELLED);
  expect_status(
      name,
      pvcurl_finalize_status(CURLE_WRITE_ERROR, true, PVCURL_STATUS_OK, 0U, false),
      PVCURL_STATUS_CANCELLED);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_ABORTED_BY_CALLBACK, false, PVCURL_STATUS_OK, 0U, false),
      PVCURL_STATUS_UNAVAILABLE);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_OPERATION_TIMEDOUT,
          true,
          PVCURL_STATUS_RESPONSE_TOO_LARGE,
          0U,
          false),
      PVCURL_STATUS_RESPONSE_TOO_LARGE);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_ABORTED_BY_CALLBACK,
          true,
          PVCURL_STATUS_HEADER_FRAMING_REJECTED,
          0U,
          false),
      PVCURL_STATUS_HEADER_FRAMING_REJECTED);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_PEER_FAILED_VERIFICATION,
          false,
          PVCURL_STATUS_OK,
          0U,
          false),
      PVCURL_STATUS_TRUST_REJECTED);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_SSL_CONNECT_ERROR, false, PVCURL_STATUS_OK, 0U, false),
      PVCURL_STATUS_UNAVAILABLE);
  expect_status(
      name,
      pvcurl_finalize_status(
          CURLE_SSL_CIPHER, false, PVCURL_STATUS_OK, 0U, false),
      PVCURL_STATUS_UNAVAILABLE);
  expect_status(
      name,
      pvcurl_finalize_status(CURLE_OK, false, PVCURL_STATUS_OK, 200U, false),
      PVCURL_STATUS_REDIRECT_REJECTED);
  ++tests_run;
}

static void test_userinfo_rejected_and_output_cleared(void) {
  const char *name = "userinfo_rejected_and_output_cleared";
  pvcurl_password_request_config_t config = valid_config();
  config.url = bytes("https://user@portal.example.invalid:4443/password");
  pvcurl_request_t *request = (pvcurl_request_t *)(uintptr_t)1U;
  expect_status(
      name,
      pvcurl_password_request_create(&config, &request),
      PVCURL_STATUS_INVALID_ARGUMENT);
  if (request != NULL) {
    fail(name, "stale output pointer survived invalid config");
  }
  ++tests_run;
}

static void test_borrowed_body_and_exact_headers(void) {
  const char *name = "borrowed_body_and_exact_headers";
  pvcurl_password_request_config_t config = valid_config();
  pvcurl_request_t *request = NULL;
  expect_status(
      name,
      pvcurl_password_request_create(&config, &request),
      PVCURL_STATUS_OK);
  if (request->body != config.body.pointer) {
    fail(name, "body was copied");
  }
  struct curl_slist *headers = NULL;
  expect_status(
      name,
      pvcurl_request_build_headers(request, &headers),
      PVCURL_STATUS_OK);
  static const char *const expected[] = {
      "Host: portal.example.invalid:4443",
      "Accept: */*",
      "User-Agent: VSG-libCurl/synthetic",
      "Content-Type: text/xml",
      "Content-Length: 3",
      "Expect:",
      "Cookie: VSG_LANGUAGE=zh_CN; "};
  struct curl_slist *item = headers;
  for (size_t index = 0U; index < sizeof(expected) / sizeof(expected[0]); ++index) {
    if (item == NULL || strcmp(item->data, expected[index]) != 0) {
      fail(name, "header order or bytes differ");
    }
    item = item->next;
  }
  if (item != NULL) {
    fail(name, "unexpected extra header");
  }
  pvcurl_slist_destroy_secure(headers);
  pvcurl_request_destroy(request);
  ++tests_run;
}

static void test_cancel_before_perform_is_network_free(void) {
  const char *name = "cancel_before_perform_is_network_free";
  pvcurl_password_request_config_t config = valid_config();
  pvcurl_request_t *request = NULL;
  expect_status(
      name,
      pvcurl_password_request_create(&config, &request),
      PVCURL_STATUS_OK);
  pvcurl_request_cancel(request);
  pvcurl_response_t response = {0};
  expect_status(
      name,
      pvcurl_request_perform(request, &response),
      PVCURL_STATUS_CANCELLED);
  expect_status(
      name,
      pvcurl_request_perform(request, &response),
      PVCURL_STATUS_INVALID_ARGUMENT);
  pvcurl_response_destroy(&response);
  pvcurl_request_destroy(request);
  ++tests_run;
}

static void test_runtime_preflight(void) {
  const char *name = "runtime_preflight";
  expect_status(name, pvcurl_runtime_preflight(), PVCURL_STATUS_OK);
  ++tests_run;
}

int main(void) {
  test_status_mapping();
  test_userinfo_rejected_and_output_cleared();
  test_borrowed_body_and_exact_headers();
  test_cancel_before_perform_is_network_free();
  test_runtime_preflight();
  (void)printf("CPortalCurlStatusTests: %u passed\n", tests_run);
  return 0;
}
