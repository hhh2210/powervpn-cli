#include <CPortalCurl.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pvcurl_bytes_t bytes(const char *value) {
  return (pvcurl_bytes_t){
      .pointer = (const uint8_t *)value,
      .length = strlen(value),
  };
}

static int parse_number(const char *text, unsigned long minimum,
                        unsigned long maximum, unsigned long *value_out) {
  errno = 0;
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value < minimum ||
      value > maximum) {
    return -1;
  }
  *value_out = value;
  return 0;
}

int main(int argc, char **argv) {
  unsigned long port = 0UL;
  unsigned long expected = 0UL;
  if (argc != 3 || parse_number(argv[1], 1UL, 65535UL, &port) != 0 ||
      parse_number(argv[2], 0UL, PVCURL_STATUS_UNAVAILABLE, &expected) != 0) {
    fputs("usage: trust-client <port> <expected-status>\n", stderr);
    return 2;
  }

  char url[128];
  char host[64];
  int url_length =
      snprintf(url, sizeof(url), "https://127.0.0.1:%lu/trust-contract", port);
  int host_length = snprintf(host, sizeof(host), "127.0.0.1:%lu", port);
  if (url_length <= 0 || (size_t)url_length >= sizeof(url) ||
      host_length <= 0 || (size_t)host_length >= sizeof(host)) {
    return 2;
  }

  pvcurl_status_t status = pvcurl_runtime_preflight();
  pvcurl_request_t *request = NULL;
  pvcurl_response_t response = {0};
  if (status == PVCURL_STATUS_OK) {
    pvcurl_request_config_t config = {
        .method = PVCURL_METHOD_GET,
        .require_set_cookie = false,
        .url = bytes(url),
        .host_header = bytes(host),
        .accept_header = bytes("*/*"),
        .user_agent_header = bytes("CPortalCurlTrustContract/1"),
        .content_type_header = {0},
        .cookie_header = bytes("VSG_LANGUAGE=zh_CN; "),
        .body = {0},
        .timeout_milliseconds = 5000U,
        .maximum_response_body_bytes = 4096U,
        .maximum_response_header_bytes = 4096U,
        .maximum_response_header_line_bytes = 1024U,
        .maximum_set_cookie_bytes = 512U,
    };
    status = pvcurl_request_create(&config, &request);
  }
  if (status == PVCURL_STATUS_OK) {
    status = pvcurl_request_perform(request, &response);
  }

  printf("status=%d http=%u body=%zu\n", (int)status, response.http_status,
         response.body_length);
  pvcurl_response_destroy(&response);
  pvcurl_request_destroy(request);
  return status == (pvcurl_status_t)expected ? 0 : 1;
}
