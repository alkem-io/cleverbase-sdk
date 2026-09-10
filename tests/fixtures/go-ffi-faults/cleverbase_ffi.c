#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cleverbase_process(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
int cleverbase_attestation_verify(const uint8_t *in, size_t in_len, uint8_t **out,
                                  size_t *out_len);
int cleverbase_attestation_verify_vp_token(const uint8_t *in, size_t in_len, uint8_t **out,
                                           size_t *out_len);
int cleverbase_attestation_issuance(const uint8_t *in, size_t in_len, uint8_t **out,
                                    size_t *out_len);
void cleverbase_free(uint8_t *out, size_t out_len);

static const uint8_t EMPTY_RESULT[] = {
    0xa2, 0x6e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x5f, 0x76, 0x65, 0x72, 0x73,
    0x69, 0x6f, 0x6e, 0x01, 0x66, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0xa0,
};
static const uint8_t WRONG_SCHEMA[] = {
    0xa2, 0x6e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x5f, 0x76, 0x65, 0x72, 0x73,
    0x69, 0x6f, 0x6e, 0x02, 0x66, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0xa0,
};
static const uint8_t INVALID_CBOR[] = {0xff};

static int fixture_response(uint8_t **out, size_t *out_len) {
  const char *mode = getenv("CLEVERBASE_FFI_FAULT");
  if (mode == NULL) {
    return 90;
  }
  if (strcmp(mode, "nonzero") == 0) {
    return 17;
  }
  if (strcmp(mode, "oversized") == 0) {
    *out = malloc(1);
    if (*out == NULL) {
      return 91;
    }
    **out = 0;
    *out_len = (size_t)INT32_MAX + 1U;
    return 0;
  }

  const uint8_t *response = EMPTY_RESULT;
  size_t response_len = sizeof(EMPTY_RESULT);
  if (strcmp(mode, "invalid_cbor") == 0) {
    response = INVALID_CBOR;
    response_len = sizeof(INVALID_CBOR);
  } else if (strcmp(mode, "wrong_schema") == 0) {
    response = WRONG_SCHEMA;
    response_len = sizeof(WRONG_SCHEMA);
  }

  *out = malloc(response_len);
  if (*out == NULL) {
    return 91;
  }
  memcpy(*out, response, response_len);
  *out_len = response_len;
  return 0;
}

#define FAULT_ENTRYPOINT(name)                                                                  \
  int name(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {                  \
    (void)in;                                                                                    \
    (void)in_len;                                                                                \
    return fixture_response(out, out_len);                                                       \
  }

FAULT_ENTRYPOINT(cleverbase_process)
FAULT_ENTRYPOINT(cleverbase_attestation_verify)
FAULT_ENTRYPOINT(cleverbase_attestation_verify_vp_token)
FAULT_ENTRYPOINT(cleverbase_attestation_issuance)

void cleverbase_free(uint8_t *out, size_t out_len) {
  (void)out_len;
  free(out);
}
