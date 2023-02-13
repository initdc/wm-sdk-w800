#include "ps_chacha20poly1305ietf_config.h"
#ifdef USE_MATRIX_CHACHA20_POLY1305_IETF

# include "osdep_stddef.h"
# include "osdep_stdint.h"

# include "crypto_verify_16.h"
# include "crypto_verify_32.h"
# include "crypto_verify_64.h"

int
psCrypto_verify_16(const unsigned char *x, const unsigned char *y)
{
    uint_fast16_t d = 0U;
    int           i;

    for (i = 0; i < 16; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

size_t
psCrypto_verify_16_bytes(void)
{
    return crypto_verify_16_BYTES;
}

int
psCrypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    uint_fast16_t d = 0U;
    int           i;

    for (i = 0; i < 32; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

size_t
psCrypto_verify_32_bytes(void)
{
    return crypto_verify_32_BYTES;
}

int
psCrypto_verify_64(const unsigned char *x, const unsigned char *y)
{
    uint_fast16_t d = 0U;
    int           i;

    for (i = 0; i < 64; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

size_t
psCrypto_verify_64_bytes(void)
{
    return crypto_verify_64_BYTES;
}

#endif /* USE_MATRIX_CHACHA20_POLY1305_IETF */
