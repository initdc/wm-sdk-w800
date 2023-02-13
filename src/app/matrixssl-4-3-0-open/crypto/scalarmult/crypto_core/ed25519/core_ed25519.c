
#include "crypto_core_ed25519.h"
#include "private/common.h"
#include "private/ed25519_ref10.h"

int
psSodium_crypto_core_ed25519_is_valid_point(const unsigned char *p)
{
    psSodium_ge25519_p3 p_p3;

    if (psSodium_ge25519_is_canonical(p) == 0 ||
        psSodium_ge25519_has_small_order(p) != 0 ||
        psSodium_ge25519_frombytes(&p_p3, p) != 0 ||
        psSodium_ge25519_is_on_curve(&p_p3) == 0 ||
        psSodium_ge25519_is_on_main_subgroup(&p_p3) == 0) {
        return 0;
    }
    return 1;
}

int
psSodium_crypto_core_ed25519_add(unsigned char *r,
                        const unsigned char *p, const unsigned char *q)
{
    psSodium_ge25519_p3     p_p3, q_p3, r_p3;
    psSodium_ge25519_p1p1   r_p1p1;
    psSodium_ge25519_cached q_cached;

    if (psSodium_ge25519_frombytes(&p_p3, p) != 0 || psSodium_ge25519_is_on_curve(&p_p3) == 0 ||
        psSodium_ge25519_frombytes(&q_p3, q) != 0 || psSodium_ge25519_is_on_curve(&q_p3) == 0) {
        return -1;
    }
    psSodium_ge25519_p3_to_cached(&q_cached, &q_p3);
    psSodium_ge25519_add(&r_p1p1, &p_p3, &q_cached);
    psSodium_ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    psSodium_ge25519_p3_tobytes(r, &r_p3);

    return 0;
}

int
psSodium_crypto_core_ed25519_sub(unsigned char *r,
                        const unsigned char *p, const unsigned char *q)
{
    psSodium_ge25519_p3     p_p3, q_p3, r_p3;
    psSodium_ge25519_p1p1   r_p1p1;
    psSodium_ge25519_cached q_cached;

    if (psSodium_ge25519_frombytes(&p_p3, p) != 0 || psSodium_ge25519_is_on_curve(&p_p3) == 0 ||
        psSodium_ge25519_frombytes(&q_p3, q) != 0 || psSodium_ge25519_is_on_curve(&q_p3) == 0) {
        return -1;
    }
    psSodium_ge25519_p3_to_cached(&q_cached, &q_p3);
    psSodium_ge25519_sub(&r_p1p1, &p_p3, &q_cached);
    psSodium_ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    psSodium_ge25519_p3_tobytes(r, &r_p3);

    return 0;
}

int
psSodium_crypto_core_ed25519_from_uniform(unsigned char *p, const unsigned char *r)
{
    psSodium_ge25519_from_uniform(p, r);

    return - psSodium_ge25519_has_small_order(p);
}

size_t
psSodium_crypto_core_ed25519_bytes(void)
{
    return psSodium_crypto_core_ed25519_BYTES;
}

size_t
psSodium_crypto_core_ed25519_uniformbytes(void)
{
    return psSodium_crypto_core_ed25519_UNIFORMBYTES;
}
