/**
 *      @file    tls.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      TLS (SSLv3.1+) specific code.
 *      http://www.faqs.org/rfcs/rfc2246.html
 *      Primarily dealing with secret generation, message authentication codes
 *      and handshake hashing.
 */
/*
 *      Copyright (c) 2013-2018 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "matrixsslImpl.h"

#ifdef USE_NATIVE_TLS_ALGS
/******************************************************************************/
# ifdef USE_TLS
/******************************************************************************/

#  define LABEL_SIZE          13
#  define LABEL_MASTERSEC     "master secret"
#  define LABEL_KEY_BLOCK     "key expansion"

#  define LABEL_EXT_SIZE          22
#  define LABEL_EXT_MASTERSEC     "extended master secret"

/* Warning: enabling this will output the derived secrets to the
   debug log. Enable only if debugging key derivation issues. */
#  ifndef DEBUG_TLS_LOG_SECRETS
/*#   define DEBUG_TLS_LOG_SECRETS */
#  endif

#  ifdef DEBUG_TLS_LOG_SECRETS
#   warning "Do NOT enable DEBUG_TLS_LOG_SECRETS in production builds"
#  endif

static int32_t genKeyBlock(ssl_t *ssl)
{
    unsigned char msSeed[SSL_HS_RANDOM_SIZE * 2 + LABEL_SIZE];
    uint32 reqKeyLen;
    int32_t rc = PS_FAIL;

    Memcpy(msSeed, LABEL_KEY_BLOCK, LABEL_SIZE);
    Memcpy(msSeed + LABEL_SIZE, ssl->sec.serverRandom,
        SSL_HS_RANDOM_SIZE);
    Memcpy(msSeed + LABEL_SIZE + SSL_HS_RANDOM_SIZE,
        ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);

    /* We must generate enough key material to fill the various keys */
    reqKeyLen = 2 * ssl->cipher->macSize +
                2 * ssl->cipher->keySize +
                2 * ssl->cipher->ivSize;
#  ifdef USE_EAP_FAST
    /**
        Generate master secret with tprf.
        Make space for additional key material (session key seed).
        @see https://tools.ietf.org/html/rfc4851#section-5.1
     */
    if (ssl->flags & SSL_FLAGS_EAP_FAST)
    {
        if (ssl->sid == NULL)
        {
            goto L_RETURN;
        }
        /* sid->masterSecret actually holds pac-key. Use tprf() here
           to derive session masterSecret, now that we're about to use it.
           masterSecret is also used after this for the finished message hash */
        rc = tprf(ssl->sid->masterSecret, EAP_FAST_PAC_KEY_LEN,
            msSeed + LABEL_SIZE, 2 * SSL_HS_RANDOM_SIZE,
            ssl->sec.masterSecret);
        if (rc < 0)
        {
            goto L_RETURN;
        }
        reqKeyLen += EAP_FAST_SESSION_KEY_SEED_LEN;
    }
#  endif

    /* Ensure there's enough room */
    if (reqKeyLen > SSL_MAX_KEY_BLOCK_SIZE)
    {
        rc = PS_MEM_FAIL;
        goto L_RETURN;
    }

#  ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_tls_1_2_prf))
    {
        if ((rc = prf2(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.keyBlock,
                 reqKeyLen, ssl->cipher->flags)) < 0)
        {
            goto L_RETURN;
        }
    }
#   ifndef USE_ONLY_TLS_1_2
    else
    {
        if ((rc = prf(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.keyBlock,
                 reqKeyLen)) < 0)
        {
            goto L_RETURN;
        }
    }
#   endif
#  else
    if ((rc = prf(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE, msSeed,
             (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.keyBlock,
             reqKeyLen)) < 0)
    {
        goto L_RETURN;
    }
#  endif
    if (ssl->flags & SSL_FLAGS_SERVER)
    {
        ssl->sec.rMACptr = ssl->sec.keyBlock;
        ssl->sec.wMACptr = ssl->sec.rMACptr + ssl->cipher->macSize;
        ssl->sec.rKeyptr = ssl->sec.wMACptr + ssl->cipher->macSize;
        ssl->sec.wKeyptr = ssl->sec.rKeyptr + ssl->cipher->keySize;
        ssl->sec.rIVptr = ssl->sec.wKeyptr + ssl->cipher->keySize;
        ssl->sec.wIVptr = ssl->sec.rIVptr + ssl->cipher->ivSize;
#  ifdef USE_EAP_FAST
        if (ssl->flags & SSL_FLAGS_EAP_FAST)
        {
            ssl->sec.eap_fast_session_key_seed = ssl->sec.wIVptr + ssl->cipher->ivSize;
        }
#  endif
    }
    else
    {
        ssl->sec.wMACptr = ssl->sec.keyBlock;
        ssl->sec.rMACptr = ssl->sec.wMACptr + ssl->cipher->macSize;
        ssl->sec.wKeyptr = ssl->sec.rMACptr + ssl->cipher->macSize;
        ssl->sec.rKeyptr = ssl->sec.wKeyptr + ssl->cipher->keySize;
        ssl->sec.wIVptr = ssl->sec.rKeyptr + ssl->cipher->keySize;
        ssl->sec.rIVptr = ssl->sec.wIVptr + ssl->cipher->ivSize;
#  ifdef USE_EAP_FAST
        if (ssl->flags & SSL_FLAGS_EAP_FAST)
        {
            ssl->sec.eap_fast_session_key_seed = ssl->sec.rIVptr + ssl->cipher->ivSize;
        }
#  endif
    }


    rc = SSL_HS_MASTER_SIZE;

#   ifdef DEBUG_TLS_LOG_SECRETS
        psTraceBytes("ssl->sec.masterSecret",
                     ssl->sec.masterSecret,
                     SSL_HS_MASTER_SIZE);
        psTraceBytes("ssl->sec.keyBlock",
                     ssl->sec.keyBlock,
                     reqKeyLen);
#   endif

L_RETURN:
    memzero_s(msSeed, sizeof(msSeed));
    if (rc < 0)
    {
        memzero_s(ssl->sec.masterSecret, SSL_HS_MASTER_SIZE);
        memzero_s(ssl->sec.keyBlock, SSL_MAX_KEY_BLOCK_SIZE);
    }
    return rc;
}

/******************************************************************************/
/*
 *      Generates all key material.
 */
int32_t tlsDeriveKeys(ssl_t *ssl)
{
    unsigned char msSeed[SSL_HS_RANDOM_SIZE * 2 + LABEL_SIZE];
    int32_t rc = PS_FAIL;

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any) && ssl->retransmit == 1)
    {
        /* The keyblock is still valid from the first pass */
        return SSL_HS_MASTER_SIZE;
    }
#  endif
/*
    If this session is resumed, we want to reuse the master secret to
    regenerate the key block with the new random values.
 */
    if (ssl->flags & SSL_FLAGS_RESUMED)
    {
        return genKeyBlock(ssl);
    }
#  ifdef USE_EAP_FAST
    /* We should only do EAP_FAST key derivation on resumed connections */
    if (ssl->flags & SSL_FLAGS_EAP_FAST)
    {
        return PS_FAIL;
    }
#  endif

/*
    master_secret = PRF(pre_master_secret, "master secret",
        client_random + server_random);
 */
    Memcpy(msSeed, LABEL_MASTERSEC, LABEL_SIZE);
    Memcpy(msSeed + LABEL_SIZE, ssl->sec.clientRandom,
        SSL_HS_RANDOM_SIZE);
    Memcpy(msSeed + LABEL_SIZE + SSL_HS_RANDOM_SIZE,
        ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);

#  ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_tls_1_2_prf))
    {
        if ((rc = prf2(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE, ssl->cipher->flags)) < 0)
        {
            return rc;
        }
#   ifndef USE_ONLY_TLS_1_2
    }
    else
    {
        if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE)) < 0)
        {
            return rc;
        }
#   endif
    }
#  else
    if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
             (SSL_HS_RANDOM_SIZE * 2) + LABEL_SIZE, ssl->sec.masterSecret,
             SSL_HS_MASTER_SIZE)) < 0)
    {
        return rc;
    }
#  endif

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
/*
        May need premaster for retransmits.  DTLS will free this when handshake
        is known to be complete
 */
        return genKeyBlock(ssl);
    }
#  endif /* USE_DTLS */
/*
     premaster is now allocated for DH reasons.  Can free here
 */
    psFree(ssl->sec.premaster, ssl->hsPool);
    ssl->sec.premaster = NULL;
    ssl->sec.premasterSize = 0;

    return genKeyBlock(ssl);
}

/* Master secret generation if extended_master_secret extension is used */
int32_t tlsExtendedDeriveKeys(ssl_t *ssl)
{
    unsigned char msSeed[SHA384_HASHLEN + LABEL_EXT_SIZE];
    unsigned char hash[SHA384_HASHLEN];
    uint32_t outLen;
    int32_t rc = PS_FAIL;

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any) && ssl->retransmit == 1)
    {
        /* The keyblock is still valid from the first pass */
        return SSL_HS_MASTER_SIZE;
    }
#  endif
/*
    If this session is resumed, we should reuse the master_secret to
    regenerate the key block with the new random values. We should not
    be here regenerating the master_secret!
 */
    if (ssl->extFlags.extended_master_secret == 0 ||
        ssl->flags & SSL_FLAGS_RESUMED)
    {
        psTraceInfo("Invalid invokation of extended key derivation.\n");
        return PS_FAIL;
    }
#  ifdef USE_EAP_FAST
    /* We should only do EAP_FAST key derivation on resumed connections */
    if (ssl->flags & SSL_FLAGS_EAP_FAST)
    {
        return PS_FAIL;
    }
#  endif

    extMasterSecretSnapshotHSHash(ssl, hash, &outLen);

/*
    master_secret = PRF(pre_master_secret, "extended master secret",
        session_hash);
 */
    Memcpy(msSeed, LABEL_EXT_MASTERSEC, LABEL_EXT_SIZE);
    Memcpy(msSeed + LABEL_EXT_SIZE, hash, outLen);

#  ifdef USE_TLS_1_2
    if (NGTD_VER(ssl, v_tls_with_tls_1_2_prf))
    {
        if ((rc = prf2(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 outLen + LABEL_EXT_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE, ssl->cipher->flags)) < 0)
        {
            return rc;
        }
#   ifndef USE_ONLY_TLS_1_2
    }
    else
    {
        if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
                 outLen + LABEL_EXT_SIZE, ssl->sec.masterSecret,
                 SSL_HS_MASTER_SIZE)) < 0)
        {
            return rc;
        }
#   endif
    }
#  else
    if ((rc = prf(ssl->sec.premaster, ssl->sec.premasterSize, msSeed,
             outLen + LABEL_EXT_SIZE, ssl->sec.masterSecret,
             SSL_HS_MASTER_SIZE)) < 0)
    {
        return rc;
    }
#  endif

#   ifdef DEBUG_TLS_LOG_SECRETS
        psTraceBytes("ssl->sec.masterSecret", ssl->sec.masterSecret, 48);
#   endif

#   ifdef ENABLE_MASTER_SECRET_EXPORT
        memcpy(ssl->masterSecret, ssl->sec.masterSecret, SSL_HS_MASTER_SIZE);
        ssl->hsMasterSecretLen = SSL_HS_MASTER_SIZE;
#   endif /* ENABLE_MASTER_SECRET_EXPORT */

#  ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
/*
        May need premaster for retransmits.  DTLS will free this when handshake
        is known to be complete
 */
        return genKeyBlock(ssl);
    }
#  endif /* USE_DTLS */
/*
     premaster is now allocated for DH reasons.  Can free here
 */
    psFree(ssl->sec.premaster, ssl->hsPool);
    ssl->sec.premaster = NULL;
    ssl->sec.premasterSize = 0;

    return genKeyBlock(ssl);
}

#  ifdef USE_SHA_MAC

#    ifdef USE_HMAC_TLS
#     ifdef USE_HMAC_TLS_LUCKY13_COUNTERMEASURE
/*
  Lucky13 countermeasure needs to perform more work than necessary
  to mask the timing side-channel. We shall take the additional dummy
  data from the end of the real input buffer in order to make cache
  timing analysis harder. This function computes the max amount of
  data that can be read after the plaintext.
*/

static
uint32_t computeLucky13WorkAmount(ssl_t *ssl,
        int32 mode,
        uint32_t ptLen)
{
    uint32_t macLen, ivLen, padLen, extraWorkLen;

    /* Lucky13 countermeasure only needed when decrypting. */
    if (mode != HMAC_VERIFY)
    {
        return ptLen;
    }

    /*
      Note: ssl->cipher->{macSize,ivSize} are the corresponding
      values for the negotiated cipher. During renegotiation,
      the negotiated cipher may be different than the currently
      active cipher.
    */
    macLen = ssl->deMacSize;
    ivLen = ssl->deIvSize;
    padLen = ssl->rec.len - macLen - ivLen - ptLen - 1;

    /* Should not get here unless we're using a block cipher. */
    psAssert(macLen > 0);

# ifdef DEBUG_LUCKY13
    Printf("record len : %d\n", ssl->rec.len);
    Printf("ivLen: %u\n", ivLen);
    Printf("ptLen: %u\n", ptLen);
    Printf("macLen: %u\n", macLen);
    Printf("padLen: %u\n", padLen);
    Printf("adding: %u\n", macLen + padLen);
# endif

    /*
      The input buffer has at least MAClen + padding len
      extra bytes after the plaintext. The minimum amount is the
      exact amount when this is the final record in the buffer.
*/
    extraWorkLen = macLen + padLen;
    return ptLen + extraWorkLen;
}
#     endif
#    endif

#   ifdef USE_SHA1
/******************************************************************************/
/*
    TLS sha1 HMAC generate/verify
 */
int32_t tlsHMACSha1(ssl_t *ssl, int32 mode, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
#    ifndef USE_HMAC_TLS
    psHmacSha1_t ctx;
#    endif
    unsigned char *key, *seq;
    unsigned char majVer, minVer, tmp[5];
    int32 i;
#    ifdef USE_DTLS
    unsigned char dtls_seq[8];
#    endif /* USE_DTLS */
#    ifdef USE_HMAC_TLS
    uint32 alt_len;
#    endif /* USE_HMAC_TLS */

    majVer = psEncodeVersionMaj(GET_ACTV_VER(ssl));
    minVer = psEncodeVersionMin(GET_ACTV_VER(ssl));

    if (mode == HMAC_CREATE)
    {
        key = ssl->sec.writeMAC;
        seq = ssl->sec.seq;
    }
    else     /* HMAC_VERIFY */
    {
        key = ssl->sec.readMAC;
        seq = ssl->sec.remSeq;
    }

    /* Sanity */
    if (key == NULL)
    {
        return PS_FAILURE;
    }

#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (mode == HMAC_CREATE)
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rsn, 6);
        }
        else     /* HMAC_VERIFY */
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->rec.epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rec.rsn, 6);
        }
    }
#    endif /* USE_DTLS */

    /*
      ssl->rec.len = length of TLSCiphertext (outer record) contents
      len = length of TLSCompressed.fragment. For block ciphers,
            len = rec.len - len(IV) - len(MAC) - len(padding) - 1.

      When using the NULL cipher, TLSCiphertext == TLSCompressed.
      When not using compression, TLSCompressed == TLSPlaintext.

      RFC 5246, 6.2.3.1: The MAC is generated as:
      MAC(MAC_write_key, seq_num +
                            TLSCompressed.type +
                            TLSCompressed.version +
                            TLSCompressed.length +
                            TLSCompressed.fragment);

      So the total amount of bytes to MAC is:
      8 (64-bit sequence number)
      +5 (TLSCompressed header)
      +len (TLSCompressed.fragment)

      When not using compression, TLSCompressed.fragment is the
      same as TLSPlaintext.fragment. Thus, the maximum number
      of bytes to MAC, when not using compression, is
      16384 + 8 + 5 = 16397.

      The Lucky thirteen name comes from the fact that 8 + 5 = 13.
    */
    tmp[0] = type;
    tmp[1] = majVer;
    tmp[2] = minVer;
    tmp[3] = (len & 0xFF00) >> 8;
    tmp[4] = len & 0xFF;

#    ifdef USE_HMAC_TLS
#     ifdef USE_HMAC_TLS_LUCKY13_COUNTERMEASURE
    /* Lucky13 countermeasure is only used on the decryption side. */
    alt_len = computeLucky13WorkAmount(ssl, mode, len);
#     else
    alt_len = len;
#     endif
    (void) psHmacSha1Tls(key, SHA1_HASH_SIZE,
        seq, 8,
        tmp, 5,
        data, len, alt_len,
        mac);
#    else
    if (psHmacSha1Init(&ctx, key, SHA1_HASH_SIZE) < 0)
    {
        return PS_FAIL;
    }
    psHmacSha1Update(&ctx, seq, 8);
    psHmacSha1Update(&ctx, tmp, 5);
    psHmacSha1Update(&ctx, data, len);
    psHmacSha1Final(&ctx, mac);
#    endif
    /* Update seq (only for normal TLS) */
    for (i = 7; i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
    return PS_SUCCESS;
}
#   endif /* USE_SHA1 */

#   if defined(USE_HMAC_SHA256) || defined(USE_HMAC_SHA384)
/******************************************************************************/
/*
    TLS sha256/sha384 HMAC generate/verify
 */
int32_t tlsHMACSha2(ssl_t *ssl, int32 mode, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac, int32 hashLen)
{
#    ifndef USE_HMAC_TLS
    psHmac_t ctx;
#    endif
    unsigned char *key, *seq;
    unsigned char majVer, minVer, tmp[5];
    int32 i;
#    ifdef USE_DTLS
    unsigned char dtls_seq[8];
#    endif /* USE_DTLS */
#    ifdef USE_HMAC_TLS
    uint32 alt_len;
#    endif /* USE_HMAC_TLS */

    majVer = psEncodeVersionMaj(GET_ACTV_VER(ssl));
    minVer = psEncodeVersionMin(GET_ACTV_VER(ssl));

    if (mode == HMAC_CREATE)
    {
        key = ssl->sec.writeMAC;
        seq = ssl->sec.seq;
    }
    else     /* HMAC_VERIFY */
    {
        key = ssl->sec.readMAC;
        seq = ssl->sec.remSeq;
    }
    /* Sanity */
    if (key == NULL)
    {
        return PS_FAILURE;
    }

#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (mode == HMAC_CREATE)
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rsn, 6);
        }
        else     /* HMAC_VERIFY */
        {
            seq = dtls_seq;
            Memcpy(dtls_seq, ssl->rec.epoch, 2);
            Memcpy(dtls_seq + 2, ssl->rec.rsn, 6);
        }
    }
#    endif /* USE_DTLS */

    tmp[0] = type;
    tmp[1] = majVer;
    tmp[2] = minVer;
    tmp[3] = (len & 0xFF00) >> 8;
    tmp[4] = len & 0xFF;

#    ifdef USE_HMAC_TLS
#     ifdef USE_HMAC_TLS_LUCKY13_COUNTERMEASURE
    /* Lucky13 countermeasure is only used on the decryption side. */
    alt_len = computeLucky13WorkAmount(ssl, mode, len);
#     else
    alt_len = len;
#     endif
    (void) psHmacSha2Tls(key, hashLen,
        seq, 8,
        tmp, 5,
        data, len, alt_len,
        mac, hashLen);
#    else
    switch (hashLen)
    {
    case SHA256_HASHLEN:
        if (psHmacInit(&ctx, HMAC_SHA256, key, hashLen) < 0)
        {
            return PS_FAIL;
        }
        break;
    case SHA384_HASHLEN:
        if (psHmacInit(&ctx, HMAC_SHA384, key, hashLen) < 0)
        {
            return PS_FAIL;
        }
        break;
    default:
        return PS_FAIL;
    }
    psHmacUpdate(&ctx, seq, 8);
    psHmacUpdate(&ctx, tmp, 5);
    psHmacUpdate(&ctx, data, len);
    psHmacFinal(&ctx, mac);
#    endif
    /* Update seq (only for normal TLS) */
    for (i = 7; i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
    return PS_SUCCESS;
}
#   endif /* USE_SHA256 || USE_SHA384 */
#  endif  /* USE_SHA_MAC */

#  ifdef USE_MD5
#   ifdef USE_MD5_MAC
/******************************************************************************/
/*
    TLS MD5 HMAC generate/verify
 */
int32_t tlsHMACMd5(ssl_t *ssl, int32 mode, unsigned char type,
    unsigned char *data, uint32 len, unsigned char *mac)
{
    psHmacMd5_t ctx;
    unsigned char *key, *seq;
    unsigned char majVer, minVer, tmp[5];
    int32 i;

    majVer = psEncodeVersionMaj(GET_ACTV_VER(ssl));
    minVer = psEncodeVersionMin(GET_ACTV_VER(ssl));

    if (mode == HMAC_CREATE)
    {
        key = ssl->sec.writeMAC;
        seq = ssl->sec.seq;
    }
    else     /* HMAC_VERIFY */
    {
        key = ssl->sec.readMAC;
        seq = ssl->sec.remSeq;
    }
    /* Sanity */
    if (key == NULL)
    {
        return PS_FAILURE;
    }

    if (psHmacMd5Init(&ctx, key, MD5_HASH_SIZE) < 0)
    {
        return PS_FAIL;
    }
#    ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (mode == HMAC_CREATE)
        {
            psHmacMd5Update(&ctx, ssl->epoch, 2);
            psHmacMd5Update(&ctx, ssl->rsn, 6);
        }
        else     /* HMAC_VERIFY */
        {
            psHmacMd5Update(&ctx, ssl->rec.epoch, 2);
            psHmacMd5Update(&ctx, ssl->rec.rsn, 6);
        }
    }
    else
    {
#    endif /* USE_DTLS */
    psHmacMd5Update(&ctx, seq, 8);
    for (i = 7; i >= 0; i--)
    {
        seq[i]++;
        if (seq[i] != 0)
        {
            break;
        }
    }
#    ifdef USE_DTLS
}
#    endif /* USE_DTLS */

    tmp[0] = type;
    tmp[1] = majVer;
    tmp[2] = minVer;
    tmp[3] = (len & 0xFF00) >> 8;
    tmp[4] = len & 0xFF;
    psHmacMd5Update(&ctx, tmp, 5);
    psHmacMd5Update(&ctx, data, len);
    psHmacMd5Final(&ctx, mac);

    return PS_SUCCESS;
}
#   endif /* USE_MD5_MAC */
#  endif  /* USE_MD5 */
# endif   /* USE_TLS */

int32 sslCreateKeys(ssl_t *ssl)
{
# ifdef USE_TLS
    if (!NGTD_VER(ssl, v_ssl_3_0))
    {
        return tlsDeriveKeys(ssl);
    }
    else
    {
#  ifndef DISABLE_SSLV3
        return sslDeriveKeys(ssl);
#  else
        return PS_ARG_FAIL;
#  endif /* DISABLE_SSLV3 */
    }
# else /* SSLv3 only below */
#  ifndef DISABLE_SSLV3
    return sslDeriveKeys(ssl);
#  endif /* DISABLE_SSLV3 */
# endif  /* USE_TLS */

    return PS_UNSUPPORTED_FAIL;
}

/******************************************************************************/
/*
    Cipher suites are chosen before they are activated with the
    ChangeCipherSuite message.  Additionally, the read and write cipher suites
    are activated at different times in the handshake process.  The following
    APIs activate the selected cipher suite callback functions.
 */
int32 sslActivateReadCipher(ssl_t *ssl)
{

    ssl->decrypt = ssl->cipher->decrypt;
    ssl->verifyMac = ssl->cipher->verifyMac;
    ssl->nativeDeMacSize = ssl->cipher->macSize;
    ssl->activeReadCipher = ssl->cipher;

    if (ssl->extFlags.truncated_hmac)
    {
        if (ssl->cipher->macSize > 0)   /* Only for HMAC-based ciphers */
        {
            ssl->deMacSize = 10;
        }
        else
        {
            ssl->deMacSize = ssl->cipher->macSize;
        }
    }
    else
    {
        ssl->deMacSize = ssl->cipher->macSize;
    }
    ssl->deBlockSize = ssl->cipher->blockSize;
    ssl->deIvSize = ssl->cipher->ivSize;
/*
    Reset the expected incoming sequence number for the new suite
 */
    Memset(ssl->sec.remSeq, 0x0, sizeof(ssl->sec.remSeq));

    if (ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL)
    {
        /* Sanity */
        if (ssl->sec.rKeyptr == NULL && ssl->sec.rMACptr == NULL)
        {
            psTraceErrr("sslActivateReadCipher sanity fail\n");
            return PS_FAILURE;
        }
        ssl->flags |= SSL_FLAGS_READ_SECURE;

# ifdef USE_TLS_1_2
        if (ssl->deMacSize == 0)
        {
            /* Need a concept for AEAD read and write start times for the
                cases surrounding changeCipherSpec if moving from one suite
                to another */
            ssl->flags |= SSL_FLAGS_AEAD_R;
            if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
            {
                ssl->flags &= ~SSL_FLAGS_NONCE_R;
            }
            else
            {
                ssl->flags |= SSL_FLAGS_NONCE_R;
            }
        }
        else
        {
            ssl->flags &= ~SSL_FLAGS_AEAD_R;
            ssl->flags &= ~SSL_FLAGS_NONCE_R;
        }
# endif
/*
        Copy the newly activated read keys into the live buffers
 */
        if (ssl->sec.rMACptr)
            Memcpy(ssl->sec.readMAC, ssl->sec.rMACptr, ssl->deMacSize);
        if (ssl->sec.rKeyptr)
            Memcpy(ssl->sec.readKey, ssl->sec.rKeyptr, ssl->cipher->keySize);
        if (ssl->sec.rIVptr)
            Memcpy(ssl->sec.readIV, ssl->sec.rIVptr, ssl->cipher->ivSize);
# ifdef DEBUG_TLS_MAC
        psTracePrintTlsKeys("read keys", ssl, PS_TRUE);
# endif /* DEBUG_TLS_MAC */

/*
        set up decrypt contexts
 */
        if (ssl->cipher->init)
        {
            if (ssl->cipher->init(&(ssl->sec), INIT_DECRYPT_CIPHER,
                    ssl->cipher->keySize) < 0)
            {
                psTraceErrr("Unable to initialize read cipher suite\n");
                return PS_FAILURE;
            }
        }

    }
    return PS_SUCCESS;
}

int32 sslActivateWriteCipher(ssl_t *ssl)
{
# ifdef USE_DTLS
    if (ACTV_VER(ssl, v_dtls_any))
    {
        if (ssl->retransmit == 0)
        {
            ssl->oencrypt = ssl->encrypt;
            ssl->ogenerateMac = ssl->generateMac;
            ssl->oenMacSize = ssl->enMacSize;
            ssl->oenNativeHmacSize = ssl->nativeEnMacSize;
            ssl->oenBlockSize = ssl->enBlockSize;
            ssl->oenIvSize = ssl->enIvSize;
            Memcpy(ssl->owriteMAC, ssl->sec.writeMAC, ssl->enMacSize);
            Memcpy(&ssl->oencryptCtx, &ssl->sec.encryptCtx,
                sizeof(psCipherContext_t));
            Memcpy(ssl->owriteIV, ssl->sec.writeIV, ssl->cipher->ivSize);
            Memcpy(ssl->owriteKey, ssl->sec.writeKey, sizeof(ssl->owriteKey));
        }
    }
# endif /* USE_DTLS */

    ssl->encrypt = ssl->cipher->encrypt;
    ssl->generateMac = ssl->cipher->generateMac;
    ssl->nativeEnMacSize = ssl->cipher->macSize;
    ssl->activeWriteCipher = ssl->cipher;

    if (ssl->extFlags.truncated_hmac)
    {
        if (ssl->cipher->macSize > 0)   /* Only for HMAC-based ciphers */
        {
            ssl->enMacSize = 10;
        }
        else
        {
            ssl->enMacSize = ssl->cipher->macSize;
        }
    }
    else
    {
        ssl->enMacSize = ssl->cipher->macSize;
    }
    ssl->enBlockSize = ssl->cipher->blockSize;
    ssl->enIvSize = ssl->cipher->ivSize;
/*
    Reset the outgoing sequence number for the new suite
 */
    Memset(ssl->sec.seq, 0x0, sizeof(ssl->sec.seq));
    if (ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL)
    {
        ssl->flags |= SSL_FLAGS_WRITE_SECURE;

# ifdef USE_TLS_1_2
        if (ssl->enMacSize == 0)
        {
            /* Need a concept for AEAD read and write start times for the
                cases surrounding changeCipherSpec if moving from one suite
                to another */
            ssl->flags |= SSL_FLAGS_AEAD_W;
            if (ssl->cipher->flags & CRYPTO_FLAGS_CHACHA)
            {
                ssl->flags &= ~SSL_FLAGS_NONCE_W;
            }
            else
            {
                ssl->flags |= SSL_FLAGS_NONCE_W;
            }
        }
        else
        {
            ssl->flags &= ~SSL_FLAGS_AEAD_W;
            ssl->flags &= ~SSL_FLAGS_NONCE_W;
        }
# endif

/*
        Copy the newly activated write keys into the live buffers
 */
        Memcpy(ssl->sec.writeMAC, ssl->sec.wMACptr, ssl->enMacSize);
        Memcpy(ssl->sec.writeKey, ssl->sec.wKeyptr, ssl->cipher->keySize);
        Memcpy(ssl->sec.writeIV, ssl->sec.wIVptr, ssl->cipher->ivSize);
# ifdef DEBUG_TLS_MAC
        psTracePrintTlsKeys("Write keys", ssl, PS_TRUE);
# endif /* DEBUG_TLS_MAC */

/*
        set up encrypt contexts
 */
        if (ssl->cipher->init)
        {
            if (ssl->cipher->init(&(ssl->sec), INIT_ENCRYPT_CIPHER,
                    ssl->cipher->keySize) < 0)
            {
                psTraceErrr("Unable to init write cipher suite\n");
                return PS_FAILURE;
            }
        }
    }
    return PS_SUCCESS;
}

/******************************************************************************/
#endif /* USE_NATIVE_TLS_ALGS */


#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
    Allocate a tlsExtension_t structure
 */
int32 matrixSslNewHelloExtension(tlsExtension_t **extension, void *userPoolPtr)
{
    psPool_t *pool = NULL;
    tlsExtension_t *ext;

    ext = psMalloc(pool, sizeof(tlsExtension_t));
    if (ext == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(ext, 0x0, sizeof(tlsExtension_t));
    ext->pool = pool;

    *extension = ext;
    return PS_SUCCESS;
}

void psCopyHelloExtension(tlsExtension_t *destination,
        const tlsExtension_t *source)
{
    const tlsExtension_t *src;
    tlsExtension_t *dst;

    psAssert(source != NULL && destination != NULL);
    psAssert(source != destination);

    src = source;
    dst = destination;

    while (1)
    {
        dst->pool = src->pool;
        dst->extType = src->extType;
        dst->extLen = src->extLen;
        dst->extData = psMalloc(src->pool, src->extLen);
        Memcpy(dst->extData, src->extData, src->extLen);
        if (src->next)
        {
            dst->next = psMalloc(src->pool, sizeof(*dst->next));
            dst = dst->next;
            src = src->next;
        }
        else
        {
            dst->next = NULL;
            break;
        }
    }
}

/*
  Make a deep copy of the extension struct for re-sending
  during renegotiations and TLS 1.3 HelloRetryRequest responses.
*/
void psAddUserExtToSession(ssl_t *ssl,
        const tlsExtension_t *ext)
{
    if (ext == NULL)
    {
        ssl->userExt = NULL;
        return;
    }
    if (ssl->userExt == ext)
    {
        return;
    }
    ssl->userExt = psMalloc(ssl->hsPool, sizeof(tlsExtension_t));
    psCopyHelloExtension(ssl->userExt, ext);
}

/******************************************************************************/
/*
    Free a tlsExtension_t structure and any extensions that have been loaded
 */
void matrixSslDeleteHelloExtension(tlsExtension_t *extension)
{
    tlsExtension_t *next, *ext;

    if (extension == NULL)
    {
        return;
    }
    ext = extension;
        /* Free first one */
    if (ext->extData)
    {
        psFree(ext->extData, ext->pool);
    }
    next = ext->next;
    psFree(ext, ext->pool);
    /* Free others */
    while (next)
    {
        ext = next;
        next = ext->next;
        if (ext->extData)
        {
            psFree(ext->extData, ext->pool);
        }
        psFree(ext, ext->pool);
    }
    return;
}

/*****************************************************************************/
/*
    Add an outgoing CLIENT_HELLO extension to a tlsExtension_t structure
    that was previously allocated with matrixSslNewHelloExtension
 */
int32 matrixSslLoadHelloExtension(tlsExtension_t *ext,
    unsigned char *extension, uint32 length, uint32 extType)
{
    tlsExtension_t *current, *new;

    if (ext == NULL || (length > 0 && extension == NULL))
    {
        return PS_ARG_FAIL;
    }
/*
    Find first empty spot in ext.  This is determined by extLen since even
    an empty extension will have a length of 1 for the 0
 */
    current = ext;
    while (current->extLen != 0)
    {
        if (current->next != NULL)
        {
            current = current->next;
            continue;
        }
        new = psMalloc(ext->pool, sizeof(tlsExtension_t));
        if (new == NULL)
        {
            return PS_MEM_FAIL;
        }
        Memset(new, 0, sizeof(tlsExtension_t));
        new->pool = ext->pool;
        current->next = new;
        current = new;
    }
/*
    Supports an empty extension which is really a one byte 00:
        ff 01 00 01 00  (two byte type, two byte len, one byte 00)

    This will either be passed in as a NULL 'extension' with a 0 length - OR -
    A pointer to a one byte 0x0 and a length of 1.  In either case, the
    structure will identify the ext with a length of 1 and a NULL data ptr
 */
    current->extType = extType;
    if (length > 0)
    {
        current->extLen = length;
        if (length == 1 && extension[0] == '\0')
        {
            current->extLen = 1;
        }
        else
        {
            current->extData = psMalloc(ext->pool, length);
            if (current->extData == NULL)
            {
                return PS_MEM_FAIL;
            }
            Memcpy(current->extData, extension, length);
        }
    }
    else if (length == 0)
    {
        current->extLen = 1;
    }

    return PS_SUCCESS;
}
#endif /* USE_CLIENT_SIDE_SSL */

/* Helper function that searches for an uint16 item in an array */
int32_t findFromUint16Array(const uint16_t *a,
        psSize_t aLen,
        const uint16_t b)
{
    psSize_t i;
    for (i = 0; i < aLen; i++)
    {
        if (a[i] == b)
        {
            return i;
        }
    }
    return PS_FAILURE;
}

psBool_t anyTls13VersionSupported(ssl_t *ssl)
{
    if (SUPP_VER(ssl, v_tls_1_3_any))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}

psBool_t anyNonTls13VersionSupported(ssl_t *ssl)
{
    if (SUPP_VER(ssl, v_tls_legacy))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}

# ifdef USE_TLS_1_3
psBool_t peerOnlySupportsTls13(ssl_t *ssl)
{
    if (PEER_SUPP_VER(ssl, v_tls_1_3_any)
            && !PEER_SUPP_VER(ssl, v_tls_legacy))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}

psBool_t weOnlySupportTls13(ssl_t *ssl)
{
    if (SUPP_VER(ssl, v_tls_1_3_any)
            && !SUPP_VER(ssl, v_tls_1_0)
            && !SUPP_VER(ssl, v_tls_1_1)
            && !SUPP_VER(ssl, v_tls_1_2))
    {
        return PS_TRUE;
    }
    return PS_FALSE;
}
# endif /* USE_TLS_1_3 */


/******************************************************************************/
