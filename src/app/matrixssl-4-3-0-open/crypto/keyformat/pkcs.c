/**
 *      @file    pkcs.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      Collection of RSA PKCS standards .
 */

/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
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

#include "../cryptoImpl.h"

/******************************************************************************/
/*
    Pad a value to be encrypted by RSA, according to PKCS#1 v1.5
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/
    When encrypting a value with RSA, the value is first padded to be
    equal to the public key size using the following method:
        00 <id> <data> 00 <value to be encrypted>
    - id denotes a public or private key operation
    - if id is private, data is however many non-zero bytes it takes to pad the
        value to the key length (randomLen = keyLen - 3 - valueLen).
    - if id is public, data is FF for the same length as described above
    - There must be at least 8 bytes of data.
 */
int32_t pkcs1Pad(const unsigned char *in, psSize_t inlen,
    unsigned char *out, psSize_t outlen,
    uint8_t cryptType, void *userPtr)
{
    unsigned char *c;
    uint32_t randomLen;

    randomLen = outlen - 3 - inlen;
    if (randomLen < 8)
    {
        psTraceCrypto("pkcs1Pad failure\n");
        return PS_LIMIT_FAIL;
    }
    c = out;
    *c = 0x00;
    c++;
    *c = (unsigned char) cryptType;
    c++;
    if (cryptType == PS_PUBKEY)
    {
        while (randomLen > 0)
        {
            *c++ = 0xFF;
            randomLen--;
        }
    }
    else
    {
        if (psGetPrngLocked(c, randomLen, userPtr) < 0)
        {
            return PS_PLATFORM_FAIL;
        }
/*
        SECURITY:  Read through the random data and change all 0x0 to 0x01.
        This is per spec that no random bytes should be 0
 */
        while (randomLen > 0)
        {
            if (*c == 0x0)
            {
                *c = 0x01;
            }
            randomLen--;
            c++;
        }
    }
    *c = 0x00;
    c++;
    Memcpy(c, in, inlen);

    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Unpad a value decrypted by RSA, according to PKCS#1 v1.5
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/

    When decrypted, the data will look like the pad, including the inital
    byte (00).  Form:
        00 <decryptType> <random data (min 8 bytes)> 00 <value to be encrypted>

    We don't worry about v2 rollback issues because we don't support v2

    If verifyUnpaddedLen is false, leave it up to the caller to check that
    the unpadded lenght matches the expected length.
 */
int32_t pkcs1UnpadExt(const unsigned char *in,
        psSize_t inlen,
        unsigned char *out,
        psSize_t outlen,
        uint8_t decryptType,
        psBool_t verifyUnpaddedLen,
        psSize_t *unpaddedLen)
{
    const unsigned char *c, *end;

    if (verifyUnpaddedLen && inlen < outlen + 10)
    {
        psTraceCrypto("pkcs1Unpad failure\n");
        return PS_ARG_FAIL;
    }
    c = in;
    end = in + inlen;

    /* Verify the first byte (block type) is correct.  */
    if (*c++ != 0x00 || *c != decryptType)
    {
        psTraceCrypto("pkcs1Unpad parse failure\n");
        return PS_FAILURE;
    }
    c++;

    /* Skip over the random, non-zero bytes used as padding */
    while (c < end && *c != 0x0)
    {
        if (decryptType == PS_PUBKEY)
        {
            if (*c != 0xFF)
            {
                psTraceCrypto("pkcs1Unpad pubkey parse failure\n");
                return PS_FAILURE;
            }
        }
        c++;
    }
    c++;

    /*
      The length of the remaining data should be equal to what was expected
      Combined with the initial length check, there must be >= 8 bytes of pad
      ftp://ftp.rsa.com/pub/pdfs/bulletn7.pdf
    */
    if (verifyUnpaddedLen)
    {
        if ((uint32) (end - c) != outlen)
        {
            psTraceCrypto("pkcs1Unpad verification failure\n");
            return PS_LIMIT_FAIL;
        }
    }
    else
    {
        if ((uint32) (end - c) > outlen)
        {
            psTraceCrypto("pkcs1Unpad output buffer to small\n");
            return PS_OUTPUT_LENGTH;
        }
    }

    if (unpaddedLen)
    {
        *unpaddedLen = (psSize_t)(end - c);
    }

    /* Copy the value bytes to the out buffer */
    while (c < end)
    {
        *out = *c;
        out++; c++;
    }

    return PS_SUCCESS;
}

int32_t pkcs1Unpad(const unsigned char *in,
        psSize_t inlen,
        unsigned char *out,
        psSize_t outlen,
        uint8_t decryptType)
{
    return pkcs1UnpadExt(in,
            inlen,
            out,
            outlen,
            decryptType,
            PS_TRUE,
            NULL);
}

#ifdef USE_PRIVATE_KEY_PARSING
#  ifdef MATRIX_USE_FILE_SYSTEM
#   ifdef USE_PKCS8
#    ifdef USE_PKCS12
/******************************************************************************/
/*
    A PKCS #7 ContentInfo, whose contentType is signedData in public-key
    integrity mode and data in password integrity mode.

    Returns integrity mode or < 0 on failure
 */
#    define PASSWORD_INTEGRITY  1
#    define PUBKEY_INTEGRITY    2
static int32 psParseIntegrityMode(const unsigned char **buf, int32 totLen)
{
    const unsigned char *p, *end;
    psSize_t totcontentlen, len, oiLen;
    int32 rc, oi;

    p = *buf;
    end = p + totLen;

    if ((rc = getAsnAlgorithmIdentifier(&p, totLen, &oi, &oiLen)) < 0)
    {
        psTraceCrypto("Initial integrity parse error\n");
        return rc;
    }

    if (oi == OID_PKCS7_DATA)
    {
        /* Data ::= OCTET STRING */
        if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
        {
            return PS_PARSE_FAIL;
        }
        if ((rc = getAsnLength(&p, (int32) (end - p), &len)) < 0)
        {
            return PS_PARSE_FAIL;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &totcontentlen) < 0)
        {
            psTraceCrypto("Couldn't parse data from ContentInfo\n");
            return PS_FAILURE;
        }
        rc = PASSWORD_INTEGRITY;
    }
    else if (oi == OID_PKCS7_SIGNED_DATA)
    {
        psTraceCrypto("SignedData integrity mode not supported\n");
        return PS_UNSUPPORTED_FAIL;
        /* rc = PUBKEY_INTEGRITY; */
    }
    else
    {
        psTraceCrypto("Unknown integrity mode\n");
        return PS_UNSUPPORTED_FAIL;
    }

    *buf = (unsigned char *) p;
    return rc;
}

/******************************************************************************/
/*
    Generate a key given a password, salt and iteration value.

    B.2 General method from PKCS#12

    Assumptions:  hash is SHA-1, password is < 128 bytes
 */
static int32 pkcs12pbe(psPool_t *pool, unsigned char *password, uint32 passLen,
    unsigned char *salt, int saltLen, int32 iter, int32 id,
    unsigned char **out, uint32 *outlen)
{
    psSha1_t ctx;
    pstm_int bigb, bigone, bigtmp;
    unsigned char diversifier[64], saltpass[192], hash[SHA1_HASH_SIZE];
    unsigned char B[65];
    unsigned char *p, *front;
    int32 i, j, copy, count, cpyLen, binsize, plen;

    *out = NULL;
    Memset(diversifier, id, 64);

    for (i = 0; i < 64; )
    {
        if ((64 - i) < saltLen)
        {
            Memcpy(&saltpass[i], salt, 64 - i);
            i = 64;
        }
        else
        {
            Memcpy(&saltpass[i], salt, saltLen);
            i += saltLen;
        }
    }

    plen = 64 * ((passLen + 64 - 1) / 64);
    if (plen + 64 > 192)
    {
        return PS_UNSUPPORTED_FAIL;
    }
    for (i = 0; i < plen; i++)
    {
        saltpass[64 + i] = password[i % passLen];
    }

    if (*outlen == SHA1_HASH_SIZE)
    {
        count = 1;
    }
    else
    {
        count = (*outlen / SHA1_HASH_SIZE) + 1;
    }
    cpyLen = *outlen;

    front = p = psMalloc(pool, cpyLen);
    if (front == NULL)
    {
        return PS_MEM_FAIL;
    }

    while (count)
    {
        psSha1Init(&ctx);
        psSha1Update(&ctx, diversifier, 64);
        psSha1Update(&ctx, saltpass, 64 + plen);
        psSha1Final(&ctx, hash);
        for (j = 1; j < iter; j++)
        {
            psSha1Init(&ctx);
            psSha1Update(&ctx, hash, SHA1_HASH_SIZE);
            psSha1Final(&ctx, hash);
        }
        /* Copy into outgoing key now */
        copy = min(cpyLen, SHA1_HASH_SIZE);
        Memcpy(p, hash, copy);
        p += copy;
        count--;
        cpyLen -= copy;

        if (cpyLen > 0)
        {
            /* manipulate saltpass */
            for (j = 0; j < 64; j++)
            {
                B[j] = hash[j % SHA1_HASH_SIZE];
            }
            if (pstm_init_for_read_unsigned_bin(pool, &bigb, 64) < 0)
            {
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            if (pstm_read_unsigned_bin(&bigb, B, 64) < 0)
            {
                pstm_clear(&bigb);
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            if (pstm_init_for_read_unsigned_bin(pool, &bigone, 1) < 0)
            {
                pstm_clear(&bigb);
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            pstm_set(&bigone, 1);
            if (pstm_add(&bigb, &bigone, &bigb) < 0)
            {
                pstm_clear(&bigone);
                pstm_clear(&bigb);
                psFree(front, pool);
                return PS_MEM_FAIL;
            }
            pstm_clear(&bigone);
            for (j = 0; j < 64 + plen; j += 64)
            {
                if (pstm_init_for_read_unsigned_bin(pool, &bigtmp, 64) < 0)
                {
                    pstm_clear(&bigone);
                    pstm_clear(&bigb);
                    psFree(front, pool);
                    return PS_MEM_FAIL;
                }
                if (pstm_read_unsigned_bin(&bigtmp, saltpass + j, 64) < 0)
                {
                    pstm_clear(&bigone);
                    pstm_clear(&bigb);
                    pstm_clear(&bigtmp);
                    psFree(front, pool);
                    return PS_MEM_FAIL;
                }
                if (pstm_add(&bigb, &bigtmp, &bigtmp) < 0)
                {
                    pstm_clear(&bigone);
                    pstm_clear(&bigb);
                    pstm_clear(&bigtmp);
                    psFree(front, pool);
                    return PS_MEM_FAIL;
                }
                binsize = pstm_unsigned_bin_size(&bigtmp);
                if (binsize > 64)
                {
                    psAssert(binsize == 65);
                    if (pstm_to_unsigned_bin(pool, &bigtmp, B) < 0)
                    {
                        pstm_clear(&bigone);
                        pstm_clear(&bigb);
                        pstm_clear(&bigtmp);
                        psFree(front, pool);
                        return PS_MEM_FAIL;
                    }
                    Memcpy(saltpass + j, B + 1, 64); /* truncate */
                }
                else if (binsize < 64)
                {
                    psAssert(binsize == 63);
                    Memset(saltpass + j, 0x0, 1); /* pad with a zero */
                    if (pstm_to_unsigned_bin(pool, &bigtmp, saltpass + j + 1) < 0)
                    {
                        pstm_clear(&bigone);
                        pstm_clear(&bigb);
                        pstm_clear(&bigtmp);
                        psFree(front, pool);
                        return PS_MEM_FAIL;
                    }
                }
                else
                {
                    if (pstm_to_unsigned_bin(pool, &bigtmp, saltpass + j) < 0)
                    {
                        pstm_clear(&bigone);
                        pstm_clear(&bigb);
                        pstm_clear(&bigtmp);
                        psFree(front, pool);
                        return PS_MEM_FAIL;
                    }
                }
                pstm_clear(&bigtmp);
            }
            pstm_clear(&bigone);
            pstm_clear(&bigb);
        }
    }

    *out = front;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Return value is how many bytes were parsed out of buf
 */
static int32 pkcs12import(psPool_t *pool, const unsigned char **buf,
    psSize_t bufLen, unsigned char *password, psSize_t passLen,
    unsigned char **plaintext, psSize_t *ptLen)
{
    psCipherContext_t ctx;
    const unsigned char *p, *start, *end;
    unsigned char *iv, *decryptKey, *pt;
    unsigned char salt[8];
    int32 rc, oi, asnint;
    uint32_t keyLen, ivLen;
    psSize_t tmplen, tmpint;
    short cipher;
    const short armor = PBE12;

    *plaintext = NULL;
    *ptLen = 0;
    decryptKey = NULL;

    p = start = *buf;
    end = p + bufLen;

    /* Encryption Algorithm */
    if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi,
             &tmpint)) < 0)
    {
        psTraceCrypto("Initial pkcs12import parse failure\n");
        return rc;
    }

    if (oi == OID_PKCS_PBESHA40RC2)
    {
#    ifdef USE_RC2
        cipher = AUTH_SAFE_RC2;
        keyLen = 8;
#    else
        psTraceCrypto("Must enable USE_RC2 in cryptoConfig.h to parse\n");
        return PS_UNSUPPORTED_FAIL;
#    endif
    }
    else if (oi == OID_PKCS_PBESHA3DES3)
    {
        cipher = AUTH_SAFE_3DES;
        keyLen = DES3_KEYLEN;
    }
    else
    {
        psTraceIntCrypto("Unsupported PBE algorithm %d\n", oi);
        return PS_UNSUPPORTED_FAIL;
    }

    if (armor == PBE12)
    {
        /* If PKCS12 param will be
           pkcs-12PbeParams ::= SEQUENCE {
            salt OCTET STRING,
            iterations INTEGER
           }
         */
        if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
        {
            psTraceCrypto("Initial PBE12 parse failure\n");
            return rc;
        }
        /* salt len */
        if ((uint32) (end - p) < 1 || (*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0 ||
            (uint32) (end - p) < tmplen ||
            tmplen != 8)
        {

            psTraceCrypto("Bad salt length parsing import\n");
            return PS_PARSE_FAIL;
        }
        Memcpy(salt, p, tmplen);
        p += tmplen;
        /* iteration count */
        if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0)
        {
            return PS_PARSE_FAIL;
        }
        if (pkcs12pbe(pool, password, passLen, salt, 8, asnint,
                PKCS12_KEY_ID, &decryptKey, &keyLen) < 0)
        {
            psTraceCrypto("Error generating pkcs12 key\n");
            return PS_UNSUPPORTED_FAIL;
        }
        ivLen = 8;
        if (pkcs12pbe(pool, password, passLen, salt, 8, asnint,
                PKCS12_IV_ID, &iv, &ivLen) < 0)
        {
            psTraceCrypto("Error generating pkcs12 iv\n");
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            return PS_UNSUPPORTED_FAIL;
        }
    }

    /* Got the keys but we still need to find the start of the encrypted data.
        Have seen a few different BER variations at this point in the spec
        depending on what wrapper we are in. Try all that we know about
     */
    if ((uint32) (end - p) < 1)
    {
        return PS_PARSE_FAIL;
    }
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE))
    {
        p++;
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
    }
    else if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {
        p++;
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
        if ((uint32) (end - p) < 1 ||
            *p++ != ASN_OCTET_STRING ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
    }
    else if (*p == ASN_OCTET_STRING)
    {
        p++;
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            return PS_PARSE_FAIL;
        }
    }
    else
    {
        psTraceCrypto("Error finding ciphertext in pkcs12import\n");
        if (decryptKey)
        {
            memset_s(decryptKey, keyLen, 0x0, keyLen);
            psFree(decryptKey, pool);
        }
        psFree(iv, pool);
        return PS_PARSE_FAIL;
    }

    if (tmplen < 1 || (uint32) (end - p) < tmplen)
    {
        return PS_PARSE_FAIL;
    }

    /* Don't decrypt in-situ because we'll need to MAC this all later */
    if ((pt = psMalloc(pool, tmplen)) == NULL)
    {
        psTraceCrypto("Out-of-memory.  Increase SSL_KEY_POOL_SIZE\n");
        if (decryptKey)
        {
            memset_s(decryptKey, keyLen, 0x0, keyLen);
            psFree(decryptKey, pool);
        }
        psFree(iv, pool);
        return PS_MEM_FAIL;
    }
    if (cipher == AUTH_SAFE_3DES)
    {
        if ((rc = psDes3Init(&ctx.des3, iv, decryptKey)) < 0)
        {
            memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            psFree(pt, pool);
            return rc;
        }
        psDes3Decrypt(&ctx.des3, p, pt, tmplen);
    }
#    ifdef USE_RC2
    if (cipher == AUTH_SAFE_RC2)
    {

        /* This is a 40-bit RC2! */
        if ((rc = psRc2Init(&ctx.rc2, iv, decryptKey, 5)) < 0)
        {
            memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            psFree(pt, pool);
            return rc;
        }
        if ((rc = psRc2Decrypt(&ctx.rc2, p, pt, tmplen)) < 0)
        {
            memset_s(&ctx, sizeof(psCipherContext_t), 0x0, sizeof(psCipherContext_t));
            if (decryptKey)
            {
                memset_s(decryptKey, keyLen, 0x0, keyLen);
                psFree(decryptKey, pool);
            }
            psFree(iv, pool);
            psFree(pt, pool);
            return rc;
        }
    }
#    endif /* USE_RC2 */

    if (decryptKey)
    {
        memset_s(decryptKey, keyLen, 0x0, keyLen);
        psFree(decryptKey, pool);
    }
    psFree(iv, pool);

    *plaintext = pt;
    *ptLen = tmplen;
    return (int32) (p - start);
}

/******************************************************************************/
/*
    Determines what the safebag is and loads the material into the users
    data structure (cert or private key)
 */
static int32 parseSafeContents(psPool_t *pool, unsigned char *password,
    uint32 passLen, psX509Cert_t **cert, psPubKey_t *privKey,
    unsigned char *buf, uint32 totlen)
{
    psX509Cert_t *currCert, *frontCert;
    const unsigned char *p, *end;
    unsigned char *pt, *safeLen;
    psSize_t tmplen, cryptlen, tmpint;
    int32 rc, bagoi, certoi;

#    ifdef PARSE_PKCS12_SAFE_ATTRIBS
    uint32 attriblen;
    int32 attriboi;
#    endif

    p = buf;
    end = p + totlen;

    /*  SafeContents ::= SEQUENCE OF SafeBag

        SafeBag ::= SEQUENCE {
            bagId     BAG-TYPE.&id ({PKCS12BagSet})
            bagValue  [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
            bagAttributes SET OF PKCS12Attribute OPTIONAL
       } */
    if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
    {
        psTraceCrypto("Initial SafeContents parse failure\n");
        if (rc == PS_PARSE_FAIL)
        {
            /* The error is probably due to decryption error.
               Issue the error as PS_AUTH_FAIL. */
            rc = PS_AUTH_FAIL;
        }
        return rc;
    }

    end = p + tmplen;

    while (p < end)
    {
        /*
           bagtypes OBJECT IDENTIFIER ::= {pkcs-12 10 1}

           BAG-TYPE ::= TYPE-IDENTIFIER
            keyBag BAG-TYPE ::= {KeyBag IDENTIFIED BY {bagtypes 1}}
            pkcs8ShroudedKeyBag BAG-TYPE ::= {PKCS8ShroudedKeyBag IDENTIFIED BY
                {bagtypes 2}}
            certBag BAG-TYPE ::= {CertBag IDENTIFIED BY {bagtypes 3}}
            crlBag BAG-TYPE ::= {CRLBag IDENTIFIED BY {bagtypes 4}}
            secretBag BAG-TYPE ::= {SecretBag IDENTIFIED BY {bagtypes 5}}
            safeContentsBag BAG-TYPE ::= {SafeContents IDENTIFIED BY
                {bagtypes 6}}

           PKCS12BagSet BAG-TYPE ::= {
            keyBag | pkcs8ShroudedKeyBag | certBag | crlBag | secretBag |
                safeContentsBag, ... -- For future extensions}

         */
        if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &bagoi,
                 &tmpint)) < 0)
        {
            psTraceCrypto("Initial BagType parse failure\n");
            if (rc == PS_PARSE_FAIL)
            {
                /* The error is probably due to decryption error.
                   Issue the error as PS_AUTH_FAIL. */
                rc = PS_AUTH_FAIL;
            }
            return rc;
        }
        safeLen = (unsigned char *) p + tmpint;
        if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
        {
            return PS_PARSE_FAIL;
        }
        if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
        {
            return PS_PARSE_FAIL;
        }

        switch (bagoi)
        {
        case OID_PKCS12_BAG_TYPE_CERT:
            /*
               CertBag ::= SEQUENCE {
               certId    BAG-TYPE.&id   ({CertTypes}),
               certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId}) }

               x509Certificate BAG-TYPE ::=
                {OCTET STRING IDENTIFIED BY {certTypes 1}}
                -- DER-encoded X.509 certificate stored in OCTET STRING
               sdsiCertificate BAG-TYPE ::=
                {IA5String IDENTIFIED BY {certTypes 2}}
                -- Base64-encoded SDSI certificate stored in IA5String

               CertTypes BAG-TYPE ::= {
                x509Certificate |
                sdsiCertificate,
                ... -- For future extensions
               }
             */
            if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p),
                     &certoi, &tmpint)) < 0)
            {
                psTraceCrypto("Initial CertBag parse failure\n");
                return rc;
            }
            if (certoi != OID_PKCS9_CERT_TYPE_X509)
            {
                psTraceIntCrypto("Unsupported CertBag type %d\n", certoi);
                return PS_UNSUPPORTED_FAIL;
            }
            if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
            {
                return PS_PARSE_FAIL;
            }
            if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return rc;
            }
            if ((*p++ != ASN_OCTET_STRING) ||
                getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
            {
                psTraceCrypto("Couldn't extract X509 CertBag\n");
                return PS_FAILURE;
            }
            /* Support cert chains */
            currCert = frontCert = *cert;
            while (currCert != NULL)
            {
                currCert = currCert->next;
            }
            if ((rc = psX509ParseCert(pool, p, tmplen, &currCert,
                     CERT_STORE_UNPARSED_BUFFER)) < 0)
            {
                psX509FreeCert(currCert);
                *cert = NULL;
                psTraceCrypto("Couldn't parse certificate from CertBag\n");
                return rc;
            }
            if (*cert == NULL)
            {
                *cert = currCert;
            }
            else
            {
                while (frontCert->next != NULL)
                {
                    frontCert = frontCert->next;
                }
                frontCert->next = currCert;
            }
            p += rc;
            break;

        case OID_PKCS12_BAG_TYPE_SHROUD:
            /* A PKCS8ShroudedKeyBag holds a private key, which has been
                shrouded in accordance with PKCS #8.  Note that a
                PKCS8ShroudedKeyBag holds only one shrouded private key. */
            if (getAsnSequence(&p, (int32) (end - p), &tmplen) < 0)
            {
                psTraceCrypto("Initial PKCS8 ShroudKeyBag parse failure\n");
                return PS_PARSE_FAIL;
            }
            if ((rc = pkcs12import(pool, &p,
                     (int32) (end - p), password, passLen, &pt, &cryptlen)) < 0)
            {
                psTraceIntCrypto("Import failed from AuthSafe %d\n", rc);
                return rc;
            }
            p += rc;
            /* Result of decrypt will be a PKCS#8 key */
            if ((rc = psPkcs8ParsePrivBin(pool, pt, cryptlen, NULL, privKey))
                < 0)
            {
                psFree(pt, pool);
                psTraceIntCrypto("Failed shroud PKCS8 key parse %d\n", rc);
                return rc;
            }
            psFree(pt, pool);
            p += cryptlen;
            break;
        case OID_PKCS12_BAG_TYPE_KEY:
            if ((rc = psPkcs8ParsePrivBin(pool, (unsigned char *) p, tmplen,
                     NULL, privKey)) < 0)
            {
                psTraceIntCrypto("Failed PKCS8 key parse %d\n", rc);
                return rc;
            }
            p += tmplen;
            break;
        default:
            psTraceIntCrypto("Unsupported BAG_TYPE %d\n", bagoi);
            return PS_UNSUPPORTED_FAIL;
        }

        /* Attributes are at the end of the data */
        while (p != safeLen)
        {
#    ifdef PARSE_PKCS12_SAFE_ATTRIBS
            /**/
            if ((rc = getAsnSet(&p, (int32) (end - p), &attriblen)) < 0)
            {
                return rc;
            }
            if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &attriboi,
                     &pLen)) < 0)
            {
                return rc;
            }
            if ((rc = getAsnSet(&p, (int32) (end - p), &attriblen)) < 0)
            {
                return rc;
            }
            if ((*p++ != ASN_OCTET_STRING) ||
                getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
            {
                psTraceCrypto("Couldn't parse PKCS#8 param salt\n");
                return PS_FAILURE;
            }
            p += tmplen;
#    else
            p = safeLen;
#    endif
        }
    }
    return totlen;
}

/******************************************************************************/
/*
    AuthenticatedSafe ::= SEQUENCE OF ContentInfo
        -- Data if unencrypted
        -- EncryptedData if password-encrypted
        -- EnvelopedData if public key-encrypted
 */
static int32 psParseAuthenticatedSafe(psPool_t *pool, psX509Cert_t **cert,
    psPubKey_t *privKey, unsigned char *importPass, int32 ipassLen,
    unsigned char **buf, int32 totLen)
{
    const unsigned char *p, *end;
    unsigned char *pt;
    psSize_t tmplen, tmpint;
    int32_t asnint;
    int32 rc, oi;

    p = *buf;
    end = p + totLen;
    if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
    {
        psTraceCrypto("Initial authenticated safe parse failure\n");
        return rc;
    }

    end = p + tmplen; /* Set end to be end of authSafe for list walk */

    while (p < end)
    {
        if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi,
                 &tmpint)) < 0)
        {
            psTraceCrypto("Initial content info parse failure\n");
            return rc;
        }
        if (oi == OID_PKCS7_ENCRYPTED_DATA)
        {
            /* password protected mode */
            if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
            {
                psTraceCrypto("Initial pkcs7 encrypted data parse failure\n");
                return PS_PARSE_FAIL;
            }
            if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return PS_PARSE_FAIL;
            }
            /* EncryptedData ::= SEQUENCE {
                version Version,
                encryptedContentInfo EncryptedContentInfo } */
            if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return rc;
            }
            /* Version */
            if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0 ||
                asnint != 0)
            {
                psTraceIntCrypto("Unsupported encryptd data version %d\n",
                    asnint);
                return PS_UNSUPPORTED_FAIL;
            }
            /*
               EncryptedContentInfo ::= SEQUENCE {
                contentType     ContentType,
                contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
                encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

               5.1 2b) If SCi is to be encrypted with a password, make a
               ContentInfo CIi of type EncryptedData.  The encryptedContentInfo
               field of CIi has its contentType field set to data and its
               encryptedContent field set to the encryption of the BER-encoding
               of SCi (note that the tag and length octets shall be present). */
            if ((rc = getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi,
                     &tmpint)) < 0)
            {
                psTraceCrypto("Initial EncryptedContentInfo parse failure\n");
                return rc;
            }
            psAssert(oi == OID_PKCS7_DATA);

            if ((rc = pkcs12import(pool, &p, (int32) (end - p), importPass,
                     ipassLen, &pt, &tmplen)) < 0)
            {
                psTraceIntCrypto("Import failed from AuthSafe %d\n", rc);
                return rc;
            }
            p += rc;

            /* pt is now a BER-encoded SafeContents */
            if ((rc = parseSafeContents(pool, importPass, ipassLen, cert,
                     privKey, pt, tmplen)) < 0)
            {
                psTraceCrypto("Error parsing encrypted safe contents\n");
                psTraceCrypto("Is it possible the password is incorrect?\n");
                psFree(pt, pool);
                return rc;
            }
            psFree(pt, pool);
            p += rc;
        }
        else if (oi == OID_PKCS7_DATA)
        {
            /* Data ::= OCTET STRING */
            if (*p++ != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
            {
                psTraceCrypto("Initial pkcs7 data parse failure\n");
                return PS_PARSE_FAIL;
            }
            if ((rc = getAsnLength(&p, (int32) (end - p), &tmplen)) < 0)
            {
                return PS_PARSE_FAIL;
            }
            if (*p++ != ASN_OCTET_STRING || getAsnLength(&p,
                    (int32) (end - p), &tmplen) < 0)
            {
                return PS_PARSE_FAIL;
            }
            if ((rc = parseSafeContents(pool, importPass, ipassLen, cert,
                     privKey, (unsigned char *) p, tmplen)) < 0)
            {
                psTraceCrypto("Error parsing plaintext safe contents\n");
                /* parseSafeContents() guesses error code according to
                   the contents of the safe. If is guessed PS_AUTH_FAIL,
                   it meant PS_PARSE_FAIL, for plaintext store. */
                if (rc == PS_AUTH_FAIL)
                {
                    rc = PS_PARSE_FAIL;
                }
                return rc;
            }
            p += rc;
        }
        else
        {
            psTraceIntCrypto("Unsupported PKCS7 data type parse %d\n", oi);
            return PS_UNSUPPORTED_FAIL;
        }
    }

    *buf = (unsigned char *) p;
    return PS_SUCCESS;
}

/******************************************************************************/
/*

    MacData ::= SEQUENCE {
        mac DigestInfo,
        macSalt OCTET STRING,
        iterations INTEGER DEFAULT 1
    }
 */
int32 psPkcs12Parse(psPool_t *pool, psX509Cert_t **cert, psPubKey_t *privKey,
    const unsigned char *file, int32 flags, unsigned char *password,
    int32 pLen, unsigned char *macPass, int32 macPassLen)
{
    unsigned char *fileBuf = NULL;
    psSizeL_t fsize;
    psRes_t rc;

    if ((rc = psGetFileBuf(pool, (const char *)file, &fileBuf, &fsize)) < PS_SUCCESS)
    {
        psTraceStrCrypto("Couldn't open PKCS#12 file %s\n", (char *) file);
        return rc;
    }

    rc = psPkcs12ParseMem(pool,
        cert,
        privKey,
        fileBuf,
        fsize,
        flags,
        password,
        pLen,
        macPass,
        macPassLen);

    psFree(fileBuf, pool);
    return rc;
}

int32 psPkcs12ParseMem(psPool_t *pool, psX509Cert_t **cert, psPubKey_t *privKey,
    const unsigned char *buf, int32 bufsize, int32 flags, unsigned char *password,
    int32 pLen, unsigned char *macPass, int32 macPassLen)
{
    psHmacSha1_t hmac;
    const unsigned char *p, *end, *macStart, *macEnd;
    unsigned char *macKey;
    unsigned char iwidePass[128];   /* 63 char password max */
    unsigned char mwidePass[128];
    unsigned char mac[SHA1_HASH_SIZE];
    unsigned char macSalt[20];
    unsigned char digest[SHA1_HASH_SIZE];
    psSize_t tmplen, tmpint;
    uint32 digestLen, macKeyLen;
    int32 i, j, rc, mpassLen, ipassLen, integrity, oi, asnint;

    *cert = NULL;

    p = buf;
    end = p + bufsize;

    /* Begin with a PFX
        PFX ::= SEQUENCE {
        version INTEGER {v3(3)}(v3,...),
        authSafe ContentInfo,
        macData    MacData OPTIONAL } */
    if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
    {
        psTraceCrypto("Initial PKCS#12 parse fail\n");
        goto ERR_PARSE;
    }
    /* Version */
    if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0 || asnint != 3)
    {
        psTraceIntCrypto("Unsupported PKCS#12 version %d\n", asnint);
        rc = PS_UNSUPPORTED_FAIL;
        goto ERR_PARSE;
    }

    /* Content type is the integrity mode (4 of the spec).
        signedData for public-key integrity or data for password integrity */
    if ((integrity = psParseIntegrityMode(&p, (int32) (end - p)))
        < PS_SUCCESS)
    {
        psTraceCrypto("Couldn't determine PKCS#12 integrity\n");
        rc = integrity;
        goto ERR_PARSE;
    }

    /* Passwords are wide BMPString types
        ipass is import password
        mpass is MAC password */
    ipassLen = (pLen * 2) + 2; /* 2 for each char put double 0x0 to terminate */
    if (ipassLen > sizeof iwidePass)
    {
        psTraceCrypto("Password too long.\n");
        rc = PS_AUTH_FAIL;
        goto ERR_PARSE;
    }
    Memset(iwidePass, 0x0, ipassLen);
    for (i = 1, j = 0; i < ipassLen - 1; i += 2, j++)
    {
        iwidePass[i] = password[j];
    }

    /* Content data is an AuthenticatedSafe */
    macStart = p;
    if ((rc = psParseAuthenticatedSafe(pool, cert, privKey, iwidePass, ipassLen,
             (unsigned char **) &p, (int32) (end - p))) < PS_SUCCESS)
    {
        psTraceIntCrypto("PKCS#12 AuthenticatedSafe parse failure %d\n", rc);
        goto ERR_PARSE;
    }
    macEnd = p;

    /* Integrity validation */
    if (integrity == PASSWORD_INTEGRITY)
    {
        mpassLen = (macPassLen * 2) + 2;
        if (mpassLen > sizeof mwidePass)
        {
            psTraceCrypto("Password too long.\n");
            rc = PS_AUTH_FAIL;
            goto ERR_PARSE;
        }
        Memset(mwidePass, 0x0, mpassLen);
        for (i = 1, j = 0; i < mpassLen - 1; i += 2, j++)
        {
            mwidePass[i] = macPass[j];
        }
        /* MacData ::= SEQUENCE {
            mac                 DigestInfo,
            macSalt             OCTET STRING,
            iterations  INTEGER DEFAULT 1
            -- Note: The default is for historical reasons and its use is
            -- deprecated. A higher value, like 1024 is recommended. } */
        if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
        {
            psTraceCrypto("Initial password integrity parse failure\n");
            goto ERR_PARSE;
        }
        /* DigestInfo ::= SEQUENCE {
            digestAlgorithm DigestAlgorithmIdentifier,
            digest          Digest } */
        if ((rc = getAsnSequence(&p, (int32) (end - p), &tmplen)) < 0)
        {
            psTraceCrypto("Sequence password integrity parse failure\n");
            goto ERR_PARSE;
        }
        if ((rc = getAsnAlgorithmIdentifier(&p, (uint32) (end - p),
                 &oi, &tmpint)) < 0)
        {
            psTraceCrypto("Algorithm password integrity parse failure\n");
            goto ERR_PARSE;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
        {
            psTraceCrypto("Octet digest password integrity parse failure\n");
            rc = PS_PARSE_FAIL;
            goto ERR_PARSE;
        }
        Memcpy(digest, p, tmplen);
        p += tmplen;
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &tmplen) < 0)
        {
            psTraceCrypto("Octet macSalt password integrity parse failure\n");
            rc = PS_PARSE_FAIL;
            goto ERR_PARSE;
        }
        if (tmplen > 20)
        {
            psTraceCrypto("macSalt length too long\n");
            rc = PS_PARSE_FAIL;
            goto ERR_PARSE;
        }
        Memcpy(macSalt, p, tmplen);
        p += tmplen;
        /* Iteration count */
        if (p != end)
        {
            if (getAsnInteger(&p, (int32) (end - p), &asnint) < 0)
            {
                psTraceCrypto("Iteration password integrity parse failure\n");
                rc = PS_PARSE_FAIL;
                goto ERR_PARSE;
            }
        }
        else
        {
            asnint = 0;
        }
        psAssert(p == end); /* That's all folks */

        if (oi == OID_SHA1_ALG)
        {
            /* When password integrity mode is used to secure a PFX PDU,
                an SHA-1 HMAC is computed on the BER-encoding of the contents
                of the content field of the authSafe field in the PFX PDU */
            macKeyLen = 20;
            if (pkcs12pbe(pool, mwidePass, mpassLen, macSalt, tmplen,
                    asnint, PKCS12_MAC_ID, &macKey, &macKeyLen) < 0)
            {
                psTraceCrypto("Error generating pkcs12 hmac key\n");
                rc = PS_UNSUPPORTED_FAIL;
                goto ERR_PARSE;
            }
            digestLen = (uint32) (macEnd - macStart);
            psHmacSha1Init(&hmac, macKey, macKeyLen);
            psHmacSha1Update(&hmac, macStart, digestLen);
            psHmacSha1Final(&hmac, mac);
            psFree(macKey, pool);
            if (Memcmp(digest, mac, SHA1_HASH_SIZE) != 0)
            {
                psTraceCrypto("CAUTION: PKCS#12 MAC did not validate\n");
                rc = PS_AUTH_FAIL;
                goto ERR_PARSE;
            }
        }
        else
        {
            psTraceCrypto("PKCS#12 must use SHA1 HMAC validation\n");
            rc = PS_UNSUPPORTED_FAIL;
            goto ERR_PARSE;
        }

    }
    rc = PS_SUCCESS;
ERR_PARSE:
    memset_s(iwidePass, sizeof(iwidePass), 0x0, sizeof(iwidePass));
    memset_s(mwidePass, sizeof(mwidePass), 0x0, sizeof(mwidePass));
    return rc;
}

#   endif /* USE_PKCS12 */
#  endif  /* MATRIX_USE_FILE_SYSTEM */

# endif   /* USE_PKCS8 */

#endif  /* USE_PRIVATE_KEY_PARSING */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_PKCS5
# ifdef USE_PBKDF1
/******************************************************************************/
/*
   Generate a key given a password and salt value.
   PKCS#5 2.0 PBKDF1 key derivation format with MD5 and count == 1 per:
   http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html

   This key is compatible with the algorithm used by OpenSSL to encrypt keys
   generated with 'openssl genrsa'.  If other encryption formats are used
   (for example PBKDF2), or an iteration count != 1 is used, they are not
   compatible with this simple implementation.  OpenSSL provides many options
   for converting key formats to the one used here.

   A 3DES key is 24 bytes long, to generate it with this algorithm,
   we md5 hash the password and salt for the first 16 bytes.  We then
   hash these first 16 bytes with the password and salt again, generating
   another 16 bytes.  We take the first 16 bytes and 8 of the second 16 to
   form the 24 byte key.

   salt is assumed to point to 8 bytes of data
   key is assumed to point to 24 bytes of data
 */
int32_t psPkcs5Pbkdf1(unsigned char *pass, uint32 passlen, unsigned char *salt,
    int32 iter, unsigned char *key)
{
    int32_t rc;
    psDigestContext_t md;
    unsigned char md5[MD5_HASH_SIZE];

    psAssert(iter == 1);

    rc = psMd5Init(&md.u.md5);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("psMd5Init failed. Please ensure non-FIPS mode.\n");
        return rc;
    }
    psMd5Update(&md.u.md5, pass, passlen);
    psMd5Update(&md.u.md5, salt, 8);
    psMd5Final(&md.u.md5, md5);
    Memcpy(key, md5, MD5_HASH_SIZE);

    rc = psMd5Init(&md.u.md5);
    if (rc != PS_SUCCESS)
    {
        psTraceCrypto("psMd5Init failed. Please ensure non-FIPS mode.\n");
        return rc;
    }

    psMd5Update(&md.u.md5, md5, MD5_HASH_SIZE);
    psMd5Update(&md.u.md5, pass, passlen);
    psMd5Update(&md.u.md5, salt, 8);
    psMd5Final(&md.u.md5, md5);
    Memcpy(key + MD5_HASH_SIZE, md5, 24 - MD5_HASH_SIZE);

    memset_s(md5, MD5_HASH_SIZE, 0x0, MD5_HASH_SIZE);
    memset_s(&md, sizeof(psDigestContext_t), 0x0, sizeof(psDigestContext_t));
    return PS_SUCCESS;
}
# endif /* USE_PBKDF1 */

# if defined(USE_HMAC_SHA1)
/******************************************************************************/
/*
    Generate a key given a password, salt and iteration value.
    PKCS#5 2.0 PBKDF2 key derivation format with HMAC-SHA per:
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html

    Given a password, a salt, and an iteration count (rounds), generate a
    key suitable for encrypting data with 3DES, AES, etc.
    key should point to storage as large as kLen
 */
void psPkcs5Pbkdf2(unsigned char *password, uint32 pLen,
    unsigned char *salt, uint32 sLen, int32 rounds,
    unsigned char *key, uint32 kLen)
{
    int32 itts;
    uint32 blkno;
    unsigned long stored, left, i;
    unsigned char buf[2][SHA1_HASH_SIZE];
    psHmacSha1_t hmac;

    psAssert(password && salt && key && kLen);

    left   = kLen;
    blkno  = 1;
    stored = 0;
    while (left != 0)
    {
        /* process block number blkno */
        Memset(buf[0], 0x0, SHA1_HASH_SIZE * 2);

        /* store current block number and increment for next pass */
        STORE32H(blkno, buf[1]);
        ++blkno;

        /* get PRF(P, S||int(blkno)) */
        psHmacSha1Init(&hmac, password, pLen);
        psHmacSha1Update(&hmac, salt, sLen);
        psHmacSha1Update(&hmac, buf[1], 4);
        psHmacSha1Final(&hmac, buf[0]);

        /* now compute repeated and XOR it in buf[1] */
        Memcpy(buf[1], buf[0], SHA1_HASH_SIZE);
        for (itts = 1; itts < rounds; ++itts)
        {
            psHmacSha1Init(&hmac, password, pLen);
            psHmacSha1Update(&hmac, buf[0], SHA1_HASH_SIZE);
            psHmacSha1Final(&hmac, buf[0]);
            for (i = 0; i < SHA1_HASH_SIZE; i++)
            {
                buf[1][i] ^= buf[0][i];
            }
        }
        /* now emit upto x bytes of buf[1] to output */
        for (i = 0; i < SHA1_HASH_SIZE && left != 0; ++i)
        {
            key[stored++] = buf[1][i];
            --left;
        }
    }

    memset_s(buf, SHA1_HASH_SIZE * 2, 0x0, SHA1_HASH_SIZE * 2);
    memset_s(&hmac, sizeof(psHmacSha1_t), 0x0, sizeof(psHmacSha1_t));
}
# endif /* USE_HMAC && USE_SHA1 */
#endif  /* USE_PKCS5 */

#if defined(USE_DH) && defined(MATRIX_USE_FILE_SYSTEM)
/******************************************************************************/
/**
    Extract Diffie-Hellman parameters from a PEM encoded file.
    This API decodes the PEM format and passes the ASN.1 encoded parameters
    to psPkcs3ParseDhParamBin() to parse the ASN.1.

    @param pool Memory pool
    @param[in] fileName File name of PEM encoded ASN.1 to load.
    @param[in,out] params Allocated parameter structure to receive parsed
        params.
    @return < on error.
 */
int32_t psPkcs3ParseDhParamFile(psPool_t *pool, const char *fileName, psDhParams_t *params)
{
    unsigned char *pemOut, *p;
    char *dhFileBuf, *start, *end;
    psSize_t baseLen, pemOutLen;
    psSizeL_t dhFileLen;
    psRes_t rc;

    if (!params || !fileName)
    {
        return PS_ARG_FAIL;
    }
    /* This is part of key assignment at startup.  Base pool is fine here */
    if ((rc = psGetFileBuf(pool, fileName,
             (unsigned char **) &dhFileBuf, &dhFileLen)) < 0)
    {
        return rc;
    }
    /* Set end to end of file buffer */
    end = dhFileBuf + dhFileLen;
    /* Set start to start of token */
    if ((start = Strstr(dhFileBuf, "-----BEGIN DH PARAMETERS-----")) == NULL)
    {
        psTraceStrCrypto("Error parsing dh file buffer header: %s\n", fileName);
        psFree(dhFileBuf, pool);
        return PS_PARSE_FAIL;
    }
    /* Move start to start of PEM data, skipping CR/LF */
    start += 29; /* Strlen("-----BEGIN DH PARAMETERS-----"); */
    while (start < end && (*start == '\x0d' || *start == '\x0a'))
    {
        start++;
    }
    /* Set end to end token */
    if ((end = Strstr(start, "-----END DH PARAMETERS-----")) == NULL)
    {
        psTraceStrCrypto("Error parsing dh file buffer footer: %s\n", fileName);
        psFree(dhFileBuf, pool);
        return PS_PARSE_FAIL;
    }
    baseLen = (uint16_t) (end - start);

    p = NULL;
    p = pemOut = psMalloc(pool, baseLen);
    if (p == NULL)
    {
        psError("Memory allocation error in psPkcs3ParseDhParamFile\n");
        psFree(dhFileBuf, pool);
        return PS_MEM_FAIL;
    }

#ifdef USE_BASE64_DECODE
    pemOutLen = baseLen;
    if (psBase64decode((unsigned char *) start, baseLen, p, &pemOutLen) != 0)
    {
        psFree(dhFileBuf, pool);
        psFree(pemOut, pool);
        return PS_PARSE_FAIL;
    }
    psFree(dhFileBuf, pool);
#else
    pemOutLen = baseLen;
    memcpy(pemOut, start, pemOutLen);
#endif

    if ((rc = psPkcs3ParseDhParamBin(pool, p, pemOutLen, params)) < 0)
    {
        psFree(pemOut, pool);
        return rc;
    }
    psFree(pemOut, pool);
    return 0;
}
#endif /* USE_DH && MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/

/******************************************************************************/
#if defined(USE_PKCS1_OAEP) || defined(USE_PKCS1_PSS)
/*
    The reason we weren't able to create a callback structure for the hash
    routines was because of the Mac relocation build errors related to
    the register usage when assembly code is used in pstm
 */
/******************************************************************************/
/*
    Perform PKCS #1 Mask Generation Function (internal)
    pool                Memory pool
    seed        The seed for MGF1
    seedlen     The length of the seed
    hash_idx    The index of the hash desired
    mask        [out] The destination
    masklen     The length of the mask desired
    return 0 if successful
 */
static int32 pkcs_1_mgf1(psPool_t *pool, const unsigned char *seed,
    unsigned long seedlen, int32 hash_idx, unsigned char *mask,
    unsigned long masklen)
{
    unsigned long hLen, x;
    uint32 counter;
    psDigestContext_t md;
    unsigned char *buf;
    int32_t rc;
    psResSize_t hLenTmp;

    if ((seed == NULL) || (mask == NULL))
    {
        return -1;
    }
    hLen = 0;

    /* Get hash output size. */
    hLenTmp = psPssHashAlgToHashLen(hash_idx);
    if (hLenTmp < 0)
    {
        psTraceIntCrypto("Unsupported MGF hash alg: %d\n",
                         hash_idx);
        return PS_UNSUPPORTED_FAIL;
    }
    hLen = hLenTmp;

    buf = psMalloc(pool, hLen);
    if (buf == NULL)
    {
        psTraceCrypto("Memory allocation error in MGF\n");
        return -1;
    }
/*
    Start counter
 */
    counter = 0;

    while (masklen > 0)
    {
        /* handle counter */
        STORE32H(counter, buf);
        ++counter;

/*
        Get hash of seed || counter
 */
        switch (hash_idx)
        {
# ifdef USE_SHA1
        case PKCS1_SHA1_ID:
            psSha1Init(&md.u.sha1);
            psSha1Update(&md.u.sha1, seed, seedlen);
            psSha1Update(&md.u.sha1, buf, 4);
            psSha1Final(&md.u.sha1, buf);
            break;
# endif
# ifdef USE_MD5
        case PKCS1_MD5_ID:
            psMd5Init(&md.u.md5);
            psMd5Update(&md.u.md5, seed, seedlen);
            psMd5Update(&md.u.md5, buf, 4);
            psMd5Final(&md.u.md5, buf);
            break;
# endif     /* USE_MD5 */
# ifdef USE_SHA256
        case PKCS1_SHA256_ID:
            psSha256Init(&md.u.sha256);
            psSha256Update(&md.u.sha256, seed, seedlen);
            psSha256Update(&md.u.sha256, buf, 4);
            psSha256Final(&md.u.sha256, buf);
            break;
# endif
# ifdef USE_SHA384
        case PKCS1_SHA384_ID:
            psSha384Init(&md.u.sha384);
            psSha384Update(&md.u.sha384, seed, seedlen);
            psSha384Update(&md.u.sha384, buf, 4);
            psSha384Final(&md.u.sha384, buf);
            break;
# endif
# ifdef USE_SHA512
        case PKCS1_SHA512_ID:
            psSha512Init(&md.u.sha512);
            psSha512Update(&md.u.sha512, seed, seedlen);
            psSha512Update(&md.u.sha512, buf, 4);
            psSha512Final(&md.u.sha512, buf);
            break;
# endif
        default:
            psTraceCrypto("Unknown PSS MFG hash function\n");
            rc = PS_UNSUPPORTED_FAIL;
            goto out_fail;
        }

        /* store it */
        for (x = 0; x < hLen && masklen > 0; x++, masklen--)
        {
            *mask++ = buf[x];
        }
    }

    rc = PS_SUCCESS;

out_fail:
    psFree(buf, pool);
    return rc;
}
#endif /* defined(USE_PKCS1_OAEP) || defined(USE_PKCS1_PSS) */


#ifdef USE_PKCS1_OAEP
/******************************************************************************/
/*
    PKCS #1 v2.00 OAEP encode
    pool                        Memory pool
    msg             The data to encode
    msglen          The length of the data to encode (octets)
    lparam          A session or system parameter (can be NULL)
    lparamlen       The length of the lparam data
    seed                        Reserved for vector testing.  Should be NULL
    seedLen                     Reserved for vector testing.  Should be 0
    modulus_bitlen  The bit length of the RSA modulus
    hash_idx        The index of the hash desired (see psHashList table above)
    out             [out] The destination for the encoded data
    outlen          [in/out] The max size and resulting size of the encoded data

    return 0 if successful, -1 on failure
 */
int32 psPkcs1OaepEncode(psPool_t *pool, const unsigned char *msg, uint32 msglen,
    const unsigned char *lparam, uint32 lparamlen,
    unsigned char *seed, uint32 seedLen,
    uint32 modulus_bitlen, int32 hash_idx,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char *DB, *lseed, *mask;
    uint32 hLen, x, y, modulus_len;
    int32 err;
    psDigestContext_t md;

    if ((msg == NULL) || (out == NULL) || (outlen == NULL) || (hash_idx < 0))
    {
        psTraceStrCrypto("Bad parameter to OAEP encode\n", NULL);
        return PS_ARG_FAIL;
    }
/*
    Verify hash routines
 */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
# ifdef USE_MD5
        hLen = MD5_HASH_SIZE;
# else
        psTraceCrypto("MD5 not supported in this build.");
        psTraceCrypto(" Please enable USE_MD5\n");
        return PS_UNSUPPORTED_FAIL;
# endif /* USE_MD5 */
    }
    else
    {
        psTraceStrCrypto("Bad hash index to OAEP encode\n", NULL);
        return PS_ARG_FAIL;
    }
/*
    Seed should be generated randomly below but this helps for test vectors
 */
    if (seed != NULL && seedLen != hLen)
    {
        psTraceIntCrypto("Seed must be length of %d\n", hLen);
        return PS_ARG_FAIL;
    }

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

/*
    Test message size
 */
    if ((2 * hLen >= (modulus_len - 2)) || (msglen > (modulus_len - 2 * hLen - 2)))
    {
        psTraceStrCrypto("Bad message size to OAEP encode\n", NULL);
        return PS_LIMIT_FAIL;
    }

/*
    Allocate ram for DB/mask/salt of size modulus_len
 */
    lseed = NULL;
    DB   = psMalloc(pool, modulus_len);
    mask = psMalloc(pool, modulus_len);
    if (DB == NULL || mask == NULL)
    {
        if (DB != NULL)
        {
            psFree(DB, pool);
        }
        if (mask != NULL)
        {
            psFree(mask, pool);
        }
        psTraceCrypto("Memory allocation error in OAEP encode\n");
        return PS_MEM_FAIL;
    }

/*
    Create lhash for DB block format:

    DB == lhash || PS || 0x01 || M, PS == k - mlen - 2hlen - 2 zeroes
 */
    x = modulus_len;

    if (lparam != NULL)
    {
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.u.sha1);
            psSha1Update(&md.u.sha1, lparam, lparamlen);
            psSha1Final(&md.u.sha1, DB);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.u.md5);
            psMd5Update(&md.u.md5, lparam, lparamlen);
            psMd5Final(&md.u.md5, DB);
        }
# endif /* USE_MD5 */
    }
    else
    {
        /* can't pass hash a NULL so use DB with zero length */
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.u.sha1);
            psSha1Update(&md.u.sha1, DB, 0);
            psSha1Final(&md.u.sha1, DB);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.u.md5);
            psMd5Update(&md.u.md5, DB, 0);
            psMd5Final(&md.u.md5, DB);
        }
# endif /* USE_MD5 */
    }

/*
    Append PS then 0x01 (to lhash)
 */
    x = hLen;
    y = modulus_len - msglen - 2 * hLen - 2;
    Memset(DB + x, 0, y);
    x += y;

    DB[x++] = 0x01;

/*
    Message (length = msglen)
 */
    Memcpy(DB + x, msg, msglen);
    x += msglen;

/*
    Use psGetPrngLocked to choose a random seed (if not provided)
 */
    if (seed != NULL)
    {
        lseed = seed;
    }
    else
    {
        lseed = psMalloc(pool, hLen);
        if (lseed == NULL)
        {
            err = PS_MEM_FAIL;
            goto LBL_ERR;
        }
        if (psGetPrngLocked(lseed, hLen, NULL) != (int32) hLen)
        {
            psTraceCrypto("psGetPrngLocked fail in OAEP encode\n");
            err = PS_PLATFORM_FAIL;
            goto LBL_ERR;
        }
    }

/*
    Compute MGF1 of seed (k - hlen - 1)
 */
    if ((err = pkcs_1_mgf1(pool, lseed, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        psTraceStrCrypto("MGF for seed failed in OAEP encode\n", NULL);
        goto LBL_ERR;
    }

/*
    xor against DB
 */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

/*
    Compute MGF1 of maskedDB (hLen)
 */
    if ((err = pkcs_1_mgf1(pool, DB, modulus_len - hLen - 1, hash_idx,
             mask, hLen)) != PS_SUCCESS)
    {
        psTraceStrCrypto("MGF for DB failed in OAEP encode\n", NULL);
        goto LBL_ERR;
    }

/*
    XOR against seed
 */
    for (y = 0; y < hLen; y++)
    {
        lseed[y] ^= mask[y];
    }

/*
    Create string of length modulus_len
 */
    if (*outlen < modulus_len)
    {
        psTraceStrCrypto("Bad outlen in OAEP encode\n", NULL);
        err = -1;
        goto LBL_ERR;
    }

/*
    Start output which is 0x00 || maskedSeed || maskedDB
 */
    x = 0;
    out[x++] = 0x00;
    Memcpy(out + x, lseed, hLen);
    x += hLen;
    Memcpy(out + x, DB, modulus_len - hLen - 1);
    x += modulus_len - hLen - 1;

    *outlen = x;

    err = PS_SUCCESS;

LBL_ERR:
    if (seed == NULL)
    {
        psFree(lseed, pool);
    }
    psFree(mask, pool);
    psFree(DB, pool);

    return err;
}

/******************************************************************************/
/*
    PKCS #1 v2.00 OAEP decode
    pool                         Memory pool
    msg              The encoded data to decode
    msglen           The length of the encoded data (octets)
    lparam           The session or system data (can be NULL)
    lparamlen        The length of the lparam
    modulus_bitlen   The bit length of the RSA modulus
    hash_idx         The index of the hash desired
    out              [out] Destination of decoding
    outlen           [in/out] The max size and resulting size of the decoding

    return 0 if successful
 */
int32 psPkcs1OaepDecode(psPool_t *pool, const unsigned char *msg, uint32 msglen,
    const unsigned char *lparam, uint32 lparamlen,
    uint32 modulus_bitlen, int32 hash_idx,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char *DB, *seed, *mask;
    uint32 hLen, x, y, modulus_len;
    int32 err;
    psDigestContext_t md;

    if ((msg == NULL) || (out == NULL) || (outlen == NULL) || (hash_idx < 0))
    {
        psTraceCrypto("Bad parameter to OAEP decode\n");
        return PS_ARG_FAIL;
    }
/*
    Verify hash routines
 */
    if (hash_idx == PKCS1_SHA1_ID)
    {
        hLen = SHA1_HASH_SIZE;
    }
    else if (hash_idx == PKCS1_MD5_ID)
    {
# ifdef USE_MD5
        hLen = MD5_HASH_SIZE;
# else
        psTraceCrypto("MD5 not supported in this build.");
        psTraceCrypto(" Please enable USE_MD5\n");
        return PS_UNSUPPORTED_FAIL;
# endif /* USE_MD5 */
    }
    else
    {
        psTraceStrCrypto("Bad hash index to OAEP decode\n", NULL);
        return PS_ARG_FAIL;
    }

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

/*
    Test hash/message size
 */
    if ((2 * hLen >= (modulus_len - 2)) || (msglen != modulus_len))
    {
        psTraceCrypto("Message/Modulus length mismatch in OAEP decode\n");
        return PS_LIMIT_FAIL;
    }

/*
    Allocate ram for DB/mask/salt of size modulus_len
 */
    DB   = psMalloc(pool, modulus_len);
    mask = psMalloc(pool, modulus_len);
    seed = psMalloc(pool, hLen);
    if (DB == NULL || mask == NULL || seed == NULL)
    {
        if (DB != NULL)
        {
            psFree(DB, pool);
        }
        if (mask != NULL)
        {
            psFree(mask, pool);
        }
        if (seed != NULL)
        {
            psFree(seed, pool);
        }
        psTraceCrypto("Memory allocation error in OAEP decode\n");
        return -1;
    }

/*
    It's now in the form

    0x00  || maskedseed || maskedDB

    1    ||   hLen     ||  modulus_len - hLen - 1
 */
    if (msg[0] != 0x00)
    {
        psTraceCrypto("Message format error in OAEP decode\n");
        err = PS_FAILURE;
        goto LBL_ERR;
    }

/*
    Now read the masked seed
 */
    x = 1;
    Memcpy(seed, msg + x, hLen);
    x += hLen;

/*
    Now read the masked DB
 */
    Memcpy(DB, msg + x, modulus_len - hLen - 1);
    x += modulus_len - hLen - 1;

/*
    Compute MGF1 of maskedDB (hLen)
 */
    if ((err = pkcs_1_mgf1(pool, DB, modulus_len - hLen - 1, hash_idx,
             mask, hLen)) != PS_SUCCESS)
    {
        psTraceCrypto("MGF for DB failed in OAEP decode\n");
        goto LBL_ERR;
    }

/*
    XOR against seed
 */
    for (y = 0; y < hLen; y++)
    {
        seed[y] ^= mask[y];
    }

/*
    Compute MGF1 of seed (k - hlen - 1)
 */
    if ((err = pkcs_1_mgf1(pool, seed, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        psTraceCrypto("MGF for seed failed in OAEP decode\n");
        goto LBL_ERR;
    }

/*
    xor against DB
 */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

/*
    compute lhash and store it in seed [reuse temps!]

    DB == lhash || PS || 0x01 || M, PS == k - mlen - 2hlen - 2 zeroes
 */
    x = modulus_len;

    if (lparam != NULL)
    {
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.u.sha1);
            psSha1Update(&md.u.sha1, lparam, lparamlen);
            psSha1Final(&md.u.sha1, seed);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.u.md5);
            psMd5Update(&md.u.md5, lparam, lparamlen);
            psMd5Final(&md.u.md5, seed);
        }
# endif /* USE_MD5 */
    }
    else
    {
        /* can't pass hash routine a NULL so use DB with zero length */
        if (hash_idx == PKCS1_SHA1_ID)
        {
            psSha1Init(&md.u.sha1);
            psSha1Update(&md.u.sha1, DB, 0);
            psSha1Final(&md.u.sha1, seed);
        }
# ifdef USE_MD5
        else
        {
            psMd5Init(&md.u.md5);
            psMd5Update(&md.u.md5, DB, 0);
            psMd5Final(&md.u.md5, seed);
        }
# endif /* USE_MD5 */
    }

/*
    Compare the lhash'es
 */
    if (Memcmp(seed, DB, hLen) != 0)
    {
        psTraceCrypto("Seed/DB mismatch in OAEP decode\n");
        err = -1;
        goto LBL_ERR;
    }

/*
    Now zeroes before a 0x01
 */
    for (x = hLen; x < (modulus_len - hLen - 1) && DB[x] == 0x00; x++)
    {
        /* step... */
    }

/*
    Error out if wasn't 0x01
 */
    if (x == (modulus_len - hLen - 1) || DB[x] != 0x01)
    {
        psTraceCrypto("DB format error in OAEP decode\n");
        err = -1;
        goto LBL_ERR;
    }

/*
    Rest is the message (and skip 0x01)
 */
    if ((modulus_len - hLen - 1) - ++x > *outlen)
    {
        psTraceCrypto("Bad outlen in OAEP decode\n");
        err = -1;
        goto LBL_ERR;
    }

/*
    Copy message
 */
    *outlen = (modulus_len - hLen - 1) - x;
    Memcpy(out, DB + x, modulus_len - hLen - 1 - x);
    x += modulus_len - hLen - 1;

    err = PS_SUCCESS;
LBL_ERR:

    psFree(seed, pool);
    psFree(mask, pool);
    psFree(DB, pool);

    return err;
}
#endif /* USE_PKCS1_OAEP */
/******************************************************************************/

#ifdef USE_PKCS1_PSS
/******************************************************************************/
/*
    PKCS #1 v2.00 Signature Encoding
    @param msghash          The hash to encode
    @param msghashlen       The length of the hash (octets)
    @param tsalt            The salt to use. Pass NULL to use a random
                            salt (recommended).
    @param saltlen          The length of tsalt or the desired random
                            salt (octets).
    @param hash_idx         The index of the hash desired
    @param modulus_bitlen   The bit length of the RSA modulus
    @param out              [out] The destination of the encoding
    @param outlen           [in/out] The max size and resulting size of the encoded data
    @return CRYPT_OK if successful
 */
int32 psPkcs1PssEncode(psPool_t *pool, const unsigned char *msghash,
    uint32 msghashlen, unsigned char *tsalt, uint32 saltlen,
    int32 hash_idx, uint32 modulus_bitlen, unsigned char *out,
    psSize_t *outlen)
{
    unsigned char *DB, *mask, *salt, *hash;
    uint32 x, y, hLen, modulus_len;
    int32 err;
    psDigestContext_t md;
    psResSize_t hLenTmp;

    if ((msghash == NULL) || (out == NULL) || (outlen == NULL))
    {
        psTraceCrypto("Bad parameter to PSS encode\n");
        return PS_ARG_FAIL;
    }

    /* Get hash output size. */
    hLenTmp = psPssHashAlgToHashLen(hash_idx);
    if (hLenTmp < 0)
    {
        psTraceIntCrypto("Unsupported MGF hash alg: %d\n",
                         hash_idx);
        return PS_UNSUPPORTED_FAIL;
    }
    hLen = hLenTmp;

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

    /* check sizes */
    if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2))
    {
        psTraceCrypto("Bad saltlen or modulus len to PSS encode\n");
        return PS_ARG_FAIL;
    }

    /* allocate ram for DB/mask/salt/hash of size modulus_len */
    err = PS_MEM_FAIL;
    if ((DB = psMalloc(pool, modulus_len)) == NULL)
    {
        return err;
    }
    Memset(DB, 0x0, modulus_len);
    if ((mask = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_DB;
    }
    Memset(mask, 0x0, modulus_len);
    if ((salt = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_MASK;
    }
    Memset(salt, 0x0, modulus_len);
    if ((hash = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_SALT;
    }
    Memset(hash, 0x0, modulus_len);

    /* generate random salt */
    if (saltlen > 0)
    {
        if (tsalt != NULL)
        {
            Memcpy(salt, tsalt, saltlen);
        }
        else
        {
            if (psGetPrngLocked(salt, saltlen, NULL) != (int32) saltlen)
            {
                err = PS_PLATFORM_FAIL;
                goto LBL_ERR;
            }
        }
    }

    /* M = (eight) 0x00 || msghash || salt, hash = H(M) */
    switch (hash_idx)
    {
# ifdef USE_SHA1
    case PKCS1_SHA1_ID:
        psSha1Init(&md.u.sha1);
        psSha1Update(&md.u.sha1, DB, 8); /* 8 0's */
        psSha1Update(&md.u.sha1, msghash, msghashlen);
        psSha1Update(&md.u.sha1, salt, saltlen);
        psSha1Final(&md.u.sha1, hash);
        break;
# endif
# ifdef USE_MD5
    case PKCS1_MD5_ID:
        psMd5Init(&md.u.md5);
        psMd5Update(&md.u.md5, DB, 8); /* 8 0's */
        psMd5Update(&md.u.md5, msghash, msghashlen);
        psMd5Update(&md.u.md5, salt, saltlen);
        psMd5Final(&md.u.md5, hash);
        break;
# endif /* USE_MD5 */
# ifdef USE_SHA256
    case PKCS1_SHA256_ID:
        psSha256Init(&md.u.sha256);
        psSha256Update(&md.u.sha256, DB, 8); /* 8 0's */
        psSha256Update(&md.u.sha256, msghash, msghashlen);
        psSha256Update(&md.u.sha256, salt, saltlen);
        psSha256Final(&md.u.sha256, hash);
        break;
# endif
# ifdef USE_SHA384
    case PKCS1_SHA384_ID:
        psSha384Init(&md.u.sha384);
        psSha384Update(&md.u.sha384, DB, 8); /* 8 0's */
        psSha384Update(&md.u.sha384, msghash, msghashlen);
        psSha384Update(&md.u.sha384, salt, saltlen);
        psSha384Final(&md.u.sha384, hash);
        break;
# endif
# ifdef USE_SHA512
    case PKCS1_SHA512_ID:
        psSha512Init(&md.u.sha512);
        psSha512Update(&md.u.sha512, DB, 8); /* 8 0's */
        psSha512Update(&md.u.sha512, msghash, msghashlen);
        psSha512Update(&md.u.sha512, salt, saltlen);
        psSha512Final(&md.u.sha512, hash);
        break;
# endif
    default:
        psTraceIntCrypto("Unsupported PSS MFG alg: %d\n", hash_idx);
        err = PS_UNSUPPORTED_FAIL;
        goto LBL_ERR;
    }

    /* generate DB = PS || 0x01 || salt
        PS == modulus_len - saltlen - hLen - 2 zero bytes */
    x = 0;
    Memset(DB + x, 0, modulus_len - saltlen - hLen - 2);
    x += modulus_len - saltlen - hLen - 2;
    DB[x++] = 0x01;
    Memcpy(DB + x, salt, saltlen);
    x += saltlen;

    /* generate mask of length modulus_len - hLen - 1 from hash */
    if ((err = pkcs_1_mgf1(pool, hash, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        goto LBL_ERR;
    }

    /* xor against DB */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

    /* output is DB || hash || 0xBC */
    if (*outlen < modulus_len)
    {
        *outlen = modulus_len;
        err = PS_LIMIT_FAIL;
        goto LBL_ERR;
    }

    /* DB len = modulus_len - hLen - 1 */
    y = 0;
    Memcpy(out + y, DB, modulus_len - hLen - 1);
    y += modulus_len - hLen - 1;

    /* hash */
    Memcpy(out + y, hash, hLen);
    y += hLen;

    /* 0xBC */
    out[y] = 0xBC;

    /* now clear the 8*modulus_len - modulus_bitlen most significant bits */
    out[0] &= 0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1));

    /* store output size */
    *outlen = modulus_len;
    err = PS_SUCCESS;

LBL_ERR: psFree(hash, pool);
LBL_SALT: psFree(salt, pool);
LBL_MASK: psFree(mask, pool);
LBL_DB: psFree(DB, pool);

    return err;
}

/******************************************************************************/
/**
    PKCS #1 v2.00 PSS decode
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  saltlen         The length of the salt used (octets)
   @param  hash_idx        The index of the hash desired
   @param  modulus_bitlen  The bit length of the RSA modulus
   @param  res             [out] The result of the comparison, 1==valid, 0==invalid

 */
int32 psPkcs1PssDecode(psPool_t *pool, const unsigned char *msghash,
    uint32 msghashlen, const unsigned char *sig, uint32 siglen,
    uint32 saltlen, int32 hash_idx, uint32 modulus_bitlen, int32 *res)
{
    unsigned char *DB, *mask, *salt, *hash;
    uint32 x, y, hLen, modulus_len;
    int32 err;
    psDigestContext_t md;
    psResSize_t hLenTmp;

    if ((msghash == NULL) || (res == NULL))
    {
        psTraceCrypto("Bad parameters to psPkcs1PssDecode\n");
        return PS_ARG_FAIL;
    }

    /* default to invalid */
    *res = 0;

    /* Get hash output size. */
    hLenTmp = psPssHashAlgToHashLen(hash_idx);
    if (hLenTmp < 0)
    {
        psTraceIntCrypto("Unsupported MGF hash alg: %d\n",
                         hash_idx);
        return PS_UNSUPPORTED_FAIL;
    }
    hLen = hLenTmp;

    modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

    /* check sizes */
    if ((saltlen > modulus_len) ||
        (modulus_len < hLen + saltlen + 2) || (siglen != modulus_len))
    {
        psTraceCrypto("Bad saltlen or modulus len to PSS decode\n");
        return PS_ARG_FAIL;
    }

    /* allocate ram for DB/mask/salt/hash of size modulus_len */
    err = PS_MEM_FAIL;
    if ((DB = psMalloc(pool, modulus_len)) == NULL)
    {
        return err;
    }
    Memset(DB, 0x0, modulus_len);
    if ((mask = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_DB;
    }
    Memset(mask, 0x0, modulus_len);
    if ((salt = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_MASK;
    }
    Memset(salt, 0x0, modulus_len);
    if ((hash = psMalloc(pool, modulus_len)) == NULL)
    {
        goto LBL_SALT;
    }
    Memset(hash, 0x0, modulus_len);

    /* ensure the 0xBC byte */
    if (sig[siglen - 1] != 0xBC)
    {
        err = PS_FAILURE;
        goto LBL_ERR;
    }

    /* copy out the DB */
    x = 0;
    Memcpy(DB, sig + x, modulus_len - hLen - 1);
    x += modulus_len - hLen - 1;

    /* copy out the hash */
    Memcpy(hash, sig + x, hLen);
    x += hLen;

    /* check the MSB */
    if ((sig[0] & ~(0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1)))) != 0)
    {
        err = PS_FAILURE;
        goto LBL_ERR;
    }

    /* generate mask of length modulus_len - hLen - 1 from hash */
    if ((err = pkcs_1_mgf1(pool, hash, hLen, hash_idx, mask,
             modulus_len - hLen - 1)) != PS_SUCCESS)
    {
        goto LBL_ERR;
    }

    /* xor against DB */
    for (y = 0; y < (modulus_len - hLen - 1); y++)
    {
        DB[y] ^= mask[y];
    }

    /* now clear the first byte [make sure smaller than modulus] */
    DB[0] &= 0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1));

    /* DB = PS || 0x01 || salt,
        PS == modulus_len - saltlen - hLen - 2 zero bytes */

    /* check for zeroes and 0x01 */
    for (x = 0; x < modulus_len - saltlen - hLen - 2; x++)
    {
        if (DB[x] != 0x00)
        {
            err = PS_FAILURE;
            goto LBL_ERR;
        }
    }

    /* check for the 0x01 */
    if (DB[x++] != 0x01)
    {
        err = PS_FAILURE;
        goto LBL_ERR;
    }

    /* M = (eight) 0x00 || msghash || salt, mask = H(M) */
    switch (hash_idx)
    {
# ifdef USE_SHA1
    case PKCS1_SHA1_ID:
        psSha1Init(&md.u.sha1);
        Memset(mask, 0x0, 8);
        psSha1Update(&md.u.sha1, mask, 8);
        psSha1Update(&md.u.sha1, msghash, msghashlen);
        psSha1Update(&md.u.sha1, DB + x, saltlen);
        psSha1Final(&md.u.sha1, mask);
        break;
# endif
# ifdef USE_MD5
    case PKCS1_MD5_ID:
        psMd5Init(&md.u.md5);
        Memset(mask, 0x0, 8);
        psMd5Update(&md.u.md5, mask, 8);
        psMd5Update(&md.u.md5, msghash, msghashlen);
        psMd5Update(&md.u.md5, DB + x, saltlen);
        psMd5Final(&md.u.md5, mask);
        break;
# endif /* USE_MD5 */
# ifdef USE_SHA256
    case PKCS1_SHA256_ID:
        psSha256Init(&md.u.sha256);
        Memset(mask, 0x0, 8);
        psSha256Update(&md.u.sha256, mask, 8);
        psSha256Update(&md.u.sha256, msghash, msghashlen);
        psSha256Update(&md.u.sha256, DB + x, saltlen);
        psSha256Final(&md.u.sha256, mask);
        break;
# endif
# ifdef USE_SHA384
    case PKCS1_SHA384_ID:
        psSha384Init(&md.u.sha384);
        Memset(mask, 0x0, 8);
        psSha384Update(&md.u.sha384, mask, 8);
        psSha384Update(&md.u.sha384, msghash, msghashlen);
        psSha384Update(&md.u.sha384, DB + x, saltlen);
        psSha384Final(&md.u.sha384, mask);
        break;
# endif
# ifdef USE_SHA512
    case PKCS1_SHA512_ID:
        psSha512Init(&md.u.sha512);
        Memset(mask, 0x0, 8);
        psSha512Update(&md.u.sha512, mask, 8);
        psSha512Update(&md.u.sha512, msghash, msghashlen);
        psSha512Update(&md.u.sha512, DB + x, saltlen);
        psSha512Final(&md.u.sha512, mask);
        break;
# endif
    default:
        psTraceIntCrypto("Unsupported PSS MFG hash alg: %d\n",
                hash_idx);
        err = PS_UNSUPPORTED_FAIL;
        goto LBL_ERR;
    }

    /* mask == hash means valid signature */
    if (Memcmp(mask, hash, hLen) == 0)
    {
        *res = 1;
    }

    err = PS_SUCCESS;

LBL_ERR:
    psFree(hash, pool);
LBL_SALT:
    psFree(salt, pool);
LBL_MASK:
    psFree(mask, pool);
LBL_DB:
    psFree(DB, pool);
    memset_s(&md, sizeof(psDigestContext_t), 0x0, sizeof(psDigestContext_t));

    return err;
}
#endif /* USE_PKCS1_PSS */

#    if defined(USE_PKCS5) && defined(USE_PBKDF1)
/******************************************************************************/
/*
    The standard is to write the number of pad bytes as the value for each
    pad byte
 */
uint32 blockCipherWritePad(unsigned char *p, unsigned char padLen)
{
    unsigned char c = padLen;

    while (c-- > 0)
    {
        *p++ = padLen;
    }
    return padLen;
}
#     endif /* USE_PKCS5 && USE_PBKDF1 */
/******************************************************************************/
