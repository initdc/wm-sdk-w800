/**
 *      @file    x509.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      X.509 Parser.
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

#ifdef USE_X509

/******************************************************************************/

# ifdef POSIX
#  include <time.h>
# endif

/******************************************************************************/

# define MAX_CERTS_PER_FILE      16

/* Maximum time length accepted.
   Allows RFC 5280 format time + nanosecond fractional time + non-Zulu time. */
# define MAX_TIME_LEN            32

# ifdef USE_CERT_PARSE
/*
    Certificate extensions
 */
#  define IMPLICIT_ISSUER_ID      1
#  define IMPLICIT_SUBJECT_ID     2
#  define EXPLICIT_EXTENSION      3

/** Enumerate X.509 milestones for issuedBefore() api */
typedef enum
{
    RFC_6818,   /* January 2013 X.509 Updates Below */
    RFC_5280,   /* May 2008 X.509 Obsoletes Below */
    RFC_3280,   /* April 2002 X.509 Obsoletes Below */
    RFC_2459,   /* January 1999 X.509 First RFC */
    X509_V3,    /* 1996 X.509v3 Pre-RFC */
    X509_V2,    /* 1993 X.509v2 Pre-RFC */
    X509_V1,    /* 1988 X.509v1 Pre-RFC */
} rfc_e;

#ifdef PS_FIND_OID_NEEDED
#  ifdef USE_CRYPTO_TRACE
#   define OID_LIST(A, B) { { A, B }, #B, oid_ ## B }
#  else
#   define OID_LIST(A, B) { { A, B }, oid_ ## B }
#  endif

/* Oid database.
   Note: This database is used only by deprecated functions.
   The current database is found in oid_names and oid_list_e. */
static const struct
{
    uint16_t oid[MAX_OID_LEN];
#  ifdef USE_CRYPTO_TRACE
    char name[33];
#  endif
    int id;
} oid_list[] = {
    /* X.509 certificate extensions */
    OID_LIST(id_ce,     id_ce_authorityKeyIdentifier),
    OID_LIST(id_ce,     id_ce_subjectKeyIdentifier),
    OID_LIST(id_ce,     id_ce_keyUsage),
    OID_LIST(id_ce,     id_ce_certificatePolicies),
    OID_LIST(id_ce,     id_ce_policyMappings),
    OID_LIST(id_ce,     id_ce_subjectAltName),
    OID_LIST(id_ce,     id_ce_issuerAltName),
    OID_LIST(id_ce,     id_ce_subjectDirectoryAttributes),
    OID_LIST(id_ce,     id_ce_basicConstraints),
    OID_LIST(id_ce,     id_ce_nameConstraints),
    OID_LIST(id_ce,     id_ce_policyConstraints),
    OID_LIST(id_ce,     id_ce_extKeyUsage),
    OID_LIST(id_ce,     id_ce_cRLDistributionPoints),
    OID_LIST(id_ce,     id_ce_cRLNumber),
    OID_LIST(id_ce,     id_ce_issuingDistributionPoint),
    OID_LIST(id_ce,     id_ce_inhibitAnyPolicy),
    OID_LIST(id_ce,     id_ce_freshestCRL),
    OID_LIST(id_pe,     id_pe_authorityInfoAccess),
    OID_LIST(id_pe,     id_pe_subjectInfoAccess),
    /* Extended Key Usage */
    OID_LIST(id_ce_eku, id_ce_eku_anyExtendedKeyUsage),
    OID_LIST(id_kp,     id_kp_serverAuth),
    OID_LIST(id_kp,     id_kp_clientAuth),
    OID_LIST(id_kp,     id_kp_codeSigning),
    OID_LIST(id_kp,     id_kp_emailProtection),
    OID_LIST(id_kp,     id_kp_timeStamping),
    OID_LIST(id_kp,     id_kp_OCSPSigning),
    /* policyIdentifiers */
    OID_LIST(id_qt,     id_qt_cps),
    OID_LIST(id_qt,     id_qt_unotice),
    /* accessDescriptors */
    OID_LIST(id_ad,     id_ad_caIssuers),
    OID_LIST(id_ad,     id_ad_ocsp),
    /* List terminator */
    OID_LIST(0,         0),
};
#endif /* PS_FIND_OID_NEEDED */

#define OID_NAME(A, B) { oid_ ## B, #B }

static const struct
{
    int id;
    const char name[33]; /* 33 is based on the current maximum length. */
} oid_names[] = {
    /* X.509 certificate extensions */
    OID_NAME(id_ce,     id_ce_authorityKeyIdentifier),
    OID_NAME(id_ce,     id_ce_subjectKeyIdentifier),
    OID_NAME(id_ce,     id_ce_keyUsage),
    OID_NAME(id_ce,     id_ce_certificatePolicies),
    OID_NAME(id_ce,     id_ce_policyMappings),
    OID_NAME(id_ce,     id_ce_subjectAltName),
    OID_NAME(id_ce,     id_ce_issuerAltName),
    OID_NAME(id_ce,     id_ce_subjectDirectoryAttributes),
    OID_NAME(id_ce,     id_ce_basicConstraints),
    OID_NAME(id_ce,     id_ce_nameConstraints),
    OID_NAME(id_ce,     id_ce_policyConstraints),
    OID_NAME(id_ce,     id_ce_extKeyUsage),
    OID_NAME(id_ce,     id_ce_cRLDistributionPoints),
    OID_NAME(id_ce,     id_ce_cRLNumber),
    OID_NAME(id_ce,     id_ce_issuingDistributionPoint),
    OID_NAME(id_ce,     id_ce_inhibitAnyPolicy),
    OID_NAME(id_ce,     id_ce_freshestCRL),
    OID_NAME(id_pe,     id_pe_authorityInfoAccess),
    OID_NAME(id_pe,     id_pe_subjectInfoAccess),
    /* Extended Key Usage */
    OID_NAME(id_ce_eku, id_ce_eku_anyExtendedKeyUsage),
    OID_NAME(id_kp,     id_kp_serverAuth),
    OID_NAME(id_kp,     id_kp_clientAuth),
    OID_NAME(id_kp,     id_kp_codeSigning),
    OID_NAME(id_kp,     id_kp_emailProtection),
    OID_NAME(id_kp,     id_kp_timeStamping),
    OID_NAME(id_kp,     id_kp_OCSPSigning),
    /* policyIdentifiers */
    OID_NAME(id_qt,     id_qt_cps),
    OID_NAME(id_qt,     id_qt_unotice),
    /* accessDescriptors */
    OID_NAME(id_ad,     id_ad_caIssuers),
    OID_NAME(id_ad,     id_ad_ocsp),
    /* List terminator */
    OID_NAME(0,         0),
};

#undef OID_NAME

#define OID_LIST_E(A, B, C, D) { oid_ ## B, D} /* A and C are for only for reader of the source code. */

/* Oid for mapping between encoding and id. */
static const struct
{
    int id;
    const char *oid_encoded;
} oid_list_e[] = {
    /* X.509 certificate extensions */
    OID_LIST_E(id_ce, id_ce_authorityKeyIdentifier, 2.5.29.35, "\x06\x03\x55\x1D\x23"),
    OID_LIST_E(id_ce, id_ce_subjectKeyIdentifier, 2.5.29.14, "\x06\x03\x55\x1D\x0E"),
    OID_LIST_E(id_ce, id_ce_keyUsage, 2.5.29.15, "\x06\x03\x55\x1D\x0F"),
    OID_LIST_E(id_ce, id_ce_certificatePolicies, 2.5.29.32, "\x06\x03\x55\x1D\x20"),
    OID_LIST_E(id_ce, id_ce_policyMappings, 2.5.29.33, "\x06\x03\x55\x1D\x21"),
    OID_LIST_E(id_ce, id_ce_subjectAltName, 2.5.29.17, "\x06\x03\x55\x1D\x11"),
    OID_LIST_E(id_ce, id_ce_issuerAltName, 2.5.29.18, "\x06\x03\x55\x1D\x12"),
    OID_LIST_E(id_ce, id_ce_subjectDirectoryAttributes, 2.5.29.9, "\x06\x03\x55\x1D\x09"),
    OID_LIST_E(id_ce, id_ce_basicConstraints, 2.5.29.19, "\x06\x03\x55\x1D\x13"),
    OID_LIST_E(id_ce, id_ce_nameConstraints, 2.5.29.30, "\x06\x03\x55\x1D\x1E"),
    OID_LIST_E(id_ce, id_ce_policyConstraints, 2.5.29.36, "\x06\x03\x55\x1D\x24"),
    OID_LIST_E(id_ce, id_ce_extKeyUsage, 2.5.29.37, "\x06\x03\x55\x1D\x25"),
    OID_LIST_E(id_ce, id_ce_cRLDistributionPoints, 2.5.29.31, "\x06\x03\x55\x1D\x1F"),
    OID_LIST_E(id_ce, id_ce_cRLNumber, 2.5.29.20, "\x06\x03\x55\x1D\x14"),
    OID_LIST_E(id_ce, id_ce_issuingDistributionPoint, 2.5.29.28, "\x06\x03\x55\x1D\x1C"),
    OID_LIST_E(id_ce, id_ce_inhibitAnyPolicy, 2.5.29.54, "\x06\x03\x55\x1D\x36"),
    OID_LIST_E(id_ce, id_ce_freshestCRL, 2.5.29.46, "\x06\x03\x55\x1D\x2E"),
    OID_LIST_E(id_pe, id_pe_authorityInfoAccess, 1.3.6.1.5.5.7.1.1, "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x01"),
    OID_LIST_E(id_pe, id_pe_subjectInfoAccess, 1.3.6.1.5.5.7.1.11, "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x0B"),
    OID_LIST_E(id_ce_eku, id_ce_eku_anyExtendedKeyUsage, 2.5.29.37.0, "\x06\x04\x55\x1D\x25\x00"),
    OID_LIST_E(id_kp, id_kp_serverAuth, 1.3.6.1.5.5.7.3.1, "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x01"),
    OID_LIST_E(id_kp, id_kp_clientAuth, 1.3.6.1.5.5.7.3.2, "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x02"),
    OID_LIST_E(id_kp, id_kp_codeSigning, 1.3.6.1.5.5.7.3.3, "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x03"),
    OID_LIST_E(id_kp, id_kp_emailProtection, 1.3.6.1.5.5.7.3.4, "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x04"),
    OID_LIST_E(id_kp, id_kp_timeStamping, 1.3.6.1.5.5.7.3.8, "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x08"),
    OID_LIST_E(id_kp, id_kp_OCSPSigning, 1.3.6.1.5.5.7.3.9, "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x09"),
    OID_LIST_E(id_qt, id_qt_cps, 1.3.6.1.5.5.7.2.1, "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x01"),
    OID_LIST_E(id_qt, id_qt_unotice, 1.3.6.1.5.5.7.2.2, "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x02"),
    OID_LIST_E(id_ad, id_ad_caIssuers, 1.3.6.1.5.5.7.48.2, "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x02"),
    OID_LIST_E(id_ad, id_ad_ocsp, 1.3.6.1.5.5.7.48.1, "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x01"),
    /* List terminator */
    OID_LIST_E(0, 0, 0, NULL),
};

#undef OID_LIST_E

/*
    Hybrid ASN.1/X.509 cert parsing helpers
 */
static int32_t getExplicitVersion(const unsigned char **pp, psSize_t len,
                                  int32_t expVal, int32_t *val);
static int32_t getTimeValidity(psPool_t *pool, const unsigned char **pp,
                               psSize_t len,
                               int32_t *notBeforeTimeType, int32_t *notAfterTimeType,
                               char **notBefore, char **notAfter);
static int32_t getImplicitBitString(psPool_t *pool, const unsigned char **pp,
                                    psSize_t len, int32_t impVal, unsigned char **bitString,
                                    psSize_t *bitLen);
static int32_t issuedBefore(rfc_e rfc, const psX509Cert_t *cert);
# endif /* USE_CERT_PARSE */

/******************************************************************************/

psRes_t psX509ParseCertData(psPool_t *pool,
                            const unsigned char *buf, psSizeL_t len,
                            psX509Cert_t **certs,
                            int32 flags)
{
    psX509Cert_t **tailp, *current;
    psRes_t err, numParsed = 0;
    psList_t *certData, *certDatas = NULL;

    /* find the tail of what we already have on certs. */
    for (tailp = certs; *tailp; tailp = &(*tailp)->next)
        ;

# ifdef USE_PEM_DECODE
    err = psPemCertBufToList(pool, buf, len, &certDatas);
# else
    err = PS_FAILURE;
# endif /* USE_PEM_DECODE */
    if (err < PS_SUCCESS)
    {
        /* PEM serialization failed or not supported. Try binary input. */
        err = psX509ParseCert(pool, buf, len, &current, flags);
        if (err < 0)
        {
            psX509FreeCert(current);
        }
        else
        {
            *tailp = current;
            tailp = &(current->next);
        }
        return err;
    }

   /*
     Recurse each individual cert buffer from within the file

     If partial parse of cert bundles is not allowed, the failure to
     load any of the certificates causes the whole function call to
     fail. If partial parse of cert bundles is allowed, parse as many
     as we can and return the number of parsed certs.
   */
    for (certData = certDatas; certData; certData = certData->next)
    {
        err = psX509ParseCert(pool,
                certData->item,
                certData->len,
                &current,
                flags);
        if (err < 0 && !(flags & CERT_ALLOW_BUNDLE_PARTIAL_PARSE))
        {
            psX509FreeCert(current);
            psFreeList(certDatas, pool);
            return err;
        }
        numParsed++;
        *tailp = current;
        tailp = &(current->next);
    }
    psFreeList(certDatas, pool);
    return numParsed;
}

# ifdef MATRIX_USE_FILE_SYSTEM
/******************************************************************************/

/******************************************************************************/
/*
    Open a PEM X.509 certificate file and parse it

    Memory info:
        Caller must free outcert with psX509FreeCert on function success
        Caller does not have to free outcert on function failure
 */
psRes_t psX509ParseCertFile(psPool_t *pool, const char *fileName,
    psX509Cert_t **outcert, int32 flags)
{
    unsigned char *fileBuf;
    psSizeL_t fileBufLen;
    psRes_t rc;
    psList_t *fileList, *currentFile;
    int32 numParsed = 0;
    psX509Cert_t *certs = NULL;

    *outcert = NULL;
/*
    First test to see if there are multiple files being passed in.
    Looking for a semi-colon delimiter
 */
    if ((rc= psParseList(pool, fileName, ';', &fileList)) < 0)
    {
        return rc;
    }
    /* Recurse each individual file */
    for  (currentFile = fileList; currentFile; currentFile = currentFile->next)
    {
        if ((rc = psGetFileBuf(pool,
                               (char *) currentFile->item,
                               &fileBuf, &fileBufLen)) < PS_SUCCESS)
        {
            psFreeList(fileList, pool);
            psX509FreeCert(certs);
            return rc;
        }

        rc = psX509ParseCertData(pool,
                                 fileBuf, fileBufLen,
                                 &certs,
                                 flags);

        if (rc < PS_SUCCESS)
        {
            psFreeList(fileList, pool);
            psX509FreeCert(certs);
            psFree(fileBuf, pool);
            return rc;
        }
        psFree(fileBuf, pool);
        numParsed += rc;
    }
    psFreeList(fileList, pool);
    *outcert = certs;
    return numParsed;
}

/******************************************************************************/
/*
 */
# endif /* MATRIX_USE_FILE_SYSTEM */
/******************************************************************************/


# ifdef USE_PKCS1_PSS
/*
    RSASSA-PSS-params ::= SEQUENCE {
        hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
        maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
        saltLength         [2] INTEGER          DEFAULT 20,
        trailerField       [3] TrailerField     DEFAULT 1
    }
    Note, each of these is sequential, but optional.
 */
static int32 getRsaPssParams(const unsigned char **pp, int32 size,
    psX509Cert_t *cert, int32 secondPass)
{
    const unsigned char *p, *end;
    int32 oi, second, asnint;
    psSize_t plen;

    p = *pp;
    /* SEQUENCE has already been pulled off into size */
    end = p + size;

    /* The signature algorithm appears twice in an X.509 cert and must be
        identical.  If secondPass is set we check for that */

    if ((uint32) (end - p) < 1)
    {
        goto L_PSS_DONE_OPTIONAL_PARAMS;
    }
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
    {
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &plen) < 0 ||
            (end - p) < plen)
        {
            psTraceCrypto("Error parsing rsapss hash alg len\n");
            return PS_PARSE_FAIL;
        }
        /* hashAlgorithm is OID */
        if (getAsnAlgorithmIdentifier(&p, (uint32) (end - p), &oi, &plen) < 0)
        {
            psTraceCrypto("Error parsing rsapss hash alg\n");
            return PS_PARSE_FAIL;
        }
        if (secondPass)
        {
            if (oi != cert->pssHash)
            {
                psTraceCrypto("rsapss hash alg doesn't repeat\n");
                return PS_PARSE_FAIL;
            }
            /* Convert to PKCS1_ ID for pssDecode on second pass */
            if (oi == OID_SHA1_ALG)
            {
                second = PKCS1_SHA1_ID;
            }
            else if (oi == OID_SHA256_ALG)
            {
                second = PKCS1_SHA256_ID;
            }
            else if (oi == OID_MD5_ALG)
            {
                second = PKCS1_MD5_ID;
#  ifdef USE_SHA384
            }
            else if (oi == OID_SHA384_ALG)
            {
                second = PKCS1_SHA384_ID;
#  endif
#  ifdef USE_SHA512
            }
            else if (oi == OID_SHA512_ALG)
            {
                second = PKCS1_SHA512_ID;
#  endif
            }
            else
            {
                psTraceCrypto("Unsupported rsapss hash alg\n");
                return PS_UNSUPPORTED_FAIL;
            }
            cert->pssHash = second;
        }
        else
        {
            /* first time, save the OID for compare */
            cert->pssHash = oi;
        }
    }
    if ((uint32) (end - p) < 1)
    {
        goto L_PSS_DONE_OPTIONAL_PARAMS;
    }
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        /* maskGenAlgorthm is OID */
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &plen) < 0 ||
            (end - p) < plen)
        {
            psTraceCrypto("Error parsing mask gen alg len\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnAlgorithmIdentifier(&p, (uint32) (end - p), &oi, &plen) < 0)
        {
            psTraceCrypto("Error parsing mask gen alg\n");
            return PS_PARSE_FAIL;
        }
        if (secondPass)
        {
            if (oi != cert->maskGen)
            {
                psTraceCrypto("rsapss mask gen alg doesn't repeat\n");
                return PS_PARSE_FAIL;
            }
        }
        cert->maskGen = oi;
        if (cert->maskGen != OID_ID_MGF1)
        {
            psTraceCrypto("Unsupported RSASSA-PSS maskGenAlgorithm\n");
            return PS_UNSUPPORTED_FAIL;
        }
        /*  MaskGenAlgorithm ::= AlgorithmIdentifier {
                {PKCS1MGFAlgorithms}
            }
            PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
                { OID id-mgf1 PARAMETERS HashAlgorithm },
                ...  -- Allows for future expansion --
            }

            The default mask generation function is MGF1 with SHA-1:

            mgf1SHA1    MaskGenAlgorithm ::= {
                algorithm   id-mgf1,
                parameters  HashAlgorithm : sha1
            }
         */
        if (getAsnAlgorithmIdentifier(&p, (uint32) (end - p), &oi, &plen) < 0)
        {
            psTraceCrypto("Error parsing mask hash alg\n");
            return PS_PARSE_FAIL;
        }
        if (secondPass)
        {
            if (oi != cert->maskHash)
            {
                psTraceCrypto("rsapss mask hash alg doesn't repeat\n");
                return PS_PARSE_FAIL;
            }
        }
        cert->maskHash = oi;
    }
    if ((uint32) (end - p) < 1)
    {
        goto L_PSS_DONE_OPTIONAL_PARAMS;
    }
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2))
    {
        /* saltLen */
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &plen) < 0 ||
            (end - p) < plen)
        {
            psTraceCrypto("Error parsing salt len length\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnInteger(&p, (uint32) (end - p), &asnint) < 0)
        {
            psTraceCrypto("Error parsing salt len\n");
            return PS_PARSE_FAIL;
        }
        if (secondPass)
        {
            if (asnint != cert->saltLen)
            {
                psTraceCrypto("Error: salt len doesn't repeat\n");
                return PS_PARSE_FAIL;
            }
        }
        cert->saltLen = asnint;
    }
    if ((uint32) (end - p) < 1)
    {
        goto L_PSS_DONE_OPTIONAL_PARAMS;
    }
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3))
    {
        /* It shall be 1 for this version of the document, which represents
            the trailer field with hexadecimal value 0xBC */
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &plen) < 0 ||
            (end - p) < plen)
        {
            psTraceCrypto("Error parsing rsapss trailer len\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnInteger(&p, (uint32) (end - p), &asnint) < 0 ||
            asnint != 0x01)
        {
            psTraceCrypto("Error parsing rsapss trailer\n");
            return PS_PARSE_FAIL;
        }
    }
    if (p != end)
    {
        psTraceCrypto("Unexpected PSS params\n");
        return PS_PARSE_FAIL;
    }
L_PSS_DONE_OPTIONAL_PARAMS:
    *pp = (unsigned char *) p;
    return PS_SUCCESS;
}
# endif /* USE_PKCS1_PSS */

/******************************************************************************/
/*
   Get the public key (SubjectPublicKeyInfo) in DER format from a psX509Cert_t.

   Precondition: the certificate must have been parsed with psX509ParseCert or
   psX509ParseCertFile with the CERT_STORE_UNPARSED_BUFFER flag set.
 */
PSPUBLIC int32 psX509GetCertPublicKeyDer(psX509Cert_t *cert,
    unsigned char *der_out,
    psSize_t *der_out_len)
{
    if (!cert || !der_out || !der_out_len)
    {
        return PS_ARG_FAIL;
    }
    if (cert->publicKeyDerOffsetIntoUnparsedBin == 0
        || cert->publicKeyDerLen == 0)
    {
        psTraceCrypto("No DER format public key stored in this cert. " \
            "CERT_STORE_DN_BUFFER flag was not used when parsing?");
        return PS_ARG_FAIL;
    }

    if (*der_out_len < cert->publicKeyDerLen)
    {
        psTraceCrypto("Output buffer is too small");
        *der_out_len = cert->publicKeyDerLen;
        return PS_OUTPUT_LENGTH;
    }

    Memcpy(der_out,
        cert->unparsedBin + cert->publicKeyDerOffsetIntoUnparsedBin,
        cert->publicKeyDerLen);

    *der_out_len = cert->publicKeyDerLen;

    return PS_SUCCESS;
}

# ifdef USE_CERT_PARSE
static
psRes_t getCertSignatureHashLen(psX509Cert_t *cert,
        psSize_t *sigHashLenOut)
{
    psResSize_t sigHashLen;

# ifdef USE_PKCS1_PSS
    if (cert->certAlgorithm == OID_RSASSA_PSS)
    {
        sigHashLen = psPssHashAlgToHashLen(cert->pssHash);
    }
    else
# endif /* USE_PKCS1_PSS */
    {
        sigHashLen = psSigAlgToHashLen(cert->sigAlgorithm);
    }

    if (sigHashLen < 0)
    {
        psTraceIntCrypto("Unsupported cert sig hash alg: %d\n",
                         (int)cert->sigAlgorithm);
        return PS_UNSUPPORTED_FAIL;
    }

    *sigHashLenOut = (psSize_t)sigHashLen;

    return PS_SUCCESS;
}
# endif /* USE_CERT_PARSE */

/*
  Parse a single, DER-encoded ASN.1 Certificate.

  Preconditions:
  - *pp points to the first octet of a DER-encoded Certificate.
  - the length of the DER-encoded Certificate is size octets.
  - cert points to an allocated and zeroized psX509Cert_t struct.

  Postconditions:
  - *pp == (pp_orig + size), where pp_orig is the original (input)
    value of *pp.
  - If return value is PS_SUCCESS, cert will contain a parsed
    and usable certificate.
  - If return value is < 0, cert->parseStatus will contain information
    about the reason of the parse failure.

  @param[in] Pointer to a memory pool
  @param[in,out] pp Pointer to a pointer pointing to the first octet
  of a DER-encoded Certificate. After parsing has completed, the underlying
  pointer will be updated to point to the octet after the final octet
  of the Certificate.
  @param[in] size Size of the DER buffer in bytes.
  @param[in] cert An allocated psX509Cert_t struct to be filled.
  with the parsed Certificate data.
  @param[in] flags
*/
static int parse_single_cert(psPool_t *pool, const unsigned char **pp,
        uint32 size, const unsigned char *far_end,
        psX509Cert_t *cert, int32 flags)
{
# ifdef USE_CERT_PARSE
    const unsigned char *tbsCertStart;
    unsigned char sha1KeyHash[SHA1_HASH_SIZE];
    psDigestContext_t hashCtx;
    psSize_t certLen;
    const unsigned char *p_subject_pubkey_info;
    size_t subject_pubkey_info_header_len;
# endif  /* USE_CERT_PARSE */
    const unsigned char *certStart, *certEnd, *end, *p;
    int32_t rc, func_rc;
    uint32_t oneCertLen;
    psSize_t len, plen;

    /*
      Initialize the cert structure.*/
    cert->pool = pool;
    cert->parseStatus = PS_X509_PARSE_FAIL; /* Default to fail status */
# ifdef USE_CERT_PARSE
    cert->extensions.bc.cA = CA_UNDEFINED;
# endif /* USE_CERT_PARSE */

    p = *pp;
    certStart = p;
    end = p + size;

    func_rc = PS_SUCCESS;

    if ((rc = getAsnSequence32(&p, (uint32_t) (far_end - p), &oneCertLen, 0))
            < 0)
    {
        psTraceCrypto("Initial cert parse error\n");
        func_rc = rc;
        goto out;
    }
    /* The whole list of certs could be > 64K bytes, but we still
       restrict individual certs to 64KB */
    if (oneCertLen > 0xFFFF)
    {
        psAssert(oneCertLen <= 0xFFFF);
        func_rc = PS_FAILURE;
        goto out;
    }
    end = p + oneCertLen;

    /*
      If the user has specified to keep the ASN.1 buffer in the X.509
      structure, now is the time to account for it
    */
    if (flags & CERT_STORE_UNPARSED_BUFFER)
    {
        cert->binLen = oneCertLen + (int32) (p - certStart);
        cert->unparsedBin = psMalloc(pool, cert->binLen);
        if (cert->unparsedBin == NULL)
        {
            psError("Memory allocation error in psX509ParseCert\n");
            func_rc = PS_MEM_FAIL;
            goto out;
        }
        Memcpy(cert->unparsedBin, certStart, cert->binLen);
    }

# ifdef ENABLE_CA_CERT_HASH
    /* We use the cert_sha1_hash type for the Trusted CA Indication so
       run a SHA1 has over the entire Certificate DER encoding. */
    psSha1PreInit(&hashCtx.u.sha1);
    psSha1Init(&hashCtx.u.sha1);
    psSha1Update(&hashCtx.u.sha1, certStart,
            oneCertLen + (int32) (p - certStart));
    psSha1Final(&hashCtx.u.sha1, cert->sha1CertHash);
# endif

# ifdef USE_CERT_PARSE
    tbsCertStart = p;
# endif /* USE_CERT_PARSE */
    /*
      TBSCertificate  ::=  SEQUENCE  {
      version                 [0]             EXPLICIT Version DEFAULT v1,
      serialNumber                    CertificateSerialNumber,
      signature                               AlgorithmIdentifier,
      issuer                                  Name,
      validity                                Validity,
      subject                                 Name,
      subjectPublicKeyInfo    SubjectPublicKeyInfo,
      issuerUniqueID  [1]             IMPLICIT UniqueIdentifier OPTIONAL,
      -- If present, version shall be v2 or v3
      subjectUniqueID [2]     IMPLICIT UniqueIdentifier OPTIONAL,
      -- If present, version shall be v2 or v3
      extensions              [3]     EXPLICIT Extensions OPTIONAL
      -- If present, version shall be v3  }
    */
    if ((rc = getAsnSequence(&p, (uint32) (end - p), &len)) < 0)
    {
        psTraceCrypto("ASN sequence parse error\n");
        func_rc = rc;
        goto out;
    }
    certEnd = p + len;
# ifdef USE_CERT_PARSE
    /*
      Start parsing TBSCertificate contents.
    */
    certLen = certEnd - tbsCertStart;
    /*
      Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    */
    if ((rc = getExplicitVersion(&p, (uint32) (end - p), 0, &cert->version))
            < 0)
    {
        psTraceCrypto("ASN version parse error\n");
        func_rc = rc;
        goto out;
    }
    switch (cert->version)
    {
    case 0:
    case 1:
#  ifndef ALLOW_VERSION_1_ROOT_CERT_PARSE
        psTraceCrypto("ERROR: v1 and v2 certificate versions insecure\n");
        cert->parseStatus = PS_X509_UNSUPPORTED_VERSION;
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;
#  else
        /* Allow locally stored, trusted version 1 and version 2 certificates
           to be parsed. The SSL layer code will still reject non v3
           certificates that arrive over-the-wire. */
        /* Version 1 certificates do not have basic constraints to
           specify a CA flag or path length. Here, the CA flag is implied
           since v1 certs can only be loaded as root. We explicitly set
           the pathLengthConstraint to allow up to 2 intermediate certs.
           This can be adjusted to allow more or less intermediate certs. */
        cert->extensions.bc.pathLenConstraint = 2;
        break;
#  endif    /* ALLOW_VERSION_1_ROOT_CERT_PARSE */
    case 2:
        /* Typical case of v3 cert */
        break;
    default:
        psTraceIntCrypto("ERROR: unknown certificate version: %d\n",
                cert->version);
        cert->parseStatus = PS_X509_UNSUPPORTED_VERSION;
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;
    }
    /*
      CertificateSerialNumber  ::=  INTEGER
      There is a special return code for a missing serial number that
      will get written to the parse warning flag
    */
    if ((rc = getSerialNum(pool, &p, (uint32) (end - p), &cert->serialNumber,
                            &cert->serialNumberLen)) < 0)
    {
        psTraceCrypto("ASN serial number parse error\n");
        func_rc = rc;
        goto out;
    }
    /*
      AlgorithmIdentifier  ::=  SEQUENCE  {
      algorithm                               OBJECT IDENTIFIER,
      parameters                              ANY DEFINED BY algorithm OPTIONAL }
    */
    if ((rc = getAsnAlgorithmIdentifier(&p, (uint32) (end - p),
                            &cert->certAlgorithm, &plen)) < 0)
    {
        psTraceCrypto("Couldn't parse algorithm identifier for certAlgorithm\n");
        cert->parseStatus = PS_X509_ALG_ID;
        func_rc = rc;
        goto out;
    }
    if (plen != 0)
    {
#  ifdef USE_PKCS1_PSS
        if (cert->certAlgorithm == OID_RSASSA_PSS)
        {
            /* RSASSA-PSS-params ::= SEQUENCE {
               hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
               maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
               saltLength         [2] INTEGER          DEFAULT 20,
               trailerField       [3] TrailerField     DEFAULT trailerFieldBC
               }
            */
            if ((rc = getAsnSequence(&p, (uint32) (end - p), &len)) < 0)
            {
                psTraceCrypto("ASN sequence parse error\n");
                func_rc = rc;
                goto out;
            }
            /* Always set the defaults before parsing */
            cert->pssHash = PKCS1_SHA1_ID;
            cert->maskGen = OID_ID_MGF1;
            cert->saltLen = SHA1_HASH_SIZE;
            /* Something other than defaults to parse here? */
            if (len > 0)
            {
                if ((rc = getRsaPssParams(&p, len, cert, 0)) < 0)
                {
                    func_rc = rc;
                    goto out;
                }
            }
        }
        else
        {
            psTraceCrypto("Unsupported X.509 certAlgorithm\n");
            func_rc = PS_UNSUPPORTED_FAIL;
            goto out;
        }
#  else
        psTraceCrypto("Unsupported X.509 certAlgorithm\n");
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;
#  endif
    }
    /*
      Name ::= CHOICE {
      RDNSequence }

      RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

      RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

      AttributeTypeAndValue ::= SEQUENCE {
      type    AttributeType,
      value   AttributeValue }

      AttributeType ::= OBJECT IDENTIFIER

      AttributeValue ::= ANY DEFINED BY AttributeType
    */
    if ((rc = psX509GetDNAttributes(pool, &p, (uint32) (end - p),
                            &cert->issuer, flags)) < 0)
    {
        psTraceCrypto("Couldn't parse issuer DN attributes\n");
        cert->parseStatus = PS_X509_ISSUER_DN;
        func_rc = rc;
        goto out;
    }
    /*
      Validity ::= SEQUENCE {
      notBefore       Time,
      notAfter        Time    }
    */
    if ((rc = getTimeValidity(pool, &p, (uint32) (end - p),
                            &cert->notBeforeTimeType, &cert->notAfterTimeType,
                            &cert->notBefore, &cert->notAfter)) < 0)
    {
        psTraceCrypto("Couldn't parse validity\n");
        func_rc = rc;
        goto out;
    }

    /* SECURITY - platforms without a date function will always succeed */
    if ((rc = validateDateRange(cert)) < 0)
    {
        psTraceCrypto("Validity date check failed\n");
        cert->parseStatus = PS_X509_DATE;
        func_rc = rc;
        goto out;
    }
    /*
      Subject DN
    */
    cert->subjectKeyDerOffsetIntoUnparsedBin = (uint16_t) (p - certStart);
    if ((rc = psX509GetDNAttributes(pool, &p, (uint32) (end - p),
                            &cert->subject, flags)) < 0)
    {
        psTraceCrypto("Couldn't parse subject DN attributes\n");
        cert->parseStatus = PS_X509_SUBJECT_DN;
        func_rc = rc;
        goto out;
    }
    /*
      SubjectPublicKeyInfo  ::=  SEQUENCE  {
      algorithm                       AlgorithmIdentifier,
      subjectPublicKey        BIT STRING      }
    */
    p_subject_pubkey_info = p;

    cert->publicKeyDerOffsetIntoUnparsedBin = (uint16_t) (p - certStart);

    if ((rc = getAsnSequence(&p, (uint32) (end - p), &len)) < 0)
    {
        psTraceCrypto("Couldn't get ASN sequence for pubKeyAlgorithm\n");
        func_rc = rc;
        goto out;
    }
    subject_pubkey_info_header_len = (p - p_subject_pubkey_info);
    cert->publicKeyDerLen = len + subject_pubkey_info_header_len;

    if ((rc = getAsnAlgorithmIdentifier(&p, (uint32) (end - p),
                            &cert->pubKeyAlgorithm, &plen)) < 0)
    {
        psTraceCrypto("Couldn't parse algorithm id for pubKeyAlgorithm\n");
        func_rc = rc;
        goto out;
    }

    /* Populate with correct type based on pubKeyAlgorithm OID */
    switch (cert->pubKeyAlgorithm)
    {
#  ifdef USE_ECC
    case OID_ECDSA_KEY_ALG:
        if (plen == 0 || plen > (int32) (end - p))
        {
            psTraceCrypto("Bad params on EC OID\n");
            func_rc = PS_PARSE_FAIL;
            goto out;
        }
        psInitPubKey(pool, &cert->publicKey, PS_ECC);
        if ((rc = getEcPubKey(pool, &p, (uint16_t) (end - p),
                                &cert->publicKey.key.ecc, sha1KeyHash)) < 0)
        {
            if (rc == PS_UNSUPPORTED_FAIL)
            {
                cert->parseStatus = PS_X509_UNSUPPORTED_ECC_CURVE;
            }
            func_rc = PS_PARSE_FAIL;
            goto out;
        }
        /* keysize will be the size of the public ecc key (2 * privateLen) */
        cert->publicKey.keysize = psEccSize(&cert->publicKey.key.ecc);
        if (cert->publicKey.keysize < (MIN_ECC_BITS / 8))
        {
            psTraceIntCrypto("ECC key size < %d\n", MIN_ECC_BITS);
            psClearPubKey(&cert->publicKey);
            cert->parseStatus = PS_X509_WEAK_KEY;
            func_rc = PS_PARSE_FAIL;
            goto out;
        }
        break;
#  endif
#  ifdef USE_RSA
    case OID_RSA_KEY_ALG:
    case OID_RSASSA_PSS:
        if (cert->pubKeyAlgorithm == OID_RSA_KEY_ALG)
        {
            psAssert(plen == 0); /* No parameters on RSA pub key OID */
        }
        else
        {
            p += plen;
        }

        psInitPubKey(pool, &cert->publicKey, PS_RSA);
        if ((rc = psRsaParseAsnPubKey(pool, &p, (uint16_t) (end - p),
                                &cert->publicKey.key.rsa, sha1KeyHash)) < 0)
        {
            psTraceCrypto("Couldn't get RSA pub key from cert\n");
            cert->parseStatus = PS_X509_MISSING_RSA;
            func_rc = rc;
            goto out;
        }
        cert->publicKey.keysize = psRsaSize(&cert->publicKey.key.rsa);

        if (cert->publicKey.keysize < (MIN_RSA_BITS / 8))
        {
            psTraceIntCrypto("RSA key size < %d\n", MIN_RSA_BITS);
            psClearPubKey(&cert->publicKey);
            cert->parseStatus = PS_X509_WEAK_KEY;
            func_rc = PS_UNSUPPORTED_FAIL;
            goto out;
        }

        break;
#  endif
#  ifdef USE_ED25519
    case OID_ED25519_KEY_ALG:
        if (plen != 0)
        {
            psTraceCrypto("Parameters not supported in Ed25519 pub keys\n");
            func_rc = PS_UNSUPPORTED_FAIL;
            goto out;
        }
        psInitPubKey(pool, &cert->publicKey, PS_ED25519);
        rc = psEd25519ParsePubKey(pool, &p, (uint16_t) (end - p),
                &cert->publicKey.key.ed25519, sha1KeyHash);
        if (rc < 0)
        {
            psTraceCrypto("Couldn't parse Ed25519 key from cert\n");
            func_rc = rc;
            goto out;
        }
        break;
#  endif /* USE_ED25519 */
    default:
        /* Note 645:RSA, 515:DSA, 518:ECDSA, 32969:GOST */
        psTraceIntCrypto(
                "Unsupported public key algorithm in cert parse: %d\n",
                cert->pubKeyAlgorithm);
        cert->parseStatus = PS_X509_UNSUPPORTED_KEY_ALG;
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;
    }

#  if defined(USE_OCSP_RESPONSE) || defined(USE_OCSP_REQUEST)
    /* A sha1 hash of the public key is useful for OCSP */
    Memcpy(cert->sha1KeyHash, sha1KeyHash, SHA1_HASH_SIZE);
#  endif

    /* As the next three values are optional, we can do a specific test here */
    if (*p != (ASN_SEQUENCE | ASN_CONSTRUCTED))
    {
        if (getImplicitBitString(pool, &p, (uint32) (end - p),
                        IMPLICIT_ISSUER_ID, &cert->uniqueIssuerId,
                        &cert->uniqueIssuerIdLen) < 0 ||
                getImplicitBitString(pool, &p, (uint32) (end - p),
                        IMPLICIT_SUBJECT_ID, &cert->uniqueSubjectId,
                        &cert->uniqueSubjectIdLen) < 0 ||
                getExplicitExtensions(pool, &p, (uint32) (end - p),
                        EXPLICIT_EXTENSION, &cert->extensions, 0) < 0)
        {
            psTraceCrypto("There was an error parsing a certificate\n"
                    "extension.  This is likely caused by an\n"
                    "extension format that is not currently\n"
                    "recognized.  Please email support\n"
                    "to add support for the extension.\n");
            cert->parseStatus = PS_X509_UNSUPPORTED_EXT;
            func_rc = PS_PARSE_FAIL;
            goto out;
        }
    }

    /* This is the end of the cert.  Do a check here to be certain */
    if (certEnd != p)
    {
        psTraceCrypto("Error. Expecting end of cert\n");
        cert->parseStatus = PS_X509_EOF;
        func_rc = PS_LIMIT_FAIL;
        goto out;
    }

    /* Reject any cert without a distinguishedName or subjectAltName */
    if (cert->subject.commonName == NULL &&
            cert->subject.country == NULL &&
            cert->subject.state == NULL &&
            cert->subject.organization == NULL &&
            cert->subject.orgUnit == NULL &&
            cert->subject.domainComponent == NULL &&
            cert->extensions.san == NULL)
    {
        psTraceCrypto("Error. Cert has no name information\n");
        cert->parseStatus = PS_X509_MISSING_NAME;
        func_rc = PS_PARSE_FAIL;
        goto out;
    }
# else  /* No TBSCertificate parsing. */
    p = certEnd;
# endif /* USE_CERT_PARSE (end of TBSCertificate parsing) */

        /* Certificate signature info */
    if ((rc = getAsnAlgorithmIdentifier(&p, (uint32) (end - p),
                            &cert->sigAlgorithm, &plen)) < 0)
    {
        psTraceCrypto("Couldn't get algorithm identifier for sigAlgorithm\n");
        func_rc = rc;
        goto out;
    }

    if (plen != 0)
    {
# ifdef USE_PKCS1_PSS
        if (cert->sigAlgorithm == OID_RSASSA_PSS)
        {
            /* RSASSA-PSS-params ::= SEQUENCE {
               hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
               maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
               saltLength         [2] INTEGER          DEFAULT 20,
               trailerField       [3] TrailerField     DEFAULT trailerFieldBC
               }
            */
            if ((rc = getAsnSequence(&p, (uint32) (end - p), &len)) < 0)
            {
                psTraceCrypto("ASN sequence parse error\n");
                func_rc = rc;
                goto out;
            }
            /* Something other than defaults to parse here? */
            if (len > 0)
            {
                if ((rc = getRsaPssParams(&p, len, cert, 1)) < 0)
                {
                    func_rc = rc;
                    goto out;
                }
            }
        }
        else
        {
            psTraceCrypto("Unsupported X.509 sigAlgorithm\n");
            func_rc = PS_UNSUPPORTED_FAIL;
            goto out;
        }
# else
        psTraceCrypto("Unsupported X.509 sigAlgorithm\n");
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;
# endif     /* USE_PKCS1_PSS */
    }
# ifdef USE_CERT_PARSE
    /*
      https://tools.ietf.org/html/rfc5280#section-4.1.1.2
      This field MUST contain the same algorithm identifier as the
      signature field in the sequence tbsCertificate (Section 4.1.2.3).
    */
    if (cert->certAlgorithm != cert->sigAlgorithm)
    {
        psTraceIntCrypto("Parse error: mismatched sig alg (tbs = %d ",
                cert->certAlgorithm);
        psTraceIntCrypto("sig = %d)\n", cert->sigAlgorithm);
        cert->parseStatus = PS_X509_SIG_MISMATCH;
        func_rc = PS_PARSE_FAIL;
        goto out;
    }

    rc = getCertSignatureHashLen(cert, &cert->sigHashLen);
    if (rc < 0)
    {
        return rc;
    }

    /* Most algorithms and APIs use pre-hashing before signature
       verification. Others (such as Ed25519) want the original
       message (i.e. TBSCertificate) as input data. */
# if defined(USE_ROT_CRYPTO) || defined(USE_ED25519) || (defined(USE_CL_RSA) && defined(USE_PKCS1_PSS))
    if (!psVerifyNeedPreHash(cert->certAlgorithm))
    {
        /* Skip pre-hashing and instead buffer the TBS. */
        (void)hashCtx; /* Not used on this code path. */
        cert->tbsCertStart = psMalloc(pool, certLen);
        if (cert->tbsCertStart == NULL)
        {
            return PS_MEM_FAIL;
        }
        Memcpy(cert->tbsCertStart, tbsCertStart, certLen);
        cert->tbsCertLen = certLen;
        goto preprocessing_complete;
    }
# endif

    /*
      Compute the hash of the cert here for CA validation
    */
    switch (cert->certAlgorithm)
    {
#  ifdef ENABLE_MD5_SIGNED_CERTS
#   ifdef USE_MD2
    case OID_MD2_RSA_SIG:
        psMd2Init(&hashCtx.u.md2);
        psMd2Update(&hashCtx.u.md2, tbsCertStart, certLen);
        psMd2Final(&hashCtx.u.md2, cert->sigHash);
        break;
#   endif   /* USE_MD2 */
#   ifdef USE_MD4
    case OID_MD4_RSA_SIG:
        psMd4Init(&hashCtx.u.md4);
        psMd4Update(&hashCtx.u.md4, tbsCertStart, certLen);
        psMd4Final(&hashCtx.u.md4, cert->sigHash);
        break;
#   endif   /* USE_MD4 */
    case OID_MD5_RSA_SIG:
        psMd5Init(&hashCtx.u.md5);
        psMd5Update(&hashCtx.u.md5, tbsCertStart, certLen);
        psMd5Final(&hashCtx.u.md5, cert->sigHash);
        break;
#  endif
#  ifdef USE_SHA1
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_RSA_SIG2:
#   ifdef USE_ECC
    case OID_SHA1_ECDSA_SIG:
#   endif
#   ifndef ENABLE_SHA1_SIGNED_CERTS
        if (cert->subject.commonNameLen == cert->issuer.commonNameLen &&
                Memcmp(cert->subject.commonName,
                        cert->issuer.commonName,
                        cert->subject.commonNameLen))
        {
            /* Without ENABLE_SHA1_SIGNED_CERTS, SHA-1 based signatures
               are only allowed for root certs. TODO: improve the above
               root cert check. */
            goto unsupported_sig_alg;
        }
#   endif /* !ENABLE_SHA1_SIGNED_CERTS */
        psSha1PreInit(&hashCtx.u.sha1);
        psSha1Init(&hashCtx.u.sha1);
        psSha1Update(&hashCtx.u.sha1, tbsCertStart, certLen);
        psSha1Final(&hashCtx.u.sha1, cert->sigHash);
        break;
#  endif /* USE_SHA1 */
#  ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA224_ECDSA_SIG:
#   endif
        psSha224PreInit(&hashCtx.u.sha256);
        psSha224Init(&hashCtx.u.sha256);
        psSha224Update(&hashCtx.u.sha256, tbsCertStart, certLen);
        psSha224Final(&hashCtx.u.sha256, cert->sigHash);
        break;
#  endif
#  ifdef USE_SHA256
    case OID_SHA256_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA256_ECDSA_SIG:
#   endif
        psSha256PreInit(&hashCtx.u.sha256);
        psSha256Init(&hashCtx.u.sha256);
        psSha256Update(&hashCtx.u.sha256, tbsCertStart, certLen);
        psSha256Final(&hashCtx.u.sha256, cert->sigHash);
        break;
#  endif
#  ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA384_ECDSA_SIG:
#   endif
        psSha384PreInit(&hashCtx.u.sha384);
        psSha384Init(&hashCtx.u.sha384);
        psSha384Update(&hashCtx.u.sha384, tbsCertStart, certLen);
        psSha384Final(&hashCtx.u.sha384, cert->sigHash);
        break;
#  endif
#  ifdef USE_SHA512
    case OID_SHA512_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA512_ECDSA_SIG:
#   endif
        psSha512PreInit(&hashCtx.u.sha512);
        psSha512Init(&hashCtx.u.sha512);
        psSha512Update(&hashCtx.u.sha512, tbsCertStart, certLen);
        psSha512Final(&hashCtx.u.sha512, cert->sigHash);
        break;
#  endif
#  ifdef USE_PKCS1_PSS
    case OID_RSASSA_PSS:
        switch (cert->pssHash)
        {
#   ifdef ENABLE_MD5_SIGNED_CERTS
        case PKCS1_MD5_ID:
            psMd5Init(&hashCtx.u.md5);
            psMd5Update(&hashCtx.u.md5, tbsCertStart, certLen);
            psMd5Final(&hashCtx.u.md5, cert->sigHash);
            break;
#   endif
#   ifdef ENABLE_SHA1_SIGNED_CERTS
        case PKCS1_SHA1_ID:
            psSha1PreInit(&hashCtx.u.sha1);
            psSha1Init(&hashCtx.u.sha1);
            psSha1Update(&hashCtx.u.sha1, tbsCertStart, certLen);
            psSha1Final(&hashCtx.u.sha1, cert->sigHash);
            break;
#   endif
#   ifdef USE_SHA224
        case PKCS1_SHA224_ID:
            psSha224PreInit(&hashCtx.u.sha256);
            psSha224Init(&hashCtx.u.sha256);
            psSha224Update(&hashCtx.u.sha256, tbsCertStart, certLen);
            psSha224Final(&hashCtx.u.sha256, cert->sigHash);
            break;
#   endif
#   ifdef USE_SHA256
        case PKCS1_SHA256_ID:
            psSha256PreInit(&hashCtx.u.sha256);
            psSha256Init(&hashCtx.u.sha256);
            psSha256Update(&hashCtx.u.sha256, tbsCertStart, certLen);
            psSha256Final(&hashCtx.u.sha256, cert->sigHash);
            break;
#   endif
#   ifdef USE_SHA384
        case PKCS1_SHA384_ID:
            psSha384PreInit(&hashCtx.u.sha384);
            psSha384Init(&hashCtx.u.sha384);
            psSha384Update(&hashCtx.u.sha384, tbsCertStart, certLen);
            psSha384Final(&hashCtx.u.sha384, cert->sigHash);
            break;
#   endif
#   ifdef USE_SHA512
        case PKCS1_SHA512_ID:
            psSha512PreInit(&hashCtx.u.sha512);
            psSha512Init(&hashCtx.u.sha512);
            psSha512Update(&hashCtx.u.sha512, tbsCertStart, certLen);
            psSha512Final(&hashCtx.u.sha512, cert->sigHash);
            break;
#   endif
        default:
            psTraceIntCrypto("Unsupported pssHash algorithm: %d\n",
                    cert->pssHash);
            cert->parseStatus = PS_X509_UNSUPPORTED_SIG_ALG;
            func_rc = PS_UNSUPPORTED_FAIL;
            goto out;
        } /* switch pssHash */
        break;
#  endif /* USE_PKCS1_PSS */

#  if defined(USE_SHA1) && !defined(ENABLE_SHA1_SIGNED_CERTS)
unsupported_sig_alg:
#  endif
    default:
        /* Note 1670:MD2 */
        psTraceIntCrypto("Unsupported cert algorithm: %d\n",
                cert->certAlgorithm);
        cert->parseStatus = PS_X509_UNSUPPORTED_SIG_ALG;
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;

    } /* switch certAlgorithm */

    /* 6 empty bytes is plenty enough to know if sigHash didn't calculate */
    if (Memcmp(cert->sigHash, "\0\0\0\0\0\0", 6) == 0)
    {
        psTraceIntCrypto("No library signature alg support for cert: %d\n",
                cert->certAlgorithm);
        cert->parseStatus = PS_X509_UNSUPPORTED_SIG_ALG;
        func_rc = PS_UNSUPPORTED_FAIL;
        goto out;
    }
# endif /* USE_CERT_PARSE */

# if defined(USE_ROT_CRYPTO) || defined(USE_ED25519) || (defined(USE_CL_RSA) && defined(USE_PKCS1_PSS))
preprocessing_complete:
# endif /* USE_ROT_CRYPTO || USE_ED25519 || (USE_CL_RSA && USE_PKCS1_PSS) */

    if ((rc = psX509GetSignature(pool, &p, (uint32) (end - p),
                            &cert->signature, &cert->signatureLen)) < 0)
    {
        psTraceCrypto("Couldn't parse signature\n");
        cert->parseStatus = PS_X509_SIGNATURE;
        func_rc = rc;
        goto out;
    }

# ifndef USE_CERT_PARSE
    /* Some APIs need certAlgorithm.*/
    cert->certAlgorithm = cert->sigAlgorithm;
# endif /* !USE_CERT_PARSE */

out:
    if (func_rc == PS_SUCCESS)
    {
        cert->parseStatus = PS_X509_PARSE_SUCCESS;
        psAssert(p == end); /* Must have parsed everything. */
    }
    psAssert(p <= end); /* Must not have parsed too much. */

    *pp = end;

    return func_rc;
}

/******************************************************************************/
/*
    Parse an X509 v3 ASN.1 certificate stream
    http://tools.ietf.org/html/rfc3280

    flags
        CERT_STORE_UNPARSED_BUFFER
        CERT_STORE_DN_BUFFER

    Memory info:
        Caller must always free outcert with psX509FreeCert.  Even on failure
 */
int32 psX509ParseCert(psPool_t *pool, const unsigned char *pp, uint32 size,
    psX509Cert_t **outcert, int32 flags)
{
    psX509Cert_t *cert;
    const unsigned char *p, *far_end;
    int32_t parsing, rc;
    int32_t numCerts = 0;
    int32_t numParsedCerts = 0;

/*
    Allocate the cert structure right away.  User MUST always call
    psX509FreeCert regardless of whether this function succeeds.
    memset is important because the test for NULL is what is used
    to determine what to free.

    If the input stream consists of multiple certs, the rest of
    the psX509Cert_t structs will be allocated in parse_single_cert().
 */
    *outcert = cert = psMalloc(pool, sizeof(psX509Cert_t));
    if (cert == NULL)
    {
        psError("Memory allocation failure in psX509ParseCert\n");
        return PS_MEM_FAIL;
    }
    Memset(cert, 0x0, sizeof(psX509Cert_t));

# ifdef ALWAYS_KEEP_CERT_DER
    flags |= CERT_STORE_UNPARSED_BUFFER;
# endif /* ALWAYS_KEEP_CERT_DER */

    p = pp;
    far_end = p + size;

    parsing = 1;
    while (parsing)
    {
        /*
          Certificate  ::=  SEQUENCE  {
          tbsCertificate          TBSCertificate,
          signatureAlgorithm      AlgorithmIdentifier,
          signatureValue          BIT STRING }
        */
        rc = parse_single_cert(pool, &p, size, far_end, cert, flags);
        if (rc == PS_SUCCESS)
        {
            numParsedCerts++;
        }
        else
        {
            psAssert(cert->parseStatus != PS_X509_PARSE_SUCCESS);
            if (!(flags & CERT_ALLOW_BUNDLE_PARTIAL_PARSE))
            {
                return rc;
            }
        }

        numCerts++;

        /*
          Check whether we reached the end of the input DER stream.

          An additional sanity check is to ensure that there are least
          MIN_CERT_SIZE bytes left in the stream. We wish to avoid
          having to call parse_single_cert for any residual garbage
          in the stream.
        */
        #define MIN_CERT_SIZE 256
        if ((p != far_end) && (p < (far_end + 1))
                && (far_end - p) > MIN_CERT_SIZE)
        {
            if (*p == 0x0 && *(p + 1) == 0x0)
            {
                parsing = 0; /* An indefinite length stream was passed in */
                /* caller will have to deal with skipping these because they
                    would have read off the TL of this ASN.1 stream */
            }
            else
            {
                cert->next = psMalloc(pool, sizeof(psX509Cert_t));
                if (cert->next == NULL)
                {
                    psError("Memory allocation error in psX509ParseCert\n");
                    return PS_MEM_FAIL;
                }
                cert = cert->next;
                Memset(cert, 0x0, sizeof(psX509Cert_t));
                cert->pool = pool;
            }
        }
        else
        {
            parsing = 0;
        }
    }

    if (flags & CERT_ALLOW_BUNDLE_PARTIAL_PARSE)
    {
        /*
          Return number of successfully parsed certs.
          Note: this flag is never set when called from the SSL layer.
        */
        psTraceIntCrypto("Parsed %d certs", numParsedCerts);
        psTraceIntCrypto(" from a total of %d certs\n", numCerts);
        return numParsedCerts;
    }

    if (numParsedCerts == 0)
        return PS_PARSE_FAIL;

    /*
      Return length of parsed DER stream.
      Some functions in the SSL layer require this.
    */
    return (int32) (p - pp);
}

# ifdef USE_CERT_PARSE
static void freeOrgUnitList(x509OrgUnit_t *orgUnit, psPool_t *allocPool)
{
    x509OrgUnit_t *ou;

    while (orgUnit != NULL)
    {
        ou = orgUnit;
        orgUnit = ou->next;
        psFree(ou->name, allocPool);
        psFree(ou, allocPool);
    }
}

static void freeDomainComponentList(x509DomainComponent_t *domainComponent,
    psPool_t *allocPool)
{
    x509DomainComponent_t *dc;

    while (domainComponent != NULL)
    {
        dc = domainComponent;
        domainComponent = dc->next;
        psFree(dc->name, allocPool);
        psFree(dc, allocPool);
    }
}

int32_t x509NewExtensions(x509v3extensions_t **extensions, psPool_t *pool)
{
    x509v3extensions_t *ext;

    ext = psMalloc(pool, sizeof(x509v3extensions_t));
    if (ext == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(ext, 0x0, sizeof(x509v3extensions_t));
    ext->pool = pool;
    ext->bc.pathLenConstraint = -1;
    ext->bc.cA = CA_UNDEFINED;
    ext->refCount = 1;

    *extensions = ext;

    return PS_SUCCESS;
}

void x509FreeExtensions(x509v3extensions_t *extensions)
{

    x509GeneralName_t *active, *inc;

#  if defined(USE_FULL_CERT_PARSE) || defined(USE_CERT_GEN)
#   ifdef USE_CERT_POLICY_EXTENSIONS
    x509PolicyQualifierInfo_t *qual_info, *qual_info_inc;
    x509PolicyInformation_t *pol_info, *pol_info_inc;
    x509policyMappings_t *pol_map, *pol_map_inc;
#   endif
    x509authorityInfoAccess_t *authInfo, *authInfoInc;
#  endif /* USE_FULL_CERT_PARSE || USE_CERT_GEN */

    if (extensions == NULL)
    {
        return;
    }
    if (extensions->refCount > 1)
    {
        extensions->refCount--;
        return;
    }
    extensions->refCount = 0;

    if (extensions->san)
    {
        active = extensions->san;
        while (active != NULL)
        {
            inc = active->next;
            psFree(active->data, extensions->pool);
            if (active->oidLen > 0)
            {
                psFree(active->oid, extensions->pool);
            }
            psFree(active, extensions->pool);
            active = inc;
        }
    }
#  if defined(USE_FULL_CERT_PARSE) || defined(USE_CERT_GEN)
    if (extensions->issuerAltName)
    {
        active = extensions->issuerAltName;
        while (active != NULL)
        {
            inc = active->next;
            psFree(active->data, extensions->pool);
            if (active->oidLen > 0)
            {
                psFree(active->oid, extensions->pool);
            }
            psFree(active, extensions->pool);
            active = inc;
        }
    }

    if (extensions->authorityInfoAccess)
    {
        authInfo = extensions->authorityInfoAccess;
        while (authInfo != NULL)
        {
            authInfoInc = authInfo->next;
            psFree(authInfo->ocsp, extensions->pool);
            psFree(authInfo->caIssuers, extensions->pool);
            psFree(authInfo, extensions->pool);
            authInfo = authInfoInc;
        }
    }
#  endif /* USE_FULL_CERT_PARSE || USE_CERT_GEN */

#  ifdef USE_CRL
    if (extensions->crlNum)
    {
        psFree(extensions->crlNum, extensions->pool);
    }
    if (extensions->crlDist)
    {
        active = extensions->crlDist;
        while (active != NULL)
        {
            inc = active->next;
            psFree(active->data, extensions->pool);
            psFree(active, extensions->pool);
            active = inc;
        }
    }
#  endif /* CRL */

#  ifdef USE_FULL_CERT_PARSE
    if (extensions->nameConstraints.excluded)
    {
        active = extensions->nameConstraints.excluded;
        while (active != NULL)
        {
            inc = active->next;
            psFree(active->data, extensions->pool);
            psFree(active, extensions->pool);
            active = inc;
        }
    }
    if (extensions->nameConstraints.permitted)
    {
        active = extensions->nameConstraints.permitted;
        while (active != NULL)
        {
            inc = active->next;
            psFree(active->data, extensions->pool);
            psFree(active->oid, extensions->pool);
            psFree(active, extensions->pool);
            active = inc;
        }
    }
#  endif /* USE_FULL_CERT_PARSE */
    if (extensions->sk.id)
    {
        psFree(extensions->sk.id, extensions->pool);
    }
    if (extensions->ak.keyId)
    {
        psFree(extensions->ak.keyId, extensions->pool);
    }
    if (extensions->ak.serialNum)
    {
        psFree(extensions->ak.serialNum,
            extensions->pool);
    }
    psX509FreeDNStruct(&extensions->ak.attribs, extensions->pool);

#  if defined(USE_FULL_CERT_PARSE) || defined(USE_CERT_GEN)
#   ifdef USE_CERT_POLICY_EXTENSIONS
    pol_info = extensions->certificatePolicy.policy;
    while (pol_info != NULL)
    {
        /* Free PolicyInformation member variables. */
        pol_info_inc = pol_info->next;
        psFree(pol_info->policyAsnOid, extensions->pool);
        qual_info = pol_info->qualifiers;
        while (qual_info != NULL)
        {
            /* Free QualifierInfo member variables. */
            qual_info_inc = qual_info->next;
            psFree(qual_info->cps, extensions->pool);
            psFree(qual_info->unoticeOrganization, extensions->pool);
            psFree(qual_info->unoticeExplicitText, extensions->pool);
            psFree(qual_info, extensions->pool);
            qual_info = qual_info_inc;
        }
        psFree(pol_info, extensions->pool);
        pol_info = pol_info_inc;
    }

    pol_map = extensions->policyMappings;
    while (pol_map != NULL)
    {
        pol_map_inc = pol_map->next;
        psFree(pol_map->issuerDomainPolicy, extensions->pool);
        psFree(pol_map->subjectDomainPolicy, extensions->pool);
        psFree(pol_map, extensions->pool);
        pol_map = pol_map_inc;
    }
#  endif /* USE_CERT_POLICY_EXTENSIONS */

    if (extensions->netscapeComment)
    {
        if (extensions->netscapeComment->comment)
        {
            psFree(extensions->netscapeComment->comment, extensions->pool);
        }
        psFree(extensions->netscapeComment, extensions->pool);
    }

    if (extensions->otherAttributes)
    {
        psDynBufUninit(extensions->otherAttributes);
        psFree(extensions->otherAttributes, extensions->pool);
    }
#  endif /* USE_FULL_CERT_PARSE || USE_CERT_GEN */
}

int32_t psX509GetNumDNAttributes(const x509DNattributes_t *DN)
{
    int32_t i;

    if (DN == NULL)
    {
        return PS_ARG_FAIL;
    }

    for (i = 0; i < DN_NUM_ATTRIBUTES_MAX; i++)
    {
        if (DN->attributeOrder[i] == 0)
        {
            break;
        }
    }

    return i;
}

int32_t psX509GetDNAttributeTypeAndValue(const x509DNattributes_t *DN,
        int32_t index,
        x509DNAttributeType_t *attrType,
        short *valueType,
        psSize_t *valueLen,
        char **value)
{
    int32_t numValues, maxIndex, i, nthOccurrence = 0;
    x509OrgUnit_t *orgUnit;
    x509DomainComponent_t *domainComponent;

    psAssert(DN && attrType && valueType && valueLen && value);

    numValues = psX509GetNumDNAttributes(DN);
    if (numValues < 0)
    {
        return PS_ARG_FAIL;
    }
    if (numValues == 0)
    {
        return PS_ARG_FAIL;
    }

    maxIndex = numValues - 1;
    if (index > maxIndex)
    {
        psTraceIntCrypto("psX509GetDNAttributeTypeAndValue: index too high " \
                "(max for this DN is %d)\n", maxIndex);
        return PS_ARG_FAIL;
    }

# define SET_VALUE(attr)                                                \
    do                                                                  \
    {                                                                   \
        *valueType = DN->attr ## Type;                                  \
        *valueLen = DN-> attr ## Len;                                   \
        *value = DN->attr;                                              \
    }                                                                   \
    while (0)

    *attrType = DN->attributeOrder[index];
    for (i = 0; i < index; i++)
    {
        /* Compute number of preceeding attributes of the this type.
           Currently needed only for orgUnit and domainComponent. */
        if (DN->attributeOrder[i] == *attrType)
        {
            nthOccurrence++;
        }
    }

    switch (*attrType)
    {
    case ATTRIB_COUNTRY_NAME:
        SET_VALUE(country);
        break;
    case ATTRIB_STATE_PROVINCE:
        SET_VALUE(state);
        break;
    case ATTRIB_ORGANIZATION:
        SET_VALUE(organization);
        break;
    case ATTRIB_ORG_UNIT:
        orgUnit = psX509GetOrganizationalUnit(DN, nthOccurrence);
        if (orgUnit == NULL)
        {
            return PS_FAILURE;
        }
        *value = orgUnit->name;
        *valueType = orgUnit->type;
        *valueLen = orgUnit->len;
        break;
    case ATTRIB_DN_QUALIFIER:
        SET_VALUE(dnQualifier);
        break;
    case ATTRIB_COMMON_NAME:
        SET_VALUE(commonName);
        break;
    case ATTRIB_SERIALNUMBER:
        SET_VALUE(serialNumber);
        break;
    case ATTRIB_DOMAIN_COMPONENT:
        domainComponent = psX509GetDomainComponent(DN, nthOccurrence);
        if (domainComponent == NULL)
        {
            return PS_FAILURE;
        }
        *value = domainComponent->name;
        *valueType = domainComponent->type;
        *valueLen = domainComponent->len;
        break;
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
    case ATTRIB_LOCALITY:
        SET_VALUE(locality);
        break;
    case ATTRIB_TITLE:
        SET_VALUE(title);
        break;
    case ATTRIB_SURNAME:
        SET_VALUE(surname);
        break;
    case ATTRIB_GIVEN_NAME:
        SET_VALUE(givenName);
        break;
    case ATTRIB_INITIALS:
        SET_VALUE(initials);
        break;
    case ATTRIB_PSEUDONYM:
        SET_VALUE(pseudonym);
        break;
    case ATTRIB_GEN_QUALIFIER:
        SET_VALUE(generationQualifier);
        break;
#  endif /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#  ifdef USE_EXTRA_DN_ATTRIBUTES
    case ATTRIB_STREET_ADDRESS:
        SET_VALUE(streetAddress);
        break;
    case ATTRIB_POSTAL_ADDRESS:
        SET_VALUE(postalAddress);
        break;
    case ATTRIB_TELEPHONE_NUMBER:
        SET_VALUE(telephoneNumber);
        break;
    case ATTRIB_UID:
        SET_VALUE(uid);
        break;
    case ATTRIB_NAME:
        SET_VALUE(name);
        break;
    case ATTRIB_EMAIL:
        SET_VALUE(email);
        break;
#  endif /* USE_EXTRA_DN_ATTRIBUTES */
    default:
        psTraceCrypto("Unsupported DN attribute type\n");
        psTraceCrypto("Maybe you need to enable " \
                "USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD or " \
                "USE_EXTRA_DN_ATTRIBUTES?\n");
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}

int32_t psX509GetDNAttributeIndex(const x509DNattributes_t *DN,
        x509DNAttributeType_t attrType,
        int32_t nth_occurrence)
{
    x509DNAttributeType_t foundType;
    short valueType;
    psSize_t valueLen;
    char *value;
    int32_t rc, ix, numFound = 0;

    for (ix = 0; ix < DN_NUM_ATTRIBUTES_MAX; ix++)
    {
        rc = psX509GetDNAttributeTypeAndValue(
                DN,
                ix,
                &foundType,
                &valueType,
                &valueLen,
                &value);
        if (rc < 0)
        {
            return rc;
        }
        if (foundType == attrType)
        {
            numFound++;
            if (numFound == nth_occurrence)
            {
                return ix;
            }
        }
    }

    return PS_FAILURE;
}

int32_t psX509GetNumOrganizationalUnits(const x509DNattributes_t *DN)
{
    x509OrgUnit_t *ou;
    int32_t res = 0;

    if (DN == NULL)
    {
        return PS_ARG_FAIL;
    }

    if (DN->orgUnit == NULL)
    {
        return 0;
    }

    res = 1;
    ou = DN->orgUnit;
    while (ou->next != NULL)
    {
        ou = ou->next;
        res++;
    }

    return res;
}

x509OrgUnit_t *psX509GetOrganizationalUnit(const x509DNattributes_t *DN,
    int32_t index)
{
    x509OrgUnit_t *ou;
    int32_t i;

    if (DN == NULL || DN->orgUnit == NULL || index < 0)
    {
        return NULL;
    }

    /*
       Note: the OU list is in reverse order. The last item
       (i.e the item with largest index) is at the list head.
     */

    i = psX509GetNumOrganizationalUnits(DN) - 1; /* Largest index. */
    if (i < 0)
    {
        return NULL;
    }

    ou = DN->orgUnit;
    if (i == index)
    {
        return ou;
    }

    while (ou->next != NULL)
    {
        ou = ou->next;
        i--;
        if (i < 0)
        {
            return NULL;
        }
        if (i == index)
        {
            return ou;
        }
    }

    return NULL;
}

int32_t psX509GetNumDomainComponents(const x509DNattributes_t *DN)
{
    x509DomainComponent_t *dc;
    int32_t res = 0;

    if (DN == NULL)
    {
        return PS_ARG_FAIL;
    }

    if (DN->domainComponent == NULL)
    {
        return 0;
    }

    res = 1;
    dc = DN->domainComponent;
    while (dc->next != NULL)
    {
        dc = dc->next;
        res++;
    }

    return res;
}

x509DomainComponent_t *psX509GetDomainComponent(const x509DNattributes_t *DN,
    int32_t index)
{
    x509DomainComponent_t *dc;
    int32_t i;

    if (DN == NULL || DN->domainComponent == NULL || index < 0)
    {
        return NULL;
    }

    /*
       Note: the DC list is in reverse order. The last item
       (i.e the item with largest index) is at the list head.
     */

    i = psX509GetNumDomainComponents(DN) - 1; /* Largest index. */
    if (i < 0)
    {
        return NULL;
    }

    dc = DN->domainComponent;
    if (i == index)
    {
        return dc;
    }

    while (dc->next != NULL)
    {
        dc = dc->next;
        i--;
        if (i < 0)
        {
            return NULL;
        }
        if (i == index)
        {
            return dc;
        }
    }

    return NULL;
}

int32_t psX509GetConcatenatedDomainComponent(const x509DNattributes_t *DN,
    char **out_str,
    size_t *out_str_len)
{
    x509DomainComponent_t *dc;
    int32_t i = 0;
    psSize_t total_len = 0;
    int32_t num_dcs = 0;
    int32_t pos = 0;

    if (DN == NULL || out_str == NULL)
    {
        return PS_ARG_FAIL;
    }

    num_dcs = psX509GetNumDomainComponents(DN);
    if (num_dcs == 0)
    {
        *out_str = NULL;
        *out_str_len = 0;
        return PS_SUCCESS;
    }

    for (i = 0; i < num_dcs; i++)
    {
        dc = psX509GetDomainComponent(DN, i);
        if (dc == NULL)
        {
            return PS_FAILURE;
        }
        total_len += dc->len - DN_NUM_TERMINATING_NULLS;
        /* We will add a dot between the components. */
        if (i != (num_dcs - 1))
        {
            total_len += 1;
        }
    }

    total_len += DN_NUM_TERMINATING_NULLS;

    *out_str = psMalloc(NULL, total_len);
    if (*out_str == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(*out_str, 0, total_len);

    /* The top-level DC is usually listed first. So we start from the
       other end. */
    pos = 0;
    for (i = num_dcs - 1; i >= 0; i--)
    {
        dc = psX509GetDomainComponent(DN, i);
        if (dc == NULL)
        {
            psFree(*out_str, NULL);
            *out_str = NULL;
            return PS_FAILURE;
        }
        Memcpy(*out_str + pos, dc->name,
            dc->len - DN_NUM_TERMINATING_NULLS);
        pos += dc->len - DN_NUM_TERMINATING_NULLS;
        if (i != 0)
        {
            (*out_str)[pos] = '.';
            pos++;
        }
    }

    if (pos != total_len - DN_NUM_TERMINATING_NULLS)
    {
        psFree(*out_str, NULL);
        *out_str = NULL;
        return PS_FAILURE;
    }

    *out_str_len = (size_t) total_len;

    return PS_SUCCESS;
}
# endif /* USE_CERT_PARSE */
# ifdef USE_FULL_CERT_PARSE
/** Long, ugly function that concatenates all the DN components
    to produce OpenSSL-style output.

    This function aims to produce output identical
    to X509_NAME_oneline(), which seems to be function used by
    the openssl x509 utility to print out DNs.

    The amount of code is rather large, so compile this only
    when USE_FULL_CERT_PARSE is defined.

    On success, the caller is responsible for freeing the
    returned string.

    Set userOriginalAttributeOrder to PS_TRUE to print out the attributes
    in the order in which they were parsed. Otherwise, the function
    will imitate the print order of the openssl x509 command-line tool.
 */
static int32_t concatenate_dn(psPool_t *pool,
    const x509DNattributes_t *dn,
    psBool_t useOriginalAttributeOrder,
    char **out_str,
    size_t *out_str_len)
{
    size_t total_len = 0;
    char *str, *p;
    const char *country_prefix = "C=";
    const char *state_prefix = "ST=";
    const char *organization_prefix = "O=";
    const char *organizationalUnit_prefix = "OU=";
    const char *dnQualifier_prefix = "/dnQualifier=";
    const char *commonName_prefix = "CN=";
    const char *serialNumber_prefix = "/serialNumber=";
    const char *domainComponent_prefix = "DC=";
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
    const char *locality_prefix = "L=";
    const char *title_prefix = "/title=";
    const char *surname_prefix = "SN=";
    const char *givenName_prefix = "GN=";
    const char *initials_prefix = "/initials=";
    const char *pseudonym_prefix = "/pseudonym=";
    const char *generationQualifier_prefix = "/generationQualifier=";
#  endif /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#  ifdef USE_EXTRA_DN_ATTRIBUTES
    const char *streetAddress_prefix = "/street=";
    const char *postalAddress_prefix = "/postalAddress=";
    const char *telephoneNumber_prefix = "/telephoneNumber=";
    const char *uid_prefix = "/UID=";
    const char *name_prefix = "/name=";
    const char *email_prefix = "/emailAddress=";
#  endif /* USE_EXTRA_DN_ATTRIBUTES */
    x509DomainComponent_t *dc;
    int num_dcs;
    x509OrgUnit_t *orgUnit;
    int num_ous;
    int first_len = 1;
    int first_field = 1;
    const x509DNAttributeType_t *parse_order = dn->attributeOrder;
    x509DNAttributeType_t print_order[DN_NUM_ATTRIBUTES_MAX] = {0};
    const x509DNAttributeType_t ossl_order[] = {
        ATTRIB_COUNTRY_NAME,
        ATTRIB_STATE_PROVINCE,
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
        ATTRIB_LOCALITY,
#  endif
        ATTRIB_ORGANIZATION,
        ATTRIB_ORG_UNIT,
        ATTRIB_COMMON_NAME,
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        ATTRIB_NAME,
#  endif
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
        ATTRIB_GIVEN_NAME,
        ATTRIB_SURNAME,
#  endif
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        ATTRIB_DOMAIN_COMPONENT,
        ATTRIB_EMAIL,
#  endif
        ATTRIB_SERIALNUMBER,
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        ATTRIB_STREET_ADDRESS,
#  endif
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
        ATTRIB_TITLE,
#  endif
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        ATTRIB_POSTAL_ADDRESS,
        ATTRIB_TELEPHONE_NUMBER,
#  endif
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
        ATTRIB_PSEUDONYM,
        ATTRIB_GEN_QUALIFIER,
        ATTRIB_INITIALS,
#  endif
        ATTRIB_DN_QUALIFIER,
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        ATTRIB_UID,
#  endif
    };
    int32_t ossl_order_len = sizeof(ossl_order)/sizeof(ossl_order[0]);
    int32_t i, j, k;
    int32_t numAttributes;
    int32_t nthOccurrenceOrgUnit = 0;
    int32_t nthOccurrenceDC = 0;
    x509DNAttributeType_t attr;

#  define INC_LEN(X)                                \
    if (dn->X ## Len > 0) {                         \
        if (!first_len && X ## _prefix[0] != '/') { \
            total_len += 2;                         \
        }                                           \
        first_len = 0;                              \
        total_len += Strlen(X ## _prefix) +         \
            dn->X ## Len -                          \
            DN_NUM_TERMINATING_NULLS;               \
    }

    INC_LEN(country);
    INC_LEN(state);
    INC_LEN(organization);
    num_ous = psX509GetNumOrganizationalUnits(dn);
    if (num_ous > 0)
    {
        for (i = 0; i < num_ous; i++)
        {
            orgUnit = psX509GetOrganizationalUnit(dn, i);
            if (orgUnit == NULL)
            {
                psTraceCrypto("psX509GetOrganizationalUnit failed\n");
                return PS_FAILURE;
            }
            if (first_len)
            {
                first_len = 0;
            }
            else
            {
                total_len += 2;
            }
            total_len += Strlen(organizationalUnit_prefix);
            total_len += orgUnit->len - DN_NUM_TERMINATING_NULLS;
        }
    }
    INC_LEN(dnQualifier);
    INC_LEN(commonName);
    INC_LEN(serialNumber);

#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
    INC_LEN(locality);
    INC_LEN(title);
    INC_LEN(surname);
    INC_LEN(givenName);
    INC_LEN(initials);
    INC_LEN(pseudonym);
    INC_LEN(generationQualifier);
#  endif /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */

#  ifdef USE_EXTRA_DN_ATTRIBUTES
    INC_LEN(streetAddress);
    INC_LEN(postalAddress);
    INC_LEN(telephoneNumber);
    INC_LEN(uid);
    INC_LEN(name);
    INC_LEN(email);
#  endif /* USE_EXTRA_DN_ATTRIBUTES */

    num_dcs = psX509GetNumDomainComponents(dn);
    if (num_dcs > 0)
    {
        for (i = 0; i < num_dcs; i++)
        {
            total_len += Strlen(domainComponent_prefix);
            if (first_len)
            {
                first_len = 0;
            }
            else
            {
                total_len += 2;
            }
            dc = psX509GetDomainComponent(dn, i);
            if (dc == NULL)
            {
                psTraceCrypto("psX509GetDomainComponent failed\n");
                return PS_FAILURE;
            }
            total_len += dc->len - DN_NUM_TERMINATING_NULLS;
        }
    }

    /*
       Sanity check.*/
    if (total_len > 100000)
    {
        psTraceCrypto("concatenate_dn: sanity limit exceeded\n");
        return PS_ARG_FAIL;
    }

    str = psMalloc(pool, total_len + 1);
    if (str == NULL)
    {
        psTraceCrypto("concatenate_dn: out of mem\n");
        return PS_MEM_FAIL;
    }
    Memset(str, 0, total_len + 1);

    p = str;

    /*
       We are going to imitate the OpenSSL output format.
       For common fields such as country (C) or state (ST), there is
       a 1-2 letter ID and the printout is e.g. "ST=[value]".
       For other fields, the prefix is "/field_name=[value]".
       Note that there is comma and a space ", " before fields with
       a 1-2 letter ID, but not before the "/field_name=" fields.
       Example:

       C=US, ST=Test State or Province, L=Test Locality, O=Organization Name,
       OU=First Organizational Unit Name, OU=Second Organizational Unit
       Name, OU=Third Organizational Unit Name, CN=Common Name
       /name=GivenName Surname, GN=Givenname, SN=Surname, DC=com,
       DC=insidesecure,
       DC=test/emailAddress=test@email.address/serialNumber=012bf123aa
       /street=MyStreetAddress99/title=Dr./postalAddress=12345
       /telephoneNumber=1111-2222-3333/pseudonym=myPseudonym
       /generationQualifier=III/initials=G.S.
       /dnQualifier=123456789/UID=root
     */

#  define PRINT_FIELD(field)                                    \
    if (dn->field ## Len > 0) {                                 \
        if (first_field) {                                      \
            first_field = 0;                                    \
        } else {                                                \
            if (field ## _prefix[0] != '/') {                   \
                *p++ = ',';                                     \
                *p++ = ' ';                                     \
            }                                                   \
        }                                                       \
        Memcpy(p, field ## _prefix, Strlen(field ## _prefix));  \
        p += Strlen(field ## _prefix);                          \
        Memcpy(p, dn->field,                                    \
                dn->field ## Len - DN_NUM_TERMINATING_NULLS);   \
        p += dn->field ## Len - DN_NUM_TERMINATING_NULLS;       \
    }

    numAttributes = psX509GetNumDNAttributes(dn);
    if (numAttributes < 0)
    {
        psTraceCrypto("psX509GetNumDNAttributes failed\n");
        return PS_FAILURE;
    }

    if (useOriginalAttributeOrder)
    {
        /* Print in parse order. */
        for (i = 0; i < numAttributes; i++)
        {
            print_order[i] = parse_order[i];
        }
    }
    else
    {
        /* Print in openssl x509's order. */
        k = 0;
        for (i = 0; i < ossl_order_len; i++)
        {
            attr = ossl_order[i];
            for (j = 0; j < DN_NUM_ATTRIBUTES_MAX; j++)
            {
                if (parse_order[j] == attr)
                {
                    print_order[k++] = attr;
                }
            }
        }
        psAssert(numAttributes == k);
    }

    for (i = 0; i < numAttributes; i++)
    {
        switch (print_order[i])
        {
        case ATTRIB_COUNTRY_NAME:
            PRINT_FIELD(country);
            break;
        case ATTRIB_ORGANIZATION:
            PRINT_FIELD(organization);
            break;
        case ATTRIB_ORG_UNIT:
            orgUnit = psX509GetOrganizationalUnit(dn, nthOccurrenceOrgUnit);
            if (orgUnit == NULL)
            {
                psTraceCrypto("psX509GetOrganizationalUnit failed\n");
                psFree(str, pool);
                return PS_FAILURE;
            }
            nthOccurrenceOrgUnit++;
            if (first_field)
            {
                first_field = 0;
            }
            else
            {
                *p++ = ',';
                *p++ = ' ';
            }
            Memcpy(p, organizationalUnit_prefix,
                    Strlen(organizationalUnit_prefix));
            p += Strlen(organizationalUnit_prefix);
            Memcpy(p, orgUnit->name,
                    orgUnit->len - DN_NUM_TERMINATING_NULLS);
            p += orgUnit->len - DN_NUM_TERMINATING_NULLS;
            break;
        case ATTRIB_DN_QUALIFIER:
            PRINT_FIELD(dnQualifier);
            break;
        case ATTRIB_STATE_PROVINCE:
            PRINT_FIELD(state);
            break;
        case ATTRIB_COMMON_NAME:
            PRINT_FIELD(commonName);
            break;
        case ATTRIB_DOMAIN_COMPONENT:
            dc = psX509GetDomainComponent(dn, nthOccurrenceDC);
            if (dc == NULL)
            {
                psTraceCrypto("psX509GetDomainComponent failed\n");
                psFree(str, pool);
                return PS_FAILURE;
            }
            nthOccurrenceDC++;
            if (first_field)
            {
                first_field = 0;
            }
            else
            {
                *p++ = ',';
                *p++ = ' ';
            }
            Memcpy(p, domainComponent_prefix,
                    Strlen(domainComponent_prefix));
            p += Strlen(domainComponent_prefix);
            Memcpy(p, dc->name, dc->len - DN_NUM_TERMINATING_NULLS);
            p += dc->len - DN_NUM_TERMINATING_NULLS;
            break;
        case ATTRIB_SERIALNUMBER:
            PRINT_FIELD(serialNumber);
            break;
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
        case ATTRIB_LOCALITY:
            PRINT_FIELD(locality);
            break;
        case ATTRIB_TITLE:
            PRINT_FIELD(title);
            break;
        case ATTRIB_SURNAME:
            PRINT_FIELD(surname);
            break;
        case ATTRIB_GIVEN_NAME:
            PRINT_FIELD(givenName);
            break;
        case ATTRIB_INITIALS:
            PRINT_FIELD(initials);
            break;
        case ATTRIB_PSEUDONYM:
            PRINT_FIELD(pseudonym);
            break;
        case ATTRIB_GEN_QUALIFIER:
            PRINT_FIELD(generationQualifier);
            break;
#  endif    /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        case ATTRIB_STREET_ADDRESS:
            PRINT_FIELD(streetAddress);
            break;
        case ATTRIB_POSTAL_ADDRESS:
            PRINT_FIELD(postalAddress);
            break;
        case ATTRIB_TELEPHONE_NUMBER:
            PRINT_FIELD(telephoneNumber);
            break;
        case ATTRIB_UID:
            PRINT_FIELD(uid);
            break;
        case ATTRIB_NAME:
            PRINT_FIELD(name);
            break;
        case ATTRIB_EMAIL:
            PRINT_FIELD(email);
            break;
#  endif    /* USE_EXTRA_DN_ATTRIBUTES */
        default:
            break;
        }
    }

    psAssert(total_len == (p - str));

    *p++ = '\0';
    *out_str = str;
    *out_str_len = total_len;

    return PS_SUCCESS;
}

int32_t psX509GetOnelineDN(const x509DNattributes_t *DN,
    char **out_str,
    size_t *out_str_len,
    uint32_t flags)
{
    psBool_t useOriginalAttributeOrder = PS_FALSE;

    if (flags & CERT_DN_USE_ORIGINAL_ATTRIBUTE_ORDER)
    {
        useOriginalAttributeOrder = PS_TRUE;
    }

    if (out_str == NULL  || out_str_len == NULL)
    {
        return PS_ARG_FAIL;
    }
    if (DN)
    {
        return concatenate_dn(NULL,
                   DN,
                   useOriginalAttributeOrder,
                   out_str,
                   out_str_len);
    }
    else
    {
        *out_str = NULL;
        *out_str_len = 0;
        return PS_ARG_FAIL;
    }
}

# endif /* USE_FULL_CERT_PARSE */

/******************************************************************************/
/*
    User must call after all calls to psX509ParseCert
    (we violate the coding standard a bit here for clarity)
 */
void psX509FreeCert(psX509Cert_t *cert)
{
    psX509Cert_t *curr, *next;
    psPool_t *pool;

    curr = cert;
    while (curr)
    {
        pool = curr->pool;
        if (curr->unparsedBin)
        {
            psFree(curr->unparsedBin, pool);
        }
# ifdef USE_CERT_PARSE
        psX509FreeDNStruct(&curr->issuer, pool);
        psX509FreeDNStruct(&curr->subject, pool);
        if (curr->serialNumber)
        {
            psFree(curr->serialNumber, pool);
        }
        if (curr->notBefore)
        {
            psFree(curr->notBefore, pool);
        }
        if (curr->notAfter)
        {
            psFree(curr->notAfter, pool);
        }
        if (curr->signature)
        {
            psFree(curr->signature, pool);
        }
        if (curr->uniqueIssuerId)
        {
            psFree(curr->uniqueIssuerId, pool);
        }
        if (curr->uniqueSubjectId)
        {
            psFree(curr->uniqueSubjectId, pool);
        }

# ifdef USE_ROT_ECC
        if (curr->pubKeyAlgorithm == OID_ECDSA_KEY_ALG)
        {
            psFree(curr->tbsCertStart, pool);
        }
# endif
# ifdef USE_ROT_RSA
        if (curr->pubKeyAlgorithm == OID_RSA_KEY_ALG)
        {
            psFree(curr->tbsCertStart, pool);
        }
# endif
# if defined(USE_CL_RSA) && defined(USE_PKCS1_PSS)
        if (curr->pubKeyAlgorithm == OID_RSASSA_PSS)
        {
            psFree(curr->tbsCertStart, pool);
        }
# endif
        if (curr->publicKey.type != PS_NOKEY)
        {
            switch (curr->pubKeyAlgorithm)
            {
#  ifdef USE_RSA
            case OID_RSA_KEY_ALG:
            case OID_RSASSA_PSS:
                psRsaClearKey(&curr->publicKey.key.rsa);
                break;
#  endif

#  ifdef USE_ECC
            case OID_ECDSA_KEY_ALG:
                psEccClearKey(&curr->publicKey.key.ecc);
                break;
#  endif

#  ifdef USE_ED25519
            case OID_ED25519_KEY_ALG:
                psFree(curr->tbsCertStart, pool);
                break;
#  endif

            default:
                psAssert(0);
                break;
            }
            curr->publicKey.type = PS_NOKEY;
        }

        x509FreeExtensions(&curr->extensions);
# endif /* USE_CERT_PARSE */
        next = curr->next;
        psFree(curr, pool);
        curr = next;
    }
}

/******************************************************************************/
/*
    Currently just returning the raw BIT STRING and size in bytes
 */
# define MIN_HASH_SIZE   16
int32_t psX509GetSignature(psPool_t *pool, const unsigned char **pp, psSize_t len,
    unsigned char **sig, psSize_t *sigLen)
{
    const unsigned char *p = *pp, *end;
    psSize_t llen;

    end = p + len;
    if (len < 1 || (*(p++) != ASN_BIT_STRING) ||
        getAsnLength(&p, len - 1, &llen) < 0 ||
        (uint32) (end - p) < llen ||
        llen < (1 + MIN_HASH_SIZE))
    {

        psTraceCrypto("Initial parse error in getSignature\n");
        return PS_PARSE_FAIL;
    }
    /* We assume this ignore_bits byte is always 0.  */
    psAssert(*p == 0);
    p++;
    /* Length was including the ignore_bits byte, subtract it */
    *sigLen = llen - 1;
    *sig = psMalloc(pool, *sigLen);
    if (*sig == NULL)
    {
        psError("Memory allocation error in getSignature\n");
        return PS_MEM_FAIL;
    }
    Memcpy(*sig, p, *sigLen);
    *pp = p + *sigLen;
    return PS_SUCCESS;
}

# ifdef USE_CERT_PARSE
/******************************************************************************/
/*
    Validate the expected name against a subset of the GeneralName rules
    for DNS, Email and IP types.
    We assume the expected name is not maliciously entered. If it is, it may
    match an invalid GeneralName in a remote cert chain.
    Returns 0 on valid format, PS_FAILURE on invalid format of GeneralName
 */
int32_t psX509ValidateGeneralName(const char *n)
{
    const char *c;
    int atfound;            /* Ampersand found */
    int notip;              /* Not an ip address */

    if (n == NULL)
    {
        return 0;
    }

    /* Must be at least one character */
    if (*n == '\0')
    {
        return PS_FAILURE;
    }

    atfound = notip = 0;
    for (c = n; *c != '\0'; c++ )
    {

        /* Negative tests first in the loop */
        /* Can't have any combination of . and - and @ together */
        if (c != n)
        {
            if (*c == '.' && *(c - 1) == '.')
            {
                return PS_FAILURE;
            }
            if (*c == '.' && *(c - 1) == '-')
            {
                return PS_FAILURE;
            }
            if (*c == '.' && *(c - 1) == '@')
            {
                return PS_FAILURE;
            }
            if (*c == '-' && *(c - 1) == '.')
            {
                return PS_FAILURE;
            }
            if (*c == '-' && *(c - 1) == '-')
            {
                return PS_FAILURE;
            }
            if (*c == '-' && *(c - 1) == '@')
            {
                return PS_FAILURE;
            }
            if (*c == '@' && *(c - 1) == '.')
            {
                return PS_FAILURE;
            }
            if (*c == '@' && *(c - 1) == '-')
            {
                return PS_FAILURE;
            }
            if (*c == '@' && *(c - 1) == '@')
            {
                return PS_FAILURE;
            }
        }

        /* Note whether we have hit a non numeric name */
        if (*c != '.' && (*c < '0' || *c > '9'))
        {
            notip++;
        }

        /* Now positive tests */
        /* Cannot start or end with . or -, but can contain them */
        if (c != n && *(c + 1) != '\0' && (*c == '.' || *c == '-'))
        {
            continue;
        }
        /* Can contain at most one @ , and not at the start or end */
        if (*c == '@')
        {
            atfound++;
            if (c != n && *(c + 1) != '\0' && atfound == 1)
            {
                continue;
            }
        }
        /* Numbers allowed generally */
        if (*c >= '0' && *c <= '9')
        {
            continue;
        }
        /* Upper and lowercase characters allowed */
        if (*c >= 'A' && *c <= 'Z')
        {
            continue;
        }
        if (*c >= 'a' && *c <= 'z')
        {
            continue;
        }

        /* Everything else is a failure */
        return PS_FAILURE;
    }
    /* RFC 1034 states if it's not an IP, it can't start with a number,
        However, RFC 1123 updates this and does allow a number as the
        first character of a DNS name.
        See the X.509 RFC: http://tools.ietf.org/html/rfc5280#section-4.2.1.6 */
    if (atfound && (*n >= '0' && *n <= '9'))
    {
        return PS_FAILURE;
    }

    /* We could at this point store whether it is a DNS, Email or IP */

    return 0;
}

/******************************************************************************/
/*
    Parses a sequence of GeneralName types*/
static int32_t parseGeneralNames(psPool_t *pool, const unsigned char **buf,
    psSize_t len, const unsigned char *extEnd,
    x509GeneralName_t **name, int16_t limit)
{
    psSize_t otherNameLen;
    const unsigned char *p, *c, *save, *end;
    x509GeneralName_t *activeName, *firstName, *prevName;
    psSize_t terminating_nils = 1; /* terminating zero. */

    if (*name == NULL)
    {
        firstName = NULL;
    }
    else
    {
        firstName = *name;
    }
    p = *buf;
    end = p + len;

#   define MIN_GENERALNAME_LEN 3 /* 1 tag, 1 length octet, 1 content octet.*/
    while (len >= MIN_GENERALNAME_LEN)
    {
        if (firstName == NULL)
        {
            activeName = firstName = psMalloc(pool, sizeof(x509GeneralName_t));
            if (activeName == NULL)
            {
                return PS_MEM_FAIL;
            }
            Memset(firstName, 0x0, sizeof(x509GeneralName_t));
            firstName->pool = pool;
            *name = firstName;
        }
        else
        {
/*
            Find the end
 */
            prevName = firstName;
            activeName = firstName->next;
            while (activeName != NULL)
            {
                prevName = activeName;
                activeName = activeName->next;
            }
            prevName->next = psMalloc(pool, sizeof(x509GeneralName_t));
            if (prevName->next == NULL)
            {
                return PS_MEM_FAIL;
            }
            activeName = prevName->next;
            Memset(activeName, 0x0, sizeof(x509GeneralName_t));
            activeName->pool = pool;
        }
        activeName->id = (x509GeneralNameType_t) (*p & 0xF);
        p++; len--;
        switch (activeName->id)
        {
        case GN_OTHER:
            Strncpy((char *) activeName->name, "other",
                sizeof(activeName->name) - 1);
            /*  OtherName ::= SEQUENCE {
                type-id    OBJECT IDENTIFIER,
                value      [0] EXPLICIT ANY DEFINED BY type-id }
             */
            save = p;
            if (getAsnLength(&p, (uint32) (extEnd - p), &otherNameLen) < 0 ||
                otherNameLen < 1 ||
                (uint32) (extEnd - p) < otherNameLen)
            {
                psTraceCrypto("ASN parse error SAN otherName\n");
                return PS_PARSE_FAIL;
            }

            if (*(p++) != ASN_OID)
            {
                psTraceCrypto("ASN parse error SAN otherName oid\n");
                return -1;
            }
            if (getAsnLength(&p, (int32) (extEnd - p), &activeName->oidLen) < 0)
            {
                psTraceCrypto("ASN parse error SAN otherName oid\n");
                return -1;
            }
            activeName->oid = psMalloc(pool, activeName->oidLen);
            if ((uint32) (extEnd - p) < activeName->oidLen)
            {

                psTraceCrypto("ASN parse error SAN otherName oid\n");
                return -1;
            }
            /* Note activeName->oidLen could be zero here */
            Memcpy(activeName->oid, p, activeName->oidLen);
            p += activeName->oidLen;
            /* value looks like
                0xA0, <len>, <TYPE>, <dataLen>, <data>
                We're supporting only string-type TYPE so just skipping it
             */
            if ((uint32) (extEnd - p) < 1 || *p != 0xA0)
            {
                psTraceCrypto("ASN parse error SAN otherName\n");
                return PS_PARSE_FAIL;
            }
            p++;     /* Jump over A0 */
            if (getAsnLength(&p, (uint32) (extEnd - p), &otherNameLen) < 0 ||
                otherNameLen < 1 ||
                (uint32) (extEnd - p) < otherNameLen)
            {
                psTraceCrypto("ASN parse error SAN otherName value\n");
                return PS_PARSE_FAIL;
            }
            if ((uint32) (extEnd - p) < 1)
            {
                psTraceCrypto("ASN parse error SAN otherName len\n");
                return PS_PARSE_FAIL;
            }
            /* TODO - validate *p == STRING type? */
            p++;     /* Jump over TYPE */
            if (len <= (p - save))
            {
                psTraceCrypto("ASN len error in parseGeneralNames\n");
                return PS_PARSE_FAIL;
            }
            else
            {
                len -= (p - save);
            }
            break;
        case GN_EMAIL:
            Strncpy((char *) activeName->name, "email",
                sizeof(activeName->name) - 1);
            break;
        case GN_DNS:
            Strncpy((char *) activeName->name, "DNS",
                sizeof(activeName->name) - 1);
            break;
        case GN_X400:
            Strncpy((char *) activeName->name, "x400Address",
                sizeof(activeName->name) - 1);
            break;
        case GN_DIR:
            Strncpy((char *) activeName->name, "directoryName",
                sizeof(activeName->name) - 1);
            break;
        case GN_EDI:
            Strncpy((char *) activeName->name, "ediPartyName",
                sizeof(activeName->name) - 1);
            break;
        case GN_URI:
            Strncpy((char *) activeName->name, "URI",
                sizeof(activeName->name) - 1);
            break;
        case GN_IP:
            Strncpy((char *) activeName->name, "iPAddress",
                sizeof(activeName->name) - 1);
            break;
        case GN_REGID:
            Strncpy((char *) activeName->name, "registeredID",
                sizeof(activeName->name) - 1);
            break;
        default:
            Strncpy((char *) activeName->name, "unknown",
                sizeof(activeName->name) - 1);
            break;
        }

        save = p;
        if (getAsnLength(&p, (uint32) (extEnd - p), &activeName->dataLen) < 0 ||
            activeName->dataLen < 1 ||
            (uint32) (extEnd - p) < activeName->dataLen)
        {
            psTraceCrypto("ASN len error in parseGeneralNames\n");
            return PS_PARSE_FAIL;
        }
        if (len <= (p - save))
        {
            psTraceCrypto("ASN len error in parseGeneralNames\n");
            return PS_PARSE_FAIL;
        }
        else
        {
            len -= (p - save);
        }
        if (len < activeName->dataLen)
        {
            psTraceCrypto("ASN len error in parseGeneralNames\n");
            return PS_PARSE_FAIL;
        }

        /*      Currently we validate that the IA5String fields are printable
            At a minimum, this prevents attacks with null terminators or
            invisible characters in the certificate.
            Additional validation of name format is done indirectly
            via byte comparison to the expected name in ValidateGeneralName
            or directly by the user in the certificate callback */
        switch (activeName->id)
        {
        case GN_EMAIL:
        case GN_DNS:
        case GN_URI:
            save = p + activeName->dataLen;
            for (c = p; c < save; c++)
            {
                if (*c < ' ' || *c > '~')
                {
#ifndef DISABLE_X509_GENERAL_NAME_SUPPORT_C_NULL
                    if (*c == '\0' && c == save - 1)
                    {
                        /* Allow single terminating zero byte. */
                        /* This may be result of writing sizeof(name)
                           bytes instead of strlen(name) bytes.
                           Many other products appear to be able to
                           interoperate with such names.
                        */

                        terminating_nils = 0;
                    }
                    else
#endif /* DISABLE_X509_GENERAL_NAME_SUPPORT_C_NULL */
                    {
                        psTraceCrypto("ASN invalid GeneralName character\n");
                        return PS_PARSE_FAIL;
                    }
                }
            }
            break;
        case GN_IP:
            if (activeName->dataLen < 4)
            {
                psTraceCrypto("Unknown GN_IP format\n");
                return PS_PARSE_FAIL;
            }
            break;
        default:
            break;
        }

        activeName->data = psMalloc(pool,
                                    activeName->dataLen + terminating_nils);
        if (activeName->data == NULL)
        {
            psError("Memory allocation error: activeName->data\n");
            return PS_MEM_FAIL;
        }
        /* This guarantees data is null terminated, even for non IA5Strings */
        Memset(activeName->data, 0x0, activeName->dataLen + terminating_nils);
        Memcpy(activeName->data, p, activeName->dataLen);

        p = p + activeName->dataLen;
        len -= activeName->dataLen;

#ifndef DISABLE_X509_GENERAL_NAME_SUPPORT_C_NULL
        if (terminating_nils == 0)
        {
            /* Remove zero byte (in string) from returned length. */
            activeName->dataLen -= 1;
        }
#endif /* DISABLE_X509_GENERAL_NAME_SUPPORT_C_NULL */

        if (limit > 0)
        {
            if (--limit == 0)
            {
                *buf = end;
                return PS_SUCCESS;
            }
        }
    }
    *buf = p;
    return PS_SUCCESS;
}

/* This functionality is considered obsolete. */
#ifdef PS_FIND_OID_NEEDED
/**
    Look up an OID in our known oid table.
    @param[in] oid Array of OID segments to look up in table.
    @param[in] oidlen Number of segments in 'oid'
    @return A valid OID enum on success, 0 on failure.
 */
static oid_e psFindOid(const uint32_t oid[MAX_OID_LEN], uint8_t oidlen)
    PSDEPRECATED_WARN;

static oid_e psFindOid(const uint32_t oid[MAX_OID_LEN], uint8_t oidlen)
{
    int i, j;

    psAssert(oidlen <= MAX_OID_LEN);
    for (j = 0; oid_list[j].id != 0; j++)
    {
        for (i = 0; i < oidlen; i++)
        {
            if ((uint16_t) (oid[i] & 0xFFFF) != oid_list[j].oid[i])
            {
                break;
            }
            if ((i + 1) == oidlen)
            {
                return (oid_e) oid_list[j].id;
            }
        }
    }
    return (oid_e) 0;
}
#endif /* PS_FIND_OID_NEEDED */

/**
    Look up an OID in our known oid table.
    @param[in] oid Copy (or reference) to oid
    @return A valid OID enum on success, 0 on failure.
 */
static oid_e psOidToEnum(psAsnOid_t oid)
{
    int i;
    uint8_t id;
    uint8_t len_encoded;
    unsigned int len;

    id = oid[0];
    len_encoded = oid[1];
    len = len_encoded + 2;

    if (id != ASN_OID || len > MAX_OID_BYTES)
    {
        return (oid_e) 0;
    }

    for (i = 0; oid_list_e[i].id != 0; i++)
    {
        if (oid_list_e[i].oid_encoded[1] == len_encoded &&
            memcmp(oid, oid_list_e[i].oid_encoded, len) == 0)
        {
            return (oid_e) oid_list_e[i].id;
        }
    }
    return (oid_e) 0;
}

#  ifdef USE_CRYPTO_TRACE
/**
    Print an OID in dot notation, with it's symbolic name, if found.
    @param[in] oid Array of OID segments print.
    @param[in] oidlen Number of segments in 'oid'
    @return void

    @note: This function is deprecated in favor of psSprintAsnOid(),
           which is similarin function but uses different arguments.
 */
static inline void psTraceOid(uint32_t oid[MAX_OID_LEN], uint8_t oidlen)
    PSDEPRECATED_WARN;
static inline void psTraceOid(uint32_t oid[MAX_OID_LEN], uint8_t oidlen)
{
    int i;
#ifdef PS_FIND_OID_NEEDED
    int j;
    int found;
#endif /* PS_FIND_OID_NEEDED */

    for (i = 0; i < oidlen; i++)
    {
        if ((i + 1) < oidlen)
        {
            psTraceIntCrypto("%u.", oid[i]);
        }
        else
        {
            psTraceIntCrypto("%u", oid[i]);
        }
    }
#ifdef PS_FIND_OID_NEEDED
    found = 0;
    for (j = 0; oid_list[j].oid[0] != 0 && !found; j++)
    {
        for (i = 0; i < oidlen; i++)
        {
            if ((uint8_t) (oid[i] & 0xFF) != oid_list[j].oid[i])
            {
                break;
            }
            if ((i + 1) == oidlen)
            {
                psTraceStrCrypto(" (%s)", oid_list[j].name);
                found++;
            }
        }
    }
#endif /* PS_FIND_OID_NEEDED */
    psTraceCrypto("\n");
}
#  else
#   define psTraceOid(A, B)
#  endif

/******************************************************************************/

/**
    Print an OID in dot notation, with it's symbolic name, if found.
    @param[in] oid Array of OID segments print.
    @param[in] oidlen Number of segments in 'oid'
    @param[out] out formatting target buffer
                    (must be sufficient: MAX_OID_PRINTED_LEN will suffice.)
    @return void
 */
const char *psSprintAsnOid(
        psAsnOid_t oid,
        char out[MAX_OID_PRINTED_LEN])
{
    int i;
    const char *orig_out = out;
    uint8_t id;
    unsigned int len;
    char *mem;
    oid_e oe;

    id = oid[0];
    len = oid[1] + 2;

    if (id != ASN_OID || len < 2 || len > MAX_OID_BYTES)
    {
        strcpy(out, "(Illegal OID)");
        return out;
    }

    mem = asnFormatOid(
            (psPool_t*) MATRIX_NO_POOL,
            (const unsigned char *) oid,
            len);

    if (mem == NULL)
    {
        strcpy(out, "(OID cannot be displayed)");
    }
    else
    {
        strcpy(out, mem);
    }

    psFree(mem, (psPool_t*) MATRIX_NO_POOL);

    oe = psOidToEnum(oid);
    if (oe != oid_0)
    {
        for (i = 0; oid_names[i].id != oid_0 && oid_names[i].id != oe; i++)
        {
            /* Search for oid_list_e entry with the oid. */
        }
        out += strlen(out);
        sprintf(out, " (%s)", oid_names[i].name);
    }
    return orig_out; /* Return buffer for convenience. */
}

/******************************************************************************/
/*
    X509v3 extensions
 */

#  ifdef USE_FULL_CERT_PARSE
#   ifdef USE_CERT_POLICY_EXTENSIONS
static
int32_t parsePolicyQualifierInfo(psPool_t *pool,
    const unsigned char *p,
    const unsigned char *extEnd,
    psSize_t fullExtLen,
    x509PolicyQualifierInfo_t *qualInfo,
    psSize_t *qual_info_len)
{
    psAsnOid_t asnOid;
    oid_e noid;
    psSize_t len;
    const unsigned char *qualifierStart, *qualifierEnd;
    const unsigned char *noticeNumbersEnd;
    int i;
    int32_t noticeNumber;

    qualifierStart = p;

    /* Parse a PolicyQualifierInfo. */
    if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
    {
        psTraceCrypto("Error parsing certificatePolicies extension\n");
        return PS_PARSE_FAIL;
    }
    *qual_info_len = len + (p - qualifierStart);
    qualifierEnd = qualifierStart + *qual_info_len;

    /* Parse policyQualifierId. */
    if (len < 1 || *p++ != ASN_OID)
    {
        psTraceCrypto("Malformed policy qualifier header\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnLength(&p, fullExtLen, &len) < 0 ||
        fullExtLen < len)
    {
        psTraceCrypto("Malformed extension length\n");
        return PS_PARSE_FAIL;
    }
    if (asnCopyOid(p, len, asnOid) < 1)
    {
        psTraceCrypto("Malformed extension OID\n");
        return PS_PARSE_FAIL;
    }
    /* PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )*/
    noid = psOidToEnum(asnOid);
    p += len;
    if (noid == oid_id_qt_cps)
    {
        if (*p++ != ASN_IA5STRING)
        {
            psTraceCrypto("Malformed extension OID\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnLength(&p, fullExtLen, &len) < 0 ||
            fullExtLen < len)
        {
            psTraceCrypto("Malformed extension length\n");
            return PS_PARSE_FAIL;
        }
        qualInfo->cps = psMalloc(pool, len + 1);
        qualInfo->cpsLen = len;
        Memcpy(qualInfo->cps,
            p, len);
        qualInfo->cps[len] = 0; /* Store as C string. */
        p += len;
    }
    else if (noid == oid_id_qt_unotice)
    {

        /* UserNotice ::= SEQUENCE {
           noticeRef        NoticeReference OPTIONAL,
           explicitText     DisplayText OPTIONAL } */
        if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
        {
            psTraceCrypto("Error parsing certificatePolicies extension\n");
            return PS_PARSE_FAIL;
        }
        if (len == 0 || p >= qualifierEnd)
        {
            /* No optional noticeRef or explicitText.
               Nothing left to parse. */
            return PS_SUCCESS;
        }
        if (*p == (ASN_SEQUENCE | ASN_CONSTRUCTED))
        {
            /*    NoticeReference ::= SEQUENCE {
                  organization     DisplayText,
                  noticeNumbers    SEQUENCE OF INTEGER } */
            if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing certificatePolicies extension\n");
                return PS_PARSE_FAIL;
            }
            /* Parse explicitText. */
            if (*p != ASN_UTF8STRING &&
                *p != ASN_VISIBLE_STRING &&
                *p != ASN_BMPSTRING &&
                *p != ASN_IA5STRING)
            {
                psTraceCrypto("Error parsing certificatePolicies extension."
                    "Only UTF8String, IA5String, BMPString and "
                    "VisibleString are supported in NoticeReferences.\n");
                return PS_PARSE_FAIL;
            }
            qualInfo->unoticeOrganizationEncoding = *p;
            p++;
            /* Parse organization. */
            if (getAsnLength(&p, fullExtLen, &len) < 0 ||
                fullExtLen < len)
            {
                psTraceCrypto("Malformed extension length\n");
                return PS_PARSE_FAIL;
            }
            qualInfo->unoticeOrganization = psMalloc(pool, len + 1);
            if (qualInfo->unoticeOrganization == NULL)
            {
                return PS_MEM_FAIL;
            }
            qualInfo->unoticeOrganizationLen = len;
            Memcpy(qualInfo->unoticeOrganization, p, len);
            qualInfo->unoticeOrganization[len] = 0;  /* Store as C string. */
            p += len;
            /* Parse noticeNumbers. */
            if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing certificatePolicies extension\n");
                return PS_PARSE_FAIL;
            }
            noticeNumbersEnd = p + len;
            i = 0;
            while (p != noticeNumbersEnd)
            {
                if (i == MAX_UNOTICE_NUMBERS)
                {
                    psTraceCrypto("Too many UserNoticeNumbers.\n");
                    return PS_PARSE_FAIL;
                }
                if (getAsnInteger(&p, len, &noticeNumber) < 0)
                {
                    psTraceCrypto("Malformed extension length\n");
                    return PS_PARSE_FAIL;
                }
                qualInfo->unoticeNumbers[i] = noticeNumber;
                i++;
            }
            qualInfo->unoticeNumbersLen = i;
        }
        if (p >= qualifierEnd)
        {
            /* The UserNotice contained noticeRef, but not explicitText. */
            return PS_SUCCESS;
        }
        /* Parse explicitText. */
        if (*p != ASN_UTF8STRING &&
            *p != ASN_VISIBLE_STRING &&
            *p != ASN_BMPSTRING &&
            *p != ASN_IA5STRING)
        {
            psTraceCrypto("Error parsing certificatePolicies extension."
                "Only UTF8String, IA5String, BMPString and "
                "VisibleString are supported in explicitText.\n");
            return PS_PARSE_FAIL;
        }
        qualInfo->unoticeExplicitTextEncoding = *p;
        p++;
        if (getAsnLength(&p, fullExtLen, &len) < 0 ||
            fullExtLen < len)
        {
            psTraceCrypto("Malformed extension length\n");
            return PS_PARSE_FAIL;
        }
        qualInfo->unoticeExplicitText = psMalloc(pool, len + 1);
        if (qualInfo->unoticeExplicitText == NULL)
        {
            return PS_MEM_FAIL;
        }
        qualInfo->unoticeExplicitTextLen = len;
        Memcpy(qualInfo->unoticeExplicitText, p, len);
        qualInfo->unoticeExplicitText[len] = 0; /* Store as C string. */
        p += len;
    }
    else
    {
        psTraceCrypto("Unsupported policyQualifierId\n");
        return PS_PARSE_FAIL;
    }

    return PS_SUCCESS;
}

static
int32_t parsePolicyInformation(psPool_t *pool,
    const unsigned char *p,
    const unsigned char *extEnd,
    psSize_t fullExtLen,
    x509PolicyInformation_t *polInfo,
    psSize_t *pol_info_len)
{
    psAsnOid_t asnOid;
    psSize_t len;
    const unsigned char *qualifierEnd;
    const unsigned char *polInfoStart, *polInfoEnd;
    x509PolicyQualifierInfo_t *qualInfo;
    psSize_t qualInfoLen;

    polInfoStart = p;

    /*
       PolicyInformation ::= SEQUENCE {
       policyIdentifier   CertPolicyId,
       policyQualifiers   SEQUENCE SIZE (1..MAX) OF
       PolicyQualifierInfo OPTIONAL }
     */

    if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
    {
        psTraceCrypto("Error parsing certificatePolicies extension\n");
        return PS_PARSE_FAIL;
    }
    *pol_info_len = len + (p - polInfoStart);
    polInfoEnd = polInfoStart + *pol_info_len;

    /* Parse CertPolicyId. */
    if (*p++ != ASN_OID)
    {
        psTraceCrypto("Malformed extension header\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnLength(&p, fullExtLen, &len) < 0 ||
        fullExtLen < len)
    {
        psTraceCrypto("Malformed extension length\n");
        return PS_PARSE_FAIL;
    }
    if (asnCopyOid(p, len, asnOid) < 1)
    {
        psTraceCrypto("Malformed extension OID\n");
        return PS_PARSE_FAIL;
    }
    p += len;

    /* Store the policy ID. */
    polInfo->policyAsnOid = psMalloc(pool, sizeof(psAsnOid_t));
    if (polInfo->policyAsnOid == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memcpy(polInfo->policyAsnOid, asnOid, sizeof(psAsnOid_t));

    if ((p >= polInfoEnd) ||
        (*p != (ASN_SEQUENCE | ASN_CONSTRUCTED)))
    {
        /* No optional PolicyQualifierInfos. */
        return PS_SUCCESS;
    }

    /* Parse policyQualifiers := SEQUENCE SIZE (1..MAX) OF
       PolicyQualifierInfo OPTIONAL*/
    if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
    {
        psTraceCrypto("Error parsing certificatePolicies extension\n");
        return PS_PARSE_FAIL;
    }
    if (len == 0)
    {
        /*
          Found at least one real-world certificate that has the
          SEQUENCE OF but with 0 policyQualifierInfos. Allow such
          certs to be parsed correctly.

          Strictly speaking this is not a valid encoding: the
          constraint (1..MAX) with OPTIONAL requires that either there
          is at least one policyQualifierInfo or the entire SEQUENCE
          OF is absent.
        */
        return PS_SUCCESS;
    }
    qualifierEnd = p + len;

    polInfo->qualifiers = psMalloc(pool, sizeof(x509PolicyQualifierInfo_t));
    if (polInfo->qualifiers == NULL)
    {
        return PS_MEM_FAIL;
    }
    Memset(polInfo->qualifiers, 0, sizeof(x509PolicyQualifierInfo_t));
    qualInfo = polInfo->qualifiers;

    /* Parse initial PolicyQualifierInfo. */
    if (parsePolicyQualifierInfo(pool,
            p,
            extEnd,
            fullExtLen,
            qualInfo,
            &qualInfoLen) < 0)
    {
        return PS_PARSE_FAIL;
    }
    p += qualInfoLen;

    /* More PolicyQualifierInfos? */
    while ((p < qualifierEnd)
           && (p < extEnd)
           && (*p == (ASN_SEQUENCE | ASN_CONSTRUCTED)))
    {
        qualInfo->next = psMalloc(pool, sizeof(x509PolicyQualifierInfo_t));
        if (qualInfo->next == NULL)
        {
            return PS_MEM_FAIL;
        }
        Memset(qualInfo->next, 0, sizeof(x509PolicyQualifierInfo_t));
        qualInfo = qualInfo->next;

        if (parsePolicyQualifierInfo(pool,
                p,
                extEnd,
                fullExtLen,
                qualInfo,
                &qualInfoLen) < 0)
        {
            return PS_PARSE_FAIL;
        }
        p += qualInfoLen;
    }

    return PS_SUCCESS;
}

static
int32_t parsePolicyConstraints(psPool_t *pool,
    const unsigned char *p,
    const unsigned char *extEnd,
    x509policyConstraints_t *policyConstraints,
    psSize_t *polConstraintsLen)
{
    psSize_t len;
    const unsigned char *polConstraintsStart, *polConstraintsEnd;
    unsigned char tag;
    int num_ints = 0;

    /*
       PolicyConstraints ::= SEQUENCE {
       requireExplicitPolicy           [0] SkipCerts OPTIONAL,
       inhibitPolicyMapping            [1] SkipCerts OPTIONAL }

       SkipCerts ::= INTEGER (0..MAX)
     */

    polConstraintsStart = p;

    if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
    {
        psTraceCrypto("Error parsing policyConstraints extension\n");
        return PS_PARSE_FAIL;
    }
    polConstraintsEnd = p + len;
    *polConstraintsLen = (polConstraintsEnd - polConstraintsStart);

    if (len == 0)
    {
        /* Empty PolicyConstraints. This is allowed by RFC 5280:
           "The behavior of clients that encounter an empty policy
           constraints field is not addressed in this profile.*/
        return PS_SUCCESS;
    }

    /* Parse up to 2 SkipCerts INTEGERS with context-specific tags 0 and 1. */
    while ( num_ints < 2 && (*p == ASN_CONTEXT_SPECIFIC ||
                             *p == (ASN_CONTEXT_SPECIFIC + 1)) )
    {
        tag = *p++;
        if (getAsnLength(&p, (uint32) (polConstraintsEnd - p), &len) < 0 ||
            (uint32) (polConstraintsEnd - p) < len)
        {
            psTraceCrypto("getAsnLength failure in policyConstraints parsing\n");
            return PS_PARSE_FAIL;
        }
        /* We only accept single-octet SkipCerts values. Should be enough
           for all reasonable applications. */
        if (len != 1)
        {
            psTraceCrypto("Too large SkipCerts value in PolicyConstraints.\n");
            return PS_PARSE_FAIL;
        }
        if (tag == ASN_CONTEXT_SPECIFIC)
        {
            policyConstraints->requireExplicitPolicy = (int32_t) *p;
        }
        else
        {
            policyConstraints->inhibitPolicyMappings = (int32_t) *p;
        }
        p += len;
        ++num_ints;
    }

    if (p != polConstraintsEnd)
    {
        psTraceCrypto("Error parsing policyConstraints extension\n");
        return PS_PARSE_FAIL;
    }

    return PS_SUCCESS;
}

static
int32_t parsePolicyMappings(psPool_t *pool,
    const unsigned char *p,
    const unsigned char *extEnd,
    x509policyMappings_t *policyMappings,
    psSize_t *polMappingsLen)
{
    psAsnOid_t asnOid;
    psSize_t len;
    const unsigned char *polMappingsStart, *polMappingsEnd;
    x509policyMappings_t *pol_map;
    int num_mappings = 0;

    /*
       PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
       issuerDomainPolicy      CertPolicyId,
       subjectDomainPolicy     CertPolicyId }
     */

    polMappingsStart = p;

    if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
    {
        psTraceCrypto("Error parsing policyMappings extension\n");
        return PS_PARSE_FAIL;
    }
    polMappingsEnd = p + len;
    *polMappingsLen = (polMappingsEnd - polMappingsStart);

    pol_map = policyMappings;
    while (p < polMappingsEnd &&
           *p == (ASN_SEQUENCE | ASN_CONSTRUCTED))
    {

        if (num_mappings > 0)
        {
            pol_map->next = psMalloc(pool, sizeof(x509policyMappings_t));
            if (pol_map->next == NULL)
            {
                return PS_MEM_FAIL;
            }
            Memset(pol_map->next, 0, sizeof(x509policyMappings_t));
            pol_map = pol_map->next;
        }

        if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
        {
            psTraceCrypto("Error parsing policyMappings extension\n");
            return PS_PARSE_FAIL;
        }

        /* Parse issuerDomainPolicy OID. */
        if (*p++ != ASN_OID)
        {
            psTraceCrypto("Malformed extension header\n");
            return PS_PARSE_FAIL;
        }

        if (getAsnLength(&p, (uint32) (polMappingsEnd - p), &len) < 0 ||
            (uint32) (polMappingsEnd - p) < len)
        {
            psTraceCrypto("getAsnLength failure in policyMappings parsing\n");
            return PS_PARSE_FAIL;
        }
        if (asnCopyOid(p, len, asnOid) < 1)
        {
            psTraceCrypto("Malformed extension OID\n");
            return PS_PARSE_FAIL;
        }
        p += len;

        pol_map->issuerDomainPolicy = psMalloc(pool, sizeof(psAsnOid_t));
        if (pol_map->issuerDomainPolicy == NULL)
        {
            psTraceCrypto("Memory allocation failure.\n");
            return PS_PARSE_FAIL;
        }
        Memcpy(pol_map->issuerDomainPolicy, asnOid, sizeof(psAsnOid_t));

        /* Parse subjectDomainPolicy OID. */
        if (*p++ != ASN_OID)
        {
            psTraceCrypto("Malformed extension header\n");
            return PS_PARSE_FAIL;
        }

        if (getAsnLength(&p, (uint32) (polMappingsEnd - p), &len) < 0 ||
            (uint32) (polMappingsEnd - p) < len)
        {
            psTraceCrypto("getAsnLength failure in policyMappings parsing\n");
            return PS_PARSE_FAIL;
        }
        if (asnCopyOid(p, len, asnOid) < 1)
        {
            psTraceCrypto("Malformed extension OID\n");
            return PS_PARSE_FAIL;
        }
        p += len;

        pol_map->subjectDomainPolicy = psMalloc(pool, sizeof(psAsnOid_t));
        if (pol_map->issuerDomainPolicy == NULL)
        {
            psTraceCrypto("Memory allocation failure.\n");
            return PS_PARSE_FAIL;
        }
        Memcpy(pol_map->subjectDomainPolicy, asnOid, sizeof(psAsnOid_t));

        ++num_mappings;
    }

    if (p != polMappingsEnd)
    {
        psTraceCrypto("Error parsing policyMappings extension\n");
        return PS_PARSE_FAIL;
    }

    return PS_SUCCESS;
}
# endif /* USE_CERT_POLICY_EXTENSIONS */

# ifdef USE_CRL
static
int32_t parseAuthorityInfoAccess(psPool_t *pool,
    const unsigned char *p,
    const unsigned char *extEnd,
    x509authorityInfoAccess_t **authInfo,
    psSize_t *authInfoLen)
{
    psSize_t len, adLen;
    const unsigned char *authInfoStart, *authInfoEnd;
    x509authorityInfoAccess_t *pAuthInfo;
    psAsnOid_t asnOid;
    oid_e noid;
    int first_entry = 0;

    authInfoStart = p;
/*

   id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }

   AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }

   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

   id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }

   id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 */

    /* AuthorityInfoAccessSyntax. */
    if (getAsnSequence(&p, (int32) (extEnd - p), &len) < 0)
    {
        psTraceCrypto("Error parsing authKeyId extension\n");
        return PS_PARSE_FAIL;
    }

    authInfoEnd = p + len;
    *authInfoLen = (authInfoEnd - authInfoStart);

    if (*authInfo == NULL)
    {
        *authInfo = psMalloc(pool, sizeof(x509authorityInfoAccess_t));
        if (*authInfo == NULL)
        {
            return PS_MEM_FAIL;
        }
        Memset(*authInfo, 0, sizeof(x509authorityInfoAccess_t));
        first_entry = 1;
    }

    pAuthInfo = *authInfo;

    while (p < authInfoEnd &&
           *p == (ASN_SEQUENCE | ASN_CONSTRUCTED))
    {

        /* Find the end of the list. */
        while (pAuthInfo->next != NULL)
        {
            pAuthInfo = pAuthInfo->next;
        }
        if (!first_entry)
        {
            /* Malloc space for a new entry. */
            pAuthInfo->next = psMalloc(pool,
                sizeof(x509authorityInfoAccess_t));
            if (pAuthInfo->next == NULL)
            {
                return PS_MEM_FAIL;
            }
            Memset(pAuthInfo->next, 0,
                sizeof(x509authorityInfoAccess_t));
            pAuthInfo = pAuthInfo->next;
        }
        else
        {
            first_entry = 0;
        }

        /* AccessDescription. */
        if (getAsnSequence(&p, (int32) (extEnd - p), &adLen) < 0)
        {
            psTraceCrypto("Error parsing authKeyId extension\n");
            return PS_PARSE_FAIL;
        }
        /* accessMethod. */
        if (*p++ != ASN_OID)
        {
            psTraceCrypto("Malformed extension header\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnLength(&p, (uint32) (authInfoEnd - p), &len) < 0 ||
            (uint32) (authInfoEnd - p) < len)
        {
            psTraceCrypto("getAsnLength failure in authInfo parsing\n");
            return PS_PARSE_FAIL;
        }
        if (asnCopyOid(p, len, asnOid) < 1)
        {
            psTraceCrypto("Malformed extension OID\n");
            return PS_PARSE_FAIL;
        }
        noid = psOidToEnum(asnOid);
        p += len;
        if (noid != oid_id_ad_caIssuers &&
            noid != oid_id_ad_ocsp)
        {
            psTraceCrypto("Unsupported AccessDescription: "
                "only oid_ad_caIssuers and id_ad_ocsp "
                "are supported. \n");
            return PS_PARSE_FAIL;
        }
        /* accessLocation. */
        switch (*p++)
        {
        case (ASN_CONTEXT_SPECIFIC + 6):
            /* uniformResourceIdentifier [6]  IA5String. */
            if (getAsnLength(&p, (uint32) (authInfoEnd - p), &len) < 0 ||
                (uint32) (authInfoEnd - p) < len)
            {
                psTraceCrypto("getAsnLength failure in authInfo parsing\n");
                return PS_PARSE_FAIL;
            }
            if (noid == oid_id_ad_ocsp)
            {
                pAuthInfo->ocsp = psMalloc(pool, len);
                if (pAuthInfo->ocsp == NULL)
                {
                    return PS_MEM_FAIL;
                }
                Memcpy(pAuthInfo->ocsp, p, len);
                pAuthInfo->ocspLen = len;
                p += len;
            }
            else     /* oid_id_ad_caIssuers */
            {
                pAuthInfo->caIssuers = psMalloc(pool, len);
                if (pAuthInfo->caIssuers == NULL)
                {
                    return PS_MEM_FAIL;
                }
                Memcpy(pAuthInfo->caIssuers, p, len);
                pAuthInfo->caIssuersLen = len;
                p += len;
            }
            break;
        default:
            psTraceCrypto("Unsupported string type in AUTH_INFO ACC "
                "(only uniformResourceIdenfitier is "
                "supported). \n");
            return PS_PARSE_FAIL;
        }
    } /* Next AccessDescription, if any. */

    return PS_SUCCESS;
}
#   endif /* USE_CRL */
#  endif /* USE_FULL_CERT_PARSE */

int32_t getExplicitExtensions(psPool_t *pool, const unsigned char **pp,
    psSize_t inlen, int32_t expVal,
    x509v3extensions_t *extensions, uint8_t known)
{
    const unsigned char *p = *pp, *end;
    const unsigned char *extEnd, *extStart, *save;
    unsigned char critical;
    psSize_t len, fullExtLen;
    psAsnOid_t asnOid;
    oid_e noid;

#  ifdef USE_FULL_CERT_PARSE
    psSize_t subExtLen;
    const unsigned char *subSave;
    int32_t nc = 0;
#   ifdef USE_CERT_POLICY_EXTENSIONS
    x509PolicyInformation_t *pPolicy;
    const unsigned char *policiesEnd;
#   endif
#  endif /* USE_FULL_CERT_PARSE */

    end = p + inlen;
    if (inlen < 1)
    {
        return PS_ARG_FAIL;
    }
    extensions->pool = pool;
    extensions->bc.cA = CA_UNDEFINED;

    if (known)
    {
        goto KNOWN_EXT;
    }
/*
    Not treating this as an error because it is optional.
 */
    if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | expVal))
    {
        return 0;
    }
    p++;
    if (getAsnLength(&p, (uint32) (end - p), &len) < 0 ||
        (uint32) (end - p) < len)
    {
        psTraceCrypto("Initial getAsnLength failure in extension parse\n");
        return PS_PARSE_FAIL;
    }
KNOWN_EXT:
/*
    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

    Extension  ::=  SEQUENCE {
        extnID          OBJECT IDENTIFIER,
        extnValue       OCTET STRING    }
 */
    if (getAsnSequence(&p, (uint32) (end - p), &len) < 0 ||
        (uint32) (end - p) < len)
    {
        psTraceCrypto("Initial getAsnSequence failure in extension parse\n");
        return PS_PARSE_FAIL;
    }
    extEnd = p + len;
    while ((p != extEnd) && *p == (ASN_SEQUENCE | ASN_CONSTRUCTED))
    {
        if (getAsnSequence(&p, (uint32) (extEnd - p), &fullExtLen) < 0)
        {
            psTraceCrypto("getAsnSequence failure in extension parse\n");
            return PS_PARSE_FAIL;
        }
        extStart = p;
/*
        Conforming CAs MUST support key identifiers, basic constraints,
        key usage, and certificate policies extensions
 */
        if (extEnd - p < 1 || *p++ != ASN_OID)
        {
            psTraceCrypto("Malformed extension header\n");
            return PS_PARSE_FAIL;
        }
        if (getAsnLength(&p, (uint32) (extEnd - p), &len) < 0 ||
            (uint32) (extEnd - p) < len)
        {
            psTraceCrypto("Malformed extension length\n");
            return PS_PARSE_FAIL;
        }
        if (asnCopyOid(p, len, asnOid) < 1)
        {
            psTraceCrypto("Malformed extension OID\n");
            return PS_PARSE_FAIL;
        }
        noid = psOidToEnum(asnOid);
        p += len;
/*
        Possible boolean value here for 'critical' id.  It's a failure if a
        critical extension is found that is not supported
 */
        critical = 0;
        if (extEnd - p < 1)
        {
            psTraceCrypto("Malformed extension length\n");
            return PS_PARSE_FAIL;
        }
        if (*p == ASN_BOOLEAN)
        {
            p++;
            if (extEnd - p < 2)
            {
                psTraceCrypto("Error parsing critical id len for cert extension\n");
                return PS_PARSE_FAIL;
            }
            if (*p != 1)
            {
                psTraceCrypto("Error parsing critical id for cert extension\n");
                return PS_PARSE_FAIL;
            }
            p++;
            if (*p > 0)
            {
                /* Officially DER TRUE must be 0xFF, openssl is more lax */
                if (*p != 0xFF)
                {
                    psTraceCrypto("Warning: DER BOOLEAN TRUE should be 0xFF\n");
                }
                critical = 1;
            }
            p++;
        }
        if (extEnd - p < 1 || (*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (uint32) (extEnd - p), &len) < 0 ||
            (uint32) (extEnd - p) < len)
        {
            psTraceCrypto("Expecting OCTET STRING in ext parse\n");
            return PS_PARSE_FAIL;
        }

        /* Set bits 1..9 to indicate criticality of known extensions */
        if (critical)
        {
            extensions->critFlags |= EXT_CRIT_FLAG(noid);
        }

        switch (noid)
        {
/*
             BasicConstraints ::= SEQUENCE {
                cA                                              BOOLEAN DEFAULT FALSE,
                pathLenConstraint               INTEGER (0..MAX) OPTIONAL }
 */
        case OID_ENUM(id_ce_basicConstraints):
            if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing BasicConstraints extension\n");
                return PS_PARSE_FAIL;
            }
/*
                "This goes against PKIX guidelines but some CAs do it and some
                software requires this to avoid interpreting an end user
                certificate as a CA."
                    - OpenSSL certificate configuration doc

                basicConstraints=CA:FALSE
 */
            if (len == 0)
            {
                extensions->bc.cA = CA_FALSE;
                break;
            }
/*
                Have seen some certs that don't include a cA bool.
 */
            if (*p == ASN_BOOLEAN)
            {
                if (extEnd - p < 3)
                {
                    psTraceCrypto("Error parsing BC extension\n");
                    return PS_PARSE_FAIL;
                }
                p++;
                if (*p++ != 1)
                {
                    psTraceCrypto("Error parse BasicConstraints CA bool\n");
                    return PS_PARSE_FAIL;
                }
                /* Officially DER TRUE must be 0xFF, openssl is more lax */
                if (*p > 0 && *p != 0xFF)
                {
                    psTraceCrypto("Warning: cA TRUE should be 0xFF\n");
                }
                if (*p > 0)
                {
                    extensions->bc.cA = CA_TRUE;
                }
                else
                {
                    extensions->bc.cA = CA_FALSE;
                }
                p++;
            }
            else
            {
                extensions->bc.cA = CA_FALSE;
            }
/*
                Now need to check if there is a path constraint. Only makes
                sense if cA is true.  If it's missing, there is no limit to
                the cert path
 */
            if (*p == ASN_INTEGER)
            {
                if (getAsnInteger(&p, (uint32) (extEnd - p),
                        &(extensions->bc.pathLenConstraint)) < 0)
                {
                    psTraceCrypto("Error parsing BasicConstraints pathLen\n");
                    return PS_PARSE_FAIL;
                }
            }
            else
            {
                extensions->bc.pathLenConstraint = -1;
            }
            break;

        case OID_ENUM(id_ce_subjectAltName):
            if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing altSubjectName extension\n");
                return PS_PARSE_FAIL;
            }
            /* NOTE: The final limit parameter was introduced for this
                case because a well known search engine site sends back
                about 7 KB worth of subject alt names and that has created
                memory problems for a couple users.  Set the -1 here to
                something reasonable (5) if you've found yourself here
                for this memory reason */
            if (parseGeneralNames(pool, &p, len, extEnd, &extensions->san,
                    -1) < 0)
            {
                psTraceCrypto("Error parsing altSubjectName names\n");
                return PS_PARSE_FAIL;
            }

            break;

        case OID_ENUM(id_ce_keyUsage):
/*
                KeyUsage ::= BIT STRING {
                    digitalSignature            (0),
                    nonRepudiation                      (1),
                    keyEncipherment                     (2),
                    dataEncipherment            (3),
                    keyAgreement                        (4),
                    keyCertSign                         (5),
                    cRLSign                                     (6),
                    encipherOnly                        (7),
                    decipherOnly                        (8) }
 */
            if (*p++ != ASN_BIT_STRING)
            {
                psTraceCrypto("Error parsing keyUsage extension\n");
                return PS_PARSE_FAIL;
            }
            if (getAsnLength(&p, (int32) (extEnd - p), &len) < 0 ||
                (uint32) (extEnd - p) < len)
            {
                psTraceCrypto("Malformed keyUsage extension\n");
                return PS_PARSE_FAIL;
            }
            if (len < 2)
            {
                psTraceCrypto("Malformed keyUsage extension\n");
                return PS_PARSE_FAIL;
            }
/*
                If the lenth is <= 3, then there might be a
                KEY_USAGE_DECIPHER_ONLY (or maybe just some empty bytes).
 */
            if (len >= 3)
            {
                if (p[2] == (KEY_USAGE_DECIPHER_ONLY >> 8) && p[0] == 7)
                {
                    extensions->keyUsageFlags |= KEY_USAGE_DECIPHER_ONLY;
                }
            }
            extensions->keyUsageFlags |= p[1];
            p = p + len;
# ifdef USE_ED25519
            /* Some Ed25519 test certs have an extra 0x00 at the end of the
               BIT STRING, which is not included in the length. This is
               an incorrect encoding, but let's be liberal in what we
               accept. */
            if (*p == 0x00)
            {
                p++;
            }
# endif
            break;

        case OID_ENUM(id_ce_extKeyUsage):
            if (getAsnSequence(&p, (int32) (extEnd - p), &fullExtLen) < 0)
            {
                psTraceCrypto("Error parsing authKeyId extension\n");
                return PS_PARSE_FAIL;
            }
            save = p;
            while (fullExtLen > 0)
            {
                if (*p++ != ASN_OID)
                {
                    psTraceCrypto("Malformed extension header\n");
                    return PS_PARSE_FAIL;
                }
                if (getAsnLength(&p, fullExtLen, &len) < 0 ||
                    fullExtLen < len)
                {
                    psTraceCrypto("Malformed extension length\n");
                    return PS_PARSE_FAIL;
                }
                if (asnCopyOid(p, len, asnOid) < 1)
                {
                    psTraceCrypto("Malformed extension OID\n");
                    return PS_PARSE_FAIL;
                }
                noid = psOidToEnum(asnOid);
                p += len;
                if (fullExtLen < (uint32) (p - save))
                {
                    psTraceCrypto("Inner OID parse fail EXTND_KEY_USAGE\n");
                    return PS_PARSE_FAIL;
                }
                fullExtLen -= (p - save);
                save = p;
                switch (noid)
                {
                case OID_ENUM(id_kp_serverAuth):
                    extensions->ekuFlags |= EXT_KEY_USAGE_TLS_SERVER_AUTH;
                    break;
                case OID_ENUM(id_kp_clientAuth):
                    extensions->ekuFlags |= EXT_KEY_USAGE_TLS_CLIENT_AUTH;
                    break;
                case OID_ENUM(id_kp_codeSigning):
                    extensions->ekuFlags |= EXT_KEY_USAGE_CODE_SIGNING;
                    break;
                case OID_ENUM(id_kp_emailProtection):
                    extensions->ekuFlags |= EXT_KEY_USAGE_EMAIL_PROTECTION;
                    break;
                case OID_ENUM(id_kp_timeStamping):
                    extensions->ekuFlags |= EXT_KEY_USAGE_TIME_STAMPING;
                    break;
                case OID_ENUM(id_kp_OCSPSigning):
                    extensions->ekuFlags |= EXT_KEY_USAGE_OCSP_SIGNING;
                    break;
                case OID_ENUM(id_ce_eku_anyExtendedKeyUsage):
                    extensions->ekuFlags |= EXT_KEY_USAGE_ANY;
                    break;
                default:
                    {
#  ifdef USE_CRYPTO_TRACE
                        char buffer[MAX_OID_PRINTED_LEN];
                        psTraceStrCrypto("WARNING: Unknown EXT_KEY_USAGE: %s\n",
                                         psSprintAsnOid(asnOid, buffer));
#  endif /* USE_CRYPTO_TRACE */
                        break;
                    }
                }     /* end switch */
            }
            break;

#  ifdef USE_FULL_CERT_PARSE

        case OID_ENUM(id_ce_nameConstraints):
            if (critical)
            {
                /* We're going to fail if critical since no real
                    pattern matching is happening yet */
                psTraceCrypto("ERROR: critical nameConstraints unsupported\n");
                return PS_PARSE_FAIL;
            }
            if (getAsnSequence(&p, (int32) (extEnd - p), &fullExtLen) < 0)
            {
                psTraceCrypto("Error parsing authKeyId extension\n");
                return PS_PARSE_FAIL;
            }
            while (fullExtLen > 0)
            {
                save = p;

                if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
                {
                    /* permittedSubtrees */
                    p++;
                    nc = 0;
                }
                if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
                {
                    /* excludedSubtrees */
                    p++;
                    nc = 1;
                }
                subExtLen = 0;
                if (getAsnLength(&p, (uint32) (extEnd - p), &subExtLen) < 0 ||
                    subExtLen < 1 || (uint32) (extEnd - p) < subExtLen)
                {
                    psTraceCrypto("ASN get len error in nameConstraint\n");
                    return PS_PARSE_FAIL;
                }
                if (fullExtLen < (subExtLen + (p - save)))
                {
                    psTraceCrypto("fullExtLen parse fail nameConstraint\n");
                    return PS_PARSE_FAIL;
                }
                fullExtLen -= subExtLen + (p - save);
                while (subExtLen > 0)
                {
                    subSave = p;
                    if (getAsnSequence(&p, (int32) (extEnd - p), &len) < 0)
                    {
                        psTraceCrypto("Error parsing nameConst ext\n");
                        return PS_PARSE_FAIL;
                    }
                    if (subExtLen < (len + (p - subSave)))
                    {
                        psTraceCrypto("subExtLen fail nameConstraint\n");
                        return PS_PARSE_FAIL;
                    }
                    subExtLen -= len + (p - subSave);
                    if (nc == 0)
                    {
                        if (parseGeneralNames(pool, &p, len, extEnd,
                                &extensions->nameConstraints.permitted, -1) < 0)
                        {
                            psTraceCrypto("Error parsing nameConstraint\n");
                            return PS_PARSE_FAIL;
                        }
                    }
                    else
                    {
                        if (parseGeneralNames(pool, &p, len, extEnd,
                                &extensions->nameConstraints.excluded, -1) < 0)
                        {
                            psTraceCrypto("Error parsing nameConstraint\n");
                            return PS_PARSE_FAIL;
                        }
                    }
                }
            }
            break;

#   ifdef USE_CRL
        case OID_ENUM(id_ce_cRLNumber):
            /* A required extension within a CRL.  Our getSerialNum is
                the version of getInteger that allows very large
                numbers.  Spec says this could be 20 octets long */
            if (getSerialNum(pool, &p, (int32) (extEnd - p),
                    &(extensions->crlNum), &len) < 0)
            {
                psTraceCrypto("Error parsing ak.serialNum\n");
                return PS_PARSE_FAIL;
            }
            extensions->crlNumLen = len;
            break;

        case OID_ENUM(id_ce_issuingDistributionPoint):
            /* RFC 3280 - Although the extension is critical, conforming
               implementations are not required to support this extension. */
            p++;
            p = p + (fullExtLen - (p - extStart));
            break;

        case OID_ENUM(id_ce_cRLDistributionPoints):
            if (getAsnSequence(&p, (int32) (extEnd - p), &fullExtLen) < 0)
            {
                psTraceCrypto("Error parsing authKeyId extension\n");
                return PS_PARSE_FAIL;
            }

            while (fullExtLen > 0)
            {
                save = p;
                if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
                {
                    psTraceCrypto("getAsnSequence fail in crldist parse\n");
                    return PS_PARSE_FAIL;
                }
                if (fullExtLen < (len + (p - save)))
                {
                    psTraceCrypto("fullExtLen parse fail crldist\n");
                    return PS_PARSE_FAIL;
                }
                fullExtLen -= len + (p - save);
                /* All memebers are optional */
                if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
                {
                    /* DistributionPointName */
                    p++;
                    if (getAsnLength(&p, (uint32) (extEnd - p), &len) < 0 ||
                        len < 1 || (uint32) (extEnd - p) < len)
                    {
                        psTraceCrypto("ASN get len error in CRL extension\n");
                        return PS_PARSE_FAIL;
                    }

                    if ((*p & 0xF) == 0)       /* fullName (GeneralNames) */
                    {
                        p++;
                        if (getAsnLength(&p, (uint32) (extEnd - p), &len) < 0
                            || len < 1 || (uint32) (extEnd - p) < len)
                        {
                            psTraceCrypto("ASN get len error in CRL extension\n");
                            return PS_PARSE_FAIL;
                        }
                        if (parseGeneralNames(pool, &p, len, extEnd,
                                &extensions->crlDist, -1) > 0)
                        {
                            psTraceCrypto("dist gen name parse fail\n");
                            return PS_PARSE_FAIL;
                        }
                    }
                    else if ((*p & 0xF) == 1)         /* RelativeDistName */
                    {
                        p++;
                        /* RelativeDistName not parsed */
                        if (getAsnLength(&p, (uint32) (extEnd - p), &len) < 0
                            || len < 1 || (uint32) (extEnd - p) < len)
                        {
                            psTraceCrypto("ASN get len error in CRL extension\n");
                            return PS_PARSE_FAIL;
                        }
                        p += len;
                    }
                    else
                    {
                        psTraceCrypto("DistributionPointName parse fail\n");
                        return PS_PARSE_FAIL;
                    }
                }
                if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
                {
                    p++;
                    /* ReasonFlags not parsed */
                    if (getAsnLength(&p, (uint32) (extEnd - p), &len) < 0 ||
                        len < 1 || (uint32) (extEnd - p) < len)
                    {
                        psTraceCrypto("ASN get len error in CRL extension\n");
                        return PS_PARSE_FAIL;
                    }
                    p += len;
                }
                if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2))
                {
                    p++;
                    /* General Names not parsed */
                    if (getAsnLength(&p, (uint32) (extEnd - p), &len) < 0 ||
                        len < 1 || (uint32) (extEnd - p) < len)
                    {
                        psTraceCrypto("ASN get len error in CRL extension\n");
                        return PS_PARSE_FAIL;
                    }
                    p += len;
                }
            }
            break;
        case OID_ENUM(id_pe_authorityInfoAccess):
            if (parseAuthorityInfoAccess(pool, p,
                    extEnd,
                    &extensions->authorityInfoAccess,
                    &len) < 0)
            {
                return PS_PARSE_FAIL;
            }
            p += len;
            break;
#   endif /* USE_CRL */
#  endif  /* FULL_CERT_PARSE */

        case OID_ENUM(id_ce_authorityKeyIdentifier):
/*
                AuthorityKeyIdentifier ::= SEQUENCE {
                keyIdentifier                   [0] KeyIdentifier                       OPTIONAL,
                authorityCertIssuer             [1] GeneralNames                        OPTIONAL,
                authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }

                KeyIdentifier ::= OCTET STRING
 */
            if (getAsnSequence(&p, (int32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing authKeyId extension\n");
                return PS_PARSE_FAIL;
            }
            /* Have seen a cert that has a zero length ext here. Let it pass. */
            if (len == 0)
            {
                break;
            }
            /* All members are optional */
            if (*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 0))
            {
                p++;
                if (getAsnLength(&p, (int32) (extEnd - p),
                        &extensions->ak.keyLen) < 0 ||
                    (uint32) (extEnd - p) < extensions->ak.keyLen)
                {
                    psTraceCrypto("Error keyLen in authKeyId extension\n");
                    return PS_PARSE_FAIL;
                }
                extensions->ak.keyId = psMalloc(pool, extensions->ak.keyLen);
                if (extensions->ak.keyId == NULL)
                {
                    psError("Mem allocation err: extensions->ak.keyId\n");
                    return PS_MEM_FAIL;
                }
                Memcpy(extensions->ak.keyId, p, extensions->ak.keyLen);
                p = p + extensions->ak.keyLen;
            }
            if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
            {
                p++;
                if (getAsnLength(&p, (int32) (extEnd - p), &len) < 0 ||
                    len < 1 || (uint32) (extEnd - p) < len)
                {
                    psTraceCrypto("ASN get len error in authKeyId extension\n");
                    return PS_PARSE_FAIL;
                }
                if ((*p ^ ASN_CONTEXT_SPECIFIC ^ ASN_CONSTRUCTED) != 4)
                {
                    /* We are just dealing with DN formats here */
                    psTraceIntCrypto("Error auth key-id name type: %d\n",
                        *p ^ ASN_CONTEXT_SPECIFIC ^ ASN_CONSTRUCTED);
                    return PS_PARSE_FAIL;
                }
                p++;
                if (getAsnLength(&p, (int32) (extEnd - p), &len) < 0 ||
                    (uint32) (extEnd - p) < len)
                {
                    psTraceCrypto("ASN get len error2 in authKeyId extension\n");
                    return PS_PARSE_FAIL;
                }
                if (psX509GetDNAttributes(pool, &p, (int32) (extEnd - p),
                        &(extensions->ak.attribs), 0) < 0)
                {
                    psTraceCrypto("Error parsing ak.attribs\n");
                    return PS_PARSE_FAIL;
                }
            }
            if ((*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 2)) ||
                (*p == ASN_INTEGER))
            {
/*
                    Treat as a serial number (not a native INTEGER)
 */
                if (getSerialNum(pool, &p, (int32) (extEnd - p),
                        &(extensions->ak.serialNum), &len) < 0)
                {
                    psTraceCrypto("Error parsing ak.serialNum\n");
                    return PS_PARSE_FAIL;
                }
                extensions->ak.serialNumLen = len;
            }
            break;

        case OID_ENUM(id_ce_subjectKeyIdentifier):
/*
                The value of the subject key identifier MUST be the value
                placed in the key identifier field of the Auth Key Identifier
                extension of certificates issued by the subject of
                this certificate.
 */
            if (*p++ != ASN_OCTET_STRING || getAsnLength(&p,
                    (int32) (extEnd - p), &(extensions->sk.len)) < 0 ||
                (uint32) (extEnd - p) < extensions->sk.len)
            {
                psTraceCrypto("Error parsing subjectKeyId extension\n");
                return PS_PARSE_FAIL;
            }
            extensions->sk.id = psMalloc(pool, extensions->sk.len);
            if (extensions->sk.id == NULL)
            {
                psError("Memory allocation error extensions->sk.id\n");
                return PS_MEM_FAIL;
            }
            Memcpy(extensions->sk.id, p, extensions->sk.len);
            p = p + extensions->sk.len;
            break;
#  ifdef USE_FULL_CERT_PARSE

#   ifdef USE_CERT_POLICY_EXTENSIONS
        case OID_ENUM(id_ce_certificatePolicies):
/*
            certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 */
            /* Parse certificatePolicies := SEQUENCE SIZE (1..MAX) OF
               PolicyInformation. */
            if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing certificatePolicies extension\n");
                return PS_PARSE_FAIL;
            }
            policiesEnd = p + len;
            extensions->certificatePolicy.policy
                = psMalloc(pool, sizeof(x509PolicyInformation_t));
            Memset(extensions->certificatePolicy.policy, 0,
                sizeof(x509PolicyInformation_t));
            pPolicy = extensions->certificatePolicy.policy;

            /* Parse a single PolicyInformation. */
            if (parsePolicyInformation(pool, p, extEnd, fullExtLen,
                    pPolicy, &len) < 0)
            {
                return PS_PARSE_FAIL;
            }
            p += len;

            /* Parse further PolicyInformations, if present. */
            while ((p < policiesEnd)
                   && (p < extEnd)
                   && (*p == (ASN_SEQUENCE | ASN_CONSTRUCTED)))
            {

                pPolicy->next = psMalloc(pool, sizeof(x509PolicyInformation_t));
                Memset(pPolicy->next, 0, sizeof(x509PolicyInformation_t));
                pPolicy = pPolicy->next;
                if (parsePolicyInformation(pool, p, extEnd, fullExtLen,
                        pPolicy, &len) < 0)
                {
                    return PS_PARSE_FAIL;
                }
                p += len;
            }     /* End or PolicyInformation parsing. */
            break;
        case OID_ENUM(id_ce_policyConstraints):
            if (parsePolicyConstraints(pool, p,
                    extEnd,
                    &extensions->policyConstraints,
                    &len) < 0)
            {
                return PS_PARSE_FAIL;
            }
            p += len;
            break;
        case OID_ENUM(id_ce_policyMappings):
            extensions->policyMappings = psMalloc(pool,
                sizeof(x509policyMappings_t));
            Memset(extensions->policyMappings, 0, sizeof(x509policyMappings_t));
            if (parsePolicyMappings(pool, p,
                    extEnd,
                    extensions->policyMappings,
                    &len) < 0)
            {
                return PS_PARSE_FAIL;
            }

            p += len;
            break;
#  endif /* USE_CERT_POLICY_EXTENSIONS */
        case OID_ENUM(id_ce_issuerAltName):
            if (getAsnSequence(&p, (uint32) (extEnd - p), &len) < 0)
            {
                psTraceCrypto("Error parsing issuerAltName extension\n");
                return PS_PARSE_FAIL;
            }
            /* NOTE: The final limit parameter was introduced for this
                case because a well known search engine site sends back
                about 7 KB worth of subject alt names and that has created
                memory problems for a couple users.  Set the -1 here to
                something reasonable (5) if you've found yourself here
                for this memory reason */
            if (parseGeneralNames(pool, &p, len, extEnd, &extensions->issuerAltName,
                    -1) < 0)
            {
                psTraceCrypto("Error parsing altSubjectName names\n");
                return PS_PARSE_FAIL;
            }
            break;
#  endif    /* USE_FULL_CERT_PARSE */
        /* These extensions are known but not handled */
        case OID_ENUM(id_ce_subjectDirectoryAttributes):
        case OID_ENUM(id_ce_inhibitAnyPolicy):
        case OID_ENUM(id_ce_freshestCRL):
        case OID_ENUM(id_pe_subjectInfoAccess):
        default:
            /* Unsupported or skipping because USE_FULL_CERT_PARSE undefd */
            if (critical)
            {
#  ifdef USE_CRYPTO_TRACE
                char buffer[MAX_OID_PRINTED_LEN];
                psTraceStrCrypto("Unsupported critical ext encountered: %s\n",
                                 psSprintAsnOid(asnOid, buffer));
#  endif /* USE_CRYPTO_TRACE */
#  ifndef ALLOW_UNKNOWN_CRITICAL_EXTENSIONS
                _psTrace("An unsupported critical extension was "
                    "encountered.  X.509 specifications say "
                    "connections must be terminated in this case. "
                    "Define ALLOW_UNKNOWN_CRITICAL_EXTENSIONS to "
                    "bypass this rule if testing and email Inside "
                    "support to inquire about this extension.\n");
                return PS_PARSE_FAIL;
#  else
#   ifdef WIN32
#    pragma message("IGNORING UNKNOWN CRITICAL EXTENSIONS IS A SECURITY RISK")
#   else
#    warning "IGNORING UNKNOWN CRITICAL EXTENSIONS IS A SECURITY RISK"
#   endif
#  endif
            }
            p++;
/*
                Skip over based on the length reported from the ASN_SEQUENCE
                surrounding the entire extension.  It is not a guarantee that
                the value of the extension itself will contain it's own length.
 */
            p = p + (fullExtLen - (p - extStart));
            break;
        }
    }
    *pp = p;
    return 0;
}

/******************************************************************************/
/*
    Although a certificate serial number is encoded as an integer type, that
    doesn't prevent it from being abused as containing a variable length
    binary value.  Get it here.
 */
int32_t getSerialNum(psPool_t *pool, const unsigned char **pp, psSize_t len,
    unsigned char **sn, psSize_t *snLen)
{
    const unsigned char *p = *pp;
    psSize_t vlen;

    if (len < 1)
    {
        psTraceCrypto("ASN getSerialNum failed\n");
        return PS_PARSE_FAIL;
    }

    if ((*p != (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 2)) &&
        (*p != ASN_INTEGER))
    {
        psTraceCrypto("X.509 getSerialNum failed on first bytes\n");
        return PS_PARSE_FAIL;
    }
    p++;

    if (len < 1 || getAsnLength(&p, len - 1, &vlen) < 0 || (len - 1) < vlen)
    {
        psTraceCrypto("ASN getSerialNum failed\n");
        return PS_PARSE_FAIL;
    }
    *snLen = vlen;

    if (vlen > 0)
    {
        *sn = psMalloc(pool, vlen);
        if (*sn == NULL)
        {
            psError("Memory allocation failure in getSerialNum\n");
            return PS_MEM_FAIL;
        }
        Memcpy(*sn, p, vlen);
        p += vlen;
    }
    *pp = p;
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    Explicit value encoding has an additional tag layer.
 */
static int32_t getExplicitVersion(const unsigned char **pp, psSize_t len,
    int32_t expVal, int32_t *val)
{
    const unsigned char *p = *pp;
    psSize_t exLen;

    if (len < 1)
    {
        psTraceCrypto("Invalid length to getExplicitVersion\n");
        return PS_PARSE_FAIL;
    }
/*
    This is an optional value, so don't error if not present.  The default
    value is version 1
 */
    if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | expVal))
    {
        *val = 0;
        return PS_SUCCESS;
    }
    p++;
    if (getAsnLength(&p, len - 1, &exLen) < 0 || (len - 1) < exLen)
    {
        psTraceCrypto("getAsnLength failure in getExplicitVersion\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnInteger(&p, exLen, val) < 0)
    {
        psTraceCrypto("getAsnInteger failure in getExplicitVersion\n");
        return PS_PARSE_FAIL;
    }
    *pp = p;
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    Tests if the certificate was issued before the given date.
    Because there is no actual issuance date in the certificate, we use the
    'notBefore' date (the initial date the certificate is valid) as the
    effective issuance date.
    @security This api is used to be more lenient on certificates that are still
    valid, but were created before certain more strict certificate rules
    were specified.

    @param[in] rfc The RFC to check against.
    @param[in] cert The cert to check the issuing date on.
    @return 1 if yes, 0 if no, -1 on parse error.
 */
static int32 issuedBefore(rfc_e rfc, const psX509Cert_t *cert)
{
    unsigned char *c;
    unsigned int y;
    unsigned short m;
    psBrokenDownTime_t t;
    int32 err;

    /* Validate the 'not before' date */
    if ((c = (unsigned char *) cert->notBefore) == NULL)
    {
        return PS_FAILURE;
    }
    err = psBrokenDownTimeImport(
        &t, (const char *) c, Strlen((const char *) c),
        cert->notBeforeTimeType == ASN_UTCTIME ?
        PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0);

    if (err)
    {
        return err;
    }

    /* Get y and m from broken-down time. */
    y = 1900 + (unsigned int) t.tm_year;
    m = 1 + (unsigned short) t.tm_mon;

    /* Must have been issued at least when X509v3 was added */
    if (y < 1996 || m < 1 || m > 12)
    {
        return -1;
    }
    switch (rfc)
    {
    case RFC_6818:
        if (y < 2013)   /* No month check needed for Jan */
        {
            return 1;
        }
        return 0;
    case RFC_5280:
        if (y < 2008 || (y == 2008 && m < 5))
        {
            return 1;
        }
        return 0;
    case RFC_3280:
        if (y < 2002 || (y == 2002 && m < 4))
        {
            return 1;
        }
        return 0;
    case RFC_2459:
        if (y < 1999)   /* No month check needed for Jan */
        {
            return 1;
        }
        return 0;
    default:
        /* Parsing error. */
        break;
    }
    return -1;
}

static psBool_t isIndefiniteDateRFC5280(psBrokenDownTime_t *t)
{
    psAssert(t != NULL);

    return (t->tm_year == 9999 - 1900 &&
            t->tm_mon == 11 &&
            t->tm_mday == 31 &&
            t->tm_hour == 23 &&
            t->tm_min == 59 &&
            t->tm_sec == 59);
}

/**
    Validate the dates in the cert to machine date.
    SECURITY - always succeeds on systems without date support
    Returns
        0 on parse success (FAIL_DATE_FLAG could be set)
        PS_FAILURE on parse error
 */
int32 validateDateRange(psX509Cert_t *cert)
{
    int32 err;
    psBrokenDownTime_t timeNow;
    psBrokenDownTime_t timeNowLinger;
    psBrokenDownTime_t beforeTime;
    psBrokenDownTime_t afterTime;
    psBrokenDownTime_t afterTimeLinger;

    if (cert->notBefore == NULL || cert->notAfter == NULL)
    {
        return PS_FAIL;
    }

    err = psGetBrokenDownGMTime(&timeNow, 0);
    if (err != PS_SUCCESS)
    {
        return PS_FAIL;
    }

    Memcpy(&timeNowLinger, &timeNow, sizeof timeNowLinger);
    err = psBrokenDownTimeAdd(&timeNowLinger, PS_X509_TIME_LINGER);
    if (err != PS_SUCCESS)
    {
        return PS_FAIL;
    }

    err = psBrokenDownTimeImport(
        &beforeTime, cert->notBefore, Strlen(cert->notBefore),
        cert->notBeforeTimeType == ASN_UTCTIME ?
        PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0);
    if (err != PS_SUCCESS)
    {
        return PS_FAIL;
    }

    err = psBrokenDownTimeImport(
        &afterTime, cert->notAfter, Strlen(cert->notAfter),
        cert->notAfterTimeType == ASN_UTCTIME ?
        PS_BROKENDOWN_TIME_IMPORT_2DIGIT_YEAR : 0);
    if (err != PS_SUCCESS)
    {
        return PS_FAIL;
    }

    if (!isIndefiniteDateRFC5280(&afterTime))
    {
        memcpy(&afterTimeLinger, &afterTime, sizeof afterTimeLinger);
        err = psBrokenDownTimeAdd(&afterTimeLinger, PS_X509_TIME_LINGER);
        if (err != PS_SUCCESS)
        {
            return PS_FAIL;
        }
        if (psBrokenDownTimeCmp(&timeNow, &afterTimeLinger) > 0)
        {
            /* afterTime is in past. */
            cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
        }
    }

    if (psBrokenDownTimeCmp(&beforeTime, &timeNowLinger) > 0)
    {
        /* beforeTime is in future. */
        cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
    }

    if (psBrokenDownTimeCmp(&beforeTime, &afterTime) > 0)
    {
        /* beforeTime is later than afterTime. */
        cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
    }

    return 0;
}


/******************************************************************************/
/*
    Implementation specific date parser.
 */
static int32_t getTimeValidity(psPool_t *pool, const unsigned char **pp,
    psSize_t len, int32_t *notBeforeTimeType,
    int32_t *notAfterTimeType,
    char **notBefore, char **notAfter)
{
    const unsigned char *p = *pp, *end;
    psSize_t seqLen, timeLen;

    end = p + len;
    if (len < 1 || *(p++) != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
        getAsnLength(&p, len - 1, &seqLen) < 0 ||
        (uint32) (end - p) < seqLen)
    {
        psTraceCrypto("getTimeValidity failed on inital parse\n");
        return PS_PARSE_FAIL;
    }
/*
    Have notBefore and notAfter times in UTCTime or GeneralizedTime formats
 */
    if ((end - p) < 1 || ((*p != ASN_UTCTIME) && (*p != ASN_GENERALIZEDTIME)))
    {
        psTraceCrypto("Malformed validity\n");
        return PS_PARSE_FAIL;
    }
    *notBeforeTimeType = *p;
    p++;
/*
    Allocate them as null terminated strings
 */
    if (getAsnLength(&p, seqLen, &timeLen) < 0 || (uint32) (end - p) < timeLen)
    {
        psTraceCrypto("Malformed validity 2\n");
        return PS_PARSE_FAIL;
    }
    if (timeLen > MAX_TIME_LEN)
    {
        return PS_PARSE_FAIL;
    }
    *notBefore = psMalloc(pool, timeLen + 1);
    if (*notBefore == NULL)
    {
        psError("Memory allocation error in getTimeValidity for notBefore\n");
        return PS_MEM_FAIL;
    }
    Memcpy(*notBefore, p, timeLen);
    (*notBefore)[timeLen] = '\0';
    p = p + timeLen;
    if ((end - p) < 1 || ((*p != ASN_UTCTIME) && (*p != ASN_GENERALIZEDTIME)))
    {
        psTraceCrypto("Malformed validity 3\n");
        return PS_PARSE_FAIL;
    }
    *notAfterTimeType = *p;
    p++;
    if (getAsnLength(&p, seqLen - timeLen, &timeLen) < 0 ||
        (uint32) (end - p) < timeLen)
    {
        psTraceCrypto("Malformed validity 4\n");
        return PS_PARSE_FAIL;
    }
    if (timeLen > MAX_TIME_LEN)
    {
        return PS_PARSE_FAIL;
    }
    *notAfter = psMalloc(pool, timeLen + 1);
    if (*notAfter == NULL)
    {
        psError("Memory allocation error in getTimeValidity for notAfter\n");
        return PS_MEM_FAIL;
    }
    Memcpy(*notAfter, p, timeLen);
    (*notAfter)[timeLen] = '\0';
    p = p + timeLen;

    *pp = p;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Could be optional.  If the tag doesn't contain the value from the left
    of the IMPLICIT keyword we don't have a match and we don't incr the pointer.
 */
static int32_t getImplicitBitString(psPool_t *pool, const unsigned char **pp,
    psSize_t len, int32_t impVal, unsigned char **bitString,
    psSize_t *bitLen)
{
    const unsigned char *p = *pp;
    int32_t ignore_bits;

    if (len < 1)
    {
        psTraceCrypto("Initial parse error in getImplicitBitString\n");
        return PS_PARSE_FAIL;
    }
/*
    We don't treat this case as an error, because of the optional nature.
 */
    if (*p != (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | impVal))
    {
        return PS_SUCCESS;
    }

    p++;
    if (getAsnLength(&p, len, bitLen) < 0
        || *bitLen < 2)
    {
        psTraceCrypto("Malformed implicitBitString\n");
        return PS_PARSE_FAIL;
    }
    ignore_bits = *p++;
    (*bitLen)--;
    psAssert(ignore_bits == 0);

    *bitString = psMalloc(pool, *bitLen);
    if (*bitString == NULL)
    {
        psError("Memory allocation error in getImplicitBitString\n");
        return PS_MEM_FAIL;
    }
    Memcpy(*bitString, p, *bitLen);
    *pp = p + *bitLen;
    return PS_SUCCESS;
}


/******************************************************************************/
/*
    Implementations of this specification MUST be prepared to receive
    the following standard attribute types in issuer names:
    country, organization, organizational-unit, distinguished name qualifier,
    state or province name, and common name
 */
int32_t psX509GetDNAttributes(psPool_t *pool, const unsigned char **pp,
    psSize_t len, x509DNattributes_t *attribs, uint32_t flags)
{
    const unsigned char *p = *pp;
    const unsigned char *dnEnd, *dnStart, *moreInSetPtr;
    x509OrgUnit_t *orgUnit;
    x509DomainComponent_t *domainComponent;
    int32 id, stringType, checkHiddenNull, moreInSet;
    psSize_t llen, setlen, arcLen;
    char *stringOut;
    uint32_t i;

#  ifdef USE_SHA1
    psSha1_t hash;
#  elif defined(USE_SHA256)
    psSha256_t hash;
#  else
/* TODO can we avoid hash altogether? We do not free/finalize the hash ctx on error return below. */
#   error USE_SHA1 or USE_SHA256 must be defined
#  endif

    for (i = 0; i < DN_NUM_ATTRIBUTES_MAX; i++)
    {
        attribs->attributeOrder[i] = 0;
    }

    dnStart = p;
    if (getAsnSequence(&p, len, &llen) < 0)
    {
        return PS_PARSE_FAIL;
    }
    dnEnd = p + llen;

/*
    The possibility of a CERTIFICATE_REQUEST message.  Set aside full DN
 */
    if (flags & CERT_STORE_DN_BUFFER)
    {
        attribs->dnencLen = (uint32) (dnEnd - dnStart);
        attribs->dnenc = psMalloc(pool, attribs->dnencLen);
        if (attribs->dnenc == NULL)
        {
            psError("Memory allocation error in getDNAttributes\n");
            return PS_MEM_FAIL;
        }
        Memcpy(attribs->dnenc, dnStart, attribs->dnencLen);
    }
    moreInSet = 0;
    while (p < dnEnd)
    {
        if (getAsnSet(&p, (uint32) (dnEnd - p), &setlen) < 0)
        {
            psTraceCrypto("Malformed DN attributes\n");
            return PS_PARSE_FAIL;
        }
        /* 99.99% of certs have one attribute per SET but did come across
            one that nested a couple at this level so let's watch out for
            that with the "moreInSet" logic */
MORE_IN_SET:
        moreInSetPtr = p;
        if (getAsnSequence(&p, (uint32) (dnEnd - p), &llen) < 0)
        {
            psTraceCrypto("Malformed DN attributes 2\n");
            return PS_PARSE_FAIL;
        }
        if (moreInSet > 0)
        {
            moreInSet -= llen + (int32) (p - moreInSetPtr);
        }
        else
        {
            if (setlen != llen + (int32) (p - moreInSetPtr))
            {
                moreInSet = setlen - (int32) (p - moreInSetPtr) - llen;
            }
        }
        if (dnEnd <= p || (*(p++) != ASN_OID) ||
            getAsnLength(&p, (uint32) (dnEnd - p), &arcLen) < 0 ||
            (uint32) (dnEnd - p) < arcLen)
        {
            psTraceCrypto("Malformed DN attributes 3\n");
            return PS_PARSE_FAIL;
        }
/*
        id-at   OBJECT IDENTIFIER       ::=     {joint-iso-ccitt(2) ds(5) 4}
        id-at-commonName                OBJECT IDENTIFIER               ::=             {id-at 3}
        id-at-serialNumber              OBJECT IDENTIFIER               ::=             {id-at 5}
        id-at-countryName               OBJECT IDENTIFIER               ::=             {id-at 6}
        id-at-localityName              OBJECT IDENTIFIER               ::=             {id-at 7}
        id-at-stateOrProvinceName               OBJECT IDENTIFIER       ::=     {id-at 8}
        id-at-organizationName                  OBJECT IDENTIFIER       ::=     {id-at 10}
        id-at-organizationalUnitName    OBJECT IDENTIFIER       ::=     {id-at 11}
 */
        *pp = p;
/*
        Currently we are skipping OIDs not of type {joint-iso-ccitt(2) ds(5) 4}
        (domainComponent is currently the only exception).
        However, we could be dealing with an OID we MUST support per RFC.
 */
        if (dnEnd - p < 2)
        {
            psTraceCrypto("Malformed DN attributes 4\n");
            return PS_LIMIT_FAIL;
        }

        /*
           Check separately for domainComponent and uid, since those do not
           start with the 0x5504 (id-at) pattern the code below expects.
         */
        /*
           Note: According to RFC 5280, "... implementations of this
           specification MUST be prepared to receive the domainComponent
           attribute, as defined in [RFC4519]."
         */
        if (arcLen == 10 &&
            *p == 0x09 &&
            *(p + 1) == 0x92 &&
            *(p + 2) == 0x26 &&
            *(p + 3) == 0x89 &&
            *(p + 4) == 0x93 &&
            *(p + 5) == 0xf2 &&
            *(p + 6) == 0x2c &&
            *(p + 7) == 0x64 &&
            *(p + 8) == 0x01)
        {
            if (*(p + 9) == 0x19)
            {
                p += 10;
                id = ATTRIB_DOMAIN_COMPONENT;
                goto oid_parsing_done;
            }
#  ifdef USE_EXTRA_DN_ATTRIBUTES
            else if (*(p + 9) == 0x01)
            {
                p += 10;
                id = ATTRIB_UID;
                goto oid_parsing_done;
            }
#  endif    /* USE_EXTRA_DN_ATTRIBUTES */
        }
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        if (arcLen == 9 &&
            *p == 0x2a &&
            *(p + 1) == 0x86 &&
            *(p + 2) == 0x48 &&
            *(p + 3) == 0x86 &&
            *(p + 4) == 0xf7 &&
            *(p + 5) == 0x0d &&
            *(p + 6) == 0x01 &&
            *(p + 7) == 0x09 &&
            *(p + 8) == 0x01)
        {
            p += 9;
            id = ATTRIB_EMAIL;
            goto oid_parsing_done;
        }
#  endif /* USE_EXTRA_DN_ATTRIBUTES */

        /* check id-at */
        if ((*p++ != 85) || (*p++ != 4))
        {
            /* OIDs we are not parsing */
            p = *pp;
/*
            Move past the OID and string type, get data size, and skip it.
            NOTE: Have had problems parsing older certs in this area.
 */
            if ((uint32) (dnEnd - p) < arcLen + 1)
            {
                psTraceCrypto("Malformed DN attributes 5\n");
                return PS_LIMIT_FAIL;
            }
            p += arcLen + 1;
            if (getAsnLength(&p, (uint32) (dnEnd - p), &llen) < 0 ||
                (uint32) (dnEnd - p) < llen)
            {
                psTraceCrypto("Malformed DN attributes 6\n");
                return PS_PARSE_FAIL;
            }
            p = p + llen;
            continue;
        }
        /* Next are the id of the attribute type and the ASN string type */
        if (arcLen != 3 || dnEnd - p < 2)
        {
            psTraceCrypto("Malformed DN attributes 7\n");
            return PS_LIMIT_FAIL;
        }
        id = (int32) * p++;
oid_parsing_done:
        /* Done with OID parsing */
        stringType = (int32) * p++;

        if (getAsnLength(&p, (uint32) (dnEnd - p), &llen) < 0 ||
            (uint32) (dnEnd - p) < llen)
        {
            psTraceCrypto("Malformed DN attributes 8\n");
            return PS_LIMIT_FAIL;
        }
/*
        For the known 8-bit character string types, we flag that we want
        to test for a hidden null in the middle of the string to address the
        issue of www.goodguy.com\0badguy.com.
        For validation purposes, BMPSTRINGs are converted to UTF-8 format.
 */
        checkHiddenNull = PS_FALSE;
        switch (stringType)
        {
        case ASN_BMPSTRING:
        {
# ifndef USE_ASN_BMPSTRING_DN_ATTRIBS
            psTraceCrypto("Error: BMPString not supported in DN attributes\n");
            psTraceCrypto("Please enable USE_ASN_BMPSTRING in cryptoConfig.h\n");
            return PS_UNSUPPORTED_FAIL;
# else
            /* MatrixSSL generally uses single byte character string
               formats. This function converts ASN_BMPSTRING to
               UTF-8 for further handling. */
            unsigned char *uc_stringOut = NULL;
            size_t length;
            int32 str_err;
            str_err = psToUtf8String(pool,
                (const unsigned char *) p,
                (size_t) llen,
                (psStringType_t) ASN_BMPSTRING,
                &uc_stringOut,
                &length,
#  if DN_NUM_TERMINATING_NULLS == 2
                PS_STRING_DUAL_NIL
#  elif DN_NUM_TERMINATING_NULLS == 1
                0
#  else
#   error "Unsupported value for DN_NUM_TERMINATING_NULLS."
#  endif
                );
            if (str_err != PS_SUCCESS)
            {
                return str_err;
            }
            /* Length checking. */
            if (length >= 0x7FFE)
            {
                /* Notice if length is too long to fit in 15 bits. */
                psFree(uc_stringOut, pool);
                return PS_LIMIT_FAIL;
            }
            stringOut = (char *) uc_stringOut;
            p = p + llen;
            llen = (uint16_t) length + DN_NUM_TERMINATING_NULLS;
            break;
# endif /* USE_ASN_BMPSTRING_DN_ATTRIBS */
        }
        case ASN_PRINTABLESTRING:
        case ASN_UTF8STRING:
        case ASN_IA5STRING:
        case ASN_T61STRING:
            /* coverity[unterminated_case] */
            checkHiddenNull = PS_TRUE;
        /* fall through */
        case ASN_BIT_STRING:
            stringOut = psMalloc(pool, llen + DN_NUM_TERMINATING_NULLS);
            if (stringOut == NULL)
            {
                psError("Memory allocation error in getDNAttributes\n");
                return PS_MEM_FAIL;
            }
            Memcpy(stringOut, p, llen);
/*
                Terminate with DN_NUM_TERMINATING_NULLS null chars to support
                standard string manipulations with any potential unicode types.
 */
            for (i = 0; i < DN_NUM_TERMINATING_NULLS; i++)
            {
                stringOut[llen + i] = '\0';
            }

            if (checkHiddenNull)
            {
                if ((uint32) Strlen(stringOut) != llen)
                {
                    psFree(stringOut, pool);
                    psTraceCrypto("Malformed DN attributes 9\n");
                    return PS_PARSE_FAIL;
                }
            }

            p = p + llen;
            /* Add null bytes for length assignments */
            llen += DN_NUM_TERMINATING_NULLS;
            break;
        default:
            psTraceIntCrypto("Unsupported DN attrib type %d\n", stringType);
            return PS_UNSUPPORTED_FAIL;
        }

        psBool_t attributeStored = PS_TRUE;

        switch (id)
        {
        case ATTRIB_COUNTRY_NAME:
            if (attribs->country)
            {
                psFree(attribs->country, pool);
            }
            attribs->country = stringOut;
            attribs->countryType = (short) stringType;
            attribs->countryLen = (short) llen;
            break;
        case ATTRIB_ORGANIZATION:
            if (attribs->organization)
            {
                psFree(attribs->organization, pool);
            }
            attribs->organization = stringOut;
            attribs->organizationType = (short) stringType;
            attribs->organizationLen = (short) llen;
            break;
        case ATTRIB_ORG_UNIT:
            orgUnit = psMalloc(pool, sizeof(x509OrgUnit_t));
            orgUnit->name = stringOut;
            orgUnit->type = (short) stringType;
            orgUnit->len = llen;
            /* Push the orgUnit onto the front of the list */
            orgUnit->next = attribs->orgUnit;
            attribs->orgUnit = orgUnit;
            break;
        case ATTRIB_DN_QUALIFIER:
            if (attribs->dnQualifier)
            {
                psFree(attribs->dnQualifier, pool);
            }
            attribs->dnQualifier = stringOut;
            attribs->dnQualifierType = (short) stringType;
            attribs->dnQualifierLen = (short) llen;
            break;
        case ATTRIB_STATE_PROVINCE:
            if (attribs->state)
            {
                psFree(attribs->state, pool);
            }
            attribs->state = stringOut;
            attribs->stateType = (short) stringType;
            attribs->stateLen = (short) llen;
            break;
        case ATTRIB_COMMON_NAME:
            if (attribs->commonName)
            {
                psFree(attribs->commonName, pool);
            }
            attribs->commonName = stringOut;
            attribs->commonNameType = (short) stringType;
            attribs->commonNameLen = (short) llen;
            break;
        case ATTRIB_SERIALNUMBER:
            if (attribs->serialNumber)
            {
                psFree(attribs->serialNumber, pool);
            }
            attribs->serialNumber = stringOut;
            attribs->serialNumberType = (short) stringType;
            attribs->serialNumberLen = (short) llen;
            break;
        case ATTRIB_DOMAIN_COMPONENT:
            domainComponent = psMalloc(pool, sizeof(x509DomainComponent_t));
            domainComponent->name = stringOut;
            domainComponent->type = (short) stringType;
            domainComponent->len = llen;
            /* Push the domainComponent onto the front of the list */
            domainComponent->next = attribs->domainComponent;
            attribs->domainComponent = domainComponent;
            break;
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
        case ATTRIB_LOCALITY:
            if (attribs->locality)
            {
                psFree(attribs->locality, pool);
            }
            attribs->locality = stringOut;
            attribs->localityType = (short) stringType;
            attribs->localityLen = (short) llen;
            break;
        case ATTRIB_TITLE:
            if (attribs->title)
            {
                psFree(attribs->title, pool);
            }
            attribs->title = stringOut;
            attribs->titleType = (short) stringType;
            attribs->titleLen = (short) llen;
            break;
        case ATTRIB_SURNAME:
            if (attribs->surname)
            {
                psFree(attribs->surname, pool);
            }
            attribs->surname = stringOut;
            attribs->surnameType = (short) stringType;
            attribs->surnameLen = (short) llen;
            break;
        case ATTRIB_GIVEN_NAME:
            if (attribs->givenName)
            {
                psFree(attribs->givenName, pool);
            }
            attribs->givenName = stringOut;
            attribs->givenNameType = (short) stringType;
            attribs->givenNameLen = (short) llen;
            break;
        case ATTRIB_INITIALS:
            if (attribs->initials)
            {
                psFree(attribs->initials, pool);
            }
            attribs->initials = stringOut;
            attribs->initialsType = (short) stringType;
            attribs->initialsLen = (short) llen;
            break;
        case ATTRIB_PSEUDONYM:
            if (attribs->pseudonym)
            {
                psFree(attribs->pseudonym, pool);
            }
            attribs->pseudonym = stringOut;
            attribs->pseudonymType = (short) stringType;
            attribs->pseudonymLen = (short) llen;
            break;
        case ATTRIB_GEN_QUALIFIER:
            if (attribs->generationQualifier)
            {
                psFree(attribs->generationQualifier, pool);
            }
            attribs->generationQualifier = stringOut;
            attribs->generationQualifierType = (short) stringType;
            attribs->generationQualifierLen = (short) llen;
            break;
#  endif    /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#  ifdef USE_EXTRA_DN_ATTRIBUTES
        case ATTRIB_STREET_ADDRESS:
            if (attribs->streetAddress)
            {
                psFree(attribs->streetAddress, pool);
            }
            attribs->streetAddress = stringOut;
            attribs->streetAddressType = (short) stringType;
            attribs->streetAddressLen = (short) llen;
            break;
        case ATTRIB_POSTAL_ADDRESS:
            if (attribs->postalAddress)
            {
                psFree(attribs->postalAddress, pool);
            }
            attribs->postalAddress = stringOut;
            attribs->postalAddressType = (short) stringType;
            attribs->postalAddressLen = (short) llen;
            break;
        case ATTRIB_TELEPHONE_NUMBER:
            if (attribs->telephoneNumber)
            {
                psFree(attribs->telephoneNumber, pool);
            }
            attribs->telephoneNumber = stringOut;
            attribs->telephoneNumberType = (short) stringType;
            attribs->telephoneNumberLen = (short) llen;
            break;
        case ATTRIB_UID:
            if (attribs->uid)
            {
                psFree(attribs->uid, pool);
            }
            attribs->uid = stringOut;
            attribs->uidType = (short) stringType;
            attribs->uidLen = (short) llen;
            break;
        case ATTRIB_NAME:
            if (attribs->name)
            {
                psFree(attribs->name, pool);
            }
            attribs->name = stringOut;
            attribs->nameType = (short) stringType;
            attribs->nameLen = (short) llen;
            break;
        case ATTRIB_EMAIL:
            if (attribs->email)
            {
                psFree(attribs->email, pool);
            }
            attribs->email = stringOut;
            attribs->emailType = (short) stringType;
            attribs->emailLen = (short) llen;
            break;
#  endif    /* USE_EXTRA_DN_ATTRIBUTES */
        default:
            /* Not a MUST support, so just ignore unknown */
            attributeStored = PS_FALSE;
            psFree(stringOut, pool);
            stringOut = NULL;
            break;
        }

        if (attributeStored)
        {
            for (i = 0; i < DN_NUM_ATTRIBUTES_MAX; i++)
            {
                if (id != ATTRIB_ORG_UNIT && id != ATTRIB_DOMAIN_COMPONENT)
                {
                    if (attribs->attributeOrder[i] == id)
                    {
                        /*
                          Storing multiple instances of the same attribute type is
                          currently only supported for OU and DC. For other attributes,
                          a new instance overwrites the previous one.
                        */
                        break;
                    }
                }
                if (attribs->attributeOrder[i] == 0)
                {
                    attribs->attributeOrder[i] = id;
                    break;
                }
            }
        }

        if (moreInSet)
        {
            goto MORE_IN_SET;
        }
    }
    /* Hash is used to quickly compare DNs */
#  ifdef USE_SHA1
    psSha1PreInit(&hash);
    psSha1Init(&hash);
    psSha1Update(&hash, dnStart, (dnEnd - dnStart));
    psSha1Final(&hash, (unsigned char *) attribs->hash);
#  else
    psSha256PreInit(&hash);
    psSha256Init(&hash);
    psSha256Update(&hash, dnStart, (dnEnd - dnStart));
    psSha256Final(&hash, (unsigned char *) attribs->hash);
#  endif
    *pp = p;
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Free helper
 */
void psX509FreeDNStruct(x509DNattributes_t *dn, psPool_t *allocPool)
{
    psFree(dn->dnenc, allocPool);

    psFree(dn->country, allocPool);
    psFree(dn->organization, allocPool);
    freeOrgUnitList(dn->orgUnit, allocPool);
    psFree(dn->dnQualifier, allocPool);
    psFree(dn->state, allocPool);
    psFree(dn->commonName, allocPool);
    psFree(dn->serialNumber, allocPool);
    freeDomainComponentList(dn->domainComponent, allocPool);
#  ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
    psFree(dn->locality, allocPool);
    psFree(dn->title, allocPool);
    psFree(dn->surname, allocPool);
    psFree(dn->givenName, allocPool);
    psFree(dn->initials, allocPool);
    psFree(dn->pseudonym, allocPool);
    psFree(dn->generationQualifier, allocPool);
#  endif /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#  ifdef USE_EXTRA_DN_ATTRIBUTES
    psFree(dn->streetAddress, allocPool);
    psFree(dn->postalAddress, allocPool);
    psFree(dn->telephoneNumber, allocPool);
    psFree(dn->uid, allocPool);
    psFree(dn->name, allocPool);
    psFree(dn->email, allocPool);
#  endif /* USE_EXTRA_DN_ATTRIBUTES */
}


/******************************************************************************/
/*
    Fundamental routine to test whether the supplied issuerCert issued
    the supplied subjectCert.  There are currently two tests that are
    performed here:
        1. A strict SHA1 hash comparison of the Distinguished Name details
        2. A test of the public key cryptographic cert signature

    subjectCert may be a chain.  Cert chains must always be passed with
    the child-most as the first in the list (the 'next' structure member
    points to the parent).  The authentication of the entire chain
    will be tested before the issuerCert is used to authenticate the
    parent-most certificate

    issuerCert will always be a treated as a single certificate even if it
    is a chain

    If there is no issuerCert the parent-most subejct cert will always
    be tested as a self-signed CA certificate.

    So there are three uses:
    1. Test a cert was issued by another (single subjectCert, single issuerCert)
    1. Test a self signed cert (single cert to subjectCert, no issuerCert)
    2. Test a CA terminated chain (cert chain to subjectCert, no issuerCert)

    This function exits with a failure code on the first authentication
    that doesn't succeed.  The 'authStatus' members may be examined for more
    information of where the authentication failed.

    The 'authStatus' member of the issuerCert will be set to PS_FALSE
    since it will not be authenticated.

    The 'authStatus' members of the subjectCert structures will always
    be reset to PS_FALSE when this routine is called and set to PS_TRUE
    when authenticated.  Any error during the authentication will set the
    current subject cert 'authStatus' member to PS_CERT_AUTH_FAIL and the
    function will return with an error code.

    Return codes:
        PS_SUCCESS                      - yes

        PS_CERT_AUTH_FAIL       - nope. these certs are not a match
        PS_UNSUPPORTED_FAIL     - unrecognized cert format
        PS_ARG_FAIL                     - local, psRsaDecryptPub
        PS_LIMIT_FAIL           - psRsaDecryptPub
        PS_FAILURE                      - internal psRsaDecryptPub failure

    There is nothing for the caller to free at the completion of this
    routine.
 */
int32 psX509AuthenticateCert(psPool_t *pool, psX509Cert_t *subjectCert,
    psX509Cert_t *issuerCert,  psX509Cert_t **foundIssuer,
    void *hwCtx, void *poolUserPtr)
{
    psX509Cert_t *ic, *sc;

    if (subjectCert == NULL)
    {
        psTraceCrypto("No subject cert given to psX509AuthenticateCert\n");
        return PS_ARG_FAIL;
    }

    /*
      Determine what we've been passed
    */
    if (issuerCert == NULL)
    {
        /* reset auth flags in subjectCert chain and find first sc and ic */
        sc = subjectCert;
        while (sc)
        {
            sc->authStatus = PS_FALSE;
            sc = sc->next;
        }
        /* Now see if this is a chain or just a single cert */
        sc = subjectCert;
        if (sc->next == NULL)
        {
            ic = sc; /* A single subject cert for self-signed test */
        }
        else
        {
            ic = sc->next;
        }
    }
    else
    {
        issuerCert->authStatus = PS_FALSE;
        ic = issuerCert; /* Easy case of single subject and single issuer */
        sc = subjectCert;
    }

    /*
      Error on first problem seen and set the subject status to FAIL
    */
    while (ic)
    {
        /*
          Certificate authority constraint only available in version 3 certs.
          Only parsing version 3 certs by default though.
        */
        if ((ic->version > 1) && (ic->extensions.bc.cA != CA_TRUE))
        {
            if (sc != ic)
            {
                psTraceCrypto("Issuer does not have basicConstraint CA permissions\n");
                sc->authStatus = PS_CERT_AUTH_FAIL_BC;
                return PS_CERT_AUTH_FAIL_BC;
            }
        }

        /*
          Use sha1 hash of issuer fields computed at parse time to compare
        */
        if (Memcmp(sc->issuer.hash, ic->subject.hash, SHA1_HASH_SIZE) != 0)
        {
#define ALLOW_INTERMEDIATES_AS_ROOTS
#  ifdef ALLOW_INTERMEDIATES_AS_ROOTS
            /* In a typical deployment, we have this trust chain:
                    leaf->intermediate->(root)
                Where leaf and intermediate are sent by the peer and root is loaded by the
                application as a trusted CA.
                In some cases, it may not be desireable to load the root cert as a CA and
                validate every certificate it has signed. This is usually due to a
                legacy v1 certificate or certificate using a weak cryptographic
                algorithm.
                Ideally, the certificate chain can be re-issued or cross-signed by a modern
                root certifiate. However, a workaround is to load the final intermediate
                certificate in the application as a trusted, non self-signed root.
                The peer sends the leaf->intermediate chain as before, but the application
                loads the intermediate, not the root as a trusted CA cert.
                Without special treatment, this arranement will fail validation because the
                intermediate has been issued by 'root', and that is what it wants to validate
                against. However, if we check to see if a copy of intermediate is itself in the
                issuer list, then we have validated to a trusted root and do not need
                to verify the signature on the intermediate.
                Note this implementation only allows the last cert in the chain sent by
                the client to be treated as root, for example in a chain with 2 intermediates:
                Peer sends l->i1->i2->(root)
                Valid CA to load: i2 or root
                Invalid CA to load: l or i1
             */
            if (sc->signatureLen == ic->signatureLen
                && memcmpct(sc->signature, ic->signature, sc->signatureLen) == 0)
            {
                /* Skip some of the signature and issuer checks */
                goto L_INTERMEDIATE_ROOT;
            }
#  endif
            if (sc == ic)
            {
                psTraceCrypto("Info: not a self-signed certificate\n");
            }
            else
            {
                psTraceCrypto("Issuer DN attributes do not match subject\n");
            }
            sc->authStatus = PS_CERT_AUTH_FAIL_DN;
            return PS_CERT_AUTH_FAIL_DN;
        }

#  ifdef USE_CRL
        /* This function operates on the global cache */
        psCRL_determineRevokedStatus(sc);
        /* The only status that is going to make us terminate the connection
            immediately is if we find REVOKED_AND_AUTHENTICATED */
        if (sc->revokedStatus == CRL_CHECK_REVOKED_AND_AUTHENTICATED)
        {
            sc->authStatus = PS_CERT_AUTH_FAIL_REVOKED;
            return PS_CERT_AUTH_FAIL_REVOKED;
        }
#  endif

        /*
          Try to verify the subject cert's signature using the issuer cert's
          public key.
        */
        {
            psRes_t res;
            const unsigned char *tbs = sc->sigHash;
            psSizeL_t tbsLen = sc->sigHashLen;
            psVerifyOptions_t opts;
            psBool_t verifyResult = PS_FALSE;

            memset(&opts, 0, sizeof(opts));
            opts.msgIsDigestInfo = PS_TRUE;

            /* Special cases: RSASSA-PSS, Ed25519 and DSA verification
               needs some extra information. */
# ifdef USE_PKCS1_PSS
            if (sc->sigAlgorithm == OID_RSASSA_PSS)
            {
                opts.rsaPssHashAlg = sc->pssHash;
                opts.rsaPssHashLen = psPssHashAlgToHashLen(sc->pssHash);
                opts.rsaPssSaltLen = sc->saltLen;
                opts.useRsaPss = PS_TRUE;
#  ifdef USE_CL_RSA
                tbs = sc->tbsCertStart;
                tbsLen = sc->tbsCertLen;
#  endif
            }
# endif /* USE_PKCS1_PSS */
# ifdef USE_ED25519
            if (sc->sigAlgorithm == OID_ED25519_KEY_ALG)
            {
                tbs = sc->tbsCertStart;
                tbsLen = sc->tbsCertLen;
                opts.msgIsDigestInfo = PS_FALSE;
            }
# endif /* USE_ED25519 */
# if defined(USE_ROT_CRYPTO) && (defined(USE_ROT_ECC) || defined(USE_ROT_RSA))
            tbs = sc->tbsCertStart;
            tbsLen = sc->tbsCertLen;
# endif
            res = psVerifySig(NULL,
                    tbs,
                    tbsLen,
                    sc->signature,
                    sc->signatureLen,
                    &ic->publicKey,
                    sc->sigAlgorithm,
                    &verifyResult,
                    &opts);
            if (res != PS_SUCCESS || verifyResult != PS_TRUE)
            {
                sc->authStatus = PS_CERT_AUTH_FAIL_SIG;
                return PS_CERT_AUTH_FAIL_SIG;
            }
        }

        /* X.509 extension tests.  Problems below here will be collected
            in flags and given to the user */

        /* Verify subject key and auth key if either is non-zero */
        if (sc->extensions.ak.keyLen > 0 || ic->extensions.sk.len > 0)
        {
            if (ic->extensions.sk.len != sc->extensions.ak.keyLen)
            {
                /* The one exception to this test would be if this is a
                    self-signed CA being authenticated with the exact same
                    self-signed CA and that certificate does not popluate
                    the Authority Key Identifier extension */
                if ((sc->signatureLen == ic->signatureLen) &&
                    (Memcmp(sc->signature, ic->signature, ic->signatureLen)
                     == 0))
                {
                    if (sc->extensions.ak.keyLen != 0)
                    {
                        psTraceCrypto("Subject/Issuer key id mismatch\n");
#ifdef DISABLE_AUTH_KEY_ID_CHECK
                        psTraceCrypto("Ignoring Subject/Issuer key id mismatch " \
                                "due to #define DISABLE_AUTH_KEY_ID_CHECK\n");
#else
                        sc->authStatus = PS_CERT_AUTH_FAIL_AUTHKEY;
#endif /* DISABLE_AUTH_KEY_ID_CHECK */
                    }
                }
                else
                {
                    psTraceCrypto("Subject/Issuer key id mismatch\n");
#ifdef DISABLE_AUTH_KEY_ID_CHECK
                    psTraceCrypto("Ignoring Subject/Issuer key id mismatch " \
                            "due to #define DISABLE_AUTH_KEY_ID_CHECK\n");
#else
                    sc->authStatus = PS_CERT_AUTH_FAIL_AUTHKEY;
#endif /* DISABLE_AUTH_KEY_ID_CHECK */
                }
            }
            else
            {
                if (Memcmp(ic->extensions.sk.id, sc->extensions.ak.keyId,
                        ic->extensions.sk.len) != 0)
                {
                    psTraceCrypto("Subject/Issuer key id data mismatch\n");
#ifdef DISABLE_AUTH_KEY_ID_CHECK
                    psTraceCrypto("Ignoring Subject/Issuer key id mismatch " \
                            "due to #define DISABLE_AUTH_KEY_ID_CHECK\n");
#else
                    sc->authStatus = PS_CERT_AUTH_FAIL_AUTHKEY;
#endif /* DISABLE_AUTH_KEY_ID_CHECK */

                }
            }
        }

        /* Ensure keyCertSign of KeyUsage. The second byte of the BIT STRING
            will always contain the relevant information. */
        if ( !(ic->extensions.keyUsageFlags & KEY_USAGE_KEY_CERT_SIGN))
        {
            int32 rc = 0;
            /* @security If keyUsageFlags is zero, it may not exist at all
                in the cert. This is allowed if the cert was issued before
                the RFC was updated to require this field for CA certificates.
                RFC3280 and above specify this as a MUST for CACerts. */
            if (ic->extensions.keyUsageFlags == 0)
            {
                rc = issuedBefore(RFC_3280, ic);
            }

            /* Iff rc == 1 we won't error */
            if (!rc)
            {
                psTraceCrypto("Issuer does not allow keyCertSign in keyUsage\n");
                sc->authFailFlags |= PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG;
                sc->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
            }
            else if (rc < 0)
            {
                psTraceCrypto("Issue date check failed\n");
                return PS_PARSE_FAIL;
            }
        }
#  ifdef ALLOW_INTERMEDIATES_AS_ROOTS
L_INTERMEDIATE_ROOT:
#  endif
        /* If date was out of range in parse, and we have no other auth errors,
            set it here. Other errors "take priority" in the return code, although
            all can be accessed with authFailFlags. */
        if (sc->authStatus == PS_FALSE
            && sc->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG)
        {
            sc->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
        }
/*
        Fall through to here only if passed all non-failure checks.
 */
        if (sc->authStatus == PS_FALSE)   /* Hasn't been touched */
        {
            sc->authStatus = PS_CERT_AUTH_PASS;
        }
/*
        Loop control for finding next ic and sc.
 */
        if (ic == sc)
        {
            *foundIssuer = ic;
            ic = NULL; /* Single self-signed test completed */
        }
        else if (ic == issuerCert)
        {
            *foundIssuer = ic;
            ic = NULL; /* If issuerCert was used, that is always final test */
        }
        else
        {
            sc = ic;
            ic = sc->next;
            if (ic == NULL)   /* Reached end of chain */
            {
                *foundIssuer = ic;
                ic = sc;      /* Self-signed test on final subectCert chain */
            }
        }

    }
    return PS_SUCCESS;
}

/******************************************************************************/
# endif /* USE_CERT_PARSE */

# ifdef USE_OCSP_RESPONSE

/******************************************************************************/

static int32_t parse_nonce_ext(const unsigned char *p, size_t sz,
    psBuf_t *nonceExtension)
{
    psParseBuf_t pb;
    psParseBuf_t extensions;
    psParseBuf_t extension;

    Memset(nonceExtension, 0, sizeof(psBuf_t));
    if (psParseBufFromStaticData(&pb, p, sz) == PS_SUCCESS)
    {
        if (psParseBufTryReadTagSub(&pb, &extensions, 0xA1))
        {
            while (psParseBufTryReadSequenceSub(&extensions,
                       &extension))
            {
                psParseBuf_t sub;
                psParseBufReadSequenceSub(&extension, &sub);
                if (psParseBufTrySkipBytes(
                        &sub,
                        (const unsigned char *)
                        "\x06\x09\x2b\x06\x01\x05"
                        "\x05\x07\x30\x01\x02", 11))
                {
                    psParseBufReadTagRef(
                        &sub, nonceExtension, 0x04);
                }
                psParseBufFinish(&sub);
                if (psParseBufFinish(&extension) != PS_SUCCESS)
                {
                    break;
                }
            }
            psParseBufFinish(&extensions);
        }
    }
    return PS_SUCCESS; /* No parsing errors detected. */
}

static void parseSingleResponseRevocationTimeAndReason(
    const unsigned char *p,
    psSize_t glen,
    psOcspSingleResponse_t *res)
{
    /* Note: res has to have been cleared before this function.
       The function does not fill-in the relevant fields if they are
       not found. */

    /* get revocation time ASN.1 (GeneralizedTime / 0x18) */
    if (glen >= sizeof(res->revocationTime) + 2 &&
        p[0] == 0x18 && p[1] == sizeof(res->revocationTime))
    {
        Memcpy(res->revocationTime, p + 2,
            sizeof(res->revocationTime));
        /* revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
           CRLReason ::= ENUMERATED [RFC 5280] */
        if (glen >= sizeof(res->revocationTime) + 0x5 &&
            p[17] == 0xa0 &&     /* [0] */
            p[18] == 0x03 &&     /* length */
            p[19] == 0x0a &&     /* ENUMERATED */
            p[20] == 0x01 &&     /* length */
            p[21] <= 10 &&       /* CRL reason code 0-10, excluding 7. */
            p[21] != 7)
        {
            res->revocationReason = p[21];
        }
    }
}

static int32_t parseSingleResponse(uint32_t len, const unsigned char **cp,
    const unsigned char *end, psOcspSingleResponse_t *res)
{
    const unsigned char *p;
    psSize_t glen, plen;
    int32_t oi;

    p = *cp;

    /*  SingleResponse ::= SEQUENCE {
            certID                  CertID,
            certStatus              CertStatus,
            thisUpdate              GeneralizedTime,
            nextUpdate          [0] EXPLICIT GeneralizedTime OPTIONAL,
            singleExtensions    [1] EXPLICIT Extensions OPTIONAL }
     */
    if (getAsnSequence(&p, (int32) (end - p), &glen) < 0)
    {
        psTraceCrypto("Initial parseSingleResponse parse failure\n");
        return PS_PARSE_FAIL;
    }
    /* CertID ::= SEQUENCE {
        hashAlgorithm            AlgorithmIdentifier
                                 {DIGEST-ALGORITHM, {...}},
        issuerNameHash     OCTET STRING, -- Hash of issuer's DN
        issuerKeyHash      OCTET STRING, -- Hash of issuer's public key
        serialNumber       CertificateSerialNumber }
     */
    if (getAsnSequence(&p, (int32) (end - p), &glen) < 0)
    {
        psTraceCrypto("Initial parseSingleResponse parse failure\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnAlgorithmIdentifier(&p, (int32) (end - p), &oi, &plen) < 0)
    {
        return PS_FAILURE;
    }
    psAssert(plen == 0);
    res->certIdHashAlg = oi;

    if ((*p++ != ASN_OCTET_STRING) ||
        getAsnLength(&p, (int32) (end - p), &glen) < 0 ||
        (uint32) (end - p) < glen)
    {
        return PS_PARSE_FAIL;
    }
    res->certIdNameHash = p;
    p += glen;

    if ((*p++ != ASN_OCTET_STRING) ||
        getAsnLength(&p, (int32) (end - p), &glen) < 0 ||
        (uint32) (end - p) < glen)
    {
        return PS_PARSE_FAIL;
    }
    res->certIdKeyHash = p;
    p += glen;

    /* serialNumber       CertificateSerialNumber

        CertificateSerialNumber  ::=  INTEGER
     */
    if ((*p != (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 2)) &&
        (*p != ASN_INTEGER))
    {
        psTraceCrypto("X.509 getSerialNum failed on first bytes\n");
        return PS_PARSE_FAIL;
    }
    p++;

    if (getAsnLength(&p, (int32) (end - p), &glen) < 0 ||
        (uint32) (end - p) < glen)
    {
        psTraceCrypto("ASN getSerialNum failed\n");
        return PS_PARSE_FAIL;
    }
    res->certIdSerialLen = glen;
    res->certIdSerial = p;
    p += glen;

    /* CertStatus ::= CHOICE {
            good                [0]     IMPLICIT NULL,
            revoked             [1]     IMPLICIT RevokedInfo,
            unknown             [2]     IMPLICIT UnknownInfo }
     */
    Memset(res->revocationTime, 0, sizeof(res->revocationTime));
    res->revocationReason = 0;
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 0))
    {
        res->certStatus = 0;
        p += 2;
    }
    else if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        res->certStatus = 1;
        psTraceCrypto("OCSP CertStatus is revoked.\n");
        /* RevokedInfo ::= SEQUENCE {
                revocationTime              GeneralizedTime,
                revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
         */
        p += 1;
        if (getAsnLength(&p, (int32) (end - p), &glen) < 0)
        {
            psTraceCrypto("Initial parseSingleResponse parse failure\n");
            return PS_PARSE_FAIL;
        }
        /* subfunction for parsing RevokedInfo. */
        parseSingleResponseRevocationTimeAndReason(p, glen, res);
        p += glen;
    }
    else if (*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 2))
    {
        res->certStatus = 2;
        p += 2; /* TOOD: Untested parse.  Might be CONSTRUCTED encoding */
        /* UnknownInfo ::= NULL */
    }
    else
    {
        psTraceCrypto("OCSP CertStatus parse fail\n");
        return PS_PARSE_FAIL;
    }

    /* thisUpdate GeneralizedTime, */
    if ((end - p) < 1 || (*p != ASN_GENERALIZEDTIME))
    {
        psTraceCrypto("Malformed thisUpdate OCSP\n");
        return PS_PARSE_FAIL;
    }
    p++;
    if (getAsnLength(&p, (uint32) (end - p), &glen) < 0 ||
        (uint32) (end - p) < glen)
    {
        return PS_PARSE_FAIL;
    }
    res->thisUpdateLen = glen;
    res->thisUpdate = p;
    p += glen;

    /* nextUpdate          [0] EXPLICIT GeneralizedTime OPTIONAL, */
    res->nextUpdate = NULL;
    res->nextUpdateLen = 0;
    if ((uint32) (end - p) >= 2 &&
        *p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
    {
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &glen) < 0 ||
            (uint32) (end - p) < glen)
        {
            return PS_PARSE_FAIL;
        }
        if (*p == ASN_GENERALIZEDTIME && glen > 2)
        {
            res->nextUpdate = p + 2;
            res->nextUpdateLen = glen - 2;
        }
        p += glen;
    }

    /* singleExtensions    [1] EXPLICIT Extensions OPTIONAL */
    if ((uint32) (end - p) >= 2 &&
        *p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &glen) < 0 ||
            (uint32) (end - p) < glen)
        {
            return PS_PARSE_FAIL;
        }
        /* TODO */
        p += glen; /* SKIPPING  */
    }

    *cp = (unsigned char *) p;
    return PS_SUCCESS;
}

static int32_t ocspParseBasicResponse(psPool_t *pool, uint32_t len,
    const unsigned char **cp, unsigned char *end,
    psOcspResponse_t *res)
{
    const unsigned char *p, *seqend, *startRes, *endRes;
    psOcspSingleResponse_t *singleResponse;
    psSha1_t sha;

#  ifdef USE_SHA256
    psSha256_t sha2;
#  endif
#  ifdef USE_SHA384
    psSha384_t sha3;
#  endif
#  ifdef USE_SHA512
    psSha512_t sha512;
#  endif
    psSize_t glen, plen;
    uint32_t blen;
    int32_t version, oid;
    int32_t cert_res;

    /* id-pkix-ocsp-basic

        BasicOCSPResponse       ::= SEQUENCE {
            tbsResponseData      ResponseData,
            signatureAlgorithm   AlgorithmIdentifier,
            signature            BIT STRING,
            certs        [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
     */
    p = *cp;

    if (getAsnSequence(&p, (uint32) (end - p), &glen) < 0)
    {
        psTraceCrypto("Initial parse error in ocspParseBasicResponse\n");
        return PS_PARSE_FAIL;
    }
    /*
        ResponseData ::= SEQUENCE {
            version              [0] EXPLICIT Version DEFAULT v1,
            responderID              ResponderID,
            producedAt               GeneralizedTime,
            responses                SEQUENCE OF SingleResponse,
            responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
     */
    startRes = p; /* A response signature will be over ResponseData */
    if (getAsnSequence(&p, (uint32) (end - p), &glen) < 0)
    {
        psTraceCrypto("Early ResponseData parse error in psOcspParseResponse\n");
        return PS_PARSE_FAIL;
    }
    if (getExplicitVersion(&p, (uint32) (end - p), 0, &version) < 0)
    {
        psTraceCrypto("Version parse error in ResponseData\n");
        return PS_PARSE_FAIL;
    }
    res->version = version;
    if (version != 0)
    {
        psTraceIntCrypto("WARNING: Unknown OCSP ResponseData version %d\n",
            version);
        return PS_VERSION_UNSUPPORTED;
    }
    /*
        ResponderID ::= CHOICE {
            byName               [1] Name,
            byKey                [2] KeyHash }
     */

    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        const unsigned char *p2;
        p++;
        if (getAsnLength32(&p, (uint32_t) (end - p), &blen, 0) < 0 ||
            (uint32_t) (end - p) < blen || blen == 0)
        {
            psTraceCrypto("Error parsing Name in ResponseData\n");
            return PS_PARSE_FAIL;
        }
        res->responderName = p;
        res->responderKeyHash = NULL;
        p2 = p;
        p += blen;
        /* Check contents of ASN Sequence containing Name. */
        if ((*p2++ != (ASN_CONSTRUCTED | ASN_SEQUENCE)) ||
            getAsnLength32(&p2, (int32) (end - p2), &blen, 0) < 0 ||
            p != p2 + blen)
        {
            psTraceCrypto("Error parsing Name in ResponseData\n");
            res->responderName = NULL;
            return PS_PARSE_FAIL;
        }
    }
    else if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2))
    {
        p++;
        if (getAsnLength32(&p, (uint32_t) (end - p), &blen, 0) < 0 ||
            (uint32_t) (end - p) < blen)
        {
            psTraceCrypto("Error parsing KeyHash in ResponseData\n");
            return PS_PARSE_FAIL;
        }
        /* KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
                         -- (i.e., the SHA-1 hash of the value of the
                         -- BIT STRING subjectPublicKey [excluding
                         -- the tag, length, and number of unused
                         -- bits] in the responder's certificate) */
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength(&p, (int32) (end - p), &glen) < 0 ||
            (uint32) (end - p) < glen ||
            glen != SHA1_HASH_SIZE)
        {

            psTraceCrypto("Couldn't parse KeyHash in ResponseData\n");
            return PS_FAILURE;
        }
        psAssert(glen == SHA1_HASH_SIZE);
        res->responderName = NULL;
        res->responderKeyHash = p;
        p += SHA1_HASH_SIZE;
    }
    else
    {
        psTraceCrypto("ResponderID parse error in ResponseData\n");
        return PS_PARSE_FAIL;
    }

    /* producedAt GeneralizedTime, */
    if ((end - p) < 1 || (*p != ASN_GENERALIZEDTIME))
    {
        psTraceCrypto("Malformed thisUpdate CRL\n");
        return PS_PARSE_FAIL;
    }
    p++;
    if (getAsnLength(&p, (uint32) (end - p), &glen) < 0 ||
        (uint32) (end - p) < glen)
    {
        psTraceCrypto("Malformed producedAt in ResponseData\n");
        return PS_PARSE_FAIL;
    }
    /* Perform quick parsing on data. */
    if (psBrokenDownTimeImport(NULL, (const char *) p, glen, 0) < 0)
    {
        return PS_PARSE_FAIL;
    }
    res->timeProducedLen = glen;
    res->timeProduced = p;
    p += glen;

    /* responses                SEQUENCE OF SingleResponse, */
    if (getAsnSequence(&p, (int32) (end - p), &glen) < 0)
    {
        psTraceCrypto("Initial SingleResponse parse failure\n");
        return PS_PARSE_FAIL;
    }

    seqend = p + glen;

    plen = 0; /* for MAX_OCSP_RESPONSES control */
    while (p < seqend)
    {
        singleResponse = &res->singleResponse[plen];
        if (parseSingleResponse(glen, &p, seqend, singleResponse) < 0)
        {
            return PS_PARSE_FAIL;
        }
        plen++;
        if (p < seqend)
        {
            /* Additional responses */
            if (plen == MAX_OCSP_RESPONSES)
            {
                psTraceCrypto("ERROR: Multiple OCSP SingleResponse items. ");
                psTraceCrypto("Increase MAX_OCSP_RESPONSES to support\n");
                return PS_PARSE_FAIL;
            }
        }
    }
    /* responseExtensions   [1] EXPLICIT Extensions OPTIONAL } */
    if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        if (parse_nonce_ext(p, end - p, &res->nonce) != PS_SUCCESS)
        {
            return PS_PARSE_FAIL;
        }
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &glen) < 0 ||
            (uint32) (end - p) < glen)
        {
            return PS_PARSE_FAIL;
        }
        /* TODO: */
        p += glen; /* SKIPPING  */
    }
    endRes = p;

    /* ResponseData DONE.  On to signature:

        signatureAlgorithm   AlgorithmIdentifier
        signature            BIT STRING,

        The value for signature SHALL be computed on the hash of the DER
        encoding of ResponseData.  The responder MAY include certificates in
        the certs field of BasicOCSPResponse that help the OCSP client
        verify the responder's signature.  If no certificates are included,
        then certs SHOULD be absent. */
    if (getAsnAlgorithmIdentifier(&p, (uint32) (end - p), &oid, &plen) < 0)
    {
        psTraceCrypto("Initial SingleResponse parse failure\n");
        return PS_PARSE_FAIL;
    }
    if (plen > 0)
    {
        psTraceCrypto("Algorithm parameters on ResponseData sigAlg\n");
        p += plen;
    }
    res->sigAlg = oid;

    switch (oid)
    {
    /* OSCP requires SHA1 so no wrapper here */
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_RSA_SIG2:
#  ifdef USE_ECC
    case OID_SHA1_ECDSA_SIG:
#  endif
        res->hashLen = SHA1_HASH_SIZE;
        psSha1PreInit(&sha);
        psSha1Init(&sha);
        psSha1Update(&sha, startRes, (int32) (endRes - startRes));
        psSha1Final(&sha, res->hashResult);
        break;
#  ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA224_ECDSA_SIG:
#   endif
        res->hashLen = SHA224_HASH_SIZE;
        psSha224PreInit(&sha2);
        psSha224Init(&sha2);
        psSha224Update(&sha2, startRes, (int32) (endRes - startRes));
        psSha224Final(&sha2, res->hashResult);
        break;
#  endif
#  ifdef USE_SHA256
    case OID_SHA256_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA256_ECDSA_SIG:
#   endif
        res->hashLen = SHA256_HASH_SIZE;
        psSha256PreInit(&sha2);
        psSha256Init(&sha2);
        psSha256Update(&sha2, startRes, (int32) (endRes - startRes));
        psSha256Final(&sha2, res->hashResult);
        break;
#  endif
#  ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA384_ECDSA_SIG:
#   endif
        res->hashLen = SHA384_HASH_SIZE;
        psSha384PreInit(&sha3);
        psSha384Init(&sha3);
        psSha384Update(&sha3, startRes, (int32) (endRes - startRes));
        psSha384Final(&sha3, res->hashResult);
        break;
#  endif
#  ifdef USE_SHA512
    case OID_SHA512_RSA_SIG:
#   ifdef USE_ECC
    case OID_SHA512_ECDSA_SIG:
#   endif
        res->hashLen = SHA512_HASH_SIZE;
        psSha512PreInit(&sha512);
        psSha512Init(&sha512);
        psSha512Update(&sha512, startRes, (int32) (endRes - startRes));
        psSha512Final(&sha512, res->hashResult);
        break;
#  endif
    default:
        psTraceCrypto("No support for sigAlg in OCSP ResponseData\n");
        return PS_UNSUPPORTED_FAIL;
    }

    if (*p++ != ASN_BIT_STRING)
    {
        psTraceCrypto("Error parsing signature in ResponseData\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnLength(&p, (int32) (end - p), &glen) < 0 ||
        (uint32) (end - p) < glen)
    {
        psTraceCrypto("Error parsing signature in ResponseData\n");
        return PS_PARSE_FAIL;
    }
    if (*p++ != 0)
    {
        psTraceCrypto("Error parsing ignore bits in ResponseData sig\n");
        return PS_PARSE_FAIL;
    }
    glen--; /* ignore bits above */
    res->sig = p;
    res->sigLen = glen;
    p += glen;

    /* certs        [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL } */
    if (end != p)
    {
        /* The responder MAY include certificates in the certs field of
            BasicOCSPResponse that help the OCSP client verify the responder's
            signature. */
        if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
        {
            psTraceCrypto("Unexpected Certificage encoding in OCSPResponse\n");
            return PS_PARSE_FAIL;
        }
        p++;
        if (getAsnLength(&p, (uint32) (end - p), &glen) < 0 ||
            (uint32) (end - p) < glen)
        {
            return PS_PARSE_FAIL;
        }
        /* If here, this is the cert that issued the OCSPResponse.  Will
            authenticate during psOcspResponseValidateOld */
        if (getAsnSequence(&p, (uint32) (end - p), &glen) < 0)
        {
            psTraceCrypto("\n");
            return PS_PARSE_FAIL;
        }
        psAssert(glen == (end - p));
        /* will handle multiple certs if needed.
           Store certificate for reference. */
        cert_res = psX509ParseCert(pool, p, glen, &res->OCSPResponseCert,
            CERT_STORE_UNPARSED_BUFFER);
        if (cert_res < 0)
        {
            psX509FreeCert(res->OCSPResponseCert);
            res->OCSPResponseCert = NULL;
            return PS_PARSE_FAIL;
        }
        p += cert_res;
    }
    psAssert(p == end);

    *cp = (unsigned char *) p;
    return PS_SUCCESS;
}

int32_t psOcspResponseGetStatus(int32_t rc)
{
    /* Check if response code is within
       PS_OCSP_MALFORMED_REQUEST ... PS_OCSP_UNAUTHORIZED range. */
    if (rc >= PS_OCSP_MALFORMED_REQUEST && rc <= PS_OCSP_UNAUTHORIZED)
    {
        rc -= PS_OCSP_MALFORMED_REQUEST - 1;
        /* Return code 4 is not used. */
        if (rc != 4)
        {
            return rc;
        }
    }

    return rc == PS_SUCCESS ? 0 /* successful */ : PS_FAILURE /* other error */;
}

int32_t psOcspParseResponse(psPool_t *pool, int32_t len, unsigned char **cp,
    unsigned char *end, psOcspResponse_t *response)
{
    const unsigned char *p;
    int32_t err;
    int32_t status, oi;
    psSize_t glen;
    uint32_t blen;

    p = *cp;
    /* psTraceBytes("OCSPResponse", p, len); */
    /*
        OCSPResponse ::= SEQUENCE {
            responseStatus          OCSPResponseStatus,
            responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL }
     */
    if (getAsnSequence(&p, (uint32) (end - p), &glen) < 0)
    {
        psTraceCrypto("Initial parse error in psOcspParseResponse\n");
        return PS_PARSE_FAIL;
    }
    if (getAsnEnumerated(&p, (uint32) (end - p), &status) < 0)
    {
        psTraceCrypto("Enum parse error in psOcspParseResponse\n");
        return PS_PARSE_FAIL;
    }
    /*
        OCSPResponseStatus ::= ENUMERATED {
            successful          (0),  -- Response has valid confirmations
            malformedRequest    (1),  -- Illegal confirmation request
            internalError       (2),  -- Internal error in issuer
            tryLater            (3),  -- Try again later
                             -- (4) is not used
            sigRequired         (5),  -- Must sign the request
            unauthorized        (6)   -- Request unauthorized
        }
     */
    if (status != 0)
    {
        /* Something other than success.  List right above here */
        psTraceCrypto("OCSPResponse contains no valid confirmations\n");
        if (status <= 6 && status != 4)
        {
            /* Map status codes to return codes. */
            return status + (PS_OCSP_MALFORMED_REQUEST - 1);
        }
        /* Status code is outside valid range. */
        return PS_PARSE_FAIL;
    }

    /* responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL, */
    if (*p == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
    {
        p++;
        if (getAsnLength32(&p, (uint32_t) (end - p), &blen, 0) < 0 ||
            (uint32_t) (end - p) < blen)
        {
            psTraceCrypto("Error parsing UserKeyingMaterial\n");
            return PS_PARSE_FAIL;
        }

        /* ResponseBytes ::= SEQUENCE {
            responseType            OBJECT IDENTIFIER,
            response                OCTET STRING }
         */
        if (getAsnSequence(&p, (uint32) (end - p), &glen) < 0)
        {
            psTraceCrypto("ResponseBytes parse error in psOcspParseResponse\n");
            return PS_PARSE_FAIL;
        }
        response->responseType = p;
        if (getAsnOID(&p, (uint32) (end - p), &oi, 1, &glen) < 0)
        {
            response->responseType = NULL;
            psTraceCrypto("responseType parse error in psOcspParseResponse\n");
            return PS_PARSE_FAIL;
        }
        if ((*p++ != ASN_OCTET_STRING) ||
            getAsnLength32(&p, (int32) (end - p), &blen, 0) < 0 ||
            (uint32) (end - p) < blen)
        {

            psTraceCrypto("Couldn't parse response in psOcspParseResponse\n");
            return PS_PARSE_FAIL;
        }
        if (oi == OID_BASIC_OCSP_RESPONSE)
        {
            /* id-pkix-ocsp-basic

                BasicOCSPResponse       ::= SEQUENCE {
                    tbsResponseData      ResponseData,
                    signatureAlgorithm   AlgorithmIdentifier,
                    signature            BIT STRING,
                    certs        [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
             */
            /* Clear response except keep response type.
               Response type only remains valid as long as parsed response
               is valid. */
            const unsigned char *responseType = response->responseType;
            Memset(response, 0, sizeof(*response));
            response->responseType = responseType;
            err = ocspParseBasicResponse(pool, blen, &p, end, response);
            if (err < 0)
            {
                psTraceCrypto("ocspParseBasicResponse failure\n");
                return err;
            }
        }
        else
        {
            psTraceCrypto("unsupported responseType in psOcspParseResponse\n");
            return PS_MESSAGE_UNSUPPORTED;
        }
    }
    psAssert(end == p);
    *cp = (unsigned char *) p;
    return PS_SUCCESS;
}

/* Check validity of OCSP response and obtain the date stamps from it.

   If time_now is not provided, the current time will be requested from
   the oeprating system.
   This function extracts data information from parsed OCSP response.
   Because the dates in psOcspResponse_t are references to memory containing
   binary OCSP response, that memory must not have been released before calling
   this function. time_linger is useful to deal with the fact that the
   peer and this host may have tiny difference in their clocks.

   @param response Pointer to OCSP response structure (from psOcspParseResponse)
   @param index The index of OCSP single response to handle (0 for the first).
   @param timeNow A pointer to structure filled in with psGetBrokenDownGMTime(),
                  or gmtime(), structure initialized to all zero or NULL.
   @param producedAt If non-NULL Will be filled in with time the structure
   was produced.
   @param thisUpdate If non-NULL Will be filled in with time the OCSP
   information was updated (usually the same as producedAt).
   @param nextUpdate If non-NULL Will be filled in with time the OCSP
   information needs to be updated.
   @param time_linger Amout of flexibility in comparison of times.
   Recommended value: PS_OCSP_TIME_LINGER (120)
   @retval PS_SUCCESS If the dates were extracted from response and the
   response in comparison with timeNow is valid.
   @retval PS_TIMEOUT_FAIL The datas were extracted from response, but
   the response has timed out. (Or the response is too far in future.)
   @retval PS_PARSE_FAIL If error occurred parsing the data information in
   the request.
 */
int32_t psOcspResponseCheckDates(psOcspResponse_t *response,
    int index,
    psBrokenDownTime_t *timeNow,
    psBrokenDownTime_t *producedAt,
    psBrokenDownTime_t *thisUpdate,
    psBrokenDownTime_t *nextUpdate,
    int time_linger)
{
    psBrokenDownTime_t tmp, tmp2, tmp3, tmp4;
    unsigned char ok = 1;
    int32 err;
    psOcspSingleResponse_t *subjectResponse;
    psBrokenDownTime_t timeNowLinger;

    if (index >= MAX_OCSP_RESPONSES)
    {
        return PS_ARG_FAIL;
    }

    if (timeNow == NULL)
    {
        Memset(&tmp, 0, sizeof tmp);
        timeNow = &tmp;
    }

    if (timeNow->tm_year == 0)
    {
        /* The structure appears not filled in, use psGetBrokenDownGMTime() to
           get the current time. */
        err = psGetBrokenDownGMTime(timeNow, 0);
        if (err != PS_SUCCESS)
        {
            return PS_FAIL;
        }
    }
    Memcpy(&timeNowLinger, timeNow, sizeof timeNowLinger);
    err = psBrokenDownTimeAdd(&timeNowLinger, time_linger);
    if (err != PS_SUCCESS)
    {
        return PS_FAIL;
    }

    if (thisUpdate == NULL)
    {
        thisUpdate = &tmp2;
    }

    if (nextUpdate == NULL)
    {
        nextUpdate = &tmp3;
    }

    if (producedAt == NULL)
    {
        producedAt = &tmp4;
    }

    ok &= psBrokenDownTimeImport(producedAt,
        (const char *) response->timeProduced,
        response->timeProducedLen,
        0) == PS_SUCCESS;

    subjectResponse = &response->singleResponse[index];

    if (subjectResponse->thisUpdate)
    {
        ok &= psBrokenDownTimeImport(thisUpdate,
            (const char *) subjectResponse->thisUpdate,
            subjectResponse->thisUpdateLen,
            0) == PS_SUCCESS;
    }
    else
    {
        ok = 0;
    }

    if (subjectResponse->nextUpdate != NULL)
    {
        /* Next update provided, OCSP is valid until that time. */
        ok &= psBrokenDownTimeImport(nextUpdate,
            (const char *) subjectResponse->nextUpdate,
            subjectResponse->nextUpdateLen,
            0) == PS_SUCCESS;
    }
    else if (ok)
    {
        /* If there is no next update, the server supports
           continous updates and nextUpdate time is considered
           identical to the this update time. */
        ok &= psBrokenDownTimeImport(nextUpdate,
            (const char *) subjectResponse->thisUpdate,
            subjectResponse->thisUpdateLen,
            0) == PS_SUCCESS;
    }

    if (ok == 1)
    {
        /* Consider linger when comparing nextUpdateTime. */
        psBrokenDownTime_t nextUpdateTimeLinger;
        Memcpy(&nextUpdateTimeLinger, nextUpdate, sizeof nextUpdateTimeLinger);
        err = psBrokenDownTimeAdd(&nextUpdateTimeLinger, time_linger);
        if (err != PS_SUCCESS)
        {
            return err;
        }

        /* Now check that current time considering linger is between
           thisUpdate and nextUpdate. */

        if (psBrokenDownTimeCmp(thisUpdate, &timeNowLinger) > 0)
        {
            /* thisUpdate is in future even considering linger => reject. */
            err = PS_TIMEOUT_FAIL;
        }
        else if (psBrokenDownTimeCmp(&nextUpdateTimeLinger, timeNow) < 0)
        {
            /* nextUpdate is in past even considering linger => reject. */
            err = PS_TIMEOUT_FAIL;
        }
        else
        {
            /* err has already been set to PS_SUCCESS */
        }
    }
    else
    {
        err = PS_PARSE_FAIL;
    }
    return err;
}


/* Diff the current time against the OCSP timestamp and confirm it's not
   longer than the user is willing to trust. */
static int32_t checkOCSPtimestamp(psOcspResponse_t *response, int index)
{
    return psOcspResponseCheckDates(response, index, NULL, NULL, NULL, NULL,
        PS_OCSP_TIME_LINGER);
}

/* Partial OCSP request parser: just locate nonceExtension if present. */
static int32_t parseOcspReq(const void *data, size_t datalen,
    psBuf_t *nonceExtension)
{
    psParseBuf_t pb;
    psParseBuf_t ocspRequest;
    psParseBuf_t tbsRequest;
    psParseBuf_t extensions;
    psParseBuf_t extension;
    psParseBuf_t requestList;
    psParseBuf_t request;
    psParseBuf_t requestCert;
    psParseBuf_t requestCertContent;
    int rc;

    rc = psParseBufFromStaticData(&pb, data, datalen);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }
    psParseBufReadSequenceSub(&pb, &ocspRequest);
    /* Ensure subbuffer is advanced and main buffer is not. */
    psParseBufReadSequenceSub(&ocspRequest, &tbsRequest);
    /* Ignore version number (v1 == 0) if present. */
    psParseBufTrySkipBytes(&tbsRequest, (const unsigned char *)
        "\xA0\x03\x02\x01\x00", 5);
    /* Skip requestorName if present. */
    psParseBufTrySkipTag(&tbsRequest, 0xA1);
    /* Skip requestList (must be present with at least one request). */
    psParseBufReadSequenceSub(&tbsRequest, &requestList);
    psParseBufReadSequenceSub(&requestList, &request);
    psParseBufReadSequenceSub(&request, &requestCert);
    psParseBufReadSequenceSub(&requestCert, &requestCertContent);
    psParseBufFinish(&requestCertContent);
    psParseBufFinish(&requestCert);
    psParseBufFinish(&request);
    psParseBufFinish(&requestList);
    if (psParseBufTryReadTagSub(&tbsRequest, &extensions, 0xA2))
    {
        while (psParseBufTryReadSequenceSub(&extensions, &extension))
        {
            psParseBuf_t sub;
            psParseBufReadSequenceSub(&extension, &sub);
            if (psParseBufTrySkipBytes(
                    &sub,
                    (const unsigned char *)
                    "\x06\x09\x2b\x06\x01\x05"
                    "\x05\x07\x30\x01\x02", 11))
            {
                psParseBufReadTagRef(
                    &sub, nonceExtension, 0x04);
            }
            psParseBufFinish(&sub);
            if (psParseBufFinish(&extension) != PS_SUCCESS)
            {
                break;
            }
        }
        psParseBufFinish(&extensions);
    }
    psParseBufFinish(&tbsRequest);
    return psParseBufFinish(&ocspRequest);
}

#define RESPONDER_NAME_MAX_LENGTH 1024

static int32_t ocspMatchResponderCert(const psOcspResponse_t *response,
    const psX509Cert_t *curr)
{
    if (response->responderKeyHash != NULL)
    {
        /* Match certificate using key hash. */
        if (memcmpct(response->responderKeyHash, curr->sha1KeyHash, 20) == 0)
        {
            return PS_SUCCESS;
        }
    }
    else if (response->responderName != NULL)
    {
        uint32_t len;
        /* Obtain the length of name tag including header.
           Note: responderName has already been validated during parsing,
           so getAsnTagLenUnsafe is ok.
        */
        len = getAsnTagLenUnsafe(response->responderName);

        if (len < 2 || len > RESPONDER_NAME_MAX_LENGTH)
        {
            return PS_FAILURE;
        }

        /* Match certificate using subject name. */
        if (curr->unparsedBin == NULL ||
            curr->binLen < curr->subjectKeyDerOffsetIntoUnparsedBin + len)
        {
            return PS_FAILURE;
        }

        if (memcmpct(curr->unparsedBin +
                curr->subjectKeyDerOffsetIntoUnparsedBin,
                response->responderName, len) == 0)
        {
            return PS_SUCCESS;
        }
    }
    return PS_FAILURE;
}

int32_t psOcspResponseValidate(psPool_t *pool, psX509Cert_t *trustedOCSP,
    psX509Cert_t *srvCerts, psOcspResponse_t *response,
    psValidateOCSPResponseOptions_t *vOpts
    )
{
    static psValidateOCSPResponseOptions_t vOptsDefault;
    psX509Cert_t *curr, *issuer, *subject, *ocspResIssuer;
    psOcspSingleResponse_t *subjectResponse = NULL;
    unsigned char sigOut[MAX_HASH_SIZE];
    int32 sigOutLen, sigType, index;
    psPool_t *pkiPool = NULL;

    psBool_t knownFlag = PS_FALSE;
    psBool_t revocationFlag = PS_FALSE;
    psBuf_t nonceExtReq = { NULL };

    /* use default validation options if not specified. */
    if (vOpts == NULL)
    {
        vOpts = &vOptsDefault;
    }

    /* Find interesting options from request. */
    if (vOpts->request)
    {
        int rc = parseOcspReq(vOpts->request, vOpts->requestLen,
            &nonceExtReq);
        if (rc != PS_SUCCESS)
        {
            return PS_ARG_FAIL;
        }
    }

    /* Find the OCSP cert that signed the response.  First place to look is
        within the OCSPResponse itself */
    issuer = NULL;
    if (response->OCSPResponseCert)
    {
        /* If there is a cert here it is something that has to be authenticated.
            We will either leave this case with a successful auth or failure */
        curr = response->OCSPResponseCert;
        while (curr != NULL)
        {
            /* The outer responderKeyHash should be matching one of the certs
                that was attached to the OCSPResonse itself */
            if (ocspMatchResponderCert(response, curr) == PS_SUCCESS)
            {
                /* Found it... but now we have to authenticate it against
                    our known list of CAs.  issuer in the context of this
                    function is the     OCSPResponse issuer but here we are looking
                    for the     CA of THAT cert so it's 'subject' in this area */
                subject = curr;
                ocspResIssuer = trustedOCSP; /* preloaded sslKeys->CA */
                while (ocspResIssuer)
                {
                    if (Memcmp(ocspResIssuer->subject.hash,
                            subject->issuer.hash, 20) == 0)
                    {

                        if (psX509AuthenticateCert(pool, subject, ocspResIssuer,
                                &ocspResIssuer, NULL, NULL) == 0)
                        {
                            /* OK, we held the CA that issued the OCSPResponse
                                so we'll now trust that cert that was provided
                                in the OCSPResponse */
                            ocspResIssuer = NULL;
                            issuer = subject;
                        }
                        else
                        {
                            /* Auth failure */
                            psTraceCrypto("Attached OCSP cert didn't auth\n");
                            return PS_FAILURE;
                        }
                    }
                    else
                    {
                        ocspResIssuer = ocspResIssuer->next;
                    }
                }
                curr = NULL;
            }
            else
            {
                curr = curr->next;
            }
        }
        if (issuer == NULL)
        {
            psTraceCrypto("Found no CA to authenticate attached OCSP cert\n");
            return PS_FAILURE; /* no preloaded CA to auth cert in response */
        }
    }

    /* Issuer will be NULL if there was no certificate attached to the
        OCSP response.  Now look to the user loaded CA files */
    if (issuer == NULL)
    {
        curr = trustedOCSP;
        while (curr != NULL)
        {
            /* Currently looking for the subjectKey extension to match the
                public key hash from the response */
            if (ocspMatchResponderCert(response, curr) == PS_SUCCESS)
            {
                issuer = curr;
                curr = NULL;
            }
            else
            {
                curr = curr->next;
            }
        }
    }

    /* It is possible a certificate embedded in the server certificate
            chain was itself the OCSP responder */
    if (issuer == NULL)
    {
        /* Don't look at the first cert in the chain because that is the
            one we are trying to find the OCSP responder public key for */
        curr = srvCerts->next;
        while (curr != NULL)
        {
            /* Currently looking for the subjectKey extension to match the
                public key hash from the response */
            if (ocspMatchResponderCert(response, curr) == PS_SUCCESS)
            {
                issuer = curr;
                curr = NULL;
            }
            else
            {
                curr = curr->next;
            }
        }
    }

    if (issuer == NULL)
    {
        psTraceCrypto("Unable to locate OCSP responder CA for validation\n");
        return PS_FAILURE;
    }

    /* Now check to see that the response is vouching for the subject cert
        that we are interested in.  The subject will always be the first
        cert in the server CERTIFICATE chain */
    subject = srvCerts;

    /* Now look to match this cert within the singleResponse members.

        There are three components to a CertID that should be used to validate
        we are looking at the correct OCSP response for the subjecct cert.

        It appears the only "unique" portion of our subject cert that
        went into the signature of this response is the serial number.
        The "issuer" information of the subject cert also went into the
        signature but that isn't exactly unique.  Seems a bit odd that the
        combo of the issuer and the serial number are the only thing that tie
        this subject cert back to the response but serial numbers are the basis
        for CRL as well so it must be good enough */
    index = 0;
    while (index < MAX_OCSP_RESPONSES)
    {
        subjectResponse = &response->singleResponse[index];
        if ((subject->serialNumberLen > 0) &&
            (subject->serialNumberLen == subjectResponse->certIdSerialLen) &&
            (Memcmp(subject->serialNumber, subjectResponse->certIdSerial,
                 subject->serialNumberLen) == 0))
        {
            break; /* got it */
        }
        index++;
    }
    if (index == MAX_OCSP_RESPONSES)
    {
        psTraceCrypto("Unable to locate our subject cert in OCSP response\n");
        return PS_FAILURE;
    }
    if (vOpts->index_p != NULL)
    {
        *(vOpts->index_p) = index; /* Write index of response. */
    }

    /* Obtain general revocation status. */
    if (subjectResponse->certStatus == 0)
    {
        knownFlag = PS_TRUE;
        revocationFlag = PS_FALSE;
    }
    else if (subjectResponse->certStatus == 1)
    {
        knownFlag = PS_TRUE;
        revocationFlag = PS_TRUE;
        /* certificate is revoked, but still check rest of the response. */
    }

    /* Is the response within the acceptable time window */
    if (checkOCSPtimestamp(response, index) != PS_SUCCESS)
    {
        psTraceCrypto("ERROR: OCSP response older than threshold\n");
        return PS_FAILURE;
    }

    /* Check if nonces match. */
    if (nonceExtReq.buf && vOpts->nonceMatch)
    {
        if (response->nonce.buf == NULL)
        {
            /* No nonce in response. */
            *(vOpts->nonceMatch) = PS_FALSE;
        }
        else
        {
            /* Compare nonces. */
            *(vOpts->nonceMatch) = psBufEq(&nonceExtReq, &response->nonce);
        }
    }

#  if 0
    /* The issuer here is pointing to the cert that signed the OCSPRespose
            and that is not necessarily the parent of the subject cert we
            are looking at.  If we want to include this test, we'd need to
            find the issuer of the subject and look at the KeyHash as
            an additional verification */

    /* Issuer portion of the validation - the subject cert issuer key and name
        hash should match what the subjectResponse reports

        POSSIBLE PROBLEMS:  Only supporting a SHA1 hash here.  The MatrixSSL
        parser will only use SHA1 for the DN and key hash. Just warning on
        this for now.  The signature validation will catch any key mismatch */
    if (subjectResponse->certIdHashAlg != OID_SHA1_ALG)
    {
        psTraceCrypto("WARNING: Non-SHA1 OCSP CertID. Issuer check bypassed\n");
    }
    else
    {
        if (Memcmp(subjectResponse->certIdKeyHash, issuer->sha1KeyHash, 20)
            != 0)
        {
            psTraceCrypto("Failed OCP issuer key hash validation\n");
            return PS_FAILURE;
        }
        /* Either subject->issuer or issuer->subject would work for testing */
        if (Memcmp(subjectResponse->certIdNameHash, issuer->subject.hash, 20)
            != 0)
        {
            psTraceCrypto("Failed OCP issuer name hash validation\n");
            return PS_FAILURE;
        }
    }
#  endif /* 0 */

    /* Finally do the sig validation */
    switch (response->sigAlg)
    {
#  ifdef USE_SHA224
    case OID_SHA224_RSA_SIG:
        sigOutLen = SHA224_HASH_SIZE;
        sigType = PS_RSA;
        break;
    case OID_SHA224_ECDSA_SIG:
        sigOutLen = SHA224_HASH_SIZE;
        sigType = PS_ECC;
        break;
#  endif
#  ifdef USE_SHA256
    case OID_SHA256_RSA_SIG:
        sigOutLen = SHA256_HASH_SIZE;
        sigType = PS_RSA;
        break;
    case OID_SHA256_ECDSA_SIG:
        sigOutLen = SHA256_HASH_SIZE;
        sigType = PS_ECC;
        break;
#  endif
#  ifdef USE_SHA384
    case OID_SHA384_RSA_SIG:
        sigOutLen = SHA384_HASH_SIZE;
        sigType = PS_RSA;
        break;
    case OID_SHA384_ECDSA_SIG:
        sigOutLen = SHA384_HASH_SIZE;
        sigType = PS_ECC;
        break;
#  endif
#  ifdef USE_SHA512
    case OID_SHA512_RSA_SIG:
        sigOutLen = SHA512_HASH_SIZE;
        sigType = PS_RSA;
        break;
    case OID_SHA512_ECDSA_SIG:
        sigOutLen = SHA512_HASH_SIZE;
        sigType = PS_ECC;
        break;
#  endif
    case OID_SHA1_RSA_SIG:
    case OID_SHA1_RSA_SIG2:
        sigOutLen = SHA1_HASH_SIZE;
        sigType = PS_RSA;
        break;
    case OID_SHA1_ECDSA_SIG:
        sigOutLen = SHA1_HASH_SIZE;
        sigType = PS_ECC;
        break;
    default:
        /* Should have been caught in parse phase */
        return PS_UNSUPPORTED_FAIL;
    }

#  ifdef USE_RSA
    /* Finally test the signature */
    if (sigType == PS_RSA)
    {
        if (issuer->publicKey.type != PS_RSA)
        {
            return PS_FAILURE;
        }
        if (pubRsaDecryptSignedElement(pkiPool, &issuer->publicKey.key.rsa,
                (unsigned char *) response->sig, response->sigLen, sigOut,
                sigOutLen, NULL) < 0)
        {
            psTraceCrypto("Unable to decode signature in psOcspResponseValidateOld\n");
            return PS_FAILURE;
        }
        if (Memcmp(response->hashResult, sigOut, sigOutLen) != 0)
        {
            psTraceCrypto("OCSP RSA signature validation failed\n");
            return PS_FAILURE;
        }
    }
#  endif
#  ifdef USE_ECC
    if (sigType == PS_ECC)
    {
        if (issuer->publicKey.type != PS_ECC)
        {
            return PS_FAILURE;
        }
        /* ECDSA signature */
        index = 0;
        if (psEccDsaVerify(pkiPool, &issuer->publicKey.key.ecc,
                response->hashResult, sigOutLen, (unsigned char *) response->sig,
                response->sigLen, &index, NULL) < 0)
        {
            psTraceCrypto("ECC OCSP sig validation");
            return PS_FAILURE;
        }
        if (index != 1)
        {
            psTraceCrypto("OCSP ECDSA signature validation failed\n");
            return PS_FAILURE;
        }
    }
#  endif

    if (vOpts->knownFlag)
    {
        *(vOpts->knownFlag) = knownFlag;
    }

    if (knownFlag == PS_FALSE)
    {
        /* The certificate is not known. */
        return PS_FAILURE;
    }
    else
    {
        if (vOpts->revocationFlag)
        {
            *(vOpts->revocationFlag) = revocationFlag;
        }

        if (vOpts->revocationTime)
        {
            (void) psBrokenDownTimeImport(
                vOpts->revocationTime,
                (const char *) subjectResponse->revocationTime,
                sizeof(subjectResponse->revocationTime), 0);
        }

        if (vOpts->revocationReason)
        {
            *(vOpts->revocationReason) =
                (x509CrlReason_t) subjectResponse->revocationReason;
        }

        /* Function fails if certificate was revoked. */
        if (revocationFlag)
        {
            return PS_CERT_AUTH_FAIL_REVOKED;
        }
    }

    /* Was able to successfully confirm OCSP signature for our subject */
    return PS_SUCCESS;
}

int32_t psOcspResponseValidateOld(psPool_t *pool, psX509Cert_t *trustedOCSP,
    psX509Cert_t *srvCerts,
    psOcspResponse_t *response)
{
    return psOcspResponseValidate(pool, trustedOCSP, srvCerts, response, NULL);
}

void psOcspResponseUninit(psOcspResponse_t *res)
{
    psX509FreeCert(res->OCSPResponseCert);
    Memset(res, 0, sizeof(*res));
}


# endif /* USE_OCSP_RESPONSE */

#endif  /* USE_X509 */
/******************************************************************************/
