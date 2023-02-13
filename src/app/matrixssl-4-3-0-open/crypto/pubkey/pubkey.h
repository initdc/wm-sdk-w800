/**
 *      @file    pubkey.h
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      Public and Private key header.
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

#ifndef _h_PS_PUBKEY
# define _h_PS_PUBKEY

/******************************************************************************/

# ifdef USE_ROT_CRYPTO
#  include "../../crypto-rot/rot/include/api_val_asset.h"
# endif

# ifdef USE_ROT_CRYPTO
# include "pubkey_rot.h"
# endif
# include "pubkey_matrix.h"
# ifdef USE_OPENSSL_CRYPTO
#  include "pubkey_openssl.h"
# endif

/******************************************************************************/

# ifdef USE_RSA
/**
    The included pubkey_* header must define:
        typedef ... psRsaKey_t;
    and
        PS_RSA_STATIC_INIT
 */
#  ifndef PS_RSA_STATIC_INIT
#   define PS_RSA_STATIC_INIT  { .size = NULL }
#  endif

# endif  /* USE_RSA */

/******************************************************************************/

# ifdef USE_ECC

#  define ECC_MAXSIZE 132 /* max private key size */

/* NOTE: In MatrixSSL usage, the ecFlags are 24 bits only */
#  define IS_SECP192R1    0x00000001
#  define IS_SECP224R1    0x00000002
#  define IS_SECP256R1    0x00000004
#  define IS_SECP384R1    0x00000008
#  define IS_SECP521R1    0x00000010
/* WARNING: Public points on Brainpool curves are not validated */
#  define IS_BRAIN224R1   0x00010000
#  define IS_BRAIN256R1   0x00020000
#  define IS_BRAIN384R1   0x00040000
#  define IS_BRAIN512R1   0x00080000
/* TLS needs one bit of info (last bit) */
#  define IS_RECVD_EXT    0x00800000

/**
    @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
enum
{
    IANA_SECP192R1  = 19,
    IANA_SECP224R1  = 21,
    IANA_SECP256R1  = 23,
    IANA_SECP384R1  = 24,
    IANA_SECP521R1  = 25,
    IANA_BRAIN256R1 = 26,
    IANA_BRAIN384R1 = 27,
    IANA_BRAIN512R1 = 28,
    IANA_X25519     = 29,
    IANA_X448       = 30,
    IANA_BRAIN224R1 = 255 /**< @note this is not defined by IANA */
};

/**
    @see ANSI X9.62 or X9.63
 */
enum
{
    ANSI_INFINITY = 0,
    ANSI_COMPRESSED0 = 2,
    ANSI_COMPRESSED1,
    ANSI_UNCOMPRESSED,
    ANSI_HYBRID0 = 6,
    ANSI_HYBRID1
};

/**
    The included pubkey_* header must define the following.
        typedef ... psEccCurve_t;
        typedef ... psEccPoint_t;
        typedef ... psEccKey_t;
    and
        PS_ECC_STATIC_INIT
    and implement the following functions.
 */
#  ifndef PS_ECC_STATIC_INIT
#   define PS_ECC_STATIC_INIT  { .type = 0 }
#  endif
extern void psGetEccCurveIdList(unsigned char *curveList, uint8_t *len);
extern void userSuppliedEccList(unsigned char *curveList, uint8_t *len,
                                uint32_t curves);
extern uint32_t compiledInEcFlags(void);
extern int32_t getEcPubKey(psPool_t * pool, const unsigned char **pp, psSize_t len,
                           psEccKey_t * pubKey, unsigned char sha1KeyHash[SHA1_HASH_SIZE]);

extern int32_t getEccParamById(psCurve16_t curveId, const psEccCurve_t **curve);
extern int32_t getEccParamByName(const char *curveName,
                                 const psEccCurve_t **curve);
extern int32_t getEccParamByOid(uint32_t oid, const psEccCurve_t **curve);
extern int32_t psEccWritePrivKeyMem(psPool_t *pool, const psEccKey_t *key,
        unsigned char **keyMem, psSize_t *keyMemLen);
#  ifdef MATRIX_USE_FILE_SYSTEM
extern int32_t psEccWritePrivKeyFile(psPool_t *pool, const psEccKey_t *key,
        const char *fileName, const char *password, uint8_t pemFlag);
#  endif /* MATRIX_USE_FILE_SYSTEM */
# endif /* USE_ECC */

/******************************************************************************/

# ifdef USE_DH
/**
    The included pubkey_* header must define:
        typedef ... psDhParams_t;
        typedef ... psDhKey_t;
    and
        PS_DH_STATIC_INIT
 */
#  ifndef PS_DH_STATIC_INIT
#   define PS_DH_STATIC_INIT  { .type = 0 }
#  endif

# endif

/******************************************************************************/

/** Public or private key */
enum PACKED
{
    PS_PUBKEY = 1,
    PS_PRIVKEY
};

/** Public Key types for psPubKey_t */
enum PACKED
{
    PS_NOKEY = 0,
    PS_RSA,
    PS_DSA,
    PS_ECC,
    PS_DH,
    PS_CL_PK, /* A public key for CL Library. May contain any key format. */
    PS_X25519,
    PS_ED25519
};

/** Signature types */
enum PACKED
{
    RSA_TYPE_SIG = 5,
    ECDSA_TYPE_SIG,
    RSAPSS_TYPE_SIG,
    DSA_TYPE_SIG,
    ED25519_TYPE_SIG
};

typedef struct psX25519Key
{
    unsigned char priv[32];
    unsigned char pub[32];
    psBool_t havePriv;
    psBool_t havePub;
} psCurve25519Key_t;

/**
    Univeral public key type.
    The pubKey name comes from the generic public-key crypto terminology and
    does not mean these key are restricted to the public side only. These
    may be private keys.
 */
typedef struct
{
# if defined(USE_RSA) || defined(USE_ECC) || defined(USE_DH) || defined(USE_X25519) || defined(USE_ED25519)
    union
    {
#  ifdef USE_RSA
        psRsaKey_t rsa;
#  endif
#  ifdef USE_ECC
        psEccKey_t ecc;
#  endif
#  ifdef USE_X25519
        psCurve25519Key_t x25519;
#  endif
#  ifdef USE_ED25519
        psCurve25519Key_t ed25519;
#  endif
#  ifdef USE_DH
        psDhKey_t dh;
#  endif
    }               key;
# endif
    psPool_t *pool;
    psSize_t keysize;           /* in bytes. 512 max for RSA 4096 */
    uint8_t type;               /* PS_RSA, PS_ECC, PS_DH */
# ifdef USE_ROT_CRYPTO
    int32_t rotSigAlg;
# endif
} psPubKey_t;

# define PS_SIGN_OPTS_ECDSA_INCLUDE_SIZE      (1ULL << 0)
# define PS_SIGN_OPTS_USE_PREALLOCATED_OUTBUF (1ULL << 1)

typedef struct {
    uint32_t flags;
    int32_t rsaPssHashAlg;
    unsigned char *rsaPssSalt;
    psSize_t rsaPssSaltLen;
    void *userData;
} psSignOpts_t;

extern int32_t pkcs1Pad(const unsigned char *in,
        psSize_t inlen,
        unsigned char *out,
        psSize_t outlen,
        uint8_t cryptType,
        void *userPtr);
extern int32_t pkcs1Unpad(const unsigned char *in,
        psSize_t inlen,
        unsigned char *out,
        psSize_t outlen,
        uint8_t decryptType);
extern int32_t pkcs1UnpadExt(const unsigned char *in,
        psSize_t inlen,
        unsigned char *out,
        psSize_t outlen,
        uint8_t decryptType,
        psBool_t verifyUnpaddedLen,
        psSize_t *unpaddedLen);

# if defined(USE_RSA) || defined(USE_ECC)

int32_t psHashLenToSigAlg(psSize_t hash_len,
        uint8_t key_type);

/** Hash some data for signature generation or verification
    purposes.

    Compute a digest that is to be signed or whose signature is
    to be verified. Supports only single-part operation.
*/
psRes_t psComputeHashForSig(const unsigned char *dataBegin,
        psSizeL_t dataLen,
        int32_t signatureAlgorithm,
        unsigned char hashOut[SHA512_HASH_SIZE],
        psSize_t * hashOutLen);

/** Algorithm-independent function for signing hashes.

    The the signature algorithm is standard RSA (not PSS), the function
    first wraps the input hash into a DigestInfo, unless the TLS 1.1 and
    below signature algorithm (sigAlg == OID_RSA_TLS_SIG_ALG)
    is used.

    The supported values for sigAlg are:
    OID_RSA_TLS_SIG_ALG  (TLS 1.1 and below custom algorithm)
    OID_SHA1_RSA_SIG     (PKCS #1.5)
    OID_SHA256_RSA_SIG   (PKCS #1.5)
    OID_SHA384_RSA_SIG   (PKCS #1.5)
    OID_RSASSA_PSS       (RSASSA-PSS)
    OID_SHA256_ECDSA_SIG (ECDSA)
    OID_SHA384_ECDSA_SIG (ECDSA)
    OID_SHA512_ECDSA_SIG (ECDSA)

    It is also possible to use a more generic sigAlg ID.
    In this case, psSign will deduce the hash algorithm to use
    from inLen (e.g. inLen == 32 would imply SHA-256):
    OID_RSA_PKCS15_SIG_ALG
    OID_ECDSA_TLS_SIG_ALG
*/
int32_t psSignHash(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSize_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts);

/** Algorithm-independent function for signing arbitrary
    data.

    This function is similar to psSignHash, expect that it also supports
    signing arbitrary (non-hash) data with Ed25519, when sigAlg is
    OID_ED25519_KEY_ALG.
*/
int32_t psSign(psPool_t *pool,
        psPubKey_t *privKey,
        int32_t sigAlg,
        const unsigned char *in,
        psSizeL_t inLen,
        unsigned char **out,
        psSize_t *outLen,
        psSignOpts_t *opts);

/**
    Struct for passing additional options to psVerify, psVerifySig
    and psHashDataAndVerifySig.
*/
typedef struct
{
    uint32 flags;
#  ifdef USE_PKCS1_PSS
    int32_t rsaPssHashAlg;
    psSize_t rsaPssHashLen;
    psSize_t rsaPssSaltLen;
#  endif
    psBool_t useRsaPss;

    /* The signed data was a DigestInfo structure. This is only
       relevant for RSA. */
    psBool_t msgIsDigestInfo;
    /* Skip pre-hashing of input data before verifying the sig? */
    psBool_t noPreHash;
} psVerifyOptions_t;

typedef psVerifyOptions_t psVerifySigOptions_t;

/** Verify the signature of a digest.
*/
psRes_t psVerifySig(psPool_t *pool,
        const unsigned char *msgIn,
        psSizeL_t msgInLen,
        const unsigned char *sig,
        psSize_t sigLen,
        psPubKey_t *key,
        int32_t signatureAlgorithm,
        psBool_t *verifyResult,
        psVerifyOptions_t *opts);

/** Verify the signature of a arbitrary data.
*/
psRes_t psVerify(psPool_t *pool,
        const unsigned char *dataBegin,
        psSizeL_t dataLen,
        const unsigned char *sig,
        psSize_t sigLen,
        psPubKey_t *key,
        int32_t signatureAlgorithm,
        psBool_t *verifyResult,
        psVerifyOptions_t *opts);

/*
    Hash some data _and_ verify the signature of the resulting
    digest.
 */
psRes_t psHashDataAndVerifySig(psPool_t *pool,
        const unsigned char *dataBegin,
        psSizeL_t dataLen,
        const unsigned char *sig,
        psSize_t sigLen,
        psPubKey_t *key,
        int32_t signatureAlgorithm,
        psBool_t *verifyResult,
        psVerifyOptions_t *opts);
# endif
/******************************************************************************/

#endif /* _h_PS_PUBKEY */
