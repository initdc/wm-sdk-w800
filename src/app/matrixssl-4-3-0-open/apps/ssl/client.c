/**
 *      @file    client.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      Simple MatrixSSL blocking client example.
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
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#ifdef __APPLE__
# ifndef _DARWIN_C_SOURCE
#  define _DARWIN_C_SOURCE
# endif
#endif
 
#ifndef NEED_PS_TIME_CONCRETE
# define NEED_PS_TIME_CONCRETE
#endif

#ifndef USE_MULTITHREADING
# define USE_MULTITHREADING
#endif

/* This example uses osdep*.h to allow porting similar to MatrixSSL's libs. */
#include "osdep_stddef.h"
#include "osdep_time.h"
#include "osdep_string.h"
#include "osdep_stdio.h"
#include "osdep_ctype.h"
#include "osdep_sys_socket.h"
#include "osdep-types.h"

#include "app.h"

/* Command line arguments parsing: */
#ifndef WIN32
# define USE_GETOPT_LONG
# ifdef USE_GETOPT_LONG
#  include <getopt.h>
# else
#  include "osdep_unistd.h"
# endif
#else
# include "XGetopt.h"
#endif

/* The MatrixSSL's API. */
#include "matrixssl/matrixsslApi.h"
#include "core/coreApi.h"
#include "core/psUtil.h"

# include "../common/client_common.h"

#  ifdef USE_TLS_1_3
#   include "testkeys/PSK/tls13_psk.h"
#  endif /* USE_TLS_1_3 */

#ifdef USE_CLIENT_SIDE_SSL

static int g_use_psk;
static int g_use_psk_sha384;

# ifndef MATRIX_TESTING_ENVIRONMENT /* Omit the message when testing. */
#  define WARNING_MESSAGE "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#  define WARNING_MESSAGE_DEFAULT_KEY
#  include "pscompilerwarning.h"
# endif

# define ALLOW_ANON_CONNECTIONS  0
# define CRL_MAX_LENGTH 2097152 /* Maximum length for CRL: 2 megabytes. */

/* #define REHANDSHAKE_TEST */
#  ifdef REHANDSHAKE_TEST
static int g_rehandshakeFlag = 0;
#  endif

/********************************** Globals ***********************************/
static unsigned char g_httpRequestHdr[] = "GET %s HTTP/1.0\r\n"
                                          "Host: %s\r\n"
                                          "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
                                          "Accept: */*\r\n"
                                          "Content-Length: 0\r\n"
                                          "\r\n";

static psList_t *g_groupList;
static psSize_t g_num_key_shares;
static psList_t *g_sigAlgsList;
static psList_t *g_sigAlgsCertList;
static psList_t *g_supportedVersionsList;
static char g_early_data_file[256];
static long int g_tls13_block_size;
static long int g_min_dh_p_size;
static unsigned char g_matrixShutdownServer[] = "MATRIX_SHUTDOWN";

extern int opterr;
static char g_ip[16];
static char g_server_name[256];
static char g_path[256];
static int g_port, g_new, g_resumed, g_ciphers, g_version, g_closeServer;
static int g_min_version, g_max_version, g_version_range_set;
static int g_disableCertNameChk;
static int g_max_verify_depth;
static uint16_t g_cipher[16];
static int g_trace;
static int g_keepalive;
static int g_req_ocsp_stapling;
static int g_disable_peer_authentication;
static int g_use_session_tickets;
static int g_handshake_until_ticket;

static uint32_t g_bytes_requested;
static uint8_t g_send_closure_alert;
static int g_print_http_response;

# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
static const char *g_on_demand_cert_file = "testkeys/RSA/3072_RSA.pem";
static const char *g_on_demand_key_file  = "testkeys/RSA/3072_RSA_KEY.pem";
# endif /* USE_EXT_CLIENT_CERT_KEY_LOADING */

struct g_sslstats
{
    int rbytes;         /* Bytes read */
    int64 hstime;
    int64 datatime;
};

/********************************** Defines ***********************************/

/****************************** Local Functions *******************************/

static int32 httpWriteRequest(ssl_t *ssl);
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
static SOCKET lsocketConnect(char *ip, int32 port, int32 *err);
static void closeConn(ssl_t *ssl, SOCKET fd);
static int32_t extensionCb(ssl_t *ssl,
                           uint16_t extType, uint8_t extLen, void *e);
# ifdef USE_TLS_1_3
static int32_t sendEarlyData(ssl_t *ssl);
# endif

# ifdef USE_CRL
static int32 fetchCRL(psPool_t *pool, char *url, uint32_t urlLen,
                      unsigned char **crlBuf, uint32_t *crlBufLen);
static int32_t fetchParseAndAuthCRLfromCert(psPool_t *pool, psX509Cert_t *cert,
                                            psX509Cert_t *potentialIssuers);

/* Enable the example on how to fetch CRLs mid-handshake.  If disabled, the
    example will show how to halt the handshake to go out and fetch and retry
    the connection (command line option -n must be specified for multiple
    connection attempts) */
#define MIDHANDSHAKE_CRL_FETCH

#  ifndef MIDHANDSHAKE_CRL_FETCH
/* In the example where we stop the handhsake to go fetch the CRL files, we
    need storage to hold the CRL URL distribution points since those are
    coming from the server cert chain which we do not keep around */
#   define CRL_MAX_SERVER_CERT_CHAIN 3
#   define CRL_MAX_URL_LEN     256
static unsigned char g_crlDistURLs[CRL_MAX_SERVER_CERT_CHAIN][CRL_MAX_URL_LEN];

static int32_t fetchParseAndAuthCRLfromUrl(psPool_t *pool, unsigned char *url,
                                           uint32_t urlLen, psX509Cert_t *potentialIssuers);
static void fetchSavedCRL(psX509Cert_t *potentialIssuers);
#  endif
# endif /* USE_CRL */

# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */

static void sslstatsPrintTime(const struct g_sslstats* stats, int conn_count);
static void addTimeDiff(int64 *t, psTime_t t1, psTime_t t2);

/* Not a public function, but needed for command-line backwards
   compatibility. */
extern int32_t psVerToFlag(psProtocolVersion_t ver);

static
int32_t print_connection_extra_details(ssl_t *ssl)
{
    int32_t rc = PS_SUCCESS;

# ifdef ENABLE_MASTER_SECRET_EXPORT
    {
        unsigned char *masterSecret = NULL;
        psSizeL_t hsMasterSecretLen = 0;
        matrixSslGetMasterSecret(
                ssl,
                &masterSecret,
                &hsMasterSecretLen);
        psTraceBytes("Master secret",
                masterSecret, hsMasterSecretLen);
    }
# endif /* ENABLE_MASTER_SECRET_EXPORT */
# ifdef USE_RFC5929_TLS_UNIQUE_CHANNEL_BINDINGS
    {
        unsigned char bindings[36];
        psSizeL_t bindingsLen = sizeof(bindings);

        rc = matrixSslGetTlsUniqueChannelBindings(
                ssl,
                bindings,
                &bindingsLen);
        if (rc < 0)
        {
            goto out;
        }
        psTraceBytes("tls-unique", bindings, bindingsLen);
    }
out:
# endif
    return rc;
}

/******************************************************************************/
/*
    Make a secure HTTP request to a defined IP and port
    Connection is made in blocking socket mode
    The connection is considered successful if the SSL/TLS session is
    negotiated successfully, a request is sent, and a HTTP response is received.
 */

static int g_alreadyopen = 0;

static int32 httpsClientConnection(sslKeys_t *keys, sslSessionId_t *sid,
    struct g_sslstats *stats)
{
    tlsExtension_t *extension;
    int32 rc, transferred, len, extLen;
    ssl_t *ssl = NULL;
    unsigned char *buf, *ext;
    httpConn_t cp;
    SOCKET fd;
    psTime_t t1, t2;
    sslSessOpts_t options;
    psList_t *sigAlg;
    psList_t *supportedVersion;
# ifdef USE_TLS_1_3
    psList_t *group;
    uint16_t groups[TLS_1_3_MAX_GROUPS] = {0};
# endif
    uint16_t sigAlgs[TLS_MAX_SIGNATURE_ALGORITHMS] = {0};
    psProtocolVersion_t supportedVersions[TLS_MAX_SUPPORTED_VERSIONS] = {0};
    psSize_t i;

# ifdef USE_ALPN
    unsigned char *alpn[MAX_PROTO_EXT];
    int32 alpnLen[MAX_PROTO_EXT];
# endif

    Memset(&cp, 0x0, sizeof(httpConn_t));
    if (g_alreadyopen == 0)
    {
        fd = lsocketConnect(g_ip, g_port, &rc);
        if (g_keepalive == 1)
        {
            g_alreadyopen = fd;
        }
    }
    else
    {
        fd = g_alreadyopen;
        rc = PS_SUCCESS;
    }
    if (fd == INVALID_SOCKET || rc != PS_SUCCESS)
    {
        return PS_PLATFORM_FAIL;
    }

    Memset(&options, 0x0, sizeof(sslSessOpts_t));

# ifdef USE_OCSP_RESPONSE
    if (g_req_ocsp_stapling)
    {
        options.OCSPstapling = 1;
    }
# endif

# ifdef USE_STATELESS_SESSION_TICKETS
    if (g_use_session_tickets)
    {
        options.ticketResumption = PS_TRUE;
    }
# endif

# ifdef USE_DH
    rc = matrixSslSessOptsSetMinDhBits(&options, g_min_dh_p_size);
    if (rc != PS_SUCCESS)
    {
        return rc;
    }
# endif

# ifdef USE_TLS_1_3

    /* Determine which groups to use. */
    if (g_groupList != 0)
    {
        group = g_groupList;
        i = 0;
        while (group)
        {
            groups[i] = psGetNamedGroupId((const char*)group->item);
            group = group->next;
            i++;
        }
        rc = matrixSslSessOptsSetKeyExGroups(&options,
                groups,
                i,
                g_num_key_shares);
        if (rc < 0)
        {
            Printf("matrixSslSessOptsSetKeyExGroups failed\n");
            goto L_CLOSE_ERR;
        }
    }
    if (g_sigAlgsCertList != 0)
    {
        sigAlg = g_sigAlgsCertList;
        i = 0;
        while (sigAlg)
        {
            sigAlgs[i] = psGetNamedSigAlgId((const char*)sigAlg->item);
            sigAlg = sigAlg->next;
            i++;
        }
        rc = matrixSslSessOptsSetSigAlgsCert(&options,
                sigAlgs,
                i);
        if (rc < 0)
        {
            Printf("matrixSslSessOptsSetSigAlgsCert failed\n");
            goto L_CLOSE_ERR;
        }
    }

# endif /* USE_TLS_1_3 */
    if (g_sigAlgsList != 0)
    {
        sigAlg = g_sigAlgsList;
        i = 0;
        while (sigAlg)
        {
            sigAlgs[i] = psGetNamedSigAlgId((const char*)sigAlg->item);
            sigAlg = sigAlg->next;
            i++;
        }
        rc = matrixSslSessOptsSetSigAlgs(&options,
                sigAlgs,
                i);
        if (rc < 0)
        {
            Printf("matrixSslSessOptsSetSigAlgs failed\n");
            goto L_CLOSE_ERR;
        }
    }

    /*
      Get version information from (in order of priority):
      - supported versions list (e.g. --tls-supported-versions 26,3)
      - version range option (e.g. --tls-version-range 3,4)
      - single version option (e.g. -V26)
    */
    if (g_supportedVersionsList)
    {
        supportedVersion = g_supportedVersionsList;
        i = 0;
        while (supportedVersion)
        {
            supportedVersions[i] = atoi((char* )supportedVersion->item);
            supportedVersions[i] = matrixSslVersionFromMinorDigit(
                    supportedVersions[i]);
            supportedVersion = supportedVersion->next;
            i++;
        }
        rc = matrixSslSessOptsSetClientTlsVersions(&options,
                supportedVersions,
                i);
        if (rc < 0)
        {
            Printf("matrixSslSessOptsSetClientTlsVersions failed\n");
            goto L_CLOSE_ERR;
        }
    }
    else if (g_version_range_set)
    {
        rc = matrixSslSessOptsSetClientTlsVersionRange(&options,
                g_min_version,
                g_max_version);
        if (rc < 0)
        {
            goto L_CLOSE_ERR;
        }
    }
    else if (g_version != 0)
    {
        options.versionFlag = psVerToFlag(matrixSslVersionFromMinorDigit(
                        g_version));
    }

    options.userPtr = keys;
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
# ifdef TEST_KEEP_PEER_CERTS
    options.keep_peer_certs = 1;
    options.keep_peer_cert_der = 1;
# endif
    if (g_max_verify_depth != 0)
        options.validateCertsOpts.max_verify_depth = g_max_verify_depth;

    matrixSslNewHelloExtension(&extension, NULL);
    if (Strlen(g_server_name) == 0)
    {
        Memcpy(g_server_name, g_ip, Strlen(g_ip));
    }
    matrixSslCreateSNIext(NULL,
            (unsigned char *) g_server_name, (uint32) Strlen(g_server_name),
            &ext, &extLen);
    matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
    psFree(ext, NULL);

# ifdef USE_ALPN
    /* Application Layer Protocol Negotiation */
    alpn[0] = (unsigned char *)psMalloc(NULL, Strlen("http/1.0"));
    Memcpy(alpn[0], "http/1.0", Strlen("http/1.0"));
    alpnLen[0] = Strlen("http/1.0");

    alpn[1] = (unsigned char *)psMalloc(NULL, Strlen("http/1.1"));
    Memcpy(alpn[1], "http/1.1", Strlen("http/1.1"));
    alpnLen[1] = Strlen("http/1.1");

    matrixSslCreateALPNext(NULL, 2, alpn, alpnLen, &ext, &extLen);
    matrixSslLoadHelloExtension(extension, ext, extLen, EXT_ALPN);
    psFree(alpn[0], NULL);
    psFree(alpn[1], NULL);
# endif

    /* We are passing the IP address of the server as the expected name */
    /* To skip certificate subject name tests, pass NULL instead of
       g_server_name */
    if (g_disableCertNameChk == 0)
    {
        rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
            certCb, g_server_name, extension, extensionCb, &options);
    }
    else
    {
        rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
            certCb, NULL, extension, extensionCb, &options);
    }
    if (rc != MATRIXSSL_REQUEST_SEND)
    {
        psTraceInt("New Client Session Failed: %d.  Exiting\n", rc);
        rc = PS_ARG_FAIL;
        goto L_CLOSE_ERR;
    }

# ifdef USE_TLS_1_3
    /* TLS 1.3 early data sending from file. Early data must be sent right
       after the matrixSslNewClientSession call */
    if (Strlen(g_early_data_file) > 0 &&
        matrixSslGetMaxEarlyData(ssl) > 0)
    {
        if (sendEarlyData(ssl) < 0)
        {
            rc = PS_FAILURE;
            goto L_CLOSE_ERR;
        }
    }
    if (g_tls13_block_size != 0)
    {
        rc = matrixSslSetTls13BlockPadding(ssl, g_tls13_block_size);
        if (rc != PS_SUCCESS)
        {
            rc = PS_FAILURE;
            goto L_CLOSE_ERR;
        }
    }
# endif

    matrixSslDeleteHelloExtension(extension);

WRITE_MORE:
    while ((len = matrixSslGetOutdata(ssl, &buf)) > 0)
    {
        if (g_trace)
        {
            psTraceBytes("SEND", buf, len);
        }
        transferred = send(fd, buf, len, 0);
        if (transferred <= 0)
        {
            Printf("Error sending\n");
            goto L_CLOSE_ERR;
        }
        else
        {
            psTraceBytes("sent", buf, len);
            /* Indicate that we've written > 0 bytes of data */
            if ((rc = matrixSslSentData(ssl, transferred)) < 0)
            {
                goto L_CLOSE_ERR;
            }
            if (rc == MATRIXSSL_REQUEST_CLOSE)
            {
                closeConn(ssl, fd);
                return MATRIXSSL_SUCCESS;
            }
            if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
            {
                Printf("TLS handshake complete.\n");
                (void)print_connection_extra_details(ssl);
                if ((matrixSslGetNegotiatedVersion(ssl) & v_tls_1_3_any)
                        && sid != NULL && g_resumed > 0)
                {
                    /* Try to receive the server's NewSessionTicket. */
                    goto READ_MORE;
                }

                /* If we sent the Finished SSL message, initiate the HTTP req */
                /* (This occurs on a resumption handshake) */
                if ((rc = httpWriteRequest(ssl)) < 0)
                {
                    goto L_CLOSE_ERR;
                }
                if (rc == MATRIXSSL_REQUEST_SEND)
                {
                    /* We have a HTTP request to send */
                    goto WRITE_MORE;
                }
                closeConn(ssl, fd);
                return MATRIXSSL_SUCCESS;
            }
            /* MATRIXSSL_REQUEST_SEND is handled by loop logic */
        }
    }

READ_MORE:
    if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0)
    {
        goto L_CLOSE_ERR;
    }
    if ((transferred = recv(fd, buf, len, 0)) < 0)
    {
        goto L_CLOSE_ERR;
    }
    if (g_trace)
    {
        //psTraceBytes("RECV", buf, transferred);
    }
    /*  If EOF, remote socket closed. But we haven't received the HTTP response
        so we consider it an error in the case of an HTTP client */
    if (transferred == 0)
    {
        goto L_CLOSE_ERR;
    }
    psGetTime(&t1, NULL);
    if ((rc = matrixSslReceivedData(ssl, (int32) transferred, &buf,
             (uint32 *) &len)) < 0)
    {
        psGetTime(&t2, NULL);
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
        if (rc == PS_PENDING && matrixSslNeedClientCert(ssl))
        {
            sslKeys_t *newKeys;

            psTrace("Loading client cert and key in response to " \
                    "CertificateRequest\n");

            /* Clear previously set identities from the ssl->keys before
               loading new ones.

               On a typical application the 'identity' keys would not be
               shared with initial NewClient call, and the ps-pending
               driven/callback driven mechanisms */
            matrixSslDeleteKeys(matrixSslGetKeys(ssl));

            /* Load the "on-demand" keys.  */
            rc = matrixSslNewKeys(&newKeys, NULL);
            if (rc < 0)
            {
                psTrace("matrixSslNewKeys failed\n");
                exit(EXIT_FAILURE);
            }
            rc = matrixSslLoadKeys(newKeys,
                    g_on_demand_cert_file,
                    g_on_demand_key_file,
                    NULL, NULL, NULL);
            if (rc < 0)
            {
                psTrace("matrixSslLoadKeys failed\n");
                exit(EXIT_FAILURE);
            }
            matrixSslSetClientIdentity(ssl, newKeys);
            (void)matrixSslClientCertUpdated(ssl);

            /* Retry now that we have the cert and the priv key. */
            rc = matrixSslReceivedData(ssl, (int32) transferred, &buf,
                    (uint32 *) &len);
            if (rc < 0)
            {
                psTrace("Retry failed\n");
            }
            goto WRITE_MORE;
        }
# endif
# ifdef USE_EXT_CERTIFICATE_VERIFY_SIGNING
# endif  /* USE_EXT_CERTIFICATE_VERIFY_SIGNING */
        if (matrixSslHandshakeIsComplete(ssl))
        {
            addTimeDiff(&stats->datatime, t1, t2);
        }
        else
        {
            addTimeDiff(&stats->hstime, t1, t2);
        }
        goto L_CLOSE_ERR;
    }
    psGetTime(&t2, NULL);
    if (matrixSslHandshakeIsComplete(ssl))
    {
        addTimeDiff(&stats->datatime, t1, t2);
    }
    else
    {
        addTimeDiff(&stats->hstime, t1, t2);
    }

PROCESS_MORE:
    switch (rc)
    {
    case MATRIXSSL_HANDSHAKE_COMPLETE:
# ifdef REHANDSHAKE_TEST
/*
            Test rehandshake capabilities of server.  A full re-handshake
            is first tested.  After that, a session resumption rehandshake
            is attempted. In that case, this client will be last to
            send handshake data and MATRIXSSL_HANDSHAKE_COMPLETE will hit on
            the WRITE_MORE handler and httpWriteRequest will occur there.

            NOTE: If the server doesn't support session resumption it is
            possible to fall into an endless rehandshake loop
 */
        if (g_rehandshakeFlag == 0)
        {
            /* Full rehandshake */
            if (matrixSslEncodeRehandshake(ssl, NULL, NULL,
                    SSL_OPTION_FULL_HANDSHAKE, g_cipher, g_ciphers) < 0)
            {
                goto L_CLOSE_ERR;
            }
            g_rehandshakeFlag = 1;
        }
        else if (g_rehandshakeFlag == 1)
        {
            /* Resumed rehandshake */
            if (matrixSslEncodeRehandshake(ssl, NULL, NULL, 0,
                    g_cipher, g_ciphers) < 0)
            {
                goto L_CLOSE_ERR;
            }
            g_rehandshakeFlag = 2;
        }
        else
        {
            if ((rc = httpWriteRequest(ssl)) < 0)
            {
                goto L_CLOSE_ERR;
            }
            if (rc != MATRIXSSL_REQUEST_SEND)
            {
                closeConn(ssl, fd);
                return MATRIXSSL_SUCCESS;
            }
        }
        goto WRITE_MORE;
# else
        Printf("TLS handshake complete.\n");
        print_connection_extra_details(ssl);

        /* We got the Finished SSL message, initiate the HTTP req */
        if ((rc = httpWriteRequest(ssl)) < 0)
        {
            goto L_CLOSE_ERR;
        }
        if (rc == MATRIXSSL_REQUEST_SEND)
        {
            /* We have a HTTP request to send */
            goto WRITE_MORE;
        }
#  ifdef TEST_KEEP_PEER_CERTS
        if (ssl->sec.cert == NULL)
        {
            Printf("Error: peer cert not kept\n");
            return MATRIXSSL_ERROR;
        }
        else
        {
            Printf("OK: peer cert still available\n");
        }
        if (ssl->sec.cert->unparsedBin == NULL ||
            ssl->sec.cert->binLen <= 0)
        {
            Printf("Error: peer cert DER not kept\n");
            return MATRIXSSL_ERROR;
        }
        else
        {
            Printf("OK: peer cert DER still available\n");
        }
#  endif
        closeConn(ssl, fd);
        return MATRIXSSL_SUCCESS;
# endif
    case MATRIXSSL_APP_DATA:
    case MATRIXSSL_APP_DATA_COMPRESSED:
        if (g_trace)
        {
            psTraceBytes("Decrypted app data", buf, len);
        }
        if (cp.flags != HTTPS_COMPLETE)
        {
            rc = httpBasicParse(&cp, buf, len, g_trace);
            if (rc < 0)
            {
                closeConn(ssl, fd);
                if (cp.parsebuf)
                {
                    Free(cp.parsebuf);
                }
                cp.parsebuf = NULL;
                cp.parsebuflen = 0;
                return MATRIXSSL_ERROR;
            }
            if (rc == HTTPS_COMPLETE)
            {
                cp.flags = HTTPS_COMPLETE;
            }
        }
        cp.bytes_received += len;
        stats->rbytes += len;
        if (g_trace)
        {
            psTraceBytes("HTTP DATA", buf, len);
            if (g_print_http_response)
            {
                char *resp_str = (char *)psMalloc(NULL, len+1);

                if (resp_str != NULL)
                {
                    psMem2Str(resp_str, buf, len);
                    resp_str[len] = '\0';
                    psTraceStr("%s", resp_str);
                    Free(resp_str);
                }
                else
                {
                    /* Memory allocation failure. Skip trace. */
                    psTraceInt("HTTP RESPONSE: %d bytes of data.\n"
                               "(Printing omitted due to memory allocation "
                               "failure)\n", (int)len);
                }
            }
        }
        rc = matrixSslProcessedData(ssl, &buf, (uint32 *) &len);
        if (rc < 0)
        {
            goto L_CLOSE_ERR;
        }
        if (g_bytes_requested > 0)
        {
            if (cp.bytes_received >= g_bytes_requested)
            {
                /* We've received all that was requested, so close */
                closeConn(ssl, fd);
                if (cp.parsebuf)
                {
                    Free(cp.parsebuf);
                }
                cp.parsebuf = NULL;
                cp.parsebuflen = 0;
                return MATRIXSSL_SUCCESS;
            }
            if (rc == 0)
            {
                /* We processed a partial HTTP message */
                goto READ_MORE;
            }
        }
        goto PROCESS_MORE;
    case MATRIXSSL_REQUEST_SEND:
        goto WRITE_MORE;
    case MATRIXSSL_REQUEST_RECV:
        goto READ_MORE;
    case MATRIXSSL_RECEIVED_ALERT:
        /* The first byte of the buffer is the level */
        /* The second byte is the description */
        if (*buf == SSL_ALERT_LEVEL_FATAL)
        {
            psTraceInt("Fatal alert: %d, closing connection.\n",
                *(buf + 1));
            goto L_CLOSE_ERR;
        }
        /* Closure alert is normal (and best) way to close */
        if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY)
        {
            closeConn(ssl, fd);
            if (cp.parsebuf)
            {
                Free(cp.parsebuf);
            }
            cp.parsebuf = NULL;
            cp.parsebuflen = 0;
            return MATRIXSSL_SUCCESS;
        }
        psTraceInt("Warning alert: %d\n", *(buf + 1));
        if ((rc = matrixSslProcessedData(ssl, &buf, (uint32 *) &len)) == 0)
        {
            /* No more data in buffer. Might as well read for more. */
            goto READ_MORE;
        }
        goto PROCESS_MORE;
    default:
        /* If rc <= 0 we fall here */
        goto L_CLOSE_ERR;
    }

L_CLOSE_ERR:
    if (cp.flags != HTTPS_COMPLETE)
    {
        psTrace("FAIL: No HTTP Response\n");
    }
    matrixSslDeleteSession(ssl);
    if (g_keepalive == 0)
    {
        close(fd);
    }
    if (cp.parsebuf)
    {
        Free(cp.parsebuf);
    }
    cp.parsebuf = NULL;
    cp.parsebuflen = 0;
    return rc;
}

/******************************************************************************/
/*
    Create an HTTP request and encode it to the SSL buffer
 */
static int32 httpWriteRequest(ssl_t *ssl)
{
    unsigned char *buf;
    int32 available, requested;

    /* If we don't have a path defined and are sending zero bytes, skip http */
    if (g_bytes_requested == 0 && *g_path == '\0')
    {
        return PS_SUCCESS;
    }

    if (g_closeServer)
    {
        /* A value of 0 to the 'new' connections is the key to sending the
            server a shutdown message */
        requested = Strlen((char *) g_matrixShutdownServer) + 1;
        if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (available < requested)
        {
            return PS_FAILURE;
        }
        Memset(buf, 0x0, requested); /* So strlen will work below */
        Strncpy((char *) buf, (char *) g_matrixShutdownServer,
            (uint32) Strlen((char *) g_matrixShutdownServer));
        if (matrixSslEncodeWritebuf(ssl, (uint32) Strlen((char *) buf)) < 0)
        {
            return PS_MEM_FAIL;
        }
        return MATRIXSSL_REQUEST_SEND;
    }

    requested = Strlen((char *) g_httpRequestHdr) + Strlen(g_path) + Strlen(g_server_name) + 1;
    if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0)
    {
        return PS_MEM_FAIL;
    }
    requested = PS_MIN(requested, available);
    Snprintf((char *) buf, requested, (char *) g_httpRequestHdr, g_path, g_server_name);

    if (g_trace)
    {
        //psTraceStr("SEND: [%s]\n", (char *) buf);
    }
    if (matrixSslEncodeWritebuf(ssl, Strlen((char *) buf)) < 0)
    {
        return PS_MEM_FAIL;
    }
    return MATRIXSSL_REQUEST_SEND;
}

static void usage(void)
{
    Printf(
        "\nusage: client { options }\n"
        "\n"
        "Options can be one or more of the following:\n"
        "\n"
        "-a                      - Disable sending closure alerts\n"
        "--no-alerts\n"
        "-b <numBytesPerRequest> - Client request size\n"
        "--request-bytes <numBytesPerRequest>\n"
        "                          Generates an HTTPS request after TLS negotiation\n"
        "                          Uses URL path of '/bytes?<numBytesPerRequest>'\n"
        "                          Mutually exclusive with '-u' flag\n"
        "-c <cipherList>         - Comma separated list of ciphers numbers\n"
        "--ciphers <cipherList\n"
        "                        - Example cipher numbers:\n"
        "                        - '53' TLS_RSA_WITH_AES_256_CBC_SHA\n"
        "                        - '47' TLS_RSA_WITH_AES_128_CBC_SHA\n"
        "                        - '10' SSL_RSA_WITH_3DES_EDE_CBC_SHA\n"
        "                        - '5'  SSL_RSA_WITH_RC4_128_SHA\n"
        "                        - '4'  SSL_RSA_WITH_RC4_128_MD5\n"
        "-C <caFile>             - Path to certificate authority file\n"
        "--ca <caFile>\n"
        "-d                      - Disable server certicate name/addr chk\n"
        "--no-name-check\n"
        "-e <useExternalVerify>  - Enable/disable external certificate verification\n"
        "--external-verify <useExternalVerify\n"
        "                          0 (turn it OFF, default)\n"
        "                          1 (turn it ON)\n"
        "--groups                - (TLS 1.3 only) Set supported key exchange groups.\n"
        "                          The argument must be a colon-separated list of TLS 1.3\n"
        "                          NamedGroup names, e.g. --groups secp256r1:secp384r1:ffdhe2048\n"
        "-h                      - Help, print usage and exit\n"
        "--help\n"
        "-k <keyLen>             - RSA keyLen (if using client auth)\n"
        "--rsa-key-len\n"
        "                        - Must be one of 1024, 2048 or 4096\n"
        "-K                      - Keepalive (Re-use socket after TLS session close)\n"
        "--keep-alive\n"
        "-n <numNewSessions>     - Num of new (full handshake) sessions\n"
        "--handshakes <numNewSessions>\n"
        "                        - Default 1\n"
        "-m <maxVerifyDepth>     - Maximum depth for certificate verification\n"
        "--depth  <maxVerifyDepth>\n"
        "--num-key-shares        -  (TLS 1.3 only) Number of key shares to include in ClientHello.\n"
        "-p <serverPortNum>      - Port number for SSL/TLS server\n"
        "--port <serverPortNum>\n"
        "                        - Default 4433 (HTTPS is 443)\n"
        "-r <numResumedSessions> - Num of resumed SSL/TLS sesssions\n"
        "--resumed <numResumedSessions>\n"
        "                        - Default 0\n"
        "-s <serverIpAddress>    - IP address of server machine/interface\n"
        "--server <serverIpAddress>\n"
        "                        - Default 127.0.0.1 (localhost)\n"
        "--server-name <name>    - The server name to send in the SNI extension\n"
        "-t                      - Enable printing of HTTP response\n"
        "--response\n"
        "-u <url path>           - URL path, eg. '/index.html'\n"
        "--url <url path>\n"
        "                          Generates an HTTPS request after TLS negotiation\n"
        "                          Mutually exclusive with '-b' flag\n"
        "-V <tlsVersion>         - SSL/TLS version to use\n"
        "--tls <tlsVersion>      - Selects a single TLS version to support\n"
        "                          '0' SSL 3.0\n"
        "                          '1' TLS 1.0\n"
        "                          '2' TLS 1.1\n"
        "                          '3' TLS 1.2\n"
        "                          '4' TLS 1.3 (default)\n"
        "                          '22' TLS 1.3 draft 22\n"
        "                          '23' TLS 1.3 draft 23\n"
        "                          '24' TLS 1.3 draft 24\n"
        "--tls-version-range <minVersion>,<maxVersion>\n"
        "                        - Set TLS version range, e.g.\n"
        "                          2,3 for TLS 1.1 - TLS 1.2\n"
        "                        - Note: Only one of the version parameters should be supplied\n"
        "                          (--tls, --tls-version-range or--tls-supported-versions)\n"
        "--tls-supported-versions <version>,<version>,...\n"
        "                        - Lists the supported versions in priority order, e.g.\n"
        "                          23,3,2 for TLS 1.3 draft 23, TLS 1.2 and TLS 1.1\n"
        "                        - Priority order is used only when TLS1.3 is enabled. Otherwise\n"
        "                          the latest version has the highest priority.\n"
        "                        - Note: Only one of the version parameters should be supplied\n"
        "                          (--tls, --tls-version-range or --tls-supported-versions)\n"
        "--no-cert               - Unset client certificate\n"
        "--cert <certificateFile>\n"
        "                        - Path to client certificate file\n"
        "--key <privateKeyFile>  - Path to client private key file\n"
        "--keytype <loadKeyMethod>\n"
        "                        - Specify format of client certificate:\n"
        "                          any (detect key and signature type)\n"
        "                          rsa (for RSA keys)\n"
        "                          ec (for EC keys ECDSA signature)\n"
        "                          ecrsa (for EC keys with RSA signature)\n"
        "--psk                    \n"
        "--psk-sha384             \n"
        "                        - Load test PSKs.\n"
        "--groups <groups>\n"
        "                        - Supported groups.\n"
        "                          For example: secp256r1:secp384r1\n"
        "--num-key-shares <numKeyShares>\n"
        "                        - For how many groups (listed by --groups)\n"
        "                          key share entries are generated in ClientHello.\n"
        "--sig-algs <sigAlgs>\n"
        "                        - Supported signature algorithms.\n"
        "                          For example: ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256\n"
        "--sig-algs-cert <sigAlgsCert>\n"
        "                        - Supported signature algorithms in TLS1.3 certs.\n"
        "                          For example: ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256\n"
        "--early-data <file>\n"
        "                        - Send supplied file using TLS1.3 early data mechanism.\n"
        "                        - Enable also -r or --resumed\n"
        "                          For example: --early-data file.dat -r1\n"
        "                        - Maximum of 16384 bytes is sent from the file.\n"
        "--tls13-block-size\n"
        "                        - Block size to pad TLS 1.3 records to.\n"
        "\n");
}

/* Returns number of cipher numbers found, or -1 if an error. */
# include "osdep_ctype.h"
static int32_t parse_cipher_list(char *cipherListString,
    psCipher16_t cipher_array[], uint8_t size_of_cipher_array)
{
    uint32 numCiphers, cipher;
    char *endPtr;

    /* Convert the cipherListString into an array of cipher numbers. */
    numCiphers = 0;
    while (cipherListString != NULL)
    {
        cipher = Strtol(cipherListString, &endPtr, 10);
        if (endPtr == cipherListString)
        {
            Printf("The remaining cipherList has no cipher numbers - '%s'\n",
                cipherListString);
            return -1;
        }
        else if (size_of_cipher_array <= numCiphers)
        {
            Printf("Too many cipher numbers supplied.  limit is %d\n",
                size_of_cipher_array);
            return -1;
        }
        cipher_array[numCiphers++] = cipher;
        while (*endPtr != '\0' && !Isdigit(*endPtr))
        {
            endPtr++;
        }
        cipherListString = endPtr;
        if (*endPtr == '\0')
        {
            break;
        }
    }

    return numCiphers;
}

/* Return 0 on good set of cmd options, return -1 if a bad cmd option is
   encountered OR a request for help is seen (i.e. '-h' option). */
static int32 process_cmd_options(int32 argc, char **argv)
{
    int optionChar, key_len, version, numCiphers;
    char *cipherListString;
    psList_t *versionRangeList;
    /* Set some default options: */
    Memset(g_cipher, 0, sizeof(g_cipher));
    Memset(g_ip,     0, sizeof(g_ip));
    Memset(g_path,   0, sizeof(g_path));

    Strcpy(g_ip,          "127.0.0.1");
    g_bytes_requested    = 0;
    g_send_closure_alert = 1;
    g_ciphers            = 0;
    g_cipher[0]          = 0;
    g_disableCertNameChk = 0;
    g_key_len            = 2048;
    g_new                = 1;
    g_port               = 4433;
    g_resumed            = 0;
    g_version            = 0;
    g_keepalive          = 0;

    opterr = 0;

    const char *optstring = "ab:C:c:de:hk:Km:n:p:r:s:tu:V:";

#ifdef USE_GETOPT_LONG
#define ARG_NO_CERT 1
#define ARG_CERT 2
#define ARG_KEY 3
#define ARG_KEYTYPE 4
#define ARG_ON_DEMAND_CERT 5
#define ARG_ON_DEMAND_KEY 6
#define ARG_TLS_VERSION_RANGE 7
#define ARG_GROUPS 8
#define ARG_NUM_KEY_SHARES 9
#define ARG_SIG_ALGS 10
#define ARG_SIG_ALGS_CERT 11
#define ARG_TLS_SUPPORTED_VERSIONS 12
#define ARG_SERVER_NAME 13
#define ARG_PSK 14
#define ARG_EARLY_DATA 15
#define ARG_REQ_OCSP_STAPLING 16
#define ARG_DISABLE_PEER_AUTHENTICATION 17
#define ARG_TLS13_BLOCK_SIZE 18
#define ARG_MIN_DH_P_SIZE 19
#define ARG_PSK_SHA384 20
#define ARG_USE_SESSION_TICKETS 21
#define ARG_HANDSHAKE_UNTIL_TICKET 22

    static struct option long_options[] =
    {
        {"no-alerts", no_argument, NULL, 'a'},
        {"request-bytes", required_argument, NULL, 'b'},
        {"ciphers", required_argument, NULL, 'c'},
        {"ca", required_argument, NULL, 'C'},
        {"no-name-check", no_argument, NULL, 'd'},
        {"external-verify", required_argument, NULL, 'e'},
        {"help", no_argument, NULL, 'h'},
        {"rsa-key-len", required_argument, NULL, 'k'},
        {"keep-alive", no_argument, NULL, 'K'},
        {"handshakes", required_argument, NULL, 'n'},
        {"depth", required_argument, NULL, 'm'},
        {"port", required_argument, NULL, 'p'},
        {"resumed", required_argument, NULL, 'r'},
        {"server", required_argument, NULL, 's'},
        {"server-name", required_argument, NULL, ARG_SERVER_NAME},
        {"response", no_argument, NULL, 't'},
        {"url", required_argument, NULL, 'u'},
        {"tls", required_argument, NULL, 'V'},
        {"tls-version-range", required_argument, NULL, ARG_TLS_VERSION_RANGE},
        {"tls-supported-versions", required_argument, NULL, ARG_TLS_SUPPORTED_VERSIONS},
        {"no-cert", no_argument, NULL, ARG_NO_CERT},
        {"cert", required_argument, NULL, ARG_CERT},
        {"key", required_argument, NULL, ARG_KEY},
        {"on-demand-cert", required_argument, NULL, ARG_ON_DEMAND_CERT},
        {"on-demand-key", required_argument, NULL, ARG_ON_DEMAND_KEY},
        {"keytype", required_argument, NULL, ARG_KEYTYPE},
        {"groups", required_argument, NULL, ARG_GROUPS},
        {"num-key-shares", required_argument, NULL, ARG_NUM_KEY_SHARES},
        {"sig-algs", required_argument, NULL, ARG_SIG_ALGS},
        {"sig-algs-cert", required_argument, NULL, ARG_SIG_ALGS_CERT},
        {"psk", no_argument, NULL, ARG_PSK},
        {"psk-sha384", no_argument, NULL, ARG_PSK_SHA384},
        {"early-data", required_argument, NULL, ARG_EARLY_DATA},
        {"tls13-block-size", required_argument, NULL, ARG_TLS13_BLOCK_SIZE},
        {"req-ocsp-stapling", no_argument, NULL, ARG_REQ_OCSP_STAPLING},
        {"disable-peer-authentication", no_argument, NULL, ARG_DISABLE_PEER_AUTHENTICATION},
        {"min-dh-p-size", required_argument, NULL, ARG_MIN_DH_P_SIZE},
        {"use-session-tickets", no_argument, NULL, ARG_USE_SESSION_TICKETS},
        {"handshake-until-ticket", no_argument, NULL, ARG_HANDSHAKE_UNTIL_TICKET},
        {0, 0, 0, 0}
    };

    int opt_index = 0;

    while ((optionChar = getopt_long(argc, argv, optstring, long_options, &opt_index)) != -1)
#else
    while ((optionChar = getopt(argc, argv, optstring)) != -1)
#endif
    {
        switch (optionChar)
        {
        case 'h':
            return -1;


        case 'a':
            g_send_closure_alert = 0;
            break;

        case 'b':
            if (*g_path)
            {
                Printf("-b and -u options cannot both be provided\n");
                return -1;
            }
            g_bytes_requested = atoi(optarg);
            Snprintf(g_path, sizeof(g_path), "/bytes?%u", g_bytes_requested);
            break;

        case 'C':
            g_clientconfig.ca_file = optarg;
            clientconfigUseFileKeys();
            break;

        case 'c':
            /* Convert the cipherListString into an array of cipher numbers. */
            cipherListString = optarg;
            numCiphers = parse_cipher_list(cipherListString, g_cipher, 16);
            if (numCiphers <= 0)
            {
                return -1;
            }
            g_ciphers = numCiphers;
            break;

        case 'd':
            g_disableCertNameChk = 1;
            break;

        case 'e':
            Printf("-e option only supported when USE_EXT_CERTIFICATE_VERIFY_SIGNING " \
                "and USE_EXT_EXAMPLE_MODULE are defined\n");
            return -1;

        case 'k':
            key_len = atoi(optarg);
            if ((key_len != 1024) && (key_len != 2048)
                    && (key_len != 3072) && (key_len != 4096))
            {
                Printf("-k option must be followed by a key_len whose value "
                    " must be 1024, 2048, 3072 or 4096\n");
                return -1;
            }
            g_key_len = key_len;
            break;

        case 'K':
            g_keepalive = 1;
            break;

        case 'm':
            g_max_verify_depth = atoi(optarg);
            break;

        case 'n':
            g_new = atoi(optarg);
            break;

        case 'p':
            g_port = atoi(optarg);
            break;

        case 't':
            g_print_http_response = 1;
            break;

        case 'r':
            g_resumed = atoi(optarg);
            break;

        case 's':
            Strncpy(g_ip, optarg, 15);
            break;

        case 'u':
            if (*g_path)
            {
                Printf("-b and -u options cannot both be provided\n");
                return -1;
            }
            Strncpy(g_path, optarg, sizeof(g_path) - 1);
            g_bytes_requested = 0;
            break;

        case 'V':
            /* Single version. */
            version = atoi(optarg);
            if (!matrixSslTlsVersionRangeSupported(
                            matrixSslVersionFromMinorDigit(version),
                            matrixSslVersionFromMinorDigit(version)))
            {
                Printf("Invalid version: %d\n", version);
                return -1;
            }
            g_version = version;
            break;

#ifdef USE_GETOPT_LONG
/* Additional options not supported through short arguments */

        case ARG_CERT:
            g_clientconfig.cert_file = optarg;
            clientconfigUseFileKeys();
            break;

        case ARG_NO_CERT:
            g_clientconfig.cert_file = NULL;
            g_clientconfig.privkey_file = optarg;
            clientconfigUseFileKeys();
            break;

        case ARG_KEY:
            g_clientconfig.privkey_file = optarg;
            clientconfigUseFileKeys();
            break;

        case ARG_KEYTYPE:
            if (Strcmp("any", optarg) == 0) {
                g_clientconfig.load_key = &loadKeysFromFile;
            } else if (Strcmp("rsa", optarg) == 0) {
                g_clientconfig.load_key = &loadRsaKeysFromFile;
            } else if (Strcmp("ec", optarg) == 0) {
                g_clientconfig.load_key = &loadECDH_ECDSAKeysFromFile;
            } else if (Strcmp("ecrsa", optarg) == 0) {
                g_clientconfig.load_key = &loadECDHRsaKeysFromFile;
            } else {
                Printf("Invalid option: %s\n", optarg);
                return -1;
            }

            g_clientconfig.loadKeysFromMemory = 0;
            break;

        case ARG_TLS_VERSION_RANGE:
            {
                if (psParseList(NULL, optarg, ',', &versionRangeList) < 0)
                {
                    Printf("Invalid version range string: %s\n",
                            optarg);
                    return -1;
                }
                g_min_version = matrixSslVersionFromMinorDigit(
                        atoi((char *)versionRangeList->item));
                g_max_version = matrixSslVersionFromMinorDigit(
                        atoi((char *)versionRangeList->next->item));
                psFreeList(versionRangeList, NULL);
                if (!matrixSslTlsVersionRangeSupported(
                                g_min_version,
                                g_max_version))
                {
                    Printf("Unsupported version range: %s\n",
                            optarg);
                    return -1;
                }
                g_version_range_set = 1;
            }
            break;

        case ARG_ON_DEMAND_CERT:
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
            g_on_demand_cert_file = optarg;
# else
            Printf("Please enable USE_EXT_CLIENT_CERT_KEY_LOADING " \
                    "in matrixsslConfig.h for --on-demand-cert\n");
# endif
            break;

        case ARG_ON_DEMAND_KEY:
# ifdef USE_EXT_CLIENT_CERT_KEY_LOADING
            g_on_demand_key_file = optarg;
# else
            Printf("Please enable USE_EXT_CLIENT_CERT_KEY_LOADING " \
                    "in matrixsslConfig.h for --on-demand-key\n");
# endif
            break;

        case ARG_GROUPS:
            if (psParseList(NULL, optarg, ':', &g_groupList) < 0)
            {
                Printf("Invalid group list: %s\n", optarg);
            }
            break;

        case ARG_NUM_KEY_SHARES:
            g_num_key_shares = atoi(optarg);
            if (g_num_key_shares > 10)
            {
                Printf("Invalid number of key shares: %hu\n", g_num_key_shares);
            }
            break;
        case ARG_SIG_ALGS:
            if (psParseList(NULL, optarg, ':', &g_sigAlgsList) < 0)
            {
                Printf("Invalid sig_alg list: %s\n", optarg);
            }
            break;
        case ARG_SIG_ALGS_CERT:
            if (psParseList(NULL, optarg, ':', &g_sigAlgsCertList) < 0)
            {
                Printf("Invalid sig_alg_cert list: %s\n", optarg);
            }
            break;
       case ARG_TLS_SUPPORTED_VERSIONS:
            if (psParseList(NULL, optarg, ',', &g_supportedVersionsList) < 0)
            {
                Printf("Invalid tls-supported-versions list: %s\n", optarg);
            }
            break;
        case ARG_SERVER_NAME:
            if (Strlen(optarg) > sizeof(g_server_name) - 1)
            {
                Printf("Server name argument too long\n");
                exit(EXIT_FAILURE);
            }
            Strncpy(g_server_name, optarg, sizeof(g_server_name) - 1);
            break;
        case ARG_PSK:
            g_clientconfig.loadPreSharedKeys = 1;
            g_use_psk = 1;
            break;
        case ARG_PSK_SHA384:
            g_clientconfig.loadPreSharedKeys = 1;
            g_use_psk_sha384 = 1;
            break;
        case ARG_EARLY_DATA:
            Strcpy(g_early_data_file, optarg);
            break;
        case ARG_TLS13_BLOCK_SIZE:
            {
                char *end;

                g_tls13_block_size = Strtol(optarg, &end, 10);
                if (end == optarg
                        || g_tls13_block_size < 0
                        || g_tls13_block_size > TLS_1_3_MAX_INNER_PLAINTEXT_LEN)
                {
                    Printf("Invalid tls13-block-size argument\n");
                    exit(EXIT_FAILURE);
                }
                Printf("Using TLS 1.3 block size %ld\n",
                        g_tls13_block_size);
            }
            break;
        case ARG_REQ_OCSP_STAPLING:
            g_req_ocsp_stapling = 1;
            break;
        case ARG_DISABLE_PEER_AUTHENTICATION:
            g_disable_peer_authentication = 1;
            break;
        case ARG_MIN_DH_P_SIZE:
            {
                char *end;

                g_min_dh_p_size = Strtol(optarg, &end, 10);
                if (end == optarg
                        || g_min_dh_p_size <= 0)
                {
                    Printf("Invaling min-dh-p argument\n");
                    exit(EXIT_FAILURE);
                }
                if (g_min_dh_p_size < MIN_DH_BITS)
                {
                    Printf("Invalid min-dh-p argument: " \
                            "must be <= MIN_DH_BITS (= %u in this build)\n",
                            (unsigned int)MIN_DH_BITS);
                    exit(EXIT_FAILURE);
                }
            }
            break;
        case ARG_USE_SESSION_TICKETS:
            g_use_session_tickets = 1;
            break;
        case ARG_HANDSHAKE_UNTIL_TICKET:
            g_handshake_until_ticket = 1;
            break;
#endif /* USE_GETOPT_LONG */
        }

    }

    return 0;
}

static void sslstatsPrintTime(const struct g_sslstats* stats, int conn_count)
{
# ifdef USE_HIGHRES_TIME
    Printf("%d usec (%d avg usec/conn SSL handshake overhead)\n",
        (int) stats->hstime, (int) (stats->hstime / conn_count));
    Printf("%d usec (%d avg usec/conn SSL data overhead)\n",
        (int) stats->datatime, (int) (stats->datatime / conn_count));
# else
    Printf("%d msec (%d avg msec/conn SSL handshake overhead)\n",
        (int) stats->hstime, (int) (stats->hstime / conn_count));
    Printf("%d msec (%d avg msec/conn SSL data overhead)\n",
        (int) stats->datatime, (int) (stats->datatime / conn_count));
# endif
}

static void addTimeDiff(int64 *t, psTime_t t1, psTime_t t2)
{
# ifdef USE_HIGHRES_TIME
    *t += psDiffUsecs(t1, t2);
# else
    *t += psDiffMsecs(t1, t2, NULL);
# endif
}


/******************************************************************************/
/*
    Main routine. Initialize SSL keys and structures, and make two SSL
    connections, the first with a blank session Id, and the second with
    a session ID populated during the first connection to do a much faster
    session resumption connection the second time.
 */
int32 main(int32 argc, char **argv)
{
    int32 rc, i, exit_code;
    sslKeys_t *keys;
    sslSessionId_t *sid = NULL;
    struct g_sslstats stats;
# ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(1, 1), &wsaData);
# endif

    rc = PS_CONFIG_CHECK_SSL;
    printf("TLS configuration consistency check: ");
    if (rc == PS_SUCCESS)
    {
        printf("OK\n");
    }
    else
    {
        printf("FAILED\n");
        PS_CONFIG_PRINTF;
        printf("Exiting: failed configuration consistency check " \
                "in main()\n");
        return EXIT_FAILURE;
    }

    exit_code = 0;

    clientconfigInitialize();

    if ((rc = matrixSslOpen()) < 0)
    {
        psTrace("MatrixSSL library init failure.  Exiting\n");
        return EXIT_FAILURE;
    }

    if (0 != process_cmd_options(argc, argv))
    {
        usage();
        clientconfigFree();
        return 0;
    }

    if (matrixSslNewKeys(&keys, NULL) < 0)
    {
        psTrace("MatrixSSL library key init failure.  Exiting\n");
        return EXIT_FAILURE;
    }

    if (g_new <= 1 && g_resumed <= 1)
    {
        g_trace = 1;
    }
    else
    {
        g_trace = 0;
    }

    if (g_bytes_requested == 0 && *g_path == '\0')
    {
        Printf("client %s:%d "
            "new:%d resumed:%d keylen:%d nciphers:%d version:%d\n",
            g_ip, g_port, g_new, g_resumed, g_key_len,
            g_ciphers, g_version);
    }
    else
    {
        Printf("client https://%s:%d%s "
            "new:%d resumed:%d keylen:%d nciphers:%d version:%d\n",
            g_ip, g_port, g_path, g_new, g_resumed, g_key_len,
            g_ciphers, g_version);
    }

    if (!clientconfigLoadKeys(keys))
    {
        return EXIT_FAILURE;
    }

# ifdef USE_TLS_1_3
    if (g_use_psk)
    {
        /* Load the TLS 1.3 test PSKs. */
        rc = matrixSslLoadTls13Psk(keys,
                g_tls13_test_psk_256,
                sizeof(g_tls13_test_psk_256),
                g_tls13_test_psk_id_sha256,
                sizeof(g_tls13_test_psk_id_sha256),
                NULL);
        if (rc < 0)
        {
            psTrace("Unable to load PSK keys.\n");
            return rc;
        }
    }
    if (g_use_psk_sha384)
    {
        rc = matrixSslLoadTls13Psk(keys,
                g_tls13_test_psk_384,
                sizeof(g_tls13_test_psk_384),
                g_tls13_test_psk_id_sha384,
                sizeof(g_tls13_test_psk_id_sha384),
                NULL);
        if (rc < 0)
        {
            psTrace("Unable to load PSK keys.\n");
            return rc;
        }
    }
# endif

# ifdef USE_CRL
    /* One initialization step that can be taken is to run through the CA
        files and see if any CRL URL distribution points are present.
        Fetch the CRL and load into the cache if found */
    fetchParseAndAuthCRLfromCert(NULL,
            sslKeysGetCACerts(keys),
            sslKeysGetCACerts(keys));
# endif

    Memset(&stats, 0x0, sizeof(struct g_sslstats));
    Printf("=== %d new connections ===\n", g_new);

    if (g_new == 0)
    {
        /* Special case where client is being used to remotely shut down
            the server for automated tests */
        g_closeServer = 1;
        g_bytes_requested = 0; /* Disable data exchange in this case */
        g_new = 1;
    }

    i = 0;
    while (true)
    {
        matrixSslNewSessionId(&sid, NULL);
# ifdef USE_CRL
#  ifndef MIDHANDSHAKE_CRL_FETCH
        /* This is part of the example for an application that has chosen to
            fail a handshake if the CRL was not available during the first
            attempted connection.  In this case, the CRL URL distribution points
            have been saved aside in g_crlDistURLs and now we will go out and
            fetch those CRLs and load them into the library cache so they
            will be available on this next connection attempt. */
        if (g_crlDistURLs[0][0] == 'h')   /* assumption is "http" */
        {
            fetchSavedCRL(sslKeysGetCACerts(keys));
        }
#  endif
# endif
        rc = httpsClientConnection(keys, sid, &stats);
        if (rc < 0)
        {
            Printf("F %d/%d\n", i, g_new);
            exit_code = EXIT_FAILURE;
            goto out;
        }
        else
        {
            Printf("N"); Fflush(stdout);
        }
        psTraceBytes("stored session_id",
                matrixSslSessionIdGetSessionId(sid),
                matrixSslSessionIdGetSessionIdLen(sid));
# ifdef USE_STATELESS_SESSION_TICKETS
        /* Store the last session ticket we receive for resumptions. */
        if (matrixSslSessionIdGetSessionTicket(sid) != NULL &&
                matrixSslSessionIdGetSessionTicketLen(sid) > 0)
        {
            const unsigned char *pMasterSecret;

            pMasterSecret = matrixSslSessionIdGetMasterSecret(sid);
            Printf("Stored a session ticket.\n");
            psTraceBytes("master secret associated with session ticket",
                    pMasterSecret,
                    48);
            /* Clear the session_id so that legacy session id based resumption
               will not be attempted. */
            matrixSslSessionIdClearSessionId(sid);
            if (g_handshake_until_ticket)
            {
                break;
            }
        }
# endif
        /* Leave the final session ID for resumed connections. */
        if (i + 1 < g_new)
        {
            matrixSslDeleteSessionId(sid);
        }
        i++;
        if (g_handshake_until_ticket)
        {
            /* Sanity limit. */
            if (i > 20)
            {
                break;
            }
        }
        else
        {
            /* User-provided limit or 1. */
            if (i == g_new)
            {
                break;
            }
        }
    }
    Printf("\n");
    if (g_bytes_requested > 0)
    {
        psAssert(g_bytes_requested * g_new == stats.rbytes);
    }
    Printf("%d bytes received\n", stats.rbytes);
    sslstatsPrintTime(&stats, g_new);

    Memset(&stats, 0x0, sizeof(struct g_sslstats));
    Printf("=== %d resumed connections ===\n", g_resumed);
    for (i = 0; i < g_resumed; i++)
    {
        rc = httpsClientConnection(keys, sid, &stats);
        if (rc < 0)
        {
            Printf("f %d/%d\n", i, g_resumed);
            exit_code = EXIT_FAILURE;
            goto out;
        }
        else
        {
            Printf("Resumed session.\n");
            Fflush(stdout);
        }
    }
    if (g_keepalive)
    {
        Printf("Closing socket\n");
        close(g_keepalive);
        g_keepalive = 0;
    }
    if (g_resumed)
    {
        if (g_bytes_requested > 0)
        {
            psAssert(g_bytes_requested * g_resumed == stats.rbytes);
        }
        Printf("\n%d bytes received\n", stats.rbytes);
        sslstatsPrintTime(&stats, g_resumed);
    }

out:
    matrixSslDeleteSessionId(sid);
    matrixSslDeleteKeys(keys);
    matrixSslClose();

    clientconfigFree();

    psFreeList(g_sigAlgsCertList, NULL);
    psFreeList(g_sigAlgsList, NULL);
    psFreeList(g_supportedVersionsList, NULL);
    psFreeList(g_groupList, NULL);

# ifdef WIN32
    psTrace("Press any key to close");
    getchar();
# endif
    return exit_code;
}

/******************************************************************************/
/*
    Close a socket and free associated SSL context and buffers
    An attempt is made to send a closure alert
 */
static void closeConn(ssl_t *ssl, SOCKET fd)
{
    unsigned char *buf;
    int32 len, rc;

    if (g_send_closure_alert)
    {
# if 1
        /* Set the socket to non-blocking to flush remaining data */
#  ifdef POSIX
        rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        psAssert(rc >= 0);
#  endif
#  ifdef WIN32
        len = 1;    /* 1 for non-block, 0 for block */
        rc = ioctlsocket(fd, FIONBIO, &len);
        psAssert(rc);
#  endif
        /* Quick attempt to send a closure alert, don't worry about failure */
        if (matrixSslEncodeClosureAlert(ssl) >= 0)
        {
            if ((len = matrixSslGetOutdata(ssl, &buf)) > 0)
            {
                if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0)
                {
                    matrixSslSentData(ssl, len);
                }
            }
        }
# endif
    }
    matrixSslDeleteSession(ssl);

    if (fd != INVALID_SOCKET && g_keepalive == 0)
    {
        close(fd);
    }
}

static int32_t extensionCb(ssl_t *ssl,
    uint16_t extType, uint8_t extLen, void *e)
{
    unsigned char *c;
    short len;
    char proto[128];

    c = (unsigned char *) e;

    if (extType == EXT_ALPN)
    {
        Memset(proto, 0x0, 128);
        /* two byte proto list len, one byte proto len, then proto */
        c += 2; /* Skip proto list len */
        len = *c; c++;
        Memcpy(proto, c, len);
        Printf("Server agreed to use %s\n", proto);
    }
    return PS_SUCCESS;
}

/******************************************************************************/
/*
    Example callback to show possible outcomes of certificate validation.
    If this callback is not registered in matrixSslNewClientSession
    the connection will be accepted or closed based on the alert value.
 */
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
# ifndef USE_ONLY_PSK_CIPHER_SUITE
    psX509Cert_t *next;

    if (g_disable_peer_authentication)
    {
        psTraceStr("Allowing anonymous connection for: %s.\n",
                cert->subject.commonName);
        return SSL_ALLOW_ANON_CONNECTION;
    }

    /* An immediate SSL_ALERT_UNKNOWN_CA alert means we could not find the
        CA to authenticate the server's certificate */
    if (alert == SSL_ALERT_UNKNOWN_CA)
    {
        /*
          SSL_ALERT_UNKNOWN_CA can also result from breach of the
          max_verify_depth limit we specified in the session options.
        */
        if (g_max_verify_depth > 0) {
            for (next = cert; next != NULL; next = next->next)
            {
                if ((next->authStatus & PS_CERT_AUTH_FAIL_PATH_LEN) &&
                        (next->authFailFlags &
                                PS_CERT_AUTH_FAIL_VERIFY_DEPTH_FLAG))
                {
                    psTrace("Maximum cert chain verify depth exceeded\n");
                    return SSL_ALERT_UNKNOWN_CA;
                }
            }
        }
        /* Example to allow anonymous connections based on a define */
        else if (ALLOW_ANON_CONNECTIONS)
        {
            if (g_trace)
            {
                psTraceStr("Allowing anonymous connection for: %s.\n",
                    cert->subject.commonName);
            }
            return SSL_ALLOW_ANON_CONNECTION;
        }
        psTrace("ERROR: No matching CA found.  Terminating connection\n");
    }

    /*  Check for "major" authentication problems within the server certificate
        chain.

        The "alert" is the translation of the very first authentication problem
        found.  So if we are dealing with a certificate chain we should walk to
        the parent-most cert to confirm there are no authentication problems
        that indicate the chain itself did not validate or this client did
        not find a CA to authenticate the server.

        Some certificate callback implemenations might choose to ignore some
        alerts that are considered minor to the use case, so this is an example
        of how to make sure a minor alert (such as expired date) is not
        overriding a more serious authentication problem
     */
    for (next = cert; next != NULL; next = next->next)
    {
        if (next->authStatus == PS_CERT_AUTH_FAIL_SIG)
        {
            psTrace("Public key signature failure in server cert chain\n");
            /* This should result in a BAD_CERTIFICATE alert */
            alert = SSL_ALERT_BAD_CERTIFICATE;
            break;
        }
        if (next->authStatus == PS_CERT_AUTH_FAIL_DN)
        {
            char *missingIssuerDN = NULL;
# ifdef USE_FULL_CERT_PARSE
            size_t missingIssuerDNLen;
# endif /* USE_FULL_CERT_PARSE */
            psRes_t rc;

            /* A CA file was never located to support this chain */
            psTrace("No CA file was found to support server's certificate\n");
            /* This should result in a SSL_ALERT_UNKNOWN_CA alert */
            alert = SSL_ALERT_UNKNOWN_CA;
            /* Print out the DN of the missing CA. */
# ifdef USE_FULL_CERT_PARSE
            rc = psX509GetOnelineDN(&next->issuer,
                                    &missingIssuerDN,
                                    &missingIssuerDNLen,
                                    0);
# else
            rc = -1;
# endif /* USE_FULL_CERT_PARSE */
            if (rc < 0)
            {
                psTrace("psX509GetOnelineDN failed\n");
            }
            else
            {
                psTraceStr("Missing CA cert:\n%s\n", missingIssuerDN);
                psFree(missingIssuerDN, NULL);
            }
            break;
        }
        if (next->authStatus == PS_CERT_AUTH_FAIL_AUTHKEY)
        {
            /* Subject and Issuer Key Id extension  */
            psTrace("Subject and Issuer Key Id mismatch error\n");
            /* This should be a BAD_CERTIFICATE alert */
            alert = SSL_ALERT_BAD_CERTIFICATE;
            break;
        }
    }

    /*
        If the expectedName passed to matrixSslNewClientSession does not
        match any of the server subject name or subjAltNames, we will have
        the alert below.
        For security, the expected name (typically a domain name) _must_
        match one of the certificate subject names, or the connection
        should not continue.
        The default MatrixSSL certificates use localhost and 127.0.0.1 as
        the subjects, so unless the server IP matches one of those, this
        alert will happen.
        To temporarily disable the subject name validation, NULL can be passed
        as expectedName to matrixNewClientSession.
     */
    if (alert == SSL_ALERT_CERTIFICATE_UNKNOWN)
    {
        psTraceStr("ERROR: %s not found in cert subject names\n",
                matrixSslGetExpectedName(ssl));
    }

    if (alert == SSL_ALERT_CERTIFICATE_EXPIRED)
    {
#  ifdef POSIX
        psTrace("ERROR: A cert did not fall within the notBefore/notAfter window\n");
#  else
        psTrace("WARNING: Certificate date window validation not implemented\n");
        alert = 0;
#  endif
    }

    if (alert == SSL_ALERT_ILLEGAL_PARAMETER)
    {
        psTrace("ERROR: Found correct CA but X.509 extension details are wrong\n");
    }

    /* Key usage related problems on chain */
    for (next = cert; next != NULL; next = next->next)
    {
        if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION)
        {
            if (next->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG)
            {
                psTrace("CA keyUsage extension doesn't allow cert signing\n");
            }
            if (next->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG)
            {
                psTrace("Cert extendedKeyUsage extension doesn't allow TLS\n");
            }
        }
    }

    if (alert == SSL_ALERT_BAD_CERTIFICATE)
    {
        /* Should never let a connection happen if this is set.  There was
            either a problem in the presented chain or in the final CA test */
        psTrace("ERROR: Problem in certificate validation.  Exiting.\n");
    }


#  ifdef USE_CRL
    /* Examples on how to look at the CRL status for the cert chain and fetch
        CRLs if they have not been loaded */
    {
        psX509Crl_t *expired;
#   ifdef MIDHANDSHAKE_CRL_FETCH
        /* Will pause this handshake to go out and fetch a CRL via HTTP GET,
            re-check for revocation and continue on if it all checks out */
        int retryOnce = 0;
RETRY_CRL_TEST_ONCE:
#   else
        /* Perhaps the more standard way is to stop the handshake if the CRLs have
            not been fetched.  Go fetch them and retry the SSL connection from
            scratch.  The connection reattempt will only occur if the -n command
            line option has been set to something greater than 1 */
        int count = 0;
        uint32_t urlLen;
        unsigned char *url;
#   endif

        /* Loop to look at the CRL status of each cert in the chain */
        for (next = cert; next != NULL; next = next->next)
        {
            switch (next->revokedStatus)
            {
            case CRL_CHECK_CRL_EXPIRED:
                psTrace("Have CRL but it is expired.  Fetching new one\n");
                /* Remove the CRL from the table */
                expired = psCRL_GetCRLForCert(next);
                if (expired)
                {
                    psAssert(expired->expired);
                    psCRL_Delete(expired);
                }
                else
                {
                    psTrace("Unexpected combo of expired but no CRL found\n");
                }
            /* MOVING INTO CRL_CHECK_EXPECTED ON PURPOSE TO REFETCH */
            case CRL_CHECK_EXPECTED:
                /* There was a CRL distribution point in this cert but we didn't
                    have the CRL to test against */
#   ifdef MIDHANDSHAKE_CRL_FETCH
                /* It is an application choice to go out and fetch CRLs in the
                    middle of the handshake like this.  It's probably not advised
                    to do this but here is an example if you'd like to do so */
                /* Only attempt this once so we don't get stuck in a loop */
                if (retryOnce)
                {
                    psTrace("Cert was not able to be tested against a CRL\n");
                    alert = SSL_ALERT_CERTIFICATE_UNKNOWN;
                    break;
                }
                psTrace("Cert expects CRL.  Mid-handshake attempt being made\n");
                /* This fetchParseAndAuthCRLfromCert will work on "next" as a chain
                    so it is correct that the server cert will look for the first
                    instance of CHECK_EXPECTED and pass that as the start of
                    chain to work upon */
                fetchParseAndAuthCRLfromCert(NULL,
                        next,
                        sslKeysGetCACerts(matrixSslGetKeys(ssl)));
                /* If all went well, every cert in the server chain will have an
                    updated status */
                retryOnce++;
                goto RETRY_CRL_TEST_ONCE;
#   else        /* MIDHANSHAKE_CRL_FETCH */

                psTrace("Cert expects CRL. Failing handshake to go fetch it\n");
                /* A more typical case if CRL testing is expected to be done is
                    to halt the handshake now, go out and fetch the CRLs and
                    try the connection again */
                /* Not clear which alert should be associated with this
                    application level decision.  Let's call it UNKNOWN */
                alert = SSL_ALERT_CERTIFICATE_UNKNOWN;

                /* Save aside the CRL URL distribution points to fetch after
                    control is given back when this handshake is done. Correct
                    to pick up from the current cert and work up as far as
                    possible */
                if (count < CRL_MAX_SERVER_CERT_CHAIN)
                {
                    Memset(g_crlDistURLs[count], 0, CRL_MAX_URL_LEN);
                    psX509GetCRLdistURL(next, (char **) &url, &urlLen);
                    if (urlLen > CRL_MAX_URL_LEN)
                    {
                        psTraceInt("CLR URL distribution point longer than %d\n",
                            CRL_MAX_URL_LEN);
                    }
                    else
                    {
                        Memcpy(g_crlDistURLs[count], url, urlLen);
                        count++;
                    }
                }
                else
                {
                    psTraceInt("Server cert chain was longer than %d\n",
                        CRL_MAX_SERVER_CERT_CHAIN);
                }

                break;

#   endif       /* MIDHANDSHAKE_CRL_FETCH */

            case CRL_CHECK_NOT_EXPECTED:
                psTrace("Cert didn't specify a CRL distribution point\n");
                break;
            case CRL_CHECK_PASSED_AND_AUTHENTICATED:
                psTrace("Cert passed CRL test and CRL was authenticated\n");
                break;
            case CRL_CHECK_PASSED_BUT_NOT_AUTHENTICATED:
                psTrace("Cert passed CRL test but CRL was not authenticated\n");
                break;
            case CRL_CHECK_REVOKED_AND_AUTHENTICATED:
                psTrace("Cert was revoked by an authenticated CRL\n");
                alert = SSL_ALERT_CERTIFICATE_REVOKED;
                break;
            case CRL_CHECK_REVOKED_BUT_NOT_AUTHENTICATED:
                psTrace("Cert was revoked but the CRL wasn't authenticated\n");
                alert = SSL_ALERT_CERTIFICATE_REVOKED;
                break;
            default:
                break;
            }
        }
    } /* End CRL local code block */
#  endif

    if (g_trace && alert == 0 && cert)
    {
        psTraceStr("SUCCESS: Validated cert for: %s.\n", cert->subject.commonName);
    }

# endif /* !USE_ONLY_PSK_CIPHER_SUITE */
    return alert;
} /* end certificate callback */


/******************************************************************************/
# ifdef USE_CRL

#  ifndef MIDHANDSHAKE_CRL_FETCH
/* Part of example for halting handshake because no CRL was available.  Now
    we have closed that handshake and are fetching the CRLs that were set
    aside during the certificate callback.  We use our list of CA files as
    potential issuers here so we can attempt a round of CRL authentications.
    This authentication round will save time during the next handshake */
static void fetchSavedCRL(psX509Cert_t *potentialIssuers)
{
    int i;

    /* Test for 'h' is assuming URL to begin with "http" */
    for (i = 0; i < CRL_MAX_SERVER_CERT_CHAIN && g_crlDistURLs[i][0] == 'h';
         i++)
    {
        fetchParseAndAuthCRLfromUrl(NULL, g_crlDistURLs[i],
            Strlen((char *) g_crlDistURLs[i]), potentialIssuers);
        Memset(g_crlDistURLs[i], 0, CRL_MAX_URL_LEN);
    }
}

/* Fetch a CRL give an URL.  Once you have it, check to see if it can be
    authenticated by any of the "potentialIssuers"

    Regardless of authentication status, add any CRL that is found
    to the global cache for     access inside the library during internal
    authentications */
static int32_t fetchParseAndAuthCRLfromUrl(psPool_t *pool, unsigned char *url,
    uint32_t urlLen, psX509Cert_t *potentialIssuers)
{
    unsigned char *crlBuf;
    uint32_t crlBufLen;
    psX509Crl_t *crl;
    psX509Cert_t *ic;

    /* url need not be freed.  It points into cert structure */
    if (fetchCRL(NULL, (char *) url, urlLen, &crlBuf, &crlBufLen) < 0)
    {
        psTrace("Unable to fetch CRL\n");
        return -1;
    }
    /* Convert the CRL stream into our structure */
    if (psX509ParseCRL(pool, &crl, crlBuf, crlBufLen) < 0)
    {
        psTrace("Unable to parse CRL\n");
        psFree(crlBuf, pool);
        return -1;
    }
    psFree(crlBuf, pool);

    /* Adding the CRL to the global cache.  This local crl is now the
        same memory as the entry in the global cache and is managed
        there.  Freeing will now be     done with psCRL_DeleteAll at
        application closure */
    psCRL_Update(crl, 1); /* The 1 will delete old CRLs */

    /* Important to separate the concept of the CRL authentication
        from the cert authentication.  Here, we run through the
        list of potential issuers the caller thinks could work */
    for (ic = potentialIssuers; ic != NULL; ic = ic->next)
    {
        if (psX509AuthenticateCRL(ic, crl, NULL) >= 0)
        {
            psTrace("NOTE: Able to authenticate CRL\n");
            break; /* Stop looking */
        }
    }
    return PS_SUCCESS;
}
#  endif /* ifndef MIDHANDSHAKE_CRL_FETCH */


/* Take the CRL Distribution URL from the "cert" (may be a chain) and go fetch
    the CRL.  Once you have it, check to see if it can be authenticated by any
    of the "potentialIssuers" OR by the "cert" chain itself.

    Regardless of authentication status, add any CRL that is found
    to the global cache for     access inside the library during internal
    authentications */
static int32_t fetchParseAndAuthCRLfromCert(psPool_t *pool, psX509Cert_t *cert,
    psX509Cert_t *potentialIssuers)
{
    char *url;
    unsigned char *crlBuf;
    uint32_t urlLen, crlBufLen;
    psX509Crl_t *crl;
    psX509Cert_t *sc, *ic;
    int32 numLoaded = 0;

    sc = cert;
    while (sc)
    {
        if (psX509GetCRLdistURL(sc, &url, &urlLen) > 0)
        {
            /* url need not be freed.  It points into cert structure */
            if (fetchCRL(NULL, url, urlLen, &crlBuf, &crlBufLen) < 0)
            {
                psTrace("Unable to fetch CRL\n");
                sc = sc->next;
                continue;
            }
            /* Convert the CRL stream into our structure */
            if (psX509ParseCRL(pool, &crl, crlBuf, crlBufLen) < 0)
            {
                psTrace("Unable to parse CRL\n");
                psFree(crlBuf, pool);
                sc = sc->next;
                continue;
            }
            psFree(crlBuf, pool);

            /* Adding the CRL to the global cache.  This local crl is now the
                same memory as the entry in the global cache and is managed
                there.  Freeing will now be     done with psCRL_DeleteAll at
                application closure */
            psCRL_Update(crl, 1); /* The 1 will delete old CRLs */
            ++numLoaded;

            /* Important to separate the concept of the CRL authentication
                from the cert authentication.  Here, we run through the
                list of potential issuers the caller thinks could work */
            for (ic = potentialIssuers; ic != NULL; ic = ic->next)
            {
                if (psX509AuthenticateCRL(ic, crl, NULL) >= 0)
                {
                    psTrace("NOTE: Able to authenticate CRL\n");
                    break; /* Stop looking */
                }
            }
            if (crl->authenticated == 0)
            {
                /* If none of our potential issuers were able to authenticate,
                    let's just run through our own "cert" chain as well.
                    The reason we are doing this is to allow this function
                    to handle cases where the "cert" is part of a server
                    cert chain where the issuer is included as part of that
                    CERTIFICATE message.  That is what we are testing here.
                    The potentialIssuers will typically be the loaded CA
                    files and that will catch the cases where the parent-most
                    certificate of the server chain will need to be
                    authenticated */
                for (ic = cert; ic != NULL; ic = ic->next)
                {
                    if (psX509AuthenticateCRL(ic, crl, NULL) >= 0)
                    {
                        psTrace("NOTE: Able to authenticate CRL\n");
                        break; /* Stop looking */
                    }
                }
            }

            /* Regardless of whether or not we could authenticate the CRL,
                run the function that recalculates the revokedStatus of
                the certificate itself.  REQUIRES g_CRL */
            psCRL_determineRevokedStatus(sc);
        }
        sc = sc->next;
    }
    psTraceInt("CRLs loaded: %d\n", numLoaded);
    return PS_SUCCESS;
}

/**
    Return the number of bytes difference between 'end' and 'start'.
    @param[in] end A pointer to valid memory, greater or equal to 'start'
    @param[in] start A pointer to valid memory, less than or equal to 'start'
    @param sanity The maximum expected difference in bytes
    @return Number of bytes that 'end' is greater than 'start'. Range is 0 <= return <= sanity.
        If end < start, 0 is returned. If 'end' - 'start' > 'sanity', 'sanity' is returned.
 */
__inline static size_t ptrdiff_safe(const void *end, const void *start, size_t sanity)
{
    ptrdiff_t d;

    if (end < start)
    {
        return 0;
    }
    d = (const unsigned char *)end - (const unsigned char *)start;
    if (d > sanity)
    {
        return sanity;
    }
    return (size_t) d;
}

/**
    Example function to retrieve a CRL using HTTP GET over POSIX sockets.
    @security This API does not fully validate all input. It should only be used to fetch
    a CRL froa trusted source with validly generated CRL data. The HTTP response of the
    trusted server should also be tested, as the HTTP parsing in this API is not flexible.
    @param [out] crlBuf is allocated by this routine and must be freed via psFree
    @return < 0 Error loading CRL. 0 on Success
 */
int32 fetchCRL(psPool_t *pool, char *url, uint32_t urlLen,
    unsigned char **crlBuf, uint32_t *crlBufLen)
{
    static unsigned char crl_getHdr[] = "GET ";

#  define GET_OH_LEN      4
    static unsigned char crl_httpHdr[] = " HTTP/1.0\r\n";
#  define HTTP_OH_LEN     11
    static unsigned char crl_hostHdr[] = "Host: ";
#  define HOST_OH_LEN     6
    static unsigned char crl_acceptHdr[] = "\r\nAccept: */*\r\n\r\n";
#  define ACCEPT_OH_LEN   17
#  define HOST_ADDR_LEN   64    /* max to hold 'www.something.com' */
#  define GET_REQ_LEN     128   /* max to hold http GET request */
#  define HTTP_REPLY_CHUNK_SIZE   2048

    SOCKET fd;
    struct hostent *ip;
    struct in_addr intaddr;
    char *pageStart, *ipAddr;
    const char *replyPtr;
    char hostAddr[HOST_ADDR_LEN], getReq[GET_REQ_LEN];
    int hostAddrLen, getReqLen, pageLen;
    ssize_t transferred;
    int32_t grown = 0;
    int32_t sawOK, sawContentLength, err, httpUriLen, port, offset;
    unsigned char crlChunk[HTTP_REPLY_CHUNK_SIZE + 1];
    unsigned char *crlBin;     /* allocated */
    uint32_t crlBinLen;

    /* Is URI in expected URL form? */
    if (Strstr(url, "http://") == NULL)
    {
        if (Strstr(url, "https://") == NULL)
        {
            psTraceStr("fetchCRL: Unsupported CRL URI: %s\n", url);
            return -1;
        }
        httpUriLen = 8;
        port = 80; /* No example yet of using SSL to fetch CRL */
    }
    else
    {
        httpUriLen = 7;
        port = 80;
    }

    /* Parsing host and page and setting up IP address and GET request */
    if ((pageStart = Strchr(url + httpUriLen, '/')) == NULL)
    {
        psTrace("fetchCRL: No host/page divider found\n");
        return -1;
    }
    if ((hostAddrLen = (int) (pageStart - url) - httpUriLen) > HOST_ADDR_LEN)
    {
        psTrace("fetchCRL: HOST_ADDR_LEN needs to be increased\n");
        return -1; /* ipAddr too small to hold */
    }

    Memset(hostAddr, 0, HOST_ADDR_LEN);
    Memcpy(hostAddr, url + httpUriLen, hostAddrLen);
    if ((ip = gethostbyname(hostAddr)) == NULL)
    {
        psTrace("fetchCRL: gethostbyname failed\n");
        return -1;
    }

    Memcpy((char *) &intaddr, (char *) ip->h_addr_list[0],
        (size_t) ip->h_length);
    if ((ipAddr = inet_ntoa(intaddr)) == NULL)
    {
        psTrace("fetchCRL: inet_ntoa failed\n");
        return -1;
    }

    pageLen = (urlLen - hostAddrLen - httpUriLen);
    getReqLen = pageLen + hostAddrLen + GET_OH_LEN + HTTP_OH_LEN +
                HOST_OH_LEN + ACCEPT_OH_LEN;
    if (getReqLen > GET_REQ_LEN)
    {
        psTrace("fetchCRL: GET_REQ_LEN needs to be increased\n");
        return -1;
    }

    /* Build the request: */
    /*  */
    /*  GET /page.crl HTTP/1.0 */
    /*  Host: www.host.com */
    /*  Accept: * / * */
    /*  */
    Memset(getReq, 0, GET_REQ_LEN);
    Memcpy(getReq, crl_getHdr, GET_OH_LEN);
    offset = GET_OH_LEN;
    Memcpy(getReq + offset, pageStart, pageLen);
    offset += pageLen;
    Memcpy(getReq + offset, crl_httpHdr, HTTP_OH_LEN);
    offset += HTTP_OH_LEN;
    Memcpy(getReq + offset, crl_hostHdr, HOST_OH_LEN);
    offset += HOST_OH_LEN;
    Memcpy(getReq + offset, hostAddr, hostAddrLen);
    offset += hostAddrLen;
    Memcpy(getReq + offset, crl_acceptHdr, ACCEPT_OH_LEN);

    /* Connect and send */
    fd = lsocketConnect(ipAddr, port, &err);
    if (fd == INVALID_SOCKET || err != PS_SUCCESS)
    {
        psTraceInt("fetchCRL: socketConnect failed: %d\n", err);
        return PS_PLATFORM_FAIL;
    }

    /* Send request and receive response */
    offset = 0;
    while (getReqLen)
    {
        if ((transferred = send(fd, getReq + offset, getReqLen, 0)) < 0)
        {
            psTraceInt("fetchCRL: socket send failed: %d\n", errno);
            close(fd);
            return PS_PLATFORM_FAIL;
        }
        getReqLen -= transferred;
        offset += transferred;
    }

    /* Get a chunk at a time so we can peek at the size on the first chunk
        and allocate the correct CRL size */
    crlBin = NULL;
    crlBinLen = 0;
    *crlBuf = NULL;
    *crlBufLen = 0;
    sawOK = sawContentLength = 0;

    /* This recv loop is not 100%.  The parse is looking for a few specific
        strings in the HTTP header to get initial status, content length,
        and \r\n\r\n for beginning of CRL data. If a recv happens to fall right
        on the boundary of any of these patterns, the behavior is undefined.
        There are some asserts sprinked around to notify if this happens.
        It SHOULD be sufficient to keep a decent size HTTP_REPLY_CHUNK_SIZE
        that you can be pretty sure will hold the entire HTTP header but
        the "recv" call itself is also a factor in how many bytes will be
        recevied in the first call */
    while ((transferred = recv(fd, crlChunk, HTTP_REPLY_CHUNK_SIZE, 0)) > 0)
    {
        crlChunk[transferred] = 0; /* Ensure zero termination for Strstr(). */
        if (crlBin == NULL)
        {
            /* Still getting the details of the HTTP response */
            /* Did we get an OK response? */
            if (sawOK == 0)
            {
                if (Strstr((const char *) crlChunk, "200 OK") == NULL)
                {
                    /* First chunk. Should be plenty large enough to hold */
                    psTrace("fetchCRL: server reply was not '200 OK'\n");
                    close(fd);
                    return -1;
                }
                sawOK++;
            }
            /* Length parse */
            if (sawContentLength == 0)
            {
                if ((replyPtr = Strstr((const char *) crlChunk,
                         "Content-Length: ")) == NULL)
                {

                    /* Apparently Content-Length is not always going to be
                        there.  See if we have the end of the header instead */
                    if ((replyPtr = Strstr((const char *) crlChunk, "\r\n\r\n"))
                        == NULL)
                    {
                        continue; /* saw neither. keep trying */
                    }
                    /* Saw \r\n\r\n but no Content-Length: can't allocate full
                        CRL buffer at once so work in chunks */
                    crlBinLen = HTTP_REPLY_CHUNK_SIZE;
                }
                else
                {
                    /* Got the Content-Length: as expected */
                    sawContentLength++;

                    /* Possible cut off right at Content-Length here which
                        would be a pain.  This assert is seeing if there are
                        at least 8 more bytes in the chunk to read the
                        integer out of.  If you hit this, some partial
                        parsing will need to be instrumented... or change
                        the chunk size if this is truly a chunk boundary */
                    psAssert((replyPtr + 16) <
                        (char *) &(crlChunk[HTTP_REPLY_CHUNK_SIZE - 24]));


                    /* Magic 16 is length of "Content-Length: " */
                    crlBinLen = (int) atoi(replyPtr + 16);
                }
            }


            /* Data begins after CRLF CRLF */
            if ((replyPtr = Strstr((const char *) crlChunk, "\r\n\r\n"))
                == NULL)
            {
                continue;
            }
            /* Possible cut off right at data start here which
                would be a pain.  This assert is seeing if there are
                4 more bytes in the chunk to advance past.  If you hit this,
                some partial parsing will need to be instrumented... or change
                the chunk size if this is truly a chunk boundary */
            psAssert((replyPtr + 4) < (char *) &(crlChunk[HTTP_REPLY_CHUNK_SIZE]));
            replyPtr += 4; /* Move past that "\r\n\r\n" to get to start */

            /* Check buffer length appears acceptable */
            if (crlBinLen < 1 || crlBinLen > CRL_MAX_LENGTH)
            {
                psTrace("fetchCRL: Unacceptable size for CRL\n");
                /* Note: If this fails you may need to check CRL_MAX_LENGTH,
                   as you possibly need to allow larger CRL. */
                close(fd);
                return -1;
            }

            /* Allocate the CRL buffer. Will be full size if sawContentLength */
            if ((crlBin = (unsigned char *)psMalloc(pool, crlBinLen)) == NULL)
            {
                psTrace("fetchCRL: Memory allocation error for CRL buffer\n");
                close(fd);
                return -1;
            }

            /* So how much do we actually have to copy our of first chunk? */
            transferred -= ptrdiff_safe(replyPtr, crlChunk, HTTP_REPLY_CHUNK_SIZE);

            if (sawContentLength)
            {
                /* Will march crlBin forward so just assign output crlBuf now */
                *crlBuf = crlBin;
                *crlBufLen = crlBinLen;
                Memcpy(crlBin, replyPtr, transferred);
                crlBin += transferred;
                psAssert((crlBin - *crlBuf) <= crlBinLen);
            }
            else
            {
                grown = 1;
                /* Keep track of index to monitor size */
                crlBinLen = transferred;
                Memcpy(crlBin, replyPtr, transferred);
            }
        }
        else
        {
            /* subsequent recv calls */
            if (sawContentLength)
            {
                Memcpy(crlBin, crlChunk, transferred);
                crlBin += transferred;
                psAssert((crlBin - *crlBuf) <= crlBinLen);
            }
            else
            {
                if (transferred + crlBinLen > (HTTP_REPLY_CHUNK_SIZE * grown))
                {
                    /* not enough room.  psRealloc */
                    grown++;
                    crlBin = (unsigned char*)psRealloc(
                            crlBin, HTTP_REPLY_CHUNK_SIZE * grown, pool);
                }
                Memcpy(crlBin + crlBinLen, crlChunk, transferred);
                crlBinLen += transferred;
            }
        }
    }
    close(fd);
    if (sawContentLength == 0)
    {
        /* These have been changing as we grow */
        *crlBuf = crlBin;
        *crlBufLen = crlBinLen;
    }
    else
    {
        psAssert(crlBinLen == (crlBin - *crlBuf));
    }

    return 0;

}
# endif /* USE_CRL */


/******************************************************************************/
/*
    Open an outgoing blocking socket connection to a remote ip and port.
    Caller should always check *err value, even if a valid socket is returned
 */
static SOCKET lsocketConnect(char *ip, int32 port, int32 *err)
{
    struct sockaddr_in addr;
    SOCKET fd;
    int32 rc;

    /* By default, this will produce a blocking socket */
    if ((fd = Socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        perror("Socket()");
        psTrace("Error creating socket\n");
        *err = SOCKET_ERRNO;
        return INVALID_SOCKET;
    }
# ifdef POSIX
    rc = fcntl(fd, F_SETFD, FD_CLOEXEC);
    psAssert(rc >= 0);
# endif
# if 0
    {
        struct linger lin;
        rc = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &rc, sizeof(rc));
        rc = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &rc, sizeof(rc));
        lin.l_onoff = 0;
        lin.l_linger = 0; /* Seconds */
        setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &lin, sizeof(struct linger));
    }
    {
        uint32 len;
        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rc, &len);
        Printf("SO_RCVBUF: %d\n", rc);
    }
# endif
# ifdef __APPLE__ /* MAC OS X */
    rc = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *) &rc, sizeof(rc));
# endif
    Memset((char *) &addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short) port);
    addr.sin_addr.s_addr = inet_addr(ip);
    rc = Connect(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0)
    {
        close(fd);
        perror("Connect()");
        *err = SOCKET_ERRNO;
    }
    else
    {
        *err = 0;
    }
    return fd;
}

# ifdef USE_TLS_1_3
static int32_t sendEarlyData(ssl_t *ssl)
{
    FILE *fp = NULL;
    unsigned char *earlyDataBuf;
    int32_t earlyDataBufLen, earlyDataLen, maxEarlyData, encodedEarlyDataLen;

    fp = Fopen(g_early_data_file, "r");
    if (!fp)
    {
        psTrace("Failed to open early data file\n");
        return PS_ARG_FAIL;
    }
    /* It is the caller's resposibility to keep track that not too much
       early data is being sent. Data can be sent in multiple records. */
    maxEarlyData = matrixSslGetMaxEarlyData(ssl);

    /* Get writebuf for maximum early data length */
    earlyDataBufLen = matrixSslGetWritebuf(ssl, &earlyDataBuf, maxEarlyData);
    if (earlyDataBufLen <= 0)
    {
        Fclose(fp);
        return PS_FAILURE;
    }
    /* Send only as many bytes as the received write buffer can fit. It might
       be less than requested size in case the fragment size is small */
    maxEarlyData = earlyDataBufLen;
    earlyDataLen = Fread(earlyDataBuf, 1, maxEarlyData, fp);
    if (earlyDataLen <= 0)
    {
        Fclose(fp);
        return PS_FAILURE;
    }
    Fclose(fp);
    encodedEarlyDataLen = matrixSslEncodeWritebuf(ssl, earlyDataLen);
    if (encodedEarlyDataLen <= 0)
    {
        return PS_FAILURE;
    }
    if (matrixSslGetEarlyDataStatus(ssl) != MATRIXSSL_EARLY_DATA_SENT)
    {
        psTrace("Unexpected early data status. Exiting\n");
        return PS_FAILURE;
    }
    return MATRIXSSL_SUCCESS;
}
# endif /* USE_TLS_1_3 */

#else

/******************************************************************************/
/*
    Stub main for compiling without client enabled
 */
int32 main(int32 argc, char **argv)
{
    Printf("USE_CLIENT_SIDE_SSL must be enabled in matrixsslConfig.h at build" \
        " time to run this application\n");
    return EXIT_FAILURE;
}
#endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/
