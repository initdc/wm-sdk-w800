/**
 *      @file    simpleServer.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      Simple MatrixSSL blocking server example.
 *      - TLS 1.2 only
 *      - P-256 and ECDSA only
 *      - Only 1 simultaneous connection.
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

#include "matrixssl/matrixsslApi.h"

# if defined(USE_SERVER_SIDE_SSL) && defined(USE_TLS_1_2) && defined(USE_SECP256R1) && defined(USE_SHA256) && defined(USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

# include <sys/types.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <ctype.h>

/* Key material. */
# include "testkeys/EC/256_EC.h"
# include "testkeys/EC/256_EC_KEY.h"
# include "testkeys/EC/256_EC_CA.h"
# ifdef USE_RSA
#  include "testkeys/RSA/3072_RSA.h"
#  include "testkeys/RSA/3072_RSA_KEY.h"
#  include "testkeys/RSA/2048_RSA_CA.h"
# endif

# ifndef SERVER_PORT
#  define SERVER_PORT 4433
# endif

static const char g_httpResponseHdr[] = "HTTP/1.0 200 OK\r\n"
    "Server: MatrixSSL 4.0.1\r\n"
    "Pragma: no-cache\r\n"
    "Cache-Control: no-cache\r\n"
    "Content-type: text/plain\r\n"
    "Content-length: 9\r\n"
    "\r\n"
    "MatrixSSL";

void cleanup(ssl_t *ssl, sslKeys_t *keys, int fd, int sock_fd);
int load_keys(sslKeys_t *keys);

# ifdef USE_ROT_CRYPTO
#  include "../../crypto-rot/rot/include/api_val.h"
static uint32_t g_longTermAssets[] = { VAL_ASSETID_INVALID,
                                       VAL_ASSETID_INVALID };
#  define IX_ECC 0
#  define IX_RSA 1

/* If enabled, getLongTermPrivAsset shall be called to fetch a
   private key asset ID. If not enabled, a plaintext test key
   shall be used. */
#  define LOAD_PRIVKEY_ASSET

#  ifdef LOAD_PRIVKEY_ASSET
uint32_t getLongTermPrivAsset(int keyType);
extern ValStatus_t psRotAssetFree(ValAssetId_t *asset);
#  endif /* LOAD_PRIVKEY_ASSET */
# endif /* USE_ROT_CRYPTO */

/* Send application data over an established TLS connection. */
static int32_t sendAppData(ssl_t *ssl,
        const unsigned char *data,
        size_t dataLen)
{
    int32_t rc;
    unsigned char *buf;

    psTraceBytes("Sending app data", data, dataLen);
    /* Get pointer to the internal plaintext buffer and fill
       it with the plaintext data. */
    rc = matrixSslGetWritebuf(ssl, &buf, dataLen);
    if (rc < dataLen)
    {
        return PS_FAILURE;
    }
    memcpy(buf, data, dataLen);

    /* Encrypt. */
    rc = matrixSslEncodeWritebuf(ssl, dataLen);
    if (rc < 0)
    {
        return PS_FAILURE;
    }
    /* Ask the main loop to send it over the wire. */
    return MATRIXSSL_REQUEST_SEND;
}

int main(int argc, char **argv)
{
    uint16_t sigAlgs[] = {
        sigalg_ecdsa_secp256r1_sha256,
# ifdef USE_RSA
        sigalg_rsa_pkcs1_sha256
# endif
    };
    int32_t sigAlgsLen = sizeof(sigAlgs)/sizeof(sigAlgs[0]);
    psProtocolVersion_t versions[1];
    sslSessOpts_t opts;
    sslKeys_t *keys = NULL;
    int32_t rc;
    uint32_t len;
    ssl_t *ssl = NULL;
    unsigned char *buf;
    ssize_t nrecv, nsent;
    int fd, sock_fd;
    struct sockaddr_in addr;
    int done_reading;
    size_t file_size_nbytes = 0;
    size_t file_received_nbytes = 0;

    rc = matrixSslOpen();
    if (rc < 0)
    {
        return EXIT_FAILURE;
    }

    rc = matrixSslNewKeys(&keys, NULL);
    if (rc < 0)
    {
        cleanup(ssl, keys, 0, 0);
        return EXIT_FAILURE;
    }

    /* Load key material into 'keys'. The called function is a simple
       wrapper for matrixSslLoadKeysMem. */
    rc = load_keys(keys);
    if (rc < 0)
    {
        cleanup(ssl, keys, 0, 0);
        return EXIT_FAILURE;
    }

    /* Setup session options. */
    Memset(&opts, 0, sizeof(opts)); /* Important. */

    /* Set TLS 1.2 as the protocol version. */
    versions[0] = v_tls_1_2;
    rc = matrixSslSessOptsSetServerTlsVersions(
            &opts,
            versions,
            1);
    if (rc < 0)
    {
        printf("matrixSslSessOptsSetClientTlsVersions failed: %d\n", rc);
        cleanup(ssl, keys, 0, 0);
        return EXIT_FAILURE;
    }

    /* Set supported ECC curves for signatures and key exchange
       Currently, the RoT Edition only supports the P-256 curve. */
    opts.ecFlags = IS_SECP256R1;

    /* Set supported signature algorithms. */
    rc = matrixSslSessOptsSetSigAlgs(
            &opts,
            sigAlgs,
            sigAlgsLen);
    if (rc < 0)
    {
        printf("matrixSslSessOptsSetSigAlgs failed: %d\n", rc);
        cleanup(ssl, keys, 0, 0);
        return EXIT_FAILURE;
    }

    /* Start listening to a TCP port for connections. */
    Memset((char *) &addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short) SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        printf("socket failed: %d\n", fd);
        cleanup(ssl, keys, 0, 0);
        return EXIT_FAILURE;
    }
    rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0)
    {
        printf("bind failed: %d\n", rc);
        cleanup(ssl, keys, fd, 0);
        return EXIT_FAILURE;
    }
    rc = listen(fd, 1);
    if (rc < 0)
    {
        printf("listen failed: %d\n", rc);
        cleanup(ssl, keys, fd, 0);
        return EXIT_FAILURE;
    }
    sock_fd = accept(fd, NULL, NULL);
    if (rc < 0)
    {
        printf("accept failed: %d\n", rc);
        cleanup(ssl, keys, fd, sock_fd);
        return EXIT_FAILURE;
    }
    printf("Received new connection\n");

    /* Create the server TLS session. */
    rc = matrixSslNewServerSession(
            &ssl,
            keys,
            NULL, /* No certCb -> no client auth required. */
            &opts);
    if (rc < 0)
    {
        printf("matrixSslNewServerSession failed: %d\n", rc);
        cleanup(ssl, keys, fd, sock_fd);
        return EXIT_FAILURE;
    }

    done_reading = 0;

    while(!done_reading)
    {
READ_MORE:
        /* Get pointer to buffer where incoming data should be read into. */
        rc = matrixSslGetReadbuf(ssl, &buf);
        if (rc < 0)
        {
            goto out_fail;
        }
        len = rc;

        printf("Got Readbuf of len: %zu\n", len);

        /* Read data from the wire. */
        nrecv = recv(sock_fd, buf, len, 0);
        if (nrecv < 0)
        {
            goto out_fail;
        }
        printf("recv'd %zu bytes\n", nrecv);

decrypt_more:
        /* Ask the TLS library to process the data we read.
           Return code will tell us what to do next. */
        rc = matrixSslReceivedData(
                ssl,
                nrecv,
                &buf,
                &len);
        if (rc < 0)
        {
            goto out_fail;
        }
        else if (rc == MATRIXSSL_RECEIVED_ALERT)
        {
            /* Handle successful connection closure and and alerts caused
               by errors. */
            if (buf[1] == SSL_ALERT_CLOSE_NOTIFY)
            {
                printf("Exiting: received close_notify from peer\n");
                goto out_ok;
            }
            else
            {
                printf("Exiting: received alert\n");
                goto out_fail;
            }
        }
        else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
        {
            printf("Handshake complete\n");
            /* Send app data over the encrypted connection. */
            rc = sendAppData(
                    ssl,
                    (const unsigned char *)g_httpResponseHdr,
                    strlen(g_httpResponseHdr));
            if (rc < 0)
            {
                goto out_fail;
            }
            goto WRITE_MORE;
        }
        else if (rc == MATRIXSSL_REQUEST_SEND)
        {
            /* Handshake messages or an alert have been encoded.
               These need to be sent over the wire. */
            goto WRITE_MORE;
        }
        else if (rc == MATRIXSSL_REQUEST_RECV)
        {
            /* Handshake still in progress. Need more messages
               from the peer. */
            goto READ_MORE;
        }
        else if (rc == MATRIXSSL_APP_DATA)
        {
            /* We received encrypted application data from the peer.
               Just print it out here. */
            unsigned char *buf_begin = buf;

            //psTraceBytes("Decrypted app data", buf, len);
            if (file_size_nbytes > 0)
            {
                file_received_nbytes += len;
            }
            else if ( len > 4)
            {
                if (!Strncmp(buf, "[file size=", strlen("[file size=")))
                {
                    /* Read off the file size. */
                    int i = strlen("[file size=");
                    int j = 0;
                    char len_str[16] = {0};
                    int file_size;

                    while (isdigit(buf[i]))
                    {
                        len_str[j++] = buf[i];
                        i++;
                    }
                    if (buf[i] != ']')
                    {
                        printf("Wrong file header\n");
                        goto out_fail;
                    }
                    i++;

                    file_size = atoi(len_str);
                    file_size_nbytes = file_size;
                    printf("Receiving a file of size: %zu\n", file_size_nbytes);
                    file_received_nbytes = len - i + 1;
                }
            }
            do
            {
                FILE *fp;
                size_t nbytes;

                fp = fopen("app-data.txt", "ab");
                if (!fp)
                {
                    printf("Could not open file: app-data.txt\n");
                }
                nbytes = fwrite(buf, 1, len, fp);
                if (nbytes != len)
                {
                    printf("fwrite failed\n");
                }
                fclose(fp);

                /* Inform the TLS library that we "processed" the data. */
                rc = matrixSslProcessedData(
                        ssl,
                        &buf,
                        &len);
                if (rc < 0)
                {
                    goto out_fail;
                }
                printf("matrixSslProcessedData rc: %d\n", rc);
            } while (rc == MATRIXSSL_APP_DATA
                    || rc == MATRIXSSL_RECEIVED_ALERT);

            if (rc == MATRIXSSL_REQUEST_RECV ||
                    file_received_nbytes < file_size_nbytes)
            {
                printf("Received %zu of %zu file bytes\n",
                        file_received_nbytes, file_size_nbytes);
                goto READ_MORE;
            }

            /* Send our HTTP response over the encrypted connection. */
            rc = sendAppData(
                    ssl,
                    (const unsigned char *)g_httpResponseHdr,
                    strlen(g_httpResponseHdr));
            if (rc < 0)
            {
                goto out_fail;
            }
            /* This test ends after we have sent our response. */
            done_reading = 1;
        }

    WRITE_MORE:
        /* Get pointer to the output data to send. */
        rc = matrixSslGetOutdata(ssl, &buf);
        while (rc > 0)
        {
            len = rc;

            /* Send it over the wire. */
            nsent = send(sock_fd, buf, len, 0);
            if (nsent <= 0)
            {
                printf("send() failed\n");
                goto out_fail;
            }

            /* Inform the TLS library how much we managed to send.
               Return code will tell us of what to do next. */
            rc = matrixSslSentData(ssl, nsent);
            if (rc < 0)
            {
                printf("matrixSslSentData failed: %d\n", rc);
                goto out_fail;
            }
            else if (rc == MATRIXSSL_REQUEST_CLOSE)
            {
                printf("Closing connection\n");
                goto out_ok;
            }
            else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE)
            {
                printf("Handshake complete\n");
                /* Try to receive encrypted app data from the client. */
                goto READ_MORE;
            }
            /* rc == PS_SUCCESS. */

            /* More data to send? */
            rc = matrixSslGetOutdata(ssl, &buf);
        }
    }

out_ok:
    rc = PS_SUCCESS;

out_fail:
    cleanup(ssl, keys, fd, sock_fd);

    if (rc == PS_SUCCESS)
    {
        return 0;
    }
    else
    {
        return EXIT_FAILURE;
    }
}

# ifdef LOAD_PRIVKEY_ASSET
extern ValStatus_t psRotAssetFree(ValAssetId_t *asset);
# endif

void cleanup(ssl_t *ssl, sslKeys_t *keys, int fd, int sock_fd)
{

    if (ssl)
    {
        matrixSslDeleteSession(ssl);
    }
    if (keys)
    {
        matrixSslDeleteKeys(keys);
    }
    if (fd != 0)
    {
        close(fd);
    }
    if (sock_fd != 0)
    {
        close(sock_fd);
    }

# ifdef LOAD_PRIVKEY_ASSET
    psRotAssetFree(&g_longTermAssets[IX_ECC]);
    psRotAssetFree(&g_longTermAssets[IX_RSA]);
# endif

    matrixSslClose();
}

/* Load certificate and key material.
   When using RoT, the private keys can also be provided in the form
   of a long term asset IDs. */
int load_keys(sslKeys_t *keys)
{
# ifdef LOAD_PRIVKEY_ASSET
    ValAssetId_t privAssetEcdsa = VAL_ASSETID_INVALID;
    ValAssetId_t privAssetRsa = VAL_ASSETID_INVALID;
# else
    uint32_t privAssetEcdsa = 0;
    uint32_t privAssetRsa = 0;
# endif
    int32_t rc;
    matrixSslLoadKeysOpts_t keyOpts;

    (void)privAssetRsa;

# ifdef LOAD_PRIVKEY_ASSET
    privAssetEcdsa = getLongTermPrivAsset(PS_ECC);
#  ifdef USE_RSA
    privAssetRsa = getLongTermPrivAsset(PS_RSA);
#  endif /* USE_RSA */
# endif /* LOAD_PRIVKEY_ASSET */

    memset(&keyOpts, 0, sizeof(keyOpts));

    keyOpts.privAssetCurveId = IANA_SECP256R1;
    keyOpts.key_type = PS_ECC;
    keyOpts.privAsset = privAssetEcdsa;
    rc = matrixSslLoadKeysMem(
            keys,
            EC256,
            EC256_SIZE,
            EC256KEY,
            EC256KEY_SIZE,
            EC256CA,
            EC256CA_SIZE,
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMemRot failed: %d\n", rc);
        return PS_FAILURE;
    }

    /* If RSA is enabled in the compile-time config, also load
       RSA keys and CA certs. */
#  ifdef USE_RSA
    /* For slightly better test coverage, we use the 3072-bit RSA
       test key here, while simpleClient uses a 2048-bit one. */
    keyOpts.privAssetModulusNBytes = 384;
    keyOpts.key_type = PS_RSA;
    keyOpts.privAsset = privAssetRsa;
    rc = matrixSslLoadKeysMem(
            keys,
            RSA3072,
            RSA3072_SIZE,
            RSA3072KEY,
            RSA3072KEY_SIZE,
            RSA2048CA,
            RSA2048CA_SIZE,
            &keyOpts);
    if (rc < 0)
    {
        printf("matrixSslLoadKeysMemRot failed: %d\n", rc);
        return PS_FAILURE;
    }
#  endif

    return PS_SUCCESS;
}

# ifdef LOAD_PRIVKEY_ASSET
/* Return the RoT asset ID of the long-term private key asset. */
uint32_t getLongTermPrivAsset(int keyType)
{
    int32_t rc;
    psPubKey_t key;
    const psEccCurve_t *curve;
    ValAssetId_t asset;

    /*
      Test implementation: simply load the key from plaintext.
*/
    switch (keyType)
    {
    case PS_ECC:
        rc = getEccParamById(IANA_SECP256R1, &curve);
        if (rc != PS_SUCCESS)
        {
            return VAL_ASSETID_INVALID;
        }
        key.key.ecc.rotKeyType = ps_ecc_key_type_ecdsa;
        rc = psEccParsePrivKey(
                NULL,
                EC256KEY,
                EC256KEY_SIZE,
                &key.key.ecc,
                curve);
        if (rc != PS_SUCCESS)
        {
            return VAL_ASSETID_INVALID;
        }

        asset = key.key.ecc.privAsset;
        g_longTermAssets[IX_ECC] = asset;

        /* Clear everything else from the key, except the asset ID. */
        key.key.ecc.longTermPrivAsset = PS_TRUE;
        psEccClearKey(&key.key.ecc);

        break;
# ifdef USE_RSA
    case PS_RSA:
        rc = psRsaParsePkcs1PrivKey(
                NULL,
                RSA3072KEY,
                RSA3072KEY_SIZE,
                &key.key.rsa);
        if (rc != PS_SUCCESS)
        {
            return VAL_ASSETID_INVALID;
        }
        asset = key.key.rsa.privSigAsset;
        g_longTermAssets[IX_RSA] = asset;

        /* Clear everything else from the key, except the asset ID. */
        key.key.rsa.longTermPrivAsset = PS_TRUE;
        psRsaClearKey(&key.key.rsa);

        break;
# endif
    default:
        printf("Unsupported key type\n");
        return VAL_ASSETID_INVALID;
    }

    return asset;
}
# endif /* # LOAD_PRIVKEY_ASSET */

# else
int main(int argc, char **argv)
{
    printf("This test requires USE_SERVER_SIDE_SSL, USE_TLS_1_2, "\
            "USE_SECP256R1, USE_SHA256 and " \
            "USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.\n");
    return 1;
}
# endif /* USE_SERVER_SIDE_SSL && USE_TLS_1_2 && USE_SECP256R1 && USE_SHA256 && USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
