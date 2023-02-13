#include "wm_config.h"

#if TLS_CONFIG_SERVER_SIDE_SSL

#include "HTTPClientWrapper.h"
#include "wm_ssl_server.h"
#include "lwip/arch.h"
#include "wm_sockets.h"


#if TLS_CONFIG_USE_POLARSSL

#elif TLS_CONFIG_USE_MBEDTLS
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

typedef struct {
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
} __tls_ssl_key_t;

static int  g_proto;

#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL 3

static void ssl_server_debug( void *ctx, int level,
                              const char *file, int line,
                              const char *str )
{
    ((void) level);

    mbedtls_printf( "%s", str );
}
#endif

int tls_ssl_server_init(void * arg)
{
	g_proto = (int)arg;

    return 0;
}


int tls_ssl_server_load_keys(tls_ssl_key_t **keys, unsigned char *certBuf,
			int32 certLen, unsigned char *privBuf, int32 privLen,
			unsigned char *CAbuf, int32 CAlen, int keyType)
{
	int ret;
	__tls_ssl_key_t *ssl_server_key = NULL;

    ssl_server_key = tls_mem_alloc(sizeof(__tls_ssl_key_t));
    if (!ssl_server_key)
        return -1;

    memset(ssl_server_key, 0, sizeof(__tls_ssl_key_t));

    mbedtls_x509_crt_init( &ssl_server_key->srvcert );
    mbedtls_pk_init( &ssl_server_key->pkey );

    //mbedtls_printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse( &ssl_server_key->srvcert, (const unsigned char *) certBuf, certLen );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %x\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &ssl_server_key->srvcert, (const unsigned char *) CAbuf, CAlen );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %x\n\n", ret );
        goto exit;
    }

    ret =  mbedtls_pk_parse_key( &ssl_server_key->pkey, (const unsigned char *) privBuf, privLen, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %x\n\n", ret );
        goto exit;
    }

    //mbedtls_printf( " ok\n" );

    if (keys) *keys = ssl_server_key;

    return 0;

exit:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_x509_crt_free( &ssl_server_key->srvcert );
    mbedtls_pk_free( &ssl_server_key->pkey );

    tls_mem_free(ssl_server_key);
    ssl_server_key = NULL;

    return -2;
}

int tls_ssl_server_handshake(tls_ssl_t **ssl_p, int fd, tls_ssl_key_t *keys)
{
    int ret;
	const char *pers = "wm_ssls";
	tls_ssl_t *ssl_server_ctx = NULL;

    ssl_server_ctx = tls_mem_alloc(sizeof(tls_ssl_t));
    if (!ssl_server_ctx)
        return -1;

    memset(ssl_server_ctx, 0, sizeof(tls_ssl_t));

    mbedtls_ssl_init( &ssl_server_ctx->ssl );
    mbedtls_ssl_config_init( &ssl_server_ctx->conf );
    mbedtls_entropy_init( &ssl_server_ctx->entropy );
    mbedtls_ctr_drbg_init( &ssl_server_ctx->ctr_drbg );
    mbedtls_net_init( &ssl_server_ctx->server_fd );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    //mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ssl_server_ctx->ctr_drbg, mbedtls_entropy_func, &ssl_server_ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %x\n", ret );
        goto exit;
    }

    //mbedtls_printf( " ok\n" );

    //mbedtls_printf( "  . Setting up the SSL data...." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &ssl_server_ctx->conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %x\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &ssl_server_ctx->conf, mbedtls_ctr_drbg_random, &ssl_server_ctx->ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &ssl_server_ctx->conf, ssl_server_debug, stdout );
#endif

    mbedtls_ssl_conf_ca_chain( &ssl_server_ctx->conf, ((__tls_ssl_key_t *)keys)->srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &ssl_server_ctx->conf, &((__tls_ssl_key_t *)keys)->srvcert, &((__tls_ssl_key_t *)keys)->pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %x\n\n", ret );
        goto exit;
    }

    //mbedtls_ssl_conf_min_version( &ssl_server_ctx->conf, g_proto, g_proto );
    //mbedtls_ssl_conf_max_version( &ssl_server_ctx->conf, g_proto, g_proto );

    if( ( ret = mbedtls_ssl_setup( &ssl_server_ctx->ssl, &ssl_server_ctx->conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %x\n\n", ret );
        goto exit;
    }

    //mbedtls_printf( " ok\n" );

    mbedtls_net_free( &ssl_server_ctx->server_fd );
	mbedtls_ssl_session_reset( &ssl_server_ctx->ssl );

    ssl_server_ctx->server_fd.fd = fd;
    mbedtls_ssl_set_bio( &ssl_server_ctx->ssl, &ssl_server_ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

	//mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &ssl_server_ctx->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %x\n\n", ret );
#ifdef MBEDTLS_ERROR_C
            char error_buf[100];
            mbedtls_strerror( ret, error_buf, 100 );
            mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
#endif
            return ret;
        }
    }

    //mbedtls_printf( " ok\n" );

    if (ssl_p) *ssl_p = ssl_server_ctx;

    return 0;

exit:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_ssl_free( &ssl_server_ctx->ssl );
    mbedtls_ssl_config_free( &ssl_server_ctx->conf );
    mbedtls_ctr_drbg_free( &ssl_server_ctx->ctr_drbg );
    mbedtls_entropy_free( &ssl_server_ctx->entropy );

    tls_mem_free(ssl_server_ctx);

    return -2;
}

int tls_ssl_server_send(tls_ssl_t *ssl, int s,char *sndbuf, int len,int flags)
{
    int ret;

    while( ( ret = mbedtls_ssl_write( &ssl->ssl, (const unsigned char *)sndbuf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            mbedtls_printf( " failed\n  ! peer closed the connection\n\n" );
            break;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            break;
        }
    }

    return ret;
}

int tls_ssl_server_recv(tls_ssl_t *ssl,int s,char *buf, int len,int flags)
{
    int ret;

    do
    {
        ret = mbedtls_ssl_read( &ssl->ssl, (unsigned char *)buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( " connection was reset by peer\n" );
                    break;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        if( ret > 0 )
            break;
    } while( 1 );

    return ret;
}

void tls_ssl_server_close_conn(tls_ssl_t *ssl, int s)
{
    int ret;

	//mbedtls_printf( "  . Closing the connection..." );

    while( ( ret = mbedtls_ssl_close_notify( &ssl->ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_close_notify returned %x\n\n", ret );
            return;
        }
    }

    //mbedtls_printf( " ok\n" );

    mbedtls_net_free( &ssl->server_fd );
	mbedtls_ssl_free( &ssl->ssl );
    mbedtls_ssl_config_free( &ssl->conf );
    mbedtls_ctr_drbg_free( &ssl->ctr_drbg );
    mbedtls_entropy_free( &ssl->entropy );

    tls_mem_free(ssl);
}

int tls_ssl_server_close(tls_ssl_key_t * keys)
{
    if (keys)
    {
        mbedtls_pk_free( &((__tls_ssl_key_t *)keys)->pkey );
        mbedtls_x509_crt_free( &((__tls_ssl_key_t *)keys)->srvcert );

        tls_mem_free(keys);
    }

    return 0;
}

#else
#include "core/coreApi.h"
#include "matrixssl/matrixssllib.h"
#include "matrixssl/matrixsslApi.h"

#include "cryptoApi.h"

static int				g_proto;

#define SOCKET_ERRNO	errno
#define SSL_TIMEOUT			245000
#define SELECT_TIME			1000

#define	GOTO_SANITY			32	/* Must be <= 255 */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET	-1
#endif


#ifdef USE_STATELESS_SESSION_TICKETS

static unsigned char sessTicketSymKey[32] = {
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08};

static unsigned char sessTicketMacKey[32] = {
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08};
int32 sessTicketCb(void *keys, unsigned char name[16], short found)
{
	if (found) {
		/* Was already cached */
		return PS_SUCCESS;
	}
	/* Example.  If name was located, the keys would be loaded this way */
	return matrixSslLoadSessionTicketKeys((sslKeys_t*)keys, name,
			sessTicketSymKey, 32, sessTicketMacKey, 32);
}
#endif

#ifdef USE_CLIENT_AUTH
#ifndef USE_ONLY_PSK_CIPHER_SUITE
/******************************************************************************/
/*
	Example callback to show possiblie outcomes of certificate validation.
	If this callback is not registered in matrixSslNewServerSession
	the connection will be accepted or closed based on the alert value.
 */
#define ALLOW_ANON_CONNECTIONS	1
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	psX509Cert_t	*next;
		
	/* Did we even find a CA that issued the certificate? */
	if (alert == SSL_ALERT_UNKNOWN_CA) {
			/* Example to allow anonymous connections based on a define */
		if (ALLOW_ANON_CONNECTIONS) {
			_psTraceStr("Allowing anonymous connection for: %s.\n",
				cert->subject.commonName);
			return SSL_ALLOW_ANON_CONNECTION;
		}
		_psTrace("ERROR: No matching CA found.  Terminating connection\n");
	}

	/* Test if the server certificate didn't match the name passed to
		expectedName in matrixSslNewClientSession */
	if (alert == SSL_ALERT_CERTIFICATE_UNKNOWN) {
		_psTraceStr("ERROR: %s not found in cert subject names\n",
			ssl->expectedName);
	}
	
	if (alert == SSL_ALERT_CERTIFICATE_EXPIRED) {
		_psTrace("WARNING: Certificate date window validation not implemented\n");
		alert = 0;
	}
	
	if (alert == SSL_ALERT_ILLEGAL_PARAMETER) {
		_psTrace("ERROR: Found correct CA but X.509 extension details are wrong\n");
	}
	
	/* Key usage related problems */
	next = cert;
	while (next) {
		if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION) {
			if (cert->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG) {
				_psTrace("CA keyUsage extension doesn't allow cert signing\n");
			}
			if (cert->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG) {
				_psTrace("Cert extendedKeyUsage extension doesn't allow TLS\n");
			}
		}
		next = next->next;
	}
	
	if (alert == SSL_ALERT_BAD_CERTIFICATE) {
		/* Should never let a connection happen if this is set.  There was
			either a problem in the presented chain or in the final CA test */
		_psTrace("ERROR: Problem in certificate validation.  Exiting.\n");	
	}

	
	if (alert == 0) _psTraceStr("SUCCESS: Validated cert for: %s.\n",
		cert->subject.commonName);
	
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return alert; 
}
#else
#define certCb NULL /* Only PSK suites so no certificates are used */
#endif
#else
#define certCb NULL /* No client auth so no possibility of cert cback */
#endif /* USE_CLIENT_AUTH */


int tls_ssl_server_init(void * arg)
{
	int rc;
	int proto_ver = (int)arg;
	switch (proto_ver) {
		case 0:
			g_proto = SSL_FLAGS_SSLV3;
			break;
		case 1:
			g_proto = SSL_FLAGS_TLS_1_0;
			break;
		case 2:
			g_proto = SSL_FLAGS_TLS_1_1;
			break;
		case 3:
			g_proto = SSL_FLAGS_TLS_1_2;
			break;
		default:
			g_proto = SSL_FLAGS_TLS_1_0;
			break;
	}
	
	if ((rc = matrixSslOpen()) < 0) {
		_psTrace("MatrixSSL library init failure.  Exiting\n");
		return rc;
	}
	return 0;
}


int tls_ssl_server_load_keys(tls_ssl_key_t **keys, unsigned char *certBuf,
			int32 certLen, unsigned char *privBuf, int32 privLen,
			unsigned char *CAbuf, int32 CAlen, int keyType)
{
	int rc;
#ifdef USE_STATELESS_SESSION_TICKETS
		unsigned char	randKey[16];
#endif 

	if (matrixSslNewKeys(keys, NULL) < 0) {
		_psTrace("MatrixSSL library key init failure.  Exiting\n");
		return -1;
	}
#ifdef USE_STATELESS_SESSION_TICKETS
	matrixSslSetSessionTicketCallback(*keys, sessTicketCb);
	psGetEntropy(randKey, 16, NULL);
	if (matrixSslLoadSessionTicketKeys(*keys, randKey,
			sessTicketSymKey, 32, sessTicketMacKey, 32) < 0) {
		_psTrace("Error loading session ticket encryption key\n");
	}
#endif
#ifdef USE_RSA
	if(KEY_RSA == keyType)
	{
		if ((rc = matrixSslLoadRsaKeysMem(*keys, certBuf, certLen, privBuf, privLen,
					CAbuf, CAlen)) < 0) {
			_psTrace("No certificate material loaded.  Exiting\n");
			matrixSslDeleteKeys(*keys);
		}
		return rc;
	}
#endif
#ifdef USE_ECC
	if(KEY_ECC == keyType)
	{
		if ((rc = matrixSslLoadEcKeysMem(*keys, certBuf, certLen, privBuf, privLen,
					CAbuf, CAlen)) < 0) {
			_psTrace("No certificate material loaded.  Exiting\n");
			matrixSslDeleteKeys(*keys);
		}
		return rc;
	}
#endif
	return PS_ARG_FAIL;
}

int tls_ssl_server_handshake(tls_ssl_t **ssl_p, int fd, tls_ssl_key_t *keys)
{
	int rc, len, transferred, val;;
	tls_ssl_t			*ssl;
	unsigned char	rSanity, wSanity;
	psTime_t now;
	psTime_t time;
	fd_set			readfd, writefd;
	struct timeval	timeout;
	int			maxfd;
	
	unsigned char	*buf;

	if ((rc = matrixSslNewServerSession(&ssl, keys, certCb,
			g_proto)) < 0) {
		_psTraceInt("matrixSslNewServerSession rc %d\n", rc);
		return rc;
	}
	memset(&time, 0, sizeof(psTime_t));
Start:
	maxfd = INVALID_SOCKET;
	timeout.tv_sec = SELECT_TIME / 1000;
	timeout.tv_usec = (SELECT_TIME % 1000) * 1000;
	FD_ZERO(&readfd);
	FD_ZERO(&writefd);
	
/*	
	Check timeouts and set readfd and writefd for connections as required.
	We use connsTemp so that removal on error from the active iteration list
		doesn't interfere with list traversal 
 */
	psGetTime(&now, NULL);
	do
	{
		/*	If timeout != 0 msec ith no new data, close */
		if ((time.tv_sec > 0 || time.tv_usec > 0) && (psDiffMsecs(time, now, NULL) > (int32)SSL_TIMEOUT)) {
			rc = PS_TIMEOUT_FAIL;
			goto L_EXIT;
		}
		/* Always select for read */
		FD_SET(fd, &readfd);
		/* Select for write if there's pending write data or connection */
		if (matrixSslGetOutdata(ssl, NULL) > 0) {
			FD_SET(fd, &writefd);
		}
		/* Housekeeping for maxsock in select call */
		if (fd > maxfd) {
			maxfd = fd;
		}
	}
	while(0);
	//printf("select start timeout %d\n", timeout.tv_sec);
	/* Use select to check for events on the sockets */
	if ((val = select(maxfd + 1, &readfd, &writefd, NULL, &timeout)) <= 0) {
		/* Select timeout */
		if (val == 0) {
			rc = PS_TIMEOUT_FAIL;
			goto L_EXIT;
		}
		/* Woke due to interrupt */
		if (SOCKET_ERRNO == EINTR) {
			rc = PS_TIMEOUT_FAIL;
			goto L_EXIT;
		}
		/* Should attempt to handle more errnos, such as EBADF */
		rc = PS_PLATFORM_FAIL;
		goto L_EXIT;
	}
	
	rSanity = wSanity = 0;
/*
	See if there's pending data to send on this connection
	We could use FD_ISSET, but this is more reliable for the current
		state of data to send.
*/
WRITE_MORE:
	if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
		/* Could get a EWOULDBLOCK since we don't check FD_ISSET */
		transferred = send(fd, buf, len, MSG_DONTWAIT);
		psTraceIntInfo("send %d\n", transferred);
		if (transferred <= 0) {
			if (SOCKET_ERRNO != EWOULDBLOCK) {
				rc = PS_PLATFORM_FAIL;
				goto L_EXIT;
			}
		} else {
			/* Indicate that we've written > 0 bytes of data */
			if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
				rc = PS_ARG_FAIL;
				goto L_EXIT;
			}
			if (rc == MATRIXSSL_REQUEST_CLOSE) {
				rc = MATRIXSSL_REQUEST_CLOSE;
				goto L_EXIT;
			} else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
				psTraceInfo("rc is MATRIXSSL_HANDSHAKE_COMPLETE\n");
				/* If the protocol is server initiated, send data here */
#ifdef ENABLE_FALSE_START					
				/* OR this could be a Chrome browser using 
					FALSE_START and the application data is already
					waiting in our inbuf for processing */
				if ((rc = matrixSslReceivedData(ssl, 0,
							&buf, (uint32*)&len)) < 0) {
					goto L_EXIT;
				}
				if (rc > 0) { /* There was leftover data */
					goto PROCESS_MORE;
				}
#endif /* ENABLE_FALSE_START  */
				rc = PS_SUCCESS;
				goto L_EXIT;
			}
			/* Update activity time */
			psGetTime(&time, NULL);
			/* Try to send again if more data to send */
			if (rc == MATRIXSSL_REQUEST_SEND || transferred < len) {
				if (wSanity++ < GOTO_SANITY) goto WRITE_MORE;
			}

			goto Start;
		}
	} 
	else if (len < 0) {
		rc = PS_ARG_FAIL;
		goto L_EXIT;
	}
	
/*
	Check the file descriptor returned from select to see if the connection
	has data to be read
*/
	if (FD_ISSET(fd, &readfd)) {
READ_MORE:
		/* Get the ssl buffer and how much data it can accept */
		/* Note 0 is a return failure, unlike with matrixSslGetOutdata */
		if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0) {
			rc = PS_ARG_FAIL;
			goto L_EXIT;
		}
		if ((transferred = recv(fd, buf, len, MSG_DONTWAIT)) < 0) {
			psTraceIntInfo("recv %d\n", transferred);
			/* We could get EWOULDBLOCK despite the FD_ISSET on goto  */
			if (SOCKET_ERRNO != EWOULDBLOCK) {
				rc = PS_PLATFORM_FAIL;
				goto L_EXIT;
			}
		}
		psTraceIntInfo("recv %d\n", transferred);
		/* If EOF, remote socket closed. This is semi-normal closure.
		   Officially, we should close on closure alert. */
		if (transferred == 0) {
/*				psTraceIntInfo("Closing connection %d on EOF\n", fd); */
			rc = PS_FAILURE;
			goto L_EXIT;
		}
/*
		Notify SSL state machine that we've received more data into the
		ssl buffer retreived with matrixSslGetReadbuf.
*/
		if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &buf, 
										(uint32*)&len)) < 0) {
			psTraceIntInfo("matrixSslReceivedData rc %d\n", rc);
			goto L_EXIT;
		}
		psTraceIntInfo("matrixSslReceivedData rc %d\n", rc);
		/* Update activity time */
		psGetTime(&time, NULL);
		
PROCESS_MORE:
		/* Process any incoming plaintext application data */
		switch (rc) {
			case MATRIXSSL_HANDSHAKE_COMPLETE:
				/* If the protocol is server initiated, send data here */
				rc = PS_SUCCESS;
				goto L_EXIT;
			case MATRIXSSL_APP_DATA:
			case MATRIXSSL_APP_DATA_COMPRESSED:
				if(len > 0){
					psTraceStrInfo("app data: %s\n", (char*)buf);
					ssl->lastData = buf;
					ssl->lastDataLen = len;
					ssl->lastDataOffset = 0;
					rc = PS_SUCCESS;
					goto L_EXIT;
				}
				/* We processed a partial HTTP message 
				if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
					goto READ_MORE;
				}
				goto PROCESS_MORE;*/
			case MATRIXSSL_REQUEST_SEND:
				/* Prevent us from reading again after the write,
				 although that wouldn't be the end of the world */
				FD_CLR(fd, &readfd);
				if (wSanity++ < GOTO_SANITY) goto WRITE_MORE;
				break;
			case MATRIXSSL_REQUEST_RECV:
				if (rSanity++ < GOTO_SANITY) goto READ_MORE; 
				break;
			case MATRIXSSL_RECEIVED_ALERT:
				/* The first byte of the buffer is the level */
				/* The second byte is the description */
				if (*buf == SSL_ALERT_LEVEL_FATAL) {
					psTraceIntInfo("Fatal alert: %d, closing connection.\n", 
								*(buf + 1));
					rc = PS_PROTOCOL_FAIL;
					goto L_EXIT;
				}
				/* Closure alert is normal (and best) way to close */
				if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
					rc = PS_FAILURE;
					goto L_EXIT;
				}
				psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
				if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
					/* No more data in buffer. Might as well read for more. */
					goto READ_MORE;
				}
				goto PROCESS_MORE;

			default:
				/* If rc <= 0 we fall here */
				rc = PS_PROTOCOL_FAIL;
				goto L_EXIT;
		}
		/* Always try to read more if we processed some data */
		if (rSanity++ < GOTO_SANITY) goto READ_MORE;
	} /*  readfd handling */
L_EXIT:
	if(rc)
	{
		matrixSslDeleteSession(ssl);
	}
	else
	{
		*ssl_p = ssl;
	}
	return rc;
}
int tls_ssl_server_send(tls_ssl_t *ssl, int s,char *sndbuf, int len,int flags)
{
	return HTTPWrapperSSLSend(ssl, s, sndbuf, len, flags);
}
int tls_ssl_server_recv(tls_ssl_t *ssl,int s,char *buf, int len,int flags)
{
	return HTTPWrapperSSLRecv(ssl, s, buf, len, flags);
}
void tls_ssl_server_close_conn(tls_ssl_t *ssl, int s)
{
	unsigned char	*buf;
	int32			len;
#if 1	
	/* Quick attempt to send a closure alert, don't worry about failure */
	if (matrixSslEncodeClosureAlert(ssl) >= 0) {
		if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
			if ((len = send(s, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(ssl, len);
			}
		}
	}
#endif
	matrixSslDeleteSession(ssl);
}

int tls_ssl_server_close(tls_ssl_key_t * keys)
{
	if(keys)
	{
		matrixSslDeleteKeys(keys);
	}
	matrixSslClose();
    return 0;
}

#endif

#endif

