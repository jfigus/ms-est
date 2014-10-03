/*
Copyright (c) 2014 by John Foley, All rights reserved.

This file is part of ms-est.

ms-est is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ms-est is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ms-est.  If not, see <http://www.gnu.org/licenses/>.
*/

// estserver.cpp : Defines the entry point for the console application.
//
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <est.h>
#include "ca_link.h"


#pragma comment(lib, "Ws2_32.lib")
#define ERRNO   GetLastError()

#define EST_PORT 8085
#define EST_REALM "estserver"
#define EST_TRUSTED_CERTS "trustedcerts.pem"
#define EST_SERVER_CERT "estservercert.pem"
#define EST_SERVER_KEY "estserverkey.pem"
#define MAX_UID_PWD 200

/*
 * We use a single EST context for the server
 */
EST_CTX *ctx;

unsigned char *trustcerts = NULL;
int trustcerts_len = 0;


static int read_binary_file (char *filename, unsigned char **contents) 
{
	FILE *fp;
	int len;

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Unable to open %s for reading\n", filename);
		return -1;
	}

	/*
	 * Determine file size
	 */
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*contents = (unsigned char*)malloc(len + 1);
	if (!*contents) {
		fprintf(stderr, "malloc failed\n");
		fclose(fp);
		return -2;
	}

	if (1 != fread(*contents, len, 1, fp)) {
		fprintf(stderr, "fread failed\n");
		fclose(fp);
		return -3;
	}

	/*
	 * Add null terminator
	 */
	*(*contents+len) = 0x0;

	fclose(fp);
	return (len);
}

/*
 * This callback is invoked by libest when the user's HTTP credentials
 * need to be authenticated.  For this prototype we'll simply authenticate
 * the user against the local windows account database.  Note, we've hard-coded
 * the domain name, which will prevent the user from being authenticated against
 * an AD domain controller.  Only HTTP basic authentication is implemented here.
 * Support for digest auth is not included.
 */
static int process_http_auth (
	EST_CTX *ctx,
	EST_HTTP_AUTH_HDR *ah, 
	X509 *peer_cert,
	void *app_data)
{
	PVOID myHandle;
	PHANDLE sth = (PHANDLE)&myHandle;
	BOOL rv;
	wchar_t user[MAX_UID_PWD];
	wchar_t pass[MAX_UID_PWD];

	mbstowcs(user, ah->user, MAX_UID_PWD);
	mbstowcs(pass, ah->pwd, MAX_UID_PWD);
	
	//FIXME: the domain name is hard-coded to ".", which means the user
	//       can only be authenticated against the local account database on the server.
	rv = LogonUser(user, L".", pass, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, sth);
	if (rv == false) {
		fprintf(stderr, "Windows logon failed: %d\n", GetLastError());
		return 0;
	} else {
		return 1;
	}
}

/*
 * This is a callback used by libest when a PCKS10 CSR needs to be
 * sent to the CA.
 */
static int process_pkcs10_enrollment (
	unsigned char *pkcs10, int p10_len,
	unsigned char **pkcs7, int *pkcs7_len,
	char *user_id, X509 *peer_cert,
	void *app_data)
{
	X509_REQ *req = NULL;
	BIO *b64;
	BIO *in = NULL;
	BIO *pem_bio = NULL;
	BUF_MEM *bptr = NULL;
	unsigned char *rv;
	char *raw;

	/* the cert request comes in as base64 encoded DER */
	b64 = BIO_new(BIO_f_base64());
	in = BIO_new_mem_buf(pkcs10, p10_len);
	in = BIO_push(b64, in);
	req = d2i_X509_REQ_bio(in, NULL);
	if (req == NULL) return NULL;

	/* now write it as a PEM cert request */
	pem_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ_NEW(pem_bio, req);
	BIO_flush(pem_bio);
	BIO_get_mem_ptr(pem_bio, &bptr);
	
	if (bptr->length > 0) {
		raw = (char *)malloc(bptr->length);
		memcpy(raw, bptr->data, bptr->length);
		/* Ask the CA to issue a new cert for this CSR */
		rv =  (unsigned char *)(ca_simple_enroll((const char *)raw, bptr->length, pkcs7_len));
	}
	BIO_free_all(in);
	BIO_free_all(pem_bio);

	//FIXME - add sanity check on pkcs7_len
	*pkcs7 = (unsigned char*)malloc(*pkcs7_len);
	if (!*pkcs7) {
		fprintf(stderr, "malloc failure\n");
		return (EST_ERR_MALLOC);
	}
	memcpy(*pkcs7, rv, *pkcs7_len);

	return EST_ERR_NONE;
}
			

static void init_est()
{
	EST_ERROR rv;
	X509 *est_cert;
	EVP_PKEY *est_key;
	BIO *certin, *keyin;

	est_apps_startup();

	/*
	 * read in the trust anchor
	 */
	trustcerts_len = read_binary_file(EST_TRUSTED_CERTS, &trustcerts);
	if (trustcerts_len <= 0) {
		fprintf(stderr, "Unable to read trusted certs file: %s\n", EST_TRUSTED_CERTS);
		exit(1);
	}

	/*
	 * read in the server's certificate to use for TLS connections from the clients
	 */
	certin = BIO_new(BIO_s_file_internal());
	if (BIO_read_filename(certin, EST_SERVER_CERT) <= 0) {
		fprintf(stderr, "Unable to read server cert: %s\n", EST_SERVER_CERT);
		exit(1);
	}
	est_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
	if (est_cert == NULL) {
		fprintf(stderr, "PEM decoding of server cert failed: %s\n", EST_SERVER_CERT);
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	BIO_free(certin);

	/*
	 * read in the server's private key to use for TLS connections from the clients
	 * FIXME: the private key must not be password protected
	 */
	keyin = BIO_new(BIO_s_file_internal());
	if (BIO_read_filename(keyin, EST_SERVER_KEY) <= 0) {
		fprintf(stderr, "Unable to read server private key: %s\n", EST_SERVER_KEY);
		exit(1);
	}
	est_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
	if (est_key == NULL) {
		fprintf(stderr, "PEM decoding of server private key failed: %s\n", EST_SERVER_KEY);
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	BIO_free(keyin);

	est_init_logger(EST_LOG_LVL_INFO, NULL);

	/*
	 * Initialize an EST context using libest
	 */
	ctx = est_server_init(
		trustcerts, trustcerts_len,
		trustcerts, trustcerts_len,
		EST_CERT_FORMAT_PEM,
		EST_REALM,
		est_cert, est_key);
	if (!ctx) {
		fprintf(stderr, "est_server_init failed\n");
		exit(1);
	}

	/*
	 * Configure the callbacks that libest requires
	 */
	if (est_set_ca_enroll_cb(ctx, &process_pkcs10_enrollment)) {
		fprintf(stderr, "Unable to set enroll CB\n");
		exit(1);
	}
	if (est_set_ca_reenroll_cb(ctx, &process_pkcs10_enrollment)) {
		fprintf(stderr, "Unable to set reenroll CB\n");
		exit(1);
	}
	if (est_set_http_auth_cb(ctx, &process_http_auth)) {
		fprintf(stderr, "Unable to set HTTP auth CB\n");
		exit(1);
	}

	/*
	 * We'll disable PoP to allow for less restrictive use since this is
	 * just a prototype.
	 */
	est_server_disable_pop(ctx);

	//FIXME - set DH parms

	/*
	 * Start the EST server
	 */
	rv = est_server_start(ctx);
	if (rv != EST_ERR_NONE) {
		fprintf(stderr, "Unable to start EST server: %d\n", rv);
		exit(1);
	}
}

static void shutdown_est ()
{
	est_server_stop(ctx);
	est_destroy(ctx);
	if (trustcerts) free(trustcerts);
	est_apps_shutdown();
}

/*
 * This routine is the entry point for handling a new
 * incoming request on the EST listenting socket.
 */
static void process_socket (int fd)
{
	est_server_handle_request(ctx, fd);
	closesocket(fd);
}


int _tmain(int argc, _TCHAR* argv[])
{
	SOCKET sock;
	SOCKET user;
	int len;
	struct sockaddr_in sa;
	struct sockaddr addr;
	int reuse_on = 1;
	int keep_running = 1;
	int rc;
	WORD wVer;
	WSADATA wsaData;

	/*
	 * Initialize winsock library
	 */
	wVer = MAKEWORD(2,2);
	rc = WSAStartup(wVer, &wsaData);
	if (rc != 0) {
		fprintf(stderr,"WSAStartup failed: %d\n", rc);
		return (1);
	}

	/*
	 * Initalize libest
	 */
	init_est();

	memset(&sa, 0x0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(EST_PORT);
	/*
	 * Open a new socket
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM, 6)) == INVALID_SOCKET) {
		fprintf(stderr, "Failed to create socket: %d (%s)\n", ERRNO, strerror(errno));
		return(1);		
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse_on, sizeof(reuse_on)) != 0) {
		fprintf(stderr, "Failed to set sock options: %d (%s)\n", ERRNO, strerror(errno));
		closesocket(sock);
		return(1);
	}
	if (bind(sock,(struct sockaddr*)&sa, sizeof(struct sockaddr_in)) != 0) {
		fprintf(stderr, "Failed to bind socket: %d (%s)\n", ERRNO, strerror(errno));
		closesocket(sock);
		return(1);
	}
	if (listen(sock, SOMAXCONN) != 0) {
		fprintf(stderr, "Failed to listen to socket: %d (%s)\n", ERRNO, strerror(errno));
		closesocket(sock);
		return(1);
	}

	fprintf(stdout, "\nThe EST server is listing on port %d...\n", EST_PORT);

	/*
	 * Start the processing loop.  This is a simple single-threaded
	 * server for now. 
	 */
	while (keep_running) {
		len = sizeof(struct sockaddr);
		user = accept(sock, (struct sockaddr*)&addr, &len);
		if (user != INVALID_SOCKET) {
			process_socket(user);
		} else {
			fprintf(stderr, "Invalid socket returned by accept()\n");
		}
	}

	closesocket(sock);
	WSACleanup();
	shutdown_est();

	return 0;
}

