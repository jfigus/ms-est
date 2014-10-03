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


This code was a learning exercise on using the Windows Certificate Services API.
There's a 99% chance this code contains memory leaks.  Minimal error handling is
implemented.  It's a mix of C and C++ code with no attempt to follow coding
standards.  I'll admit to having no experience with Windows development and minimal
experience with C++.  There appears to be many ways to handle the Windows unicode
multibyte string conversion required in this module.  Frankly, I don't know if this
is being done properly here.  These string conversions are prone to buffer overflow
attacks.  Prudence is warranted if this code is going to be put into a product.

*/
#include <stdio.h>
#include <certenroll.h>
#include <certsrv.h>
#include <certcli.h>
#include <wincrypt.h>
#include <Windows.h>
#include <comutil.h>
#include <comdef.h>
#include <tchar.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/lhash.h>
#include <openssl/err.h>

//#include "enrollCommon.h"

#define MAX_FILE_SZ 4096

//FIXME: for now we'll just use a global variable to hold the signed
//       cert that will be returned to the user.  Our server only 
//       processes on a single thread, so we're safe for the time
//       being.
unsigned char cert_out[4096];

#define _JumpIfError(hr, label, pszMessage) \
	{ \
    if (S_OK != (hr)) \
    { \
        wprintf(L"Error in %S: 0x%x\n", pszMessage, hr); \
        goto label; \
    } \
	}
#define _JumpError(hr, label, pszMessage) \
    { \
		wprintf(L"Error in %S: 0x%x\n", pszMessage, hr); \
		goto label; \
    }



/*
 * Utility function to take a list of certs in a BIO and
 * convert it to a stack of X509 records.
 */
static int ossl_add_certs_from_BIO(STACK_OF(X509) *stack, BIO *in)
{
    int count=0;
    int ret= -1;
    STACK_OF(X509_INFO) *sk=NULL;
    X509_INFO *xi;


    /* This loads from a file, a stack of x509/crl/pkey sets */
    sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL);
    if (sk == NULL) {
		fprintf(stderr, "\nerror reading certs from BIO\n");
		goto end;
    }

    /* scan over it and pull out the CRL's */
    while (sk_X509_INFO_num(sk)) {
		xi=sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL) {
			sk_X509_push(stack,xi->x509);
			xi->x509=NULL;
			count++;
		}
		X509_INFO_free(xi);
    }

    ret=count;
end:
    /* never need to OPENSSL_free x */
    if (in != NULL) BIO_free(in);
    if (sk != NULL) sk_X509_INFO_free(sk);
    return(ret);
}


/*
 * This utility function takes a list of certificate that hav been written 
 * to a BIO, reads the BIO, and converts it to a pkcs7 certificate.
 * The input form is PEM encoded X509 certificates in a BIO.
 * The pkcs7 data is then written to a new BIO and returned to the
 * caller.
 */
static BIO * ossl_get_certs_pkcs7(BIO *in)
{
    STACK_OF(X509) *cert_stack=NULL;
    PKCS7_SIGNED *p7s = NULL;
    PKCS7 *p7 = NULL;
    BIO *out;
    int buflen = 0;


    //FIXME: error handling and memory leaks needs to be
    //       addressed here.
    if ((p7=PKCS7_new()) == NULL) {
	fprintf(stderr, "\npkcs7_new failed in %s", __FUNCTION__);
        return NULL;
    }
    if ((p7s=PKCS7_SIGNED_new()) == NULL) { 
	fprintf(stderr, "\npkcs7_signed_new failed in %s", __FUNCTION__);
        return NULL;
    }
    p7->type=OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign=p7s;
    p7s->contents->type=OBJ_nid2obj(NID_pkcs7_data);
    if (!ASN1_INTEGER_set(p7s->version,1)) {
		fprintf(stderr, "\nASN1_integer_set failed in %s", __FUNCTION__);
		return NULL;
    }

    if ((cert_stack=sk_X509_new_null()) == NULL) {
		fprintf(stderr, "\nstack mallock failed in %s", __FUNCTION__);
        return NULL;
    }
    p7s->cert=cert_stack;

    if (ossl_add_certs_from_BIO(cert_stack, in) < 0) {
		fprintf(stderr, "\nerror loading certificates\n");
        ERR_print_errors_fp(stderr);
		return NULL;
    }

    out = BIO_new(BIO_s_mem());
    if (!out) {
		printf("\nBIO_new failed\n");
        return NULL;
    }

    buflen = PEM_write_bio_PKCS7(out,p7);
    if (!buflen) {
		fprintf(stderr, "\nerror in PEM_write_bio_PKCS7\n");
        ERR_print_errors_fp(stderr);
		return NULL;
    }
    if (p7 != NULL) PKCS7_free(p7);

    return out;
}

static unsigned char* convert_x509_to_pkcs7(unsigned char *x509, int len, int *pkcs7_len)
{
	BIO *in;
	BIO *out;
	BIO *pem_out;
	unsigned char *pkcs7;
	X509 *der_x509;

	//Convert x509 cert to BIO,  this is DER
	in = BIO_new_mem_buf(x509, len);

	//Convert DER to PEM
	der_x509 = d2i_X509_bio(in, NULL);
	pem_out = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(pem_out,der_x509);

	//Convert PEM x509 to PKCS7
	out = ossl_get_certs_pkcs7(pem_out);

	//Convert back to char*
	*pkcs7_len = BIO_get_mem_data(out, (char **)&pkcs7);
	return pkcs7;
}


static PCWSTR convert_to_wchar(const char *s, int len)
{
	size_t orig_size = len + 1;
	size_t converted_chars = 0;
	PCWSTR wcstring;

	wcstring = (PCWSTR) malloc(sizeof(WCHAR) * orig_size);
	if (wcstring) {
		mbstowcs_s(&converted_chars, (wchar_t *)wcstring, orig_size, s, _TRUNCATE);
	}
	return (wcstring);
}

/*
This is the primary entry point into this module.  It takes in a PKCS10 certificate
signing request and returns a X.509 certificate.  It attempts to use the
Microsoft CA API to sign the the CSR.  The Microsoft CA should be configured
to automatically enroll new certificates, which is not the default mode for the CA.
*/
extern "C" unsigned char * ca_simple_enroll(const char *pkcs10, int p10_len, int *cert_len)
{
    HRESULT hr = S_OK;
    DWORD fCoInit = 0;
    ICertRequest2* pCertRequest2 = NULL;
    ICertConfig* pCertConfig = NULL;
    IX509Enrollment* pEnroll = NULL; 
    IX509CertificateRequestPkcs10* pPkcs10 = NULL;
    BSTR strCAConfig = NULL;
    BSTR strRequest = NULL;
    BSTR strCert = NULL;
    BSTR strDisposition = NULL;
    BSTR strSubject = NULL;
	BSTR raw_cert = NULL;
    LONG pDisposition = 0;
	DWORD dwRet = 0;
	DWORD bytes_read = 0;
	DWORD bytes_written = 0;
	PCWSTR pkcs10_w;
	_bstr_t b;
	unsigned char *pkcs7_out;
	
	//Set the length to zero here.  We'll check this to 
	//determine if the cert needs to be returned to the
	//caller later.
	*cert_len = 0;

	// CoInitializeEx
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    _JumpIfError(hr, error, "CoInitializeEx");
    fCoInit = 1;

	//Convert the pkcs10 cert to windows friendly data
	pkcs10_w = convert_to_wchar(pkcs10, p10_len);
	raw_cert = SysAllocString(pkcs10_w);
	free((void*)pkcs10_w);
    if (NULL == raw_cert)
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "SysAllocString");
    }

    // Create ICertConfig
    hr = CoCreateInstance(
            __uuidof(CCertConfig),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(ICertConfig),
            (void**)&pCertConfig);
    _JumpIfError(hr, error, "CoCreateInstance");

    // Get CA config from UI
    hr = pCertConfig->GetConfig(CC_LOCALACTIVECONFIG, &strCAConfig);
    _JumpIfError(hr, error, "GetConfig");

    // Create ICertRequest2
    hr = CoCreateInstance(
            __uuidof(CCertRequest),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(ICertRequest2),
            (void**)&pCertRequest2);
    _JumpIfError(hr, error, "CoCreateInstance");
  
    // Submit the CSR request to the CA
    hr = pCertRequest2->Submit(
            /*CR_IN_BINARY | CR_IN_PKCS10*/ /*CR_IN_BASE64 | CR_IN_FORMATANY*/
			CR_IN_BASE64HEADER | CR_IN_PKCS10, 
            raw_cert /*strRequest*/, 
            NULL, 
            strCAConfig,
            &pDisposition);   
    _JumpIfError(hr, error, "Submit");

    // Check the submission status.  If CA isn't configured for auto enroll
	// then the cert will not be issued by the CA.
    if (pDisposition != CR_DISP_ISSUED) // Not enrolled
    {
        hr = pCertRequest2->GetDispositionMessage(&strDisposition);
        _JumpIfError(hr, error, "GetDispositionMessage");
        
        if (pDisposition == CR_DISP_UNDER_SUBMISSION) // Pending
        {
            wprintf(L"The submission is pending: %ws\n", strDisposition);
            _JumpError(hr, error, "Submit");
        } 
        else // Failed
        {
            wprintf(L"The submission failed: %ws\n", strDisposition);
            pCertRequest2->GetLastStatus(&hr);
            _JumpError(hr, error, "Submit");
        }
    }

    // Get the certifcate
    hr = pCertRequest2->GetCertificate(
            /*CR_OUT_BASE64 | CR_OUT_CHAIN, */
            CR_OUT_BINARY, 
            &strCert);
    _JumpIfError(hr, error, "GetCertificate");


	//Return the cert to the caller
	//Note: this code is totally hacked due to my complete ignorance on how
	//      Microsoft multi-byte strings are suppose to work.  There appears
	//      to be no easy way to convert from a BSTR to char.
	b.Assign(strCert);
	LPCTSTR t = (LPCTSTR)b;
	DWORD c_len = SysStringByteLen(strCert); 
	DWORD idx = 0;
	while (idx < c_len) {
		cert_out[idx] = ((unsigned char *)t)[idx];
		idx++;
	}
	cert_out[idx] = 0;

	//Lastly, convert the cert from DER to pkcs7, we leverage openssl for this
	pkcs7_out = convert_x509_to_pkcs7(cert_out, c_len, cert_len);

error:
	SysFreeString(raw_cert);
    SysFreeString(strCAConfig);
    SysFreeString(strRequest);
    SysFreeString(strCert);
    SysFreeString(strDisposition);

    if (NULL != pCertConfig) pCertConfig->Release();
    if (NULL != pCertRequest2) pCertRequest2->Release();
    if (NULL != pEnroll) pEnroll->Release();
    if (NULL != pPkcs10) pPkcs10->Release();
    if (fCoInit) CoUninitialize();
	if (*cert_len)
		return pkcs7_out;
	else
		return 0;
}


