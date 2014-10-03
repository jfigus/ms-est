ms-est
======

This project is a experimental EST server that runs on Windows and uses the Microsoft
Certificate Services API to enroll certificates.  This is a minimal EST server
based on the libest project (https://github.com/cisco/libest).  The libest source
was ported to Windows and compiled using Visual Studio 2010 C++.  

This EST server has significant limitations.  Keep in mind this server was coded
quickly under the hack-a-thon approach.  It's been tested to run on Windows Server
2008 R2 Enterprise.  These limitations include:

* The CA must be configured to automatically approve new certificate requests.
  If the CA requires new requests to be manually approved, the EST server will
  generate an error.  The RFC 7030 retry logic hasn't been fully implemented in
  this EST server.

* All the libest configuration options are hard-coded in this EST server.  It's
  hard-coded to listen on TCP port 8085.  The PoP required option is disabled.
  Only HTTP basic authentication is enabled (SRP and HTTP digest auth are not). 
  The file names that contain the server certificate and private key are
  hard-coded in the EST server code. The server does not configure DH parameters,
  which limits the TLS cipher suites supported by the EST server.

* HTTP basic authentication is performed against the local Windows account
  database.  The Win32 LogonUser() function is used to perform this.  The
  domain name argument for this call is hard-coded to ".", which limits
  the user authentication to the users configured locally on the server.  In other
  words, authentication against an AD domain will not work.

* This is a console application that needs to be run through a cmd shell.  No
  attempt has been made to make this a Windows service and integrate the logging
  into the Windows event log.

* There is no IPv6 support.  Only IPv4 has been attempted.

* Some of the safe string handling in libest didn't port well to Windows.  No 
  attempt was made to properly safeguard against buffer overflows and other
  attacks on string handling.  I'll admit to being a newbie Windows developer
  and don't fully understand the history and difference between wchar_t, 
  LPCWSTR, BStr, etc.  This is left as future work.

* There is no integration with the Windows CAPI certificate store.  The certificate
  and private key used by the EST server are simply stored on the local file
  system in PEM format.  They must reside in the same directory where
  estserver.exe is run from (Program Files(x86)\ESTServer directory).

* All logging is done to the console.  Some of the libest logging macros didn't 
  port well to Windows.  No effort was made to address this properly.  This
  experimental EST server simply dumps messages to stderr and stdout.

* This EST server is single threaded.  Thus, it can only process a single
  EST request at any time.

* There is no support for a password protected private key.  The estserverkey.pem
  file should be unencrypted.


OK, with all the limitations noted above, this server has been tested using the
libest client running on a Linux system.  The four primary EST flows supported
by libest are working: /cacerts, /csrattrs, /simpleenroll, and /simplereenroll.
This was tested using a simple PKI hierarchy of a root CA issuing certificates
directly to end-entities.  The instructions below assume this hierarchy.  It
should be possible to use subordinate CAs as well, but the steps below may need
to be adjusted.  Use the following instructions to setup this EST server.

1) You will need to install/configure Microsoft Certificate Services on the server 
   (refer to Microsoft for this procedure).  These instructions are not repeated
   here.

2) You will need to change the Microsoft Certificate Services configuration to
   automatically approve new certificate requests.  Go to Administrative Tools ->
   Certification Authority.  Right-click on your instance name and select
   Properties.  Click on the Policy Module tab and click the Properties button. 
   Select the option that says "Follow the settings in the certificate template, 
   if applicable.  Otherwise, automatically issue the certificate.".  (If you've
   changed the default certificate template, then you'll need to make this change
   there as well.)

3) Export the trust anchor from your CA.  EST Server needs this certificate for
   the /cacerts response. Go to Administrative Tools -> Certification Authority.  
   Right-click on your instance name and select Properties.  Click on the 
   General tab.  Click View Certificate. Click the Details tab. Click the
   Copy to File button.  Follow the wizard and choose the "Base-64 encoded X.509"
   file format.  Save the file to c:\program files(x86)\ESTServer\trustedcerts.pem.

   Note: The EST server is hard-coded to look for the trustedcerts.pem file in the
         same directory where estserver.exe is run from.  This file contains the 
	 trust anchors returned in the /cacerts response.  These certs are also
	 used by EST Server to authenticate the identity of any EST clients that
	 present a certificate at the TLS layer.  You may observe that the
	 trustedcerts.pem file is overloaded for both uses, which is not ideal.
	 Libest allows for these two uses to be isolated, but the EST Server
	 doesn't leverage this capability at this time.  This is left for future work.
	 You may add additional root certificates to the trustedcerts.pem file
	 if you want to authenticate EST clients using certificates issued by
	 another CA.  But some people will argue this violates RFC 7030.

   Note 2: EST Server installs with a sample trustedcerts.pem file.  This will
         allow you to easily start up the process.  But this file will not contain
	 the correct root cert required for your CA instance.

4) Similar to the trustedcerts.pem file, EST Server comes preinstalled with a
   server certificate and private key in the files estservercert.pem and 
   estserverkey.pem.  You can use these sample files to easily start the server. 
   However, to properly integrate with your CA, you should issue a new 
   certificate from your CA for the EST Server process.  This new certificate needs
   to go into the estservercert.pem file and should be PEM encoded.  The associated
   private key for the certificate needs to go into the estserverkey.pem file and
   should not be password protected (or encrypted).  Both of these files need
   to go into the same directory as estserver.exe (c:\Program Files(x86)\ESTServer).

5) Finally, you are now ready to start the EST Server process.  Open a cmd shell, navigate
   to c:\Program Files(x86)\EST Server.  Run the estserver.exe process from the cmd
   shell.  You should see the message "The EST server is up and running..." displayed 
   on the console.  At this point you can use any EST client compliant with RFC 7030
   to enroll a new certificate.





