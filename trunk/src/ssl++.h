#ifndef sslplusplus_h
#define sslplusplus_h

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <string.h>
#include <iostream>


struct Name
{
	char* longName;
	char* shortName;
	char* value;
};

class OpenSSLCertificate
{
	public: 
		OpenSSLCertificate (X509* c);
		
		int getSubjectInfoSize ();
		int getIssuerInfoSize ();
		Name ** getSubjectInfo ();
		Name ** getIssuerInfo ();
	
		X509* getRawCertificate () {return cert;};
	
	private:
		X509* cert;
};

/*
* OpenSSLBaseSocket is the parent of OpenSSLServerSocket class and OpenSSLSocket class
* It must never be instantiated directly.
*/
class OpenSSLBaseSocket
{
	public:

		bool hasError() {return err;};
		char* getErrorMessage () {return errorMessage;};
		
		void setValidCipherList (char* cipherList);
		char* getValidCipherList ();
		
		void setFailIfCertExpired (bool fail) {failIfCertExpired = fail;};
		bool getFailIfCertExpired () {return failIfCertExpired;};
		
		void setCRLCheck (bool check);
		bool getCRLCheck () {return doCRLChecking;};

		OpenSSLCertificate* getPeerCertificate () 
		{
			if (!peerCertificate)
			{
				err = true;
				errorMessage = "There is no peer certificate";
			}
			return peerCertificate;
		};
		
		OpenSSLBaseSocket ();
		~OpenSSLBaseSocket ();

	protected:

		SSL_CTX* context;
		BIO* socket;
		
		char* validCipherList;
		bool failIfCertExpired;
		bool doCRLChecking;
		
		OpenSSLCertificate* peerCertificate;

		bool err;
		char* errorMessage;
};

//OpenSSLSocket: Open SSL client socket
class OpenSSLSocket: public OpenSSLBaseSocket
{
	public:
		OpenSSLSocket (char* CACertFile, char* trustDir, char* ClientCertFile, char* ClientKeyFile, char* password);
		~OpenSSLSocket ();
		
		OpenSSLSocket (SSL_CTX* ctx, SSL* s, BIO* bio);
		void setClose ();
		
		void reConnect (char* addressPort);
		void connect(char* addressPort);
		bool acceptSSLHandshake ();
		
		const char* getActualCipherList ();
		
		int write (char* buffer, int numberOfBytes);
		int read (char* buffer, int numberOfBytes);
		
		bool writeString (std::string str);
		std::string* readString ();
		
		bool writeInt(int i);
		int readInt ();
	
	private:
		SSL* ssl;	
		bool returnedByAccept;
};

/**
 * OpenSSLSocket: OpenSSL server socket
 */
class OpenSSLServerSocket:public OpenSSLBaseSocket
{
	public:
		OpenSSLServerSocket (char* AddressPort, char* CACertFile, char* trustDir, char* ServerCertFile, char* ServerKeyFile, char* password);
		~OpenSSLServerSocket ();
		
		OpenSSLSocket* accept ();
		
		/**
		* This one also accepts and return the socket but it does not call
		* SSL_accept() so this must be explicitly done by calling OpenSSLSocket's acceptSSLHanshake call
		*/
		OpenSSLSocket* acceptRaw ();
		
		void loadDHParam (char* DHParamFile);
		
		void disableClientAuthentication ();
	
	private:
		DH* dhParam;
};

#endif // sslplusplus_h
