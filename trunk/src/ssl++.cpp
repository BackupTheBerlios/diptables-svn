
#include "ssl++.h"

OpenSSLCertificate::OpenSSLCertificate (X509* c)
{
	cert = c;
}

int OpenSSLCertificate::getSubjectInfoSize ()
{
	return X509_NAME_entry_count(X509_get_subject_name (cert));	
}

int OpenSSLCertificate::getIssuerInfoSize ()
{
	return X509_NAME_entry_count (X509_get_issuer_name(cert));
}

Name** OpenSSLCertificate::getSubjectInfo ()
{
	X509_NAME* subject = X509_get_subject_name (cert);
	int numberOfItems = X509_NAME_entry_count(subject);

	Name** subjectInfo = new Name*[numberOfItems];
	
	for (int i=0; i < numberOfItems; i++)
		subjectInfo [i] = new Name;
	
	for (int i=0; i < numberOfItems; i++)
	{
		X509_NAME_ENTRY *thisEntry = X509_NAME_get_entry(subject, i);
		
		ASN1_OBJECT *thisEntryObject = X509_NAME_ENTRY_get_object(thisEntry);
		
		int size = X509_NAME_get_text_by_OBJ (subject, thisEntryObject, 0,0);

		subjectInfo [i]->value = new char [size + 2];
		X509_NAME_get_text_by_OBJ (subject, thisEntryObject, subjectInfo [i]->value, size+1);

		subjectInfo [i]->shortName = (char*) OBJ_nid2sn(OBJ_obj2nid(thisEntryObject));
		subjectInfo [i]->longName = (char*) OBJ_nid2ln(OBJ_obj2nid(thisEntryObject));
	}
	
	return subjectInfo;
}

Name** OpenSSLCertificate::getIssuerInfo ()
{
	X509_NAME* issuer = X509_get_issuer_name (cert);
	int numberOfItems = X509_NAME_entry_count(issuer);

	Name** issuerInfo = new Name*[numberOfItems];
	
	for (int i=0; i < numberOfItems; i++)
		issuerInfo [i] = new Name;
	
	for (int i=0; i < numberOfItems; i++)
	{
		X509_NAME_ENTRY *thisEntry = X509_NAME_get_entry(issuer, i);
		
		ASN1_OBJECT *thisEntryObject = X509_NAME_ENTRY_get_object(thisEntry);
		
		int size = X509_NAME_get_text_by_OBJ (issuer, thisEntryObject, 0,0);

		issuerInfo [i]->value = new char [size + 2];
		X509_NAME_get_text_by_OBJ (issuer, thisEntryObject, issuerInfo [i]->value, size+1);

		issuerInfo [i]->shortName = (char*) OBJ_nid2sn(OBJ_obj2nid(thisEntryObject));
		issuerInfo [i]->longName = (char*) OBJ_nid2ln(OBJ_obj2nid(thisEntryObject));
	}
	
	return issuerInfo;
}

OpenSSLBaseSocket::OpenSSLBaseSocket ()
{
	SSL_library_init ();
	err = false;
	errorMessage = "";
	
	failIfCertExpired = true;
	doCRLChecking = false;

	peerCertificate = 0;
	
	socket = 0;
	
	context = 0;
	
	validCipherList = 0;
}

OpenSSLBaseSocket::~OpenSSLBaseSocket ()
{
}


/*
* calling this function on a non-initialized socket will lead to error.
* However its your own duty to be carefull to never new a pure OpenSSLBaseSocket
* object because its not designed for such a purpose.
*/
void OpenSSLBaseSocket::setValidCipherList (char* cipherList)
{
	if (context)
	{
		int result = SSL_CTX_set_cipher_list (context, cipherList);
		if ( result == 1 )
			validCipherList = cipherList;
		else
		{
			err = true;
			errorMessage = "The cipher list is not valid";
		}
	}
	else
	{
		err = true;
		errorMessage = "The context is not initialized";
	}
}

char* OpenSSLBaseSocket::getValidCipherList ()
{
	if (context)
		return validCipherList;
	else 
	{
		err= true;
		errorMessage = "The context is not initialized";
		return 0;
	}
}

void OpenSSLBaseSocket::setCRLCheck(bool check)
{
	if (context)
	{
		X509_STORE * store = SSL_CTX_get_cert_store(context);
		if (!store)
			{
				err = true;
				errorMessage = "No trust store is loaded";
				return;
			}
		if (check)
		{
			X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		}
		else
		{
			X509_STORE_set_flags(store, 0);
		}
	}
	else
	{
		err=true;
		errorMessage = "The context is not initialized";
		return;
	}

}

OpenSSLSocket::OpenSSLSocket (char* CACertFile, char* trustDir, char* ClientCertFile, char* ClientKeyFile, char* password)
{
	returnedByAccept = false;
	ssl = 0;
	int result = 0;
	
	context = SSL_CTX_new (SSLv3_method());
	setValidCipherList ("AES256-SHA");
	
	if (password)
		SSL_CTX_set_default_passwd_cb_userdata (context, (void*) password);

	// load CA certificate
	if (CACertFile)
	{
		result = SSL_CTX_load_verify_locations (context, CACertFile, 0);
		if (result != 1)
		{
			err = true;
			errorMessage = "Could not load CA certificate";

			return;
		}
	}
	if (trustDir)
	{
		result = SSL_CTX_load_verify_locations (context, 0, trustDir);
		if (result != 1)
		{
			err = true;
			errorMessage = "Could not load trust directory";

			return;
		}
	}
	
	// load my certificate
	if (ClientCertFile)
	{
		result = SSL_CTX_use_certificate_chain_file (context, ClientCertFile);
		if (result != 1)
		{
			err = true;
			errorMessage = "Could not load client's certificate";
			return;
		}
	}
	
	// load my private key 
	if (ClientKeyFile)
	{
		result = SSL_CTX_use_RSAPrivateKey_file (context, ClientKeyFile, SSL_FILETYPE_PEM);
		if (result != 1)
		{
			err = true;
			errorMessage = "Could not load client's private key";
			return;
		}
	}
		
	SSL_CTX_set_verify (context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	SSL_CTX_set_verify_depth (context, 1);
	//
	SSL_CTX_set_options (context, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	SSL_CTX_set_mode (context, SSL_MODE_AUTO_RETRY);	
}

void OpenSSLSocket::setClose ()
{
	BIO_set_fd(socket, BIO_get_fd (socket,0), 1);
}

OpenSSLSocket::~OpenSSLSocket ()
{
	if (!returnedByAccept && context) SSL_CTX_free(context);
	if (ssl)
	{ 
		SSL_free(ssl);
	}
}

void OpenSSLSocket::reConnect(char* addressPort)
{
	err = false;
	connect (addressPort);
}
void OpenSSLSocket::connect(char* addressPort)
{
	if (returnedByAccept)
	{
		err = true;
		errorMessage = "Calling connect is not allowed on this type of sockets";
		return;
	}
	
	socket = BIO_new_connect (addressPort);
	if ( !socket )
	{
		err = true;
		errorMessage = "Could not create the socket";
		return;
	}
	
	int result = BIO_do_connect (socket);

	if (result != 1)
	{
		err = true;
		errorMessage = "Could not connect the socket to remote host ";
		return;
	}

	ssl = SSL_new(context);
	if (!ssl)
	{
		err = true;
		errorMessage ="Could not initiate SSL session";
		return;
	}
	
	SSL_set_connect_state(ssl);	
	SSL_set_bio (ssl, socket, socket);
	
	result = SSL_connect (ssl);
	
	if (result != 1)
	{
		err = true;
		if (SSL_get_error (ssl, result)==SSL_ERROR_SSL)
		{
			errorMessage = "SSL handshake failed. Reason: Certificate or cipher list is not accepted.";
		}
		else
			errorMessage = "SSL handshake failed";
	}
	
	X509* tempPeerCertificate = SSL_get_peer_certificate (ssl);
	
	int verificationResult = SSL_get_verify_result (ssl);
	
	//if (!failIfCertExpired && verificationResult == X509_V_ERR_CERT_HAS_EXPIRED)
	
	if ((!tempPeerCertificate || verificationResult != X509_V_OK)
		&& !(!failIfCertExpired && verificationResult == X509_V_ERR_CERT_HAS_EXPIRED))
	{
		err = true;
		if (verificationResult == X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE)
			errorMessage = "Unable to decrypt peer's certificate signature";
		else if (verificationResult == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)
			errorMessage = "Unable to get issuer peer's certificate";
		else if (verificationResult == X509_V_ERR_UNABLE_TO_GET_CRL)
			errorMessage = "Unable to get the CRL for peer's certificate";
		else if (verificationResult == X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE)
			errorMessage = "Unable to decrypt the CRL signature for peer's certificate";
		else if (verificationResult == X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)
			errorMessage = "Unable to decode issuer public key of peer's certificate";
		else if (verificationResult == X509_V_ERR_CERT_SIGNATURE_FAILURE)
			errorMessage = "Invalid signature in peer's certificate";
		else if (verificationResult == X509_V_ERR_CRL_SIGNATURE_FAILURE)
			errorMessage = "Invalid CRL signature";
		else if (verificationResult == X509_V_ERR_CERT_NOT_YET_VALID)
			errorMessage = "Peer's Certificate is not valid yet";
		else if (verificationResult ==  X509_V_ERR_CERT_HAS_EXPIRED)
			errorMessage = "Certificate has expired";
		else if (verificationResult ==  X509_V_ERR_CRL_NOT_YET_VALID)
			errorMessage = "CRL is not valid yet";
		else if (verificationResult ==  X509_V_ERR_CRL_HAS_EXPIRED)
			errorMessage = "CRL has expired";
		else if (verificationResult ==  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD)
			errorMessage = "Invalid format in notBefore field of peer's certificate";
		else if (verificationResult ==  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD)
			errorMessage = "Invalid format in notAfter field of peer's certificate";
		else if (verificationResult ==  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD)
			errorMessage = "Invalid format in CRL's lastUpdate field";
		else if (verificationResult ==  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD)
			errorMessage = "Invalid format in CRL's nextUpdate field";
		else if (verificationResult ==  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
			errorMessage = "The peer's certificate is self signed";
		else if (verificationResult ==  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
			errorMessage = "The peer's certificate chain contains self signed certificates";
		else if (verificationResult ==  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
			errorMessage = "Cannot find issuer certificate of the peer's certificate in local trust list";
		else if (verificationResult ==   X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)
			errorMessage = "Unable to verify peer's certificate signature (leaf certificate)";
		else if (verificationResult ==  X509_V_ERR_CERT_CHAIN_TOO_LONG)
			errorMessage = "Peer's certificate chain is too long";
		else if (verificationResult ==  X509_V_ERR_CERT_REVOKED)
			errorMessage = "Peer's certificate is revoked";
		else if (verificationResult ==  X509_V_ERR_INVALID_CA)
			errorMessage = "Invalid CA certificate";
		else if (verificationResult ==  X509_V_ERR_PATH_LENGTH_EXCEEDED)
			errorMessage = "Path length constraint exceeded";
		else if (verificationResult ==  X509_V_ERR_INVALID_PURPOSE)
			errorMessage = "The peer's certificate cannot be used for this purpose";
		else if (verificationResult ==  X509_V_ERR_CERT_UNTRUSTED)
			errorMessage = "The root CA is not marked as trusted";
		else if (verificationResult ==  X509_V_ERR_CERT_REJECTED)
			errorMessage = "The root CA is marked to reject the specified purpose";
		else if (verificationResult ==  X509_V_ERR_KEYUSAGE_NO_CERTSIGN)
			errorMessage = "The keyUsage field of issuer does not allow signing";
		else
			errorMessage = "SSL handshake failed";
		return;
	}
	peerCertificate = new OpenSSLCertificate (tempPeerCertificate);
}

/** This constructor is used merely to build sockets returned from an accept call 
 *  on a server socket and must not be used to create general client sockets.
 *  The major differece is that this constructor returns a connected, handshaked socket
 *  ready for use. Never connect is allowed to be called on this socket!!
 */
OpenSSLSocket::OpenSSLSocket (SSL_CTX* ctx, SSL* s, BIO* bio)
{
	returnedByAccept = true;
	
	context = ctx;
	socket = bio;
	ssl = s;
}

bool OpenSSLSocket::acceptSSLHandshake ()
{
	int result = SSL_accept (ssl);

	if (result != 1)
	{
		err = true;
		if (SSL_get_error (ssl, result) == SSL_ERROR_SSL)
		{
			errorMessage = "SSL handshake failed. Reason: Certificate is not accepted.";
		}
		else 
			errorMessage = "SSL handshake failed";
		return false;
	}

	bool clientAuth = (SSL_CTX_get_verify_mode(context) == SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
	
	if (clientAuth)
	{
		X509* tempPeerCertificate = SSL_get_peer_certificate (ssl);
		int verificationResult = SSL_get_verify_result (ssl);
		if ((!tempPeerCertificate || verificationResult != X509_V_OK)
			&& !(!failIfCertExpired && verificationResult == X509_V_ERR_CERT_HAS_EXPIRED))
		{
			err = true;
			if (verificationResult == X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE)
				errorMessage = "Unable to decrypt peer's certificate signature";
			else if (verificationResult == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)
				errorMessage = "Unable to get issuer peer's certificate";
			else if (verificationResult == X509_V_ERR_UNABLE_TO_GET_CRL)
				errorMessage = "Unable to get the CRL for peer's certificate";
			else if (verificationResult == X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE)
				errorMessage = "Unable to decrypt the CRL signature for peer's certificate";
			else if (verificationResult == X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)
				errorMessage = "Unable to decode issuer public key of peer's certificate";
			else if (verificationResult == X509_V_ERR_CERT_SIGNATURE_FAILURE)
				errorMessage = "Invalid signature in peer's certificate";
			else if (verificationResult == X509_V_ERR_CRL_SIGNATURE_FAILURE)
				errorMessage = "Invalid CRL signature";
			else if (verificationResult == X509_V_ERR_CERT_NOT_YET_VALID)
				errorMessage = "Peer's Certificate is not valid yet";
			else if (verificationResult ==  X509_V_ERR_CERT_HAS_EXPIRED)
				errorMessage = "Certificate has expired";
			else if (verificationResult ==  X509_V_ERR_CRL_NOT_YET_VALID)
				errorMessage = "CRL is not valid yet";
			else if (verificationResult ==  X509_V_ERR_CRL_HAS_EXPIRED)
				errorMessage = "CRL has expired";
			else if (verificationResult ==  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD)
				errorMessage = "Invalid format in notBefore field of peer's certificate";
			else if (verificationResult ==  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD)
				errorMessage = "Invalid format in notAfter field of peer's certificate";
			else if (verificationResult ==  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD)
				errorMessage = "Invalid format in CRL's lastUpdate field";
			else if (verificationResult ==  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD)
				errorMessage = "Invalid format in CRL's nextUpdate field";
			else if (verificationResult ==  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
				errorMessage = "The peer's certificate is self signed";
			else if (verificationResult ==  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
				errorMessage = "The peer's certificate chain contains self signed certificates";
			else if (verificationResult ==  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
				errorMessage = "Cannot find issuer certificate of the peer's certificate in local trust list";
			else if (verificationResult ==   X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)
				errorMessage = "Unable to verify peer's certificate signature (leaf certificate)";
			else if (verificationResult ==  X509_V_ERR_CERT_CHAIN_TOO_LONG)
				errorMessage = "Peer's certificate chain is too long";
			else if (verificationResult ==  X509_V_ERR_CERT_REVOKED)
				errorMessage = "Peer's certificate is revoked";
			else if (verificationResult ==  X509_V_ERR_INVALID_CA)
				errorMessage = "Invalid CA certificate";
			else if (verificationResult ==  X509_V_ERR_PATH_LENGTH_EXCEEDED)
				errorMessage = "Path length constraint exceeded";
			else if (verificationResult ==  X509_V_ERR_INVALID_PURPOSE)
				errorMessage = "The peer's certificate cannot be used for this purpose";
			else if (verificationResult ==  X509_V_ERR_CERT_UNTRUSTED)
				errorMessage = "The root CA is not marked as trusted";
			else if (verificationResult ==  X509_V_ERR_CERT_REJECTED)
				errorMessage = "The root CA is marked to reject the specified purpose";
			else if (verificationResult ==  X509_V_ERR_KEYUSAGE_NO_CERTSIGN)
				errorMessage = "The keyUsage field of issuer does not allow signing";
			else
				errorMessage = "SSL handshake failed";
			return false;
		}
		peerCertificate = new OpenSSLCertificate (tempPeerCertificate);
	}
	return true;
}

int OpenSSLSocket::write (char* buffer, int numberOfBytes)
{
	int totalWritten = 0;
	int thisTurnWritten = 0;
	
	for (totalWritten = 0;  totalWritten < numberOfBytes;  totalWritten += thisTurnWritten)
        {
            thisTurnWritten = SSL_write (ssl, buffer+totalWritten, numberOfBytes-totalWritten);
	    
            if (thisTurnWritten == 0)
	    	{
			break;
		}
	    else if (thisTurnWritten < 0)
		{
			err = true;
			errorMessage = "Error Writing to socket";
			break;
		}
        }
	return totalWritten;
}

int OpenSSLSocket::read (char* buffer, int numberOfBytes)
{
	int totalRead = 0;
	int thisTurnRead = 0;
	
	for (totalRead = 0;  totalRead < numberOfBytes;  totalRead += thisTurnRead)
        {

            thisTurnRead = SSL_read(ssl, buffer + totalRead, numberOfBytes-totalRead);
            
	    if (thisTurnRead == 0)
			break;
	    if (thisTurnRead < 0)
		{
			err = true;
			errorMessage = "Error Reading from socket";
			break;
		}
        }
	return totalRead;
}

bool OpenSSLSocket::writeString (std::string str)
{
	int sizeOfStr = str.size();
	writeInt(sizeOfStr);
	
	char* strBytes = strdup(str.c_str());
	
	int sizeOfWritten = write (strBytes, sizeOfStr);
	
	free (strBytes);
	
	return (sizeOfWritten == sizeOfStr);
}

std::string* OpenSSLSocket::readString ()
{
	int sizeOfStr=0;
	char* strBytes=0;
	std::string* str = new std::string ("");
	
	sizeOfStr = readInt();
	strBytes = new char [sizeOfStr];
	read (strBytes, sizeOfStr);
	
	for (int i=0; i<sizeOfStr; i++)
		*str += strBytes [i];
	return str; 
}

bool OpenSSLSocket::writeInt(int i)
{
	int* ii = &i;
	char* intBytes = (char*) ii;
	int sizeOfWritten = write (intBytes, sizeof (i));
	return (sizeof (i)==sizeOfWritten);
}

int OpenSSLSocket::readInt ()
{
	char* intBytes = new char [sizeof(int)];
	read (intBytes, sizeof(int)); 
	int* i  = (int*) intBytes;
	return *i;
}

const char* OpenSSLSocket::getActualCipherList ()
{
	if (ssl)
	{
		SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
		if (cipher)
			return SSL_CIPHER_get_name(cipher);
		else
		{
			err = true;
			errorMessage = "No SSL session has been stablished";
			return 0;
		}
	}
	else
	{
		err = true;
		errorMessage = "SSL not initialized";
		return 0;
	}
}

OpenSSLServerSocket::OpenSSLServerSocket (char* AddressPort, char* CACertFile, char* trustDir, char* ServerCertFile, char* ServerKeyFile, char* password)
{
	dhParam =0;
	
	int result = 0;
	context = SSL_CTX_new (SSLv3_method());
	
	setValidCipherList ("AES256-SHA");
	
	if (password)
		SSL_CTX_set_default_passwd_cb_userdata (context, (void*) password);
		
	if (!ServerCertFile || !ServerKeyFile)
		{
			err = true;
			errorMessage = "One of the required key material is not provided";
			return;
		}
	
	if (CACertFile!=0)
		result = SSL_CTX_load_verify_locations (context, CACertFile, 0);
	else
		result = SSL_CTX_load_verify_locations (context, 0, trustDir);
	
	if (result != 1)
		{
			err = true;
			errorMessage = "Cannot load CA certificate or trust directory";
			return;
		}
	
	
	result = SSL_CTX_use_certificate_chain_file (context, ServerCertFile);
	if (result != 1)
		{
			err = true;
			errorMessage = "Cannot load server's certificate";
			return;
		}

	
	result = SSL_CTX_use_RSAPrivateKey_file (context, ServerKeyFile, SSL_FILETYPE_PEM);
	if (result != 1)
		{
			err = true;
			errorMessage = "Cannot load server's private key";
			return;
		}
	
	SSL_CTX_set_verify (context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	
	SSL_CTX_set_verify_depth (context, 1);    
	
	SSL_CTX_set_options (context, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	
	SSL_CTX_set_mode (context, SSL_MODE_AUTO_RETRY);
	
	socket = BIO_new_accept (AddressPort);
	if ( !socket )
	{
		err = true;
		errorMessage = "Could not create the socket";
		return;
	}
		
	result = -1;
	if (socket)
		result = BIO_do_accept (socket);
	if (result < 0)
	{
		err = true;
		errorMessage = "Could not bind the socket";
		return;
	}
}

OpenSSLServerSocket::~OpenSSLServerSocket ()
{
	if (context) 
	{
		SSL_CTX_free(context);
	}
	if (socket)
	{
		BIO_free (socket);
	}
	
}

void OpenSSLServerSocket::loadDHParam (char* DHParamFile)
{
	BIO *bio;

    bio = BIO_new_file(DHParamFile, "r");
    if (!bio)
	{
		err = true;
        errorMessage ="Error opening DH Parameters file";
		return;
	}
    dhParam = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dhParam)
	{
		err = true;
        errorMessage = "Error reading DH parameters from dh512.pem";
		return;
	}	
    BIO_free(bio);
	
	int result = SSL_CTX_set_tmp_dh(context, dhParam);
	if (result!=1)
	{
		err=true;
		errorMessage = "Could not load DH Parameters";
		return;
	}
	SSL_CTX_set_options (context, SSL_OP_NO_SSLv2|SSL_OP_SINGLE_DH_USE);
}

/**
* This one also accepts and return the socket but it does not call
* SSL_accept() so this must be explicitly done by calling OpenSSLSocket's acceptSSLHanshake call
*/
OpenSSLSocket* OpenSSLServerSocket::acceptRaw ()
{
	int result = BIO_do_accept (socket);
	if (result < 0)
	{
		err = true;
		errorMessage = "Could not accept on the socket";
		return 0;
	}

	BIO* newsocket = BIO_pop (socket);
	if (! newsocket)
	{
		err = true;
		errorMessage = "No connection could be accepted";
		return 0;
	}

	SSL* ssl = SSL_new(context);
	if (! ssl)
	{
		err = true;
		errorMessage = "Could not initiate the SSL session";
		return 0;
	}
		
	SSL_set_accept_state(ssl);
	SSL_set_bio (ssl, newsocket, newsocket);
	return new OpenSSLSocket (context, ssl, newsocket);
}

OpenSSLSocket* OpenSSLServerSocket::accept ()
{
	OpenSSLSocket * accepted = acceptRaw ();
	
	bool res = accepted -> acceptSSLHandshake ();
	if (!res)
	{
		err = true;
		errorMessage = accepted->getErrorMessage();
		return 0;
	}
	
	return accepted;
}

void OpenSSLServerSocket::disableClientAuthentication()
{
	SSL_CTX_set_verify (context, SSL_VERIFY_NONE, 0);
}
