#include "ssl++.h" 
#include "configfilereader.h"
#include "logger.h"
#include "unistd.h"
#include <signal.h>
#include <string.h>
#include <sys/types.h>


using namespace std;

sig_atomic_t stillContinue = 1;
OpenSSLServerSocket* server=0;

void terminatHandler (int signalNumber)
{
	stillContinue = 0;
	if (server)
	{
		delete server;
		server = 0;
	}
	
}

void regiterSignal ()
{
	struct sigaction sa;
	memset (&sa, 0, sizeof(sa));
	sa.sa_handler = &terminatHandler;
	sigaction (SIGUSR1, &sa, 0);
}

int main ()
{
	
	OpenSSLSocket* socket;
	time_t currentTime;
	
	ConfigFileReader configFile ("/usr/local/diptables/conf/diptablesserver.conf");
	if (configFile.hasError())
	{
		cout << configFile.getErrorMessage() << endl;
		return -1;
	}
	
	std::string logDir = configFile.getValueOf("LogDir");
	if (logDir=="")
	{
		cout << "No log directory specified in config file." << endl;
		return -1;
	}
	
	std::string logLimit = configFile.getValueOf("LogLimit");
	int logLimitInt = atoi (logLimit.c_str());
	
	if (logLimit=="" || !logLimitInt>0)
	{
		cout << "No valid log limit specified in config file." << endl;
		return -1;
	}
	
	Logger logger (logDir, logLimitInt);
	
	if (logger.hasError())
	{
		cout << "Logging Error: " << logger.getErrorMessage() << endl;
		return -1;
	}
	
		
	char* myAddress = strdup ((configFile.getValueOf("IP") +":" + configFile.getValueOf("Port")).c_str());
	char* caCertFile = strdup (configFile.getValueOf("CA").c_str());
	char* myCertFile = strdup (configFile.getValueOf("Certificate").c_str());
	char* myKeyFile = strdup (configFile.getValueOf("PrivateKey").c_str());
	char* dhParam = strdup (configFile.getValueOf("DHParam").c_str());
	
	currentTime = time(0);
	logger.log (asctime(localtime(&currentTime)));

	logger.log ("listening on: " + configFile.getValueOf("IP") +":" + configFile.getValueOf("Port") + "\n\n");
	
	server = new OpenSSLServerSocket (myAddress, caCertFile,0, myCertFile, myKeyFile, 0);
	
	if (server->hasError())
	{
		cout << server-> getErrorMessage () << endl;
		
		free (myAddress);
		free (caCertFile);
		free (myCertFile);
		free (myKeyFile);
		free (dhParam);
		delete server;
		return -1;
	}
	
	server->loadDHParam (dhParam);
	if (server->hasError())
	{
		cout << server-> getErrorMessage () << endl;
		
		free (myAddress);
		free (caCertFile);
		free (myCertFile);
		free (myKeyFile);
		free (dhParam);
		delete server;
		return -1;
	}
	
	server->setValidCipherList("DHE-RSA-AES256-SHA");
	
	regiterSignal(); // so that this loop can be stopped
	while (stillContinue)
	{
		if (server)
			socket = server->acceptRaw ();
		else
			break;
		int pid = fork ();
		if (pid==0)
		{
			if (server)
				socket->acceptSSLHandshake();
			else 
				break;
			// here we should think of something to prevent denial of service
	
			if (server && server->hasError())
				cout << server->getErrorMessage() << endl;
			if (socket && socket->hasError())
				cout << socket->getErrorMessage () <<endl;
			OpenSSLCertificate* peerCert = socket ->getPeerCertificate();
	
			int size = peerCert-> getSubjectInfoSize ();
	
			Name** test = peerCert->getSubjectInfo();
		
			currentTime = time(0);
			logger.log (asctime(localtime(&currentTime)));

			for (int i=size-1; i>=0; i--)
			{
				logger.log (test [i]->longName);
				logger.log ("(");
				logger.log (test [i]->shortName);
				logger.log ("):");
				logger.log (test [i]->value);
				logger.log (" / ");
			}
			logger.log ("\n");
		
			std::string* str = socket->readString();
			logger.log ("command: "+ *str + "\n\n");
		
			system ((*str +" 2>1 > /dev/null").c_str());
			delete str;
			
			exit(0);
		}
	}
	
	free (myAddress);
	free (caCertFile);
	free (myCertFile);
	free (myKeyFile);
	free (dhParam);
	
	if (server)
		delete server;
	if (socket)
		delete socket;
}
