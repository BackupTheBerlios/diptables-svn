#include "ssl++.h"
#include <string.h>
#include "configfilereader.h"

using namespace std;

int main (int argc , char* argv[])
{
	bool broadcast = false;
	bool localCommand = true;
	string* addressPort;
	int addressPortIndex=0;
	string command = "iptables ";

	for (int i=1; i < argc -1; i++)
	{
		if (strcmp("--remote", argv[i])==0)
		{
			localCommand = false;
			addressPortIndex = i+1;
			addressPort = new string (argv[i+1]);
			if (*addressPort=="ALL")
				broadcast = true;
			break;
		}
	}

	if (localCommand)
	{
		for (int i=1; i < argc; i++)
		{
			command += argv [i];
			if (i != argc - 1)
				command += ' ';
		}
		cout <<"debug: " << command <<endl;
		system (command.c_str());
		return 0;
	}
	// else if remote command

	ConfigFileReader configFile ("/usr/local/diptables/conf/diptables.conf");
	if (configFile.hasError())
	{
		cout << configFile.getErrorMessage() << endl;
		return -1;
	}

	char* caCertFile = strdup (configFile.getValueOf("CA").c_str());
	char* myCertFile = strdup (configFile.getValueOf("Certificate").c_str());
	char* myKeyFile = strdup (configFile.getValueOf("PrivateKey").c_str());

	OpenSSLSocket* socket = new OpenSSLSocket (caCertFile, 0, myCertFile, myKeyFile,0);

	if (socket->hasError())
	{
		cout << socket->getErrorMessage() << endl;
		free(caCertFile);
		free(myCertFile);
		free(myKeyFile);
		delete addressPort;
		delete socket;
		return -1;
	}

	socket->setValidCipherList("DHE-RSA-AES256-SHA");

	for (int i=1; i < argc; i++)
	{
		if (i !=addressPortIndex-1 && i !=addressPortIndex)
		{
			command += argv [i];
			if (i != argc - 1)
				command += ' ';
		}
	}

	// send the command to remote hosts
	if (broadcast)
	{
		std::map <std::string, std::string> keyValueMap = configFile.getAll();
		std::map <std::string, std::string>::iterator m;
		delete addressPort;
		for (m=keyValueMap.begin(); m != keyValueMap.end(); ++m)
		{
			if ((m->first).substr(0,8) == "[remote]")
			{
				char* ipPort = strdup((m->second).c_str());
				socket ->connect (ipPort);
				if (socket->hasError())
				{
					cout << socket->getErrorMessage () <<endl;
					free(ipPort);
					free(caCertFile);
					free(myCertFile);
					free(myKeyFile);
					delete socket;
					return -1;
				}
				cout <<"trying command '" << command <<"' on remote host "<<ipPort<<"..."<<endl;
				socket->writeString (command);

			}
		}
	}
	else
	{
		socket ->connect (argv [addressPortIndex]);
		if (socket->hasError())
		{
			// perhaps it's an alias name
			std::string str = configFile.getValueOf("[remote] " + *addressPort);
			char* ipPort = strdup (str.c_str());
			//cout << "debug: IPPort: " <<ipPort <<endl;
			socket ->reConnect (ipPort);
			if (socket->hasError())
			{
				cout << socket->getErrorMessage () <<endl;
				free(caCertFile);
				free(myCertFile);
				free(myKeyFile);
				delete socket;
				delete addressPort;
				return -1;
			}
			else
			{
				delete addressPort;
				addressPort = new std::string (str);
			}
		}
		cout <<"trying command '" << command <<"' on remote host "<<*addressPort <<"..."<<endl;
		socket->writeString (command);
		OpenSSLCertificate* peerCert = socket ->getPeerCertificate();

		int size = peerCert-> getSubjectInfoSize ();
		cout << "Server Info:" << endl;
		Name** test = peerCert->getSubjectInfo();
		for (int i=0; i<size; i++)
		{
			if (i!= size -1)
				cout<< test [i]->longName << " (" << test [i]->shortName << "): " << test [i]->value <<"/";
			else
				cout<< test [i]->longName << " (" << test [i]->shortName << "): " << test [i]->value <<endl;
		}

		size = peerCert-> getIssuerInfoSize ();

		cout << "Issuer of Server Info:" << endl;
		Name** t = peerCert->getIssuerInfo();
		for (int i=0; i<size; i++)
		{
			if (i!=size -1)
				cout << t[i]->longName << " (" << t[i]->shortName << "): " << t [i]->value <<"/";
			else
				cout << t[i]->longName << " (" << t[i]->shortName << "): " << t [i]->value <<endl;
		}
	}


	free(caCertFile);
	free(myCertFile);
	free(myKeyFile);

	delete socket;
	delete addressPort;
	return 0;
}
