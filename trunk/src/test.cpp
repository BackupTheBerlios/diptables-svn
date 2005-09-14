#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h> // for debugging

#include "logger.h"

using namespace std;

sig_atomic_t stillContinue = 1;

void terminatHandler (int signalNumber)
{
	stillContinue = 0;
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
	//regiterSignal ();
	Logger logger ("/root/projects/diptables/log", 4);
	
	if (logger.hasError())
		cout << logger.getErrorMessage() <<endl;
	
	//cout <<"debug: lien" <<30<<endl;
	for (int i =0; i < 10; i++)
		logger.log ("in the name of Allah");
	
}
