#include <stdlib.h>
#include <iostream> 

using namespace std;

int main (int argc, char* argv[])
{
	if (argc != 2)
	{
		cout <<"Usage: diptablesd start|stop|restart" <<endl;
		return -1;
	}
	string command (argv[1]);
	
	if (command == "start")
	{
		system ("/usr/local/diptables/bin/diptablesserver &");
	}
	else if (command=="stop")
	{
		system ("killall -SIGUSR1 diptablesserver");
	}
	else if (command=="restart")
	{
		system ("killall -SIGUSR1 diptablesserver");
		system ("/usr/local/diptables/bin/diptablesserver &");
	}
	else 
	{
		cout <<"Usage: diptablesd start|stop|restart" <<endl;
		return -1;
	}
	return 0;
}

