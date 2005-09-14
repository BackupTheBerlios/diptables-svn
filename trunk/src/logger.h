#ifndef logger_h
#define logger_h

#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

class Logger
{
	private:
		enum LogFileState
		{
			NonExistant, NotFull, Full
		};
		string file1;
		string file2;
		fstream currentFile;
		
		int microSize;
		int macroSize;
		int maxSize;
		
		bool error;
		std::string errorMessage;
		
		void rotate();
	public:
		bool hasError() {return error;};
		std::string getErrorMessage () {return errorMessage;};
		
		void log (std::string str);
		void log (char* str) {log (*(new std::string(str)));};
		Logger(string path, int size);
		~Logger();
};

#endif
