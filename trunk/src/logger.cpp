#include "logger.h"

Logger::Logger(std::string path, int size)
{
	error = false;
	maxSize = size;
	microSize=0;
	struct stat pathStat;
	stat (path.c_str(), &pathStat);
	if (!S_ISDIR(pathStat.st_mode))
	{
		error = true;
		errorMessage = "Invalid directory for logging";
		return;
	}
	
	file1 = "1.log";
	file2 = "2.log";

	if (path [path.size()-1]!='/')
	{
		file1 = path + "/" + file1;
		file2 = path + "/" + file2;
	}
	else
	{
		file1 = path + file1;
		file2 = path + file2;
	}
	
	rotate();
}

void Logger::log (std::string str)
{
	currentFile << str;
	currentFile.flush();
	int thisSize = str.size();
	
	macroSize = macroSize + (microSize + thisSize)/1024;
	microSize = (microSize + thisSize)%1024;
	
	if (macroSize >= maxSize)
	{
		currentFile.close();
		rotate();
	}
}

void Logger::rotate ()
{
	Logger::LogFileState state1, state2;
	int size1 = 0;
	int size2 = 0;
	fstream logFile1;
	fstream logFile2;
	struct stat stat1;
	struct stat stat2;
	
	logFile1.open (file1.c_str() ,ios::in);
	if (!logFile1.is_open())
		state1 = Logger::NonExistant;
	else
	{
		stat (file1.c_str(), &stat1);
		size1 = stat1.st_size;
		if (size1 >= (maxSize * 1024 )/ 2)
			state1 = Logger::Full;
		else
			state1 = Logger::NotFull;
	}
	logFile1.close();
	
	logFile2.open (file2.c_str() ,ios::in);
	if (!logFile2.is_open())
		state2 = Logger::NonExistant;
	else
	{
		stat (file2.c_str(), &stat2);
		size2 = stat2.st_size;
		if (size2 >= (maxSize*1024) / 2)
			state2 = Logger::Full;
		else
			state2 = Logger::NotFull;
	}
	logFile2.close();

	//size1 = size1/1024;
	//size2 = size2/1024;
	
	if (state2==Logger::NonExistant)
	{
		if (state1==Logger::Full)
		{
			currentFile.open(file2.c_str(), ios::app | ios::out);
			macroSize = size2/1024;
			microSize = size2%1024;
		}
		else
		{
			currentFile.open(file1.c_str(), ios::app | ios::out);
			macroSize = size1/1024;
			microSize = size1%1024;
		}
	}
	else if (state2==Logger::NotFull)
	{
		if (state1!=Logger::NotFull)
		{
			currentFile.open(file2.c_str(), ios::app | ios::out);
			macroSize = size2/1024;
			microSize = size2%1024;
		}
		else
		{
			system (("rm -f " + file2).c_str());
			currentFile.open(file1.c_str(), ios::trunc | ios::out);
			macroSize = microSize = 0;
		}
	}
	else if (state1==Logger::Full)
	{
		currentFile.open(file1.c_str(), ios::trunc | ios::out);
		macroSize = microSize=0;
	}
	else
	{
		currentFile.open(file1.c_str(), ios::app | ios::out);
		macroSize = size1/1024;
		microSize = size1%1024;
	}
}

Logger::~Logger()
{
	if (currentFile.is_open())
		currentFile.close();	
}
