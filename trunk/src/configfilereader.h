#ifndef configfilereader_h
#define configfilereader_h

#include <iostream>
#include <map>
#include <fstream>

using namespace std;

class ConfigFileReader
{
	private:
		void stripComments (std::string &str);
		
		/*
		* processes the line and adds the key-value pair to the map. Or raise error if happens 
		*/
		void processLine (std::string &str);
		
		bool error;
		std::string errorMessage;
		std::map <std::string,std::string>* keyValueMap;
		std::fstream configFile;
		void trimString (std::string &str);
	public:
		
		std::string getValueOf(std::string key);
		
		std::map <std::string,std::string> getAll ();
			
		bool hasError () {return error;};
		std::string getErrorMessage () {return errorMessage;};
		
		ConfigFileReader(std::string fileName);
		~ConfigFileReader();


};

#endif
