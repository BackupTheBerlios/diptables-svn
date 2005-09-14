#include "configfilereader.h"

void ConfigFileReader::processLine (std::string &str)
{
	if (str=="")
		return;
	int index = str.find ('=');
	
	if (index == 0 || index == str.size())
	{
		error = true;
		errorMessage = "Invalid line in config file";
		return;
	}
	
	std::string key = str.substr (0 , index);

	std::string value = str.substr (index + 1, str.size()-index-1);
	
	trimString(key);
	trimString(value);
	
		
	if (key == "" || value == "")
	{
		error = true;
		errorMessage = "Invalid line in config file";
		return;
	}
	
	(*keyValueMap) [key] = value;
}

void ConfigFileReader::stripComments (std::string &str)
{
	if (str=="")
		return;
	int index = str.find('#');
	if (index >= 0)
		str.erase (index, str.size() - index);
}

void ConfigFileReader::trimString(std::string &str)
{
	if (str=="")
		return;
		
	int i=0;
	while (i<str.size() && (str [i]=='\n' || str [i]=='\t' || str [i]==' '))
	{
		i++;
	}
	str.erase (0,i);
	
	i=str.size()-1;
	while (i>0 && (str [i]=='\n' || str [i]=='\t' || str [i]==' '))
	{
		i--;
	}
	str.erase (i+1, str.size()-i-1);
	
}

std::string ConfigFileReader::getValueOf(std::string key)
{
	if (keyValueMap->find (key)== keyValueMap->end())
		return "";
	else
		return (*keyValueMap) [key];
}

ConfigFileReader::ConfigFileReader(std::string fileName)
{
	error = false;
	errorMessage = "";
	keyValueMap = new std::map <std::string,std::string>;
	
	configFile.open(fileName.c_str(), ios::in);
	
	if (!configFile.is_open())
	{
		error = true;
		errorMessage = "The config file could not be opened";
		configFile.close();
		return;
	}
	
	std::string* line;
	
	char buff [1024];	
	while (!configFile.eof())
	{
		memset (buff, 0, 1024);
		configFile.getline (buff,1024);
		
		line = new std::string (buff);
		
		stripComments (*line);
		
		trimString (*line);
		
		if ((*line)!="" && (*line)[0]!='#')
		{
//			std::cout <<"debug: "<< *line << std::endl;
			processLine (*line);
		
		}
		delete line;
		line =0;
	}
}

ConfigFileReader::~ConfigFileReader()
{
	configFile.close();
	delete keyValueMap;
}

std::map <std::string,std::string> ConfigFileReader:: getAll()
{
	std::map <std::string,std::string> returnValue = *keyValueMap;
	return returnValue;
}
