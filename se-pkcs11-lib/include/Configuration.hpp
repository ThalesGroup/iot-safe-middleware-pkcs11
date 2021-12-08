/*
*  PKCS#11 library for IoT Safe
*  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
*  Copyright (C) 2009-2021 Thales
*
*  This library is free software; you can redistribute it and/or
*  modify it under the terms of the GNU Lesser General Public
*  License as published by the Free Software Foundation; either
*  version 2.1 of the License, or (at your option) any later version.
*
*  This library is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*  Lesser General Public License for more details.
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
*/
#ifndef __CONFIGURATION_H__
#define __CONFIGURATION_H__


#include <map>
#include <string>


// A entry is a map of {key,value} pair
typedef std::pair<std::string, std::string> TEntryPair;

// A section is a map of {key,value} pairs (an entry)
typedef std::map<std::string, std::string> TSection;
typedef TSection::iterator TSectionIterator;

// A Configuration is a map of sections
typedef std::map<std::string, TSection> TConfiguration;
typedef TConfiguration::iterator TConfigurationIterator;
typedef std::pair<std::string, TSection> TConfigurationPair;


/*
*/
class Configuration
{

public:
	
	Configuration( ); // Constructor is hidden

	void load( const std::string& szConfigurationFileName );
	void getValue( const std::string& sectionName, const std::string& parameterName, std::string &result );
	void getConfigurationFilePath( std::string &result );
	bool checkSection( const std::string& sectionName );

private:

	std::string m_szConfigurationfilePath;
	TConfiguration m_configuration;

	void strip( const std::string& str, std::string &result, const std::string& what = " \t\0\n" );
	bool parse( const std::string& configurationFileName );
	std::string::size_type findComment( const std::string& str );
	bool findTag( std::string::size_type& start, std::string::size_type& end, const std::string& str );
	bool isSection( const std::string& str );
	bool isKey( const std::string& str );
	void getKeyName( const std::string& str, std::string &result );
	void getKeyValue( const std::string& str, std::string &result );
	void getSectionName( const std::string& str, std::string &result );
	void suppressAllOccurencesOfThisCharacter( const std::string& s, char c, std::string& result );

};

#endif // __CONFIGURATION_H__
