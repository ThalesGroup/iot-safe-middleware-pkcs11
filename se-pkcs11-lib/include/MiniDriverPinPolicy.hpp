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
#ifndef __GEMALTO_PIN_POLICY__
#define __GEMALTO_PIN_POLICY__

#include <boost/foreach.hpp>
#include <memory>
#include "MiniDriverModuleService.hpp"


const unsigned char g_PolicyLength = 14;
const unsigned char PARAMETER_KEY_MAX_ATTEMPS  = 0;
const unsigned char PARAMETER_KEY_MIN_LENGTH  = 1;
const unsigned char PARAMETER_KEY_MAX_LENGTH  = 2;
const unsigned char PARAMETER_KEY_CHAR_SET  = 3;
const unsigned char PARAMETER_KEY_COMPLEXITY_RULE_1  = 4;
const unsigned char PARAMETER_KEY_COMPLEXITY_RULE_2  = 5;
const unsigned char PARAMETER_KEY_ADJACENT_ALLOWED = 6;
const unsigned char PARAMETER_KEY_HISTORY = 7;
const unsigned char PARAMETER_KEY_ALLOW_UNBLOCK = 8;
const unsigned char PARAMETER_KEY_ALLOW_SSO = 9;
const unsigned char PARAMETER_KEY_ONE_OF_EACH_CHAR_SET = 10;
const unsigned char PARAMETER_KEY_MANDATORY_CHAR_SET = 11;
const unsigned char PARAMETER_KEY_MAX_SEQUENCE_LEN = 12;
const unsigned char PARAMETER_KEY_MAX_ADJACENT_NB = 13;

const unsigned char PARAMETER_VALUE_MIN_LENGTH = 4;
const unsigned char PARAMETER_VALUE_MAX_LENGTH = 255;

/*
*/
class MiniDriverPinPolicy {

public:

    MiniDriverPinPolicy( ) { reset( ); }

    inline void setCardModuleService( MiniDriverModuleService* a_pCardModule ) { m_CardModule = a_pCardModule; }

    void read( unsigned char a_ucRole  );

    inline const unsigned char& getMaxAttemps( void ) { return get( PARAMETER_KEY_MAX_ATTEMPS ); }
    inline const unsigned char& getPinMinLength( void ) { return get( PARAMETER_KEY_MIN_LENGTH ); }
    inline const unsigned char& getPinMaxLength(  void ) { return get( PARAMETER_KEY_MAX_LENGTH ); }
    inline const unsigned char& getCharSet( void ) { return get( PARAMETER_KEY_CHAR_SET ); }
    inline const unsigned char& getComplexityRule1( void ) { return get( PARAMETER_KEY_COMPLEXITY_RULE_1 ); }
    inline const unsigned char& getComplexityRule2( void ) { return get( PARAMETER_KEY_COMPLEXITY_RULE_2 ); }
    inline const unsigned char& getAdjacentAllowed( void ) { return get( PARAMETER_KEY_ADJACENT_ALLOWED ); }
    inline const unsigned char& getHistory( void ) { return get( PARAMETER_KEY_HISTORY ); }
    inline const unsigned char& getAllowUnblock( void ) { return get( PARAMETER_KEY_ALLOW_UNBLOCK ); }
    inline const unsigned char& getAllowSSO( void ) { return get( PARAMETER_KEY_ALLOW_SSO ); }
    inline const unsigned char& getOneCharForEachCharSet( void ) { return get( PARAMETER_KEY_ONE_OF_EACH_CHAR_SET ); }
    inline const unsigned char& getMandatoryCharSet( void ) { return get( PARAMETER_KEY_MANDATORY_CHAR_SET ); }
    inline const unsigned char& getMaxSequenceLen( void ) { return get( PARAMETER_KEY_MAX_SEQUENCE_LEN ); }
    inline const unsigned char& getMaxAdjacent( void ) { return get( PARAMETER_KEY_MAX_ADJACENT_NB ); }
    inline bool empty( void ) { BOOST_FOREACH( unsigned char& e, m_ucaPinPolicy ) { if( e ) { return false; } } return true; }

    void print( void );

protected:

    inline void reset( void ) { memset( m_ucaPinPolicy, 0, sizeof( m_ucaPinPolicy ) ); }
    inline void set( unsigned char const & a_ucParameterIndex, unsigned char const & a_ucParameterValue ) { m_ucaPinPolicy[ a_ucParameterIndex ] = a_ucParameterValue; }
    inline unsigned char & get( unsigned char const &a_ucParameterIndex ) { return m_ucaPinPolicy[ a_ucParameterIndex ]; }
    void write( void );

    MiniDriverModuleService* m_CardModule;

	unsigned char m_ucaPinPolicy[g_PolicyLength];
};


#endif // __GEMALTO_PIN_POLICY__
