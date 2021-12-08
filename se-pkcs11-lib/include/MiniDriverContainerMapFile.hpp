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
#ifndef __GEMALTO_MINIDRIVER_CONTAINER_MAP_FILE__
#define __GEMALTO_MINIDRIVER_CONTAINER_MAP_FILE__

#ifndef NO_FILESYSTEM
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/serialization/array.hpp>
#include <boost/archive/archive_exception.hpp>
#endif

#include <array>
#include <boost/shared_ptr.hpp>
#include <string>
#include "MiniDriverContainer.hpp"
#include "Array.h"
#include "MiniDriverModuleService.hpp"


const int g_MaxContainer = 15;


class MiniDriverFiles;


/*
*/
class MiniDriverContainerMapFile {

public:

    static unsigned char CONTAINER_INDEX_INVALID;

	MiniDriverContainerMapFile( const MiniDriverAuthentication& authentication) : m_Authentication(authentication)  { }    

	inline void setMiniDriverFiles( MiniDriverFiles* p ) { m_MiniDriverFiles = p; }
    void clear( void );
    void containerDelete( const unsigned char&, const unsigned char& );
    inline MiniDriverContainer& containerGet( const unsigned char& a_ucContainerIndex ) { if( a_ucContainerIndex > g_MaxContainer ) { throw MiniDriverException( ); } return m_Containers[ a_ucContainerIndex ]; }

    void containerSearch( MiniDriverAuthentication::ROLES,unsigned char& );
    void containerSearch( MiniDriverAuthentication::ROLES,unsigned char&, MiniDriverAuthentication::ROLES& );

    inline const MiniDriverContainer* containerGet( void ) { return m_Containers; }

    void containerRead( void );
    void containerCreate( MiniDriverAuthentication::ROLES, unsigned char&, const bool&, unsigned char&, u1Array*, const int&, u1Array* );
    void containerSetDefault( const unsigned char&, const bool& );
    bool containerGetMatching( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, const u1Array* a_pPublicKeyModulus );
    inline unsigned char containerCount( void ) { return (unsigned char)g_MaxContainer; }
    inline void containerSetTypeForSignatureKey( const unsigned char& a_ucContainerIndex, const unsigned char& a_ContainerTypeForSignatureKey ) { m_Containers[ a_ucContainerIndex ].setContainerTypeForSignatureKey( a_ContainerTypeForSignatureKey ); }
    inline void containerSetTypeForExchangeKey( const unsigned char& a_ucContainerIndex, const unsigned char& a_ContainerTypeForExchangeKey ) { m_Containers[ a_ucContainerIndex ].setContainerTypeForExchangeKey( a_ContainerTypeForExchangeKey ); }
    inline void containerSetPinIdentifier( const unsigned char& a_ucContainerIndex, const MiniDriverAuthentication::ROLES& a_ContainerPinIdentifier ) { m_Containers[ a_ucContainerIndex ].setPinIdentifier( a_ContainerPinIdentifier ); }
    inline bool containerIsImportedSignatureKey( const unsigned char& a_ucContainerIndex ) { return m_Containers[ a_ucContainerIndex ].isImportedSignatureKey( ); }
    inline bool containerIsImportedExchangeKey( const unsigned char& a_ucContainerIndex ) { return m_Containers[ a_ucContainerIndex ].isImportedExchangeKey( ); }
    inline MiniDriverAuthentication::ROLES containerGetPinIdentifier( const unsigned char& a_ucContainerIndex ) { return m_Containers[ a_ucContainerIndex ].getPinIdentifier( ); }
    unsigned char containerGetFree( void );
 
    // void print( void );

    void containerUpdatePinInfo( void );

	inline bool Validate () { 
		for (size_t i = 0; i < g_MaxContainer; i++)
			if (!m_Containers[i].Validate())
				return false;
		return true; 
	}

private:

    std::string computeContainerName( const unsigned char* a_pBuffer, const size_t& a_BufferLength );

    void write( void );

    // Containers managed by the MiniDriver
	MiniDriverContainer m_Containers [ g_MaxContainer ];
	u1ArraySerializable m_ContainerMapFileBinary;
    MiniDriverFiles* m_MiniDriverFiles;
    const MiniDriverAuthentication& m_Authentication;

	///////////////////////////
	// Disk cache management //
	//////////////////////////

#ifndef NO_FILESYSTEM

	// Disk serialization and deserialization
    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int version ) {

        //Log::begin( "MiniDriverContainerMapFile::serialize" );
       if (version < 128)
          throw boost::archive::archive_exception(boost::archive::archive_exception::unsupported_class_version);

        ar & m_Containers;
        //print( );

        ar & (m_ContainerMapFileBinary);
		Log::logCK_UTF8CHAR_PTR ( "Container Map File Binary", m_ContainerMapFileBinary.GetBuffer( ), m_ContainerMapFileBinary.GetLength( ) );

        //Log::end( "MiniDriverContainerMapFile::serialize" );
    }

#endif
};

#ifndef NO_FILESYSTEM
BOOST_CLASS_VERSION( MiniDriverContainerMapFile, 128 )
#endif

#endif // __GEMALTO_CARD_CACHE__
