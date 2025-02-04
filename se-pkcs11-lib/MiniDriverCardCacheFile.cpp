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
#ifdef WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <Windows.h>
#endif

#include "util.h"
#include "MiniDriver.hpp"
#include "MiniDriverCardCacheFile.hpp"
#include "Log.hpp"
#include "MiniDriverException.hpp"
#include "Timer.hpp"

const unsigned char MAX_RETRY = 2;


/*
*/
void MiniDriverCardCacheFile::write( void ) {

   u4 cardcfSize = 6;
   std::string g_stPathCardCF( szCACHE_FILE );
   try
   {
      // Get the file from the smart card in order to keep its size the same
      std::unique_ptr<u1Array> ba(m_pCardModuleService->getFileProperties(&g_stPathCardCF));

      u4 b0 = ba->ReadU1At(3);
      u4 b1 = ba->ReadU1At(4);
      u4 b2 = ba->ReadU1At(5);
      u4 b3 = ba->ReadU1At(6);

      cardcfSize =  b3 << 24;
      cardcfSize |= (b2 << 16);
      cardcfSize |= (b1 << 8);
      cardcfSize |= b0;           
    }
    catch(...)
    {}
	
   std::unique_ptr<u1Array> f;

   if (cardcfSize != 6)
   {
      try
      {
         f.reset(m_pCardModuleService->readFileWithoutMemoryCheck( &g_stPathCardCF ));
      }
      catch (...) {}

      if (!f.get())
      {
          // Create a buffer to write the file oncard
          f.reset( new u1Array( 6 ) );
      }
      else if (f->GetLength() < 6)
         f->Resize(6);
   }
   else
      f.reset( new u1Array( 6 ) );

    // Set the version flag
    f->SetU1At( 0, m_ucVersion );

    // Set the PIN freshness counter
    f->SetU1At( 1, m_ucPinsFreshness );

    // Set the container freshness counter
    IntToLittleEndian< unsigned short >( m_wContainersFreshness, f->GetBuffer( ), 2 );

    // Set the file freshness counter
    IntToLittleEndian< unsigned short >( m_wFilesFreshness, f->GetBuffer( ), 4 );

    // Write cache file back
    m_pCardModuleService->writeFile( &g_stPathCardCF, f.get( ) );
}


/*
*/
void MiniDriverCardCacheFile::notifyChange( const ChangeType& a_change ) {

    switch( a_change ) {

    case PINS:
        m_ucPinsFreshness++;
        Log::log( "MiniDriverCardCacheFile::notifyChange - PINS" );
        break;

    case CONTAINERS:
        m_wContainersFreshness++;
        Log::log( "MiniDriverCardCacheFile::notifyChange - CONTAINERS" );
        break;

    case FILES:
        m_wFilesFreshness++;
        Log::log( "MiniDriverCardCacheFile::notifyChange - FILES" );
        break;

    case NONE:
    default:
        // No update
        break;
    };

    write( );
}


/*
*/
void MiniDriverCardCacheFile::hasChanged( ChangeType& a_Pins, ChangeType& a_Containers, ChangeType& a_Files ) {

    Log::begin( "MiniDriverCardCacheFile::hasChanged" );
    Timer t;
    t.start( );

    a_Pins = NONE;
    a_Containers = NONE;
    a_Files = NONE;

    Log::log( "MiniDriverCardCacheFile::hasChanged - Inner Version <%#02x>", m_ucVersion );
    Log::log( "MiniDriverCardCacheFile::hasChanged - Inner PIN freshness counter <%#02x>", m_ucPinsFreshness );
    Log::log( "MiniDriverCardCacheFile::hasChanged - Inner Containers freshness counter <%#04x>", m_wContainersFreshness );
    Log::log( "MiniDriverCardCacheFile::hasChanged - Inner Files freshness counter <%#04x>", m_wFilesFreshness );

    // Get the file from the smart card
	std::string g_stPathCardCF( szCACHE_FILE );
   std::unique_ptr<u1Array> f(m_pCardModuleService->readFileWithoutMemoryCheck( &g_stPathCardCF ));

    if( f.get() ) {

        std::string s;
        Log::toString( f->GetBuffer( ), f->GetLength( ), s );
        Log::log( "MiniDriverCardCacheFile::hasChanged - cardcf <%s>", s.c_str( ) );

        // Get the version
        unsigned char ucVersion = f->ReadU1At( 0 );
        Log::log( "MiniDriverCardCacheFile::hasChanged - Read Version <0x%#02x>", ucVersion );
        
        if( !m_bInitialized || (ucVersion != m_ucVersion )) {
        
            m_ucVersion = ucVersion;
        }

        // Get the PIN freshness counter
        unsigned char bPinsFreshness = f->ReadU1At( 1 );
        Log::log( "MiniDriverCardCacheFile::hasChanged - Read PIN freshness counter <%#02x>", bPinsFreshness );

        if( !m_bInitialized || (m_ucPinsFreshness != bPinsFreshness) ) {

            Log::log( "MiniDriverCardCacheFile::hasChanged - $$$$$ PIN freshness counter changed $$$$$" );
            m_ucPinsFreshness = bPinsFreshness;
            a_Pins = PINS;
        }

        // Get the container freshness counter
        unsigned short wContainersFreshness = LittleEndianToInt< unsigned short >( f->GetBuffer( ), 2 );
        Log::log( "MiniDriverCardCacheFile::hasChanged - Read Containers freshness counter <%#02x>", wContainersFreshness );

        if( !m_bInitialized || (m_wContainersFreshness != wContainersFreshness) ) {

            Log::log( "MiniDriverCardCacheFile::hasChanged - $$$$$ CONTAINER freshness counter changed $$$$$" );
            m_wContainersFreshness = wContainersFreshness;
            a_Containers = CONTAINERS;
        }

        // Get the file freshness counter
        unsigned short wFilesFreshness = LittleEndianToInt< unsigned short >( f->GetBuffer( ), 4 );
        Log::log( "MiniDriverCardCacheFile::hasChanged - Read Files freshness counter <%#02x>", wFilesFreshness );

        if( !m_bInitialized || (m_wFilesFreshness != wFilesFreshness) ) {

            Log::log( "MiniDriverCardCacheFile::hasChanged - $$$$$ FILE freshness counter changed $$$$$" );
            m_wFilesFreshness = wFilesFreshness;
            a_Files = FILES;
        }

		m_bInitialized = true;
    }

    t.stop( "MiniDriverCardCacheFile::read" );
    Log::end( "MiniDriverCardCacheFile::read" );
}


/*** 
	For debugging session only 
**/
/*
void MiniDriverCardCacheFile::print( void ) {
    
    Log::begin( "MiniDriverCardCacheFile::print" );
    Log::log( "Version <%ld>", m_ucVersion );
    Log::log( "m_ucPinsFreshness <%ld>", m_ucPinsFreshness );
    Log::log( "m_wContainersFreshness <%ld>", m_wContainersFreshness );
    Log::log( "m_wFilesFreshness <%ld>", m_wFilesFreshness );
    Log::end( "MiniDriverCardCacheFile::print" );
}
*/
