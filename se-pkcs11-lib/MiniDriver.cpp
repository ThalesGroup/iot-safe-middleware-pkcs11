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
#ifndef NO_FILESYSTEM
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#endif
#include <boost/shared_array.hpp>
#include <boost/foreach.hpp>
#include <boost/crc.hpp>
#include "MiniDriver.hpp"
#include "Log.hpp"
#include "Except.h"
#include "MiniDriverException.hpp"
#include "util.h"
#include "zlib.h"
#include "MiniDriverModuleService.hpp"

#ifdef WIN32 
#include <shlobj.h> // For SHGetFolderPath
#else
#endif
#include <fstream>
#include <openssl/x509v3.h>

#include "filesystem.h"
#include "PCSCMissing.h"


const unsigned MiniDriver::s_iMinLengthKeyRSA = 512;
const unsigned MiniDriver::s_iMaxLengthKeyRSA = 2048;
const unsigned MiniDriver::s_iMinLengthKeyECC = 256;
const unsigned MiniDriver::s_iMaxLengthKeyECC = 521;

#define BLOCK_SIZE 1024


/*
*/
void MiniDriver::read( const bool& a_bEnableDiskCache ) {

   Log::begin( "MiniDriver::read" );
   Timer t;
   t.start( );

   Log::log( "MiniDriver::read - Cache enabled = %s", a_bEnableDiskCache? "TRUE" : "FALSE");

#ifdef NO_FILESYSTEM
   m_bEnableDiskCache = false;
#else
   m_bEnableDiskCache = a_bEnableDiskCache;
#endif

   try {
      // Read the smart card serial number
      getSerialNumber( );
      if( !m_u1aSerialNumber ) {
         m_stFileName = "";
         m_bEnableDiskCache = false;
      }

#ifndef NO_FILESYSTEM

	  if( m_bEnableDiskCache ) {
         try {
#ifdef WIN32 
            // For each user (roaming) data, use the CSIDL_APPDATA value. 
            // This defaults to the following path: "\Documents and Settings\All Users\Application Data" 
            TCHAR szPath[MAX_PATH];
            SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, szPath);
            std::string sCacheDirectoryPath = std::string (szPath) + std::string ("\\Gemalto\\PKCS11");

#else
            char *home = getenv ("HOME");
            std::string sCacheDirectoryPath;
            if (home)
               sCacheDirectoryPath = std::string (home) + std::string ("/.cache/Gemalto/PKCS11/");
            else
               sCacheDirectoryPath = std::string ("/tmp/Gemalto/PKCS11/");
#endif

			if (!isDirectoryExist (sCacheDirectoryPath)) {
			
               Log::log ("MiniDriver::read - cache directory <%s> doesn't exist. Creating it ...", sCacheDirectoryPath.c_str ());

			   if (!makePath (sCacheDirectoryPath)) {
                  std::string msg = "";
                  Log::toString (msg, "Cache directory creation failed ! <%s>", sCacheDirectoryPath.c_str ());
                  Log::error ("MiniDriver::read", msg.c_str ());
                  m_bEnableDiskCache = false;
               }
            }
            else
            {
               Log::log ("MiniDriver::read - cache directory <%s> exists.", sCacheDirectoryPath.c_str ());
            }

            if( m_bEnableDiskCache ) {

               // Build the cache file name
               std::string sCacheFileName = "";
               toString (m_u1aSerialNumber->GetBuffer( ), m_u1aSerialNumber->GetLength( ), sCacheFileName );
               sCacheFileName += std::string( ".p11" );
               m_stFileName = sCacheDirectoryPath + std::string( "/" ) + sCacheFileName;
               Log::log( "MiniDriver::read - Cache file <%s>", m_stFileName.c_str( ) );

               // Read the cache from the disk
               cacheDeserialize ();
            }
         }
         catch(...)
         {
            Log::log( "MiniDriver::read - Exception while trying to use cache on disk");
         }
      }
      else
      {
         Log::log( "MiniDriver::read - Cache disable in the configuration");
      }

#endif

      // by defaul, we are on a dynamic profile
      m_bIsStaticProfile = false;
      if (GetCardModel() == JAVA_STUB)
      {
         m_bIsStaticProfile = !m_CardModule->IsPlusCard();

         Log::log( "MiniDriver::read - MD card static profile = %s", m_bIsStaticProfile? "TRUE" : "FALSE");
      }

      m_Files.setStaticProfile(m_bIsStaticProfile);

      MiniDriverCardCacheFile::ChangeType p = MiniDriverCardCacheFile::NONE;
      MiniDriverCardCacheFile::ChangeType c = MiniDriverCardCacheFile::NONE;
      MiniDriverCardCacheFile::ChangeType f = MiniDriverCardCacheFile::NONE;

	  Log::log( "MiniDriver::read - Before MiniDriverFiles::hasChanged ...");
      m_Files.hasChanged( p, c, f );
	  Log::log( "MiniDriver::read - Before MiniDriverFiles::containerUpdatePinInfo ...");
      m_Files.containerUpdatePinInfo();

      m_Authentication.read( );

      if (m_bIsStaticProfile)
      {
         std::list<u1> usableRoles;
         m_CardModule->getStaticRoles(usableRoles);
         m_Authentication.setStaticRoles(usableRoles);
      }

      m_CardModule->SetPinPadSupported (m_Authentication.isPinPadSupported());

   } catch( ... ) {

      Log::log("MiniDriver::read - Exception");
   }

   t.stop( "MiniDriver::read" );
   Log::end( "MiniDriver::read" );
}


/* Store the files, the file list and the containers into a disk file
*/
void MiniDriver::cacheSerialize( void ) {

#ifndef NO_FILESYSTEM

	// Cache enabled/disbled
   if( !m_bEnableDiskCache ) {
      return;
   }

   // Name of the cache
   if( m_stFileName.empty( ) ) {
      return;
   }

   //m_Files.print( );
   //m_Authentication.print( );

   m_Files.cacheDisableWrite( );

   Log::begin( "MiniDriver::cacheSerialize" );
   Timer t;
   t.start( );

   std::ofstream ofs( m_stFileName.c_str( ), std::ios_base::out | std::ios_base::binary | std::ios_base::trunc );

   if( ofs.is_open( ) ) {

      // Write class instance to archive. Writing seems to work ok.
      boost::archive::text_oarchive oa( ofs );

      const MiniDriver& m = (MiniDriver&)*this;

      oa << m;
      ofs.flush( );
      ofs.close( );
   }

   boost::crc_32_type::value_type computedValue = 0;

   std::ifstream ifs( m_stFileName.c_str( ), std::ios::in | std::ios::binary );

   if( ifs.is_open( ) ) {

      // Get the length of the file
      ifs.seekg( 0, std::ios::end );

      unsigned int l = (unsigned int)ifs.tellg( );

      // Read the whole file
      ifs.seekg( 0, std::ios::beg );
      std::unique_ptr< char > p( new char[ l ] );
      ifs.read( p.get( ), l );

      // Compute the CRC of the file
      boost::crc_32_type computedCRC; 
      computedCRC.process_bytes( p.get( ), l );
      computedValue = computedCRC.checksum( ); 

      ifs.close( );
   }

   // Add the CRC to the file
   ofs.open( m_stFileName.c_str( ), std::ios::in | std::ios::binary );

   if( ofs.is_open( ) ) {

      ofs.seekp( 0, std::ios::end );

      // ofs << computedValue;
      ofs.write( (char*)&computedValue, sizeof( computedValue ) );
      ofs.flush( );
      ofs.close( );
   }

   // m_Files.print( );
   // m_Authentication.print( );

   t.stop( "MiniDriver::cacheSerialize" );
   Log::end( "MiniDriver::cacheSerialize" );

#endif			// NO_FILESYSTEM
}


#ifndef NO_FILESYSTEM

/* Load the files, the file list and the containers from a disk file
*/
void MiniDriver::cacheDeserialize( void ) {

   if( !m_bEnableDiskCache ) {
      return;
   }

   if( m_stFileName.empty( ) ) {
      return;
   }

   Log::begin( "MiniDriver::cacheDeserialize" );
   Timer t;
   t.start( );

   boost::crc_32_type::value_type readValue = 0; 

   std::ifstream ifs( m_stFileName.c_str( ), std::ios::in | std::ios::binary );

   if( ifs.is_open( ) ) {

      try {

         boost::archive::text_iarchive ia( ifs );

         MiniDriver& m = (MiniDriver&)*this;

         // Read the cache from the file
         ia >> m;

         // Read the CRC from the file
         ifs.seekg( 0, std::ios::end );
         unsigned int l = (unsigned int)ifs.tellg( ) - 4;
         ifs.seekg( l, std::ios::beg );

         ifs.read( (char*)&readValue, sizeof( readValue ) );

         ifs.close( );

		 if (!m.Validate())
		 {
			 Log::error( "MiniDriver::cacheDeserialize", "MiniDriver instance validation failed" );
			 throw MiniDriverException( SCARD_E_INVALID_VALUE );
		 }

      } catch( ... ) {

         Log::error( "MiniDriver::cacheDeserialize", "deserialization failed" );

         m_Files.clear( MiniDriverCardCacheFile::PINS );
         m_Files.clear( MiniDriverCardCacheFile::FILES );
         m_Files.clear( MiniDriverCardCacheFile::CONTAINERS );
         m_Files.clearCardCacheFile();

         ifs.close( );

         std::remove( m_stFileName.c_str( ) );
      }
   }

   // Compute the CRC of the file
   boost::crc_32_type::value_type computedValue = 0;

   ifs.open( m_stFileName.c_str( ), std::ios::in | std::ios::binary );

   if( ifs.is_open( ) ) {

      // Get the length of the file
      ifs.seekg( 0, std::ios::end );

      unsigned int l = (unsigned int)ifs.tellg( ) - 4;

      // Read the whole file
      ifs.seekg( 0, std::ios::beg );

      std::unique_ptr< char > p( new char[ l ] );

      ifs.read( p.get( ), l );

      // Compute the CRC of the file
      boost::crc_32_type computedCRC; 
      computedCRC.process_bytes( p.get( ), l );
      computedValue = computedCRC.checksum( ); 

      ifs.close( );
   }

   // Check the both CRC
   if( computedValue != readValue ) {

      // Clear the cache
      m_Files.clear( MiniDriverCardCacheFile::PINS );
      m_Files.clear( MiniDriverCardCacheFile::FILES );
      m_Files.clear( MiniDriverCardCacheFile::CONTAINERS );

      // Remove the cache file
      std::remove( m_stFileName.c_str( ) );
   }

   //m_Files.print( );
   //m_Authentication.print( );

   t.stop( "MiniDriver::cacheDeserialize" );
   Log::end( "MiniDriver::cacheDeserialize" );
}

#endif			// NO_FILESYSTEM


/*
*/
u1Array* MiniDriver::getCardID( void ) {

    u1Array* pRet = NULL;
    try {

        // Read the cardid file containing a unique 16-byte binary identifier for the smart card (GUID).
        std::string s( szCARD_IDENTIFIER_FILE );

        // std::unique_ptr< u1Array > f( m_CardModule->readFile( &s ) );
        std::string stDirectory;
        std::unique_ptr< u1Array > f( m_Files.readFileWithoutCheck( stDirectory, s ) );

        // Get the 12th last bytes as serial number
        pRet = new u1Array( *f, 4, 12 );

    } catch( MiniDriverException& ) {

    }

    return pRet;
}


/*
*/
u1Array* MiniDriver::getSerialNumber( void ) {

   Log::begin( "MiniDriver::getSerialNumber" );
   Timer t;
   t.start( );

   if( !m_u1aSerialNumber.get( ) ) {

      u1Array* pID = getCardID ();
      if (pID)
      {
         m_u1aSerialNumber.reset (pID);
         Log::logCK_UTF8CHAR_PTR( "MiniDriver::getSerialNumber - Serial number", m_u1aSerialNumber->GetBuffer( ), m_u1aSerialNumber->GetLength( ) );
     }

      //// Try first to load the serial number in a V2+ way
      //try {

      //    m_u1aSerialNumber.reset( m_CardModule->getCardProperty( CARD_SERIAL_NUMBER, 0 ) );

      //    Log::log( "MiniDriver::getSerialNumber - GetCardProperty" );

      //} catch( MiniDriverException& ) {

      //    Log::error( " MiniDriver::getSerialNumber", "No card property for the serial number" );

      //    try {

      //        // Try at last to get the serial number in a old V2 way
      //        m_u1aSerialNumber.reset( m_CardModule->getSerialNumber( ) );

      //        Log::log( "MiniDriver::getSerialNumber - getSerialNumber" );

      //    } catch( ... ) {

      //        Log::error( " MiniDriver::getSerialNumber", "Impossible to get the serial number" );
      //    }
      //}
   }

   t.stop( "MiniDriver::getSerialNumber" );
   Log::end( "MiniDriver::getSerialNumber" );

   return m_u1aSerialNumber.get( );
}


/*
*/
void MiniDriver::createFile(  const std::string& a_stDirectory, const std::string& a_stFile, const bool& a_bIsReadProtected ) {

   Log::begin( "MiniDriver::createFile" );
   Timer t;
   t.start( );

   u1Array ac( 3 );

   // Administrator access condition
   ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

   // User access condition
   ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

   // Everyone access condition
   ac.GetBuffer( )[ 2 ] = ( a_bIsReadProtected ? 0 : MiniDriverFiles::CARD_PERMISSION_READ );

   m_Files.createFile( a_stDirectory, a_stFile, &ac );

   cacheSerialize( );

   t.stop( "MiniDriver::createFile" );
   Log::end( "MiniDriver::createFile" );
}


/* If a container already exists using the same public key modulus then the container index will be updated with the index of this container.
The keyspec will also be updated. The file name will anyway build automaticaly
*/
void MiniDriver::createCertificate( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stCertificateName, u1Array* a_pValue, u1Array* a_pModulus, const bool& a_bSmartCardLogon ) {

   Log::begin( "MiniDriver::createCertificate" );
   Timer t;
   t.start( );

   a_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

   // Try to find a container using the same public key modulus. 
   // In this case the index & the key spec are updated and must be used.
   m_Files.containerGetMatching( role, a_ucContainerIndex, a_ucKeySpec, a_stCertificateName, a_pModulus );

   // No existing container uses that public key modulus. 
   if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_ucContainerIndex ) {

      // Find an empty container
      m_Files.containerSearch( role, a_ucContainerIndex );

      // No empty container 
      if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_ucContainerIndex ) {
         throw MiniDriverException( SCARD_E_WRITE_TOO_MANY );
      }
   }

   // Build the certificate name to associate it to the container 
   if (    (a_ucKeySpec == MiniDriverContainer::KEYSPEC_EXCHANGE)
      ||  (a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDHE_256)
      ||  (a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDHE_384)
      ||  (a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDHE_521)
      )
   {
      a_stCertificateName = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );
   }
   else
   {
      a_stCertificateName = std::string( szUSER_SIGNATURE_CERT_PREFIX );
   }

   Util::toStringHex( a_ucContainerIndex, a_stCertificateName );

   // compress the certificate
   unsigned long ccLen = a_pValue->GetLength( );

   boost::shared_array< unsigned char > cc( new unsigned char[ ccLen + 4 ] );
   cc[ 0 ] = 0x01;
   cc[ 1 ] = 0x00;
   cc[ 2 ] = (BYTE)( ccLen & 0xff ); // Put the low byte of the word
   cc[ 3 ] = (BYTE)( ( ccLen & 0xff00 ) >> 8 ); // Put the high byte of the word

   // Set compression level at 6, same as Minidriver
   compress2( (unsigned char*)&cc[ 4 ], &ccLen, a_pValue->GetBuffer( ), ccLen, 6 );

   u1Array compressedCert( ccLen + 4 );

   compressedCert.SetBuffer( cc.get( ) );

   u1Array ac( 3 );

   // Administrator access conditions
   ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

   // User access conditions
   ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

   // Everyone access conditions
   ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

   unsigned int uiFreeMem = m_CardModule->GetMemory();
   if (m_CardModule->HasMemoryBug() && (uiFreeMem < (compressedCert.GetLength() + 1024)))
   {
      throw MiniDriverException( SCARD_E_NO_MEMORY );
   }

   m_Files.createFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &ac );

   try
   {
      m_Files.writeFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &compressedCert );

      // Set the default certificate
      m_Files.containerSetDefault( a_ucContainerIndex, a_bSmartCardLogon );
   }
   catch(MiniDriverException& x)
   {
      m_Files.deleteFile(std::string( szBASE_CSP_DIR ), a_stCertificateName);
      throw x;
   }

   cacheSerialize( );

   t.stop( "MiniDriver::createCertificate" );
   Log::end( "MiniDriver::createCertificate" );
}


/*
*/
void MiniDriver::readCertificate( const std::string& a_stFile, boost::shared_ptr< u1Array >& a_pCertificateValue ) {

   Log::begin( "MiniDriver::readCertificate" );
   Timer t;
   t.start( );

   // Read certificate file
   std::unique_ptr<u1Array> pCompressedCertificate ( m_Files.readFile( std::string( szBASE_CSP_DIR ), a_stFile ) );

   // Decompress the certificate
   if (pCompressedCertificate.get() && pCompressedCertificate->GetLength() > 4)
   {
      // check if it is compressed by looking for the MS header 0100
      if (0 == memcmp(pCompressedCertificate->GetBuffer(), "\x01\x00", 2))
      {
         unsigned long ulOrigLen = pCompressedCertificate->ReadU1At( 3 ) * 256 + pCompressedCertificate->ReadU1At( 2 );

         a_pCertificateValue.reset( new u1Array( ulOrigLen ) );

         uncompress( a_pCertificateValue->GetBuffer( ), &ulOrigLen, pCompressedCertificate->GetBuffer( ) + 4, pCompressedCertificate->GetLength( ) - 4 );
      }
      else
      {
         // Not compressed : juste return the whole value
         a_pCertificateValue.reset( new u1Array( pCompressedCertificate->GetLength() ) );
         a_pCertificateValue->SetBuffer(pCompressedCertificate->GetBuffer());
      }
   }
   else
      a_pCertificateValue.reset( new u1Array( 0 ) );

   t.stop( "MiniDriver::readCertificate" );
   Log::end( "MiniDriver::readCertificate" );
}


/*
*/
void MiniDriver::createCertificateRoot( std::string& a_stCertificateName, u1Array* a_pValue ) {

   Log::begin( "MiniDriver::createCertificateRoot" );
   Timer t;
   t.start( );

   // Try to find a free container index out of the range of the containers managed by the MniDriver
   unsigned char ucContainerIndex = m_Files.containerGetFreeRoot( );

   // Build the certificate name to associate it to the container 
   a_stCertificateName = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );
   Util::toStringHex( ucContainerIndex, a_stCertificateName );

   // compress the certificate
   unsigned long ccLen = a_pValue->GetLength( );

   boost::shared_array< unsigned char > cc( new unsigned char[ ccLen + 4 ] );
   cc[ 0 ] = 0x01;
   cc[ 1 ] = 0x00;
   cc[ 2 ] = (BYTE)( ccLen & 0xff ); // Put the low byte of the word
   cc[ 3 ] = (BYTE)( ( ccLen & 0xff00 ) >> 8 ); // Put the high byte of the word

   // Set compression level at 6, same as Minidriver
   compress2( (unsigned char*)&cc[ 4 ], &ccLen, a_pValue->GetBuffer( ), ccLen, 6 );

   u1Array compressedCert( ccLen + 4 );

   compressedCert.SetBuffer( cc.get( ) );

   u1Array ac( 3 );

   // Administrator access conditions
   ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

   // User access conditions
   ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

   // Everyone access conditions
   ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

   unsigned int uiFreeMem = m_CardModule->GetMemory();
   if ( m_CardModule->HasMemoryBug()
      && (uiFreeMem < ((compressedCert.GetLength() + a_pValue->GetLength() + 1024))))
   {
      throw MiniDriverException( SCARD_E_NO_MEMORY );
   }

   m_Files.createFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &ac );

   try
   {
      m_Files.writeFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &compressedCert );
   }
   catch(MiniDriverException& x)
   {
      m_Files.deleteFile(std::string( szBASE_CSP_DIR ), a_stCertificateName);
      throw x;
   }


   try {

      std::string stPathCertificateRoot( szROOT_STORE_FILE );
      std::unique_ptr< u1Array > pCompressedRoots;
      bool bmsRootCreated = false;

      try {

         pCompressedRoots.reset( m_Files.readFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot ) );

      } catch( ... ) {

         // The msroot file does not exist. Create it.
         u1Array ac( 3 );

         // Administrator access conditions
         ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

         // User access conditions
         ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

         // Everyone access conditions
         ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

         m_Files.createFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot, &ac );

         bmsRootCreated = true;
      }

      // decode certificate to get an X509 pointer
      const unsigned char* pCertBytes = (const unsigned char*) a_pValue->GetBuffer();
      X509* pCert = d2i_X509(NULL, &pCertBytes, a_pValue->GetLength( ));

      if (pCert)
      {
         // check to see if it is a root before adding it to msroot
         if ( (0 == X509_NAME_cmp(X509_get_subject_name(pCert), X509_get_issuer_name(pCert)))
            ||	X509_check_ca(pCert) // accept also CAs
            )
         {

            // Parse the msroot to get the list of existing root certificates
            std::list<X509*> certList;

            if ( pCompressedRoots.get() && (pCompressedRoots->GetLength() > 4) )
            {
               std::unique_ptr< u1Array > pRoots;
               if ( 0 == memcmp(pCompressedRoots->GetBuffer(), "\x01\x00", 2) )
               {
                  unsigned long ulOrigLen = pCompressedRoots->ReadU1At( 3 ) * 256 + pCompressedRoots->ReadU1At( 2 );

                  pRoots.reset( new u1Array( ulOrigLen ) );

                  uncompress( pRoots->GetBuffer( ), &ulOrigLen, pCompressedRoots->GetBuffer( ) + 4, pCompressedRoots->GetLength( ) - 4 );
               }
               else
               {
                  // Not compressed : juste copy the whole value
                  pRoots.reset( new u1Array( pCompressedRoots->GetLength() ) );
                  pRoots->SetBuffer(pCompressedRoots->GetBuffer());
               }

               Util::ParsePkcs7(pRoots->GetBuffer(), pRoots->GetLength(), certList);
            }

            if (Util::AddCertToList(pCert, certList))
            {
               pCert = NULL; // set it to NULL to avoid freeing it since it belongs now to the list

               // serialize the new list
               std::vector<unsigned char> p7Bytes;
               if (Util::CreatePkcs7(certList, p7Bytes))
               {
                  unsigned long p7Len = p7Bytes.size();
                  pCompressedRoots.reset( new u1Array( p7Len + 4 ) );
                  pCompressedRoots->SetU1At(0, 0x01);
                  pCompressedRoots->SetU1At(1, 0x00);
                  pCompressedRoots->SetU1At(2, (BYTE)( p7Len & 0xff )); // Put the low byte of the word
                  pCompressedRoots->SetU1At(3, (BYTE)( (BYTE)( ( p7Len & 0xff00 ) >> 8 ))); // Put the high byte of the word

                  // Set compression level at 6, same as Minidriver
                  unsigned long compressedLen = p7Len;
                  compress2( (unsigned char*) pCompressedRoots->GetBuffer() + 4, &compressedLen, &p7Bytes[0], p7Len, 6 );

                  u1Array compressedP7( compressedLen + 4 );

                  compressedP7.SetBuffer( pCompressedRoots->GetBuffer() );

                  try
                  {
                     m_Files.writeFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot, &compressedP7 );
                  }
                  catch(MiniDriverException& x)
                  {
                     if (bmsRootCreated)
                        m_Files.deleteFile(std::string( szBASE_CSP_DIR ), stPathCertificateRoot);
                     Util::FreeCertList(certList);
                     if (pCert) X509_free(pCert);
                     throw x;
                  }
               }
            }

            Util::FreeCertList(certList);
         }

         if (pCert) X509_free(pCert);
      }
   }
   catch (...) {}

   cacheSerialize( );

   t.stop( "MiniDriver::createCertificateRoot" );
   Log::end( "MiniDriver::createCertificateRoot" );
}


/*
*/
void MiniDriver::deleteCertificateRoot( u1Array* a_pValue ) {

   Log::begin( "MiniDriver::deleteCertificateRoot" );
   Timer t;
   t.start( );

   bool bUpdated = false;
   // decode certificate to get an X509 pointer
   const unsigned char* pCertBytes = (const unsigned char*) a_pValue->GetBuffer();
   X509* pCert = d2i_X509(NULL, &pCertBytes, a_pValue->GetLength( ));
   if (!pCert)
   {
      Log::log("MiniDriver::deleteCertificateRoot - Not a valid certificate");
   }
   else if ( (0 != X509_NAME_cmp(X509_get_subject_name(pCert), X509_get_issuer_name(pCert))) // check to see if it is a root before adding it to msroot
            &&	!X509_check_ca(pCert) // accept also CAs
            )
   {
      Log::log("MiniDriver::deleteCertificateRoot - Not a root certificate");
   }
   else
   {
      try {

         std::string stPathCertificateRoot( szROOT_STORE_FILE );
         std::unique_ptr< u1Array > pCompressedRoots;

         try {

            pCompressedRoots.reset( m_Files.readFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot ) );

         } catch( ... ) {

         }

         if (pCert && pCompressedRoots.get() && (pCompressedRoots->GetLength() > 4))
         {
            // Parse the msroot to get the list of existing root certificates
            std::list<X509*> certList;

            std::unique_ptr< u1Array > pRoots;
            if ( 0 == memcmp(pCompressedRoots->GetBuffer(), "\x01\x00", 2) )
            {
               unsigned long ulOrigLen = pCompressedRoots->ReadU1At( 3 ) * 256 + pCompressedRoots->ReadU1At( 2 );

               pRoots.reset( new u1Array( ulOrigLen ) );

               uncompress( pRoots->GetBuffer( ), &ulOrigLen, pCompressedRoots->GetBuffer( ) + 4, pCompressedRoots->GetLength( ) - 4 );
            }
            else
            {
               // Not compressed : juste copy the whole value
               pRoots.reset( new u1Array( pCompressedRoots->GetLength() ) );
               pRoots->SetBuffer(pCompressedRoots->GetBuffer());
            }

            if (Util::ParsePkcs7(pRoots->GetBuffer(), pRoots->GetLength(), certList))
            {
               if (Util::DeleteCertFromList(pCert, certList))
               {
                  // serialize the new list
                  std::vector<unsigned char> p7Bytes;
                  if (Util::CreatePkcs7(certList, p7Bytes))
                  {
                     unsigned long p7Len = p7Bytes.size();
                     pCompressedRoots.reset( new u1Array( p7Len + 4 ) );
                     pCompressedRoots->SetU1At(0, 0x01);
                     pCompressedRoots->SetU1At(1, 0x00);
                     pCompressedRoots->SetU1At(2, (BYTE)( p7Len & 0xff )); // Put the low byte of the word
                     pCompressedRoots->SetU1At(3, (BYTE)( (BYTE)( ( p7Len & 0xff00 ) >> 8 ))); // Put the high byte of the word

                     // Set compression level at 6, same as Minidriver
                     unsigned long compressedLen = p7Len;
                     compress2( (unsigned char*) pCompressedRoots->GetBuffer() + 4, &compressedLen, &p7Bytes[0], p7Len, 6 );

                     u1Array compressedP7( compressedLen + 4 );

                     compressedP7.SetBuffer( pCompressedRoots->GetBuffer() );

                     try
                     {
                        bUpdated = true;
                        m_Files.writeFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot, &compressedP7 );
                     }
                     catch(MiniDriverException& x)
                     {
                        Util::FreeCertList(certList);
                        if (pCert) X509_free(pCert);
                        throw x;
                     }
                  }
               }

               Util::FreeCertList(certList);
            }
         }         
      }
      catch (...) {}
   }

   if (bUpdated)
      cacheSerialize( );

   if (pCert) X509_free(pCert);

   t.stop( "MiniDriver::deleteCertificateRoot" );
   Log::end( "MiniDriver::deleteCertificateRoot" );
}


/*
*/
void MiniDriver::containerCreate( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, u1Array* a_pPublicKeyModulus, const int& a_KeySize, u1Array* a_pKeyValue )
{ 
   unsigned int uiFreeMem = m_CardModule->GetMemory();
   if ( m_CardModule->HasMemoryBug() )
      // emperical security limit for not blocking the card afterwards because of the memory bug
   {
      if ((a_ucKeySpec <= MiniDriverContainer::KEYSPEC_SIGNATURE)  && (uiFreeMem < 4096))
         throw MiniDriverException( SCARD_E_NO_MEMORY );
      if ((a_ucKeySpec >= MiniDriverContainer::KEYSPEC_ECDSA_256) && (uiFreeMem < 3072))
         throw MiniDriverException( SCARD_E_NO_MEMORY );
   }

   m_Files.containerCreate( role, a_ucContainerIndex, a_bKeyImport, a_ucKeySpec, a_pPublicKeyModulus, a_KeySize, a_pKeyValue ); 
}


/*
*/
void MiniDriver::unblockPin( MiniDriverAuthentication::ROLES role, u1Array* a_PinSo, u1Array* a_PinUser ) {

   Log::begin( "MiniDriver::unblockPin" );
   Timer t;
   t.start( );

   m_Authentication.unblockPin( role, a_PinSo, a_PinUser );

   if( isAuthenticated( role ) ) {

      if( !isReadOnly( ) ) {
         try
         {
            // Update the MiniDriver Card Cache File
            m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
         }
         catch(...)
         {
            Log::log( "MiniDriver::unblockPin - Filed to update the cardcf (probably USER PIN was not presented before)");
         }
      }

   } else {

      // Update the MiniDriver Card Cache File
      if( !isReadOnly( ) ) {

         bool bDoLogout = false;

         if (a_PinUser->GetLength())
         {
            verifyPin( role, a_PinUser);
            bDoLogout = true;
         }

         try
         {
            m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
         }
         catch(...)
         {
            Log::log( "MiniDriver::unblockPin - Filed to update the cardcf (probably USER PIN was not presented before)");
         }

         if (bDoLogout)
         {
            logOut( role );
         }
      }

      if( administratorIsAuthenticated( ) ) {

         administratorLogin( a_PinSo );
      }
   }

   cacheSerialize( );

   t.stop( "MiniDriver::unblockPin" );
   Log::end( "MiniDriver::unblockPin" );
}


/*
*/
void MiniDriver::administratorChangeKey( u1Array* a_OldKey, u1Array* a_NewKey ) {

   Log::begin( "MiniDriver::administratorChangeKey" );
   Timer t;
   t.start( );

   m_Authentication.administratorChangeKey( a_OldKey, a_NewKey );

   //// Update the MiniDriver Card Cache File
   //m_Files.notifyChange( MiniDriverCardCacheFile::PINS );

   cacheSerialize( );

   t.stop( "MiniDriver::administratorChangeKey" );
   Log::end( "MiniDriver::administratorChangeKey" );
}


/*
*/
void MiniDriver::changePin( MiniDriverAuthentication::ROLES role, u1Array* a_pOldPIN, u1Array* a_pNewPIN ) {

   Log::begin( "MiniDriver::changePin" );
   Timer t;
   t.start( );

   m_Authentication.changePin( role, a_pOldPIN, a_pNewPIN );

   if( isAuthenticated( role ) ) {

      // Update the MiniDriver Card Cache File
      if( !isReadOnly( ) ) {

         try
         {
            m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
         }
         catch(...)
         {
            Log::log( "MiniDriver::changePin - Filed to update the cardcf (probably USER PIN was not presented before)");
         }
      }

   } else {

      // Update the MiniDriver Card Cache File
      if( !isReadOnly( ) ) {

         bool bDoLogout = false;
         if (a_pNewPIN->GetLength())
         {
            verifyPin( role, a_pNewPIN );
            bDoLogout = true;
         }

         try
         {
            m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
         }
         catch(...)
         {
            Log::log( "MiniDriver::changePin - Filed to update the cardcf (probably USER PIN was not presented before)");
         }

         if (bDoLogout)
            logOut( role );
      }
   }

   cacheSerialize( );

   t.stop( "MiniDriver::changePin" );
   Log::end( "MiniDriver::changePin" );
}


/*
*/
void MiniDriver::toString( const unsigned char* buffer, std::size_t size, std::string &result ) {

   if( !buffer || ( size <= 0 ) ) {

      result = "";

      return;
   }

   std::ostringstream oss;

   oss.rdbuf( )->str( "" );

   // Display hexadeciaml uppercase character
   oss << std::hex << std::uppercase;

   // No blank but zero instead
   oss << std::setfill('0');

   for( std::size_t i = 0; i < size; ++i ) {

      oss << std::setw( 2 ) << static_cast< int >( buffer[ i ] );
   }

   result.assign( oss.str( ) );
}


/*
*/
void MiniDriver::setSmartCardReader(  std::string sSMCReaderName, BYTE* pbAtr, DWORD cbAtr ) { 

	std::string a_stUri = "MSCM";

	m_CardModule.reset( new MiniDriverModuleService(new CardModuleAPI( &sSMCReaderName, (u2) 5, &a_stUri, pbAtr, cbAtr  ) ) );
	m_Authentication.setCardModule( m_CardModule.get( ) ); 
	m_Files.setCardModuleService( m_CardModule.get( ) ); 
}

