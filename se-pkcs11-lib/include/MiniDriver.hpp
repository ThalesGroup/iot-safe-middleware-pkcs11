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
#ifndef __GEMALTO_MINIDRIVER_FACADE__
#define __GEMALTO_MINIDRIVER_FACADE__

#include <sys/stat.h>
#include <string>

#ifndef NO_FILESYSTEM
#include <boost/serialization/serialization.hpp>
#include <boost/ptr_container/serialize_ptr_map.hpp>
#include <boost/archive/archive_exception.hpp>
#endif
#include <boost/shared_ptr.hpp>
#include "MiniDriverFiles.hpp"
#include "MiniDriverContainerMapFile.hpp"
#include "MiniDriverAuthentication.hpp"
#include "MiniDriverException.hpp"
#include "CardManager.hpp"
#include "PCSCMissing.h"

class MiniDriverModuleService;


/*
*/
class MiniDriver {

public:
    typedef enum { SMART_CARD_TYPE_V1 = 0x00, SMART_CARD_TYPE_V2 = 0x01, SMART_CARD_TYPE_V2PLUS = 0x02 } SMARTCARD_TYPE;
    const static unsigned int s_iMinLengthKeyRSA;
    const static unsigned int s_iMinLengthKeyECC;
    const static unsigned int s_iMaxLengthKeyRSA;
    const static unsigned int s_iMaxLengthKeyECC;

    MiniDriver() : m_Authentication(), m_Files(m_Authentication), m_bIsStaticProfile(false) {}
    inline virtual ~MiniDriver( ) { }

    inline void saveCache( void ) { try { cacheSerialize( ); } catch( ... ) { } }

	void read( const bool& );

    // Smart card management

    // Initialize the object managing the communication with the smart card
    void setSmartCardReader( std::string sSMCReader, BYTE* pbAtr, DWORD cbAtr  );
    inline const MiniDriverModuleService* getCardModule( void ) { return m_CardModule.get( ); }
    u1Array* getCardID( void );
    u1Array* getSerialNumber( void );
    inline void CheckSmartCardType(void) { if( m_CardModule.get( ) ) m_CardModule->CheckSmartCardType(); }
	inline bool IsMultiPinSupported(void) const { if( m_CardModule.get( ) ) return m_CardModule->IsMultiPinSupported(); else return false; }
	inline bool IsGCEnabled(void) const { if( m_CardModule.get( ) ) return m_CardModule->IsGCEnabled(); else return false; }
    inline void forceGarbageCollection( void ) { try { if( m_CardModule.get( ) ) { m_CardModule->ForceGarbageCollector( ); } } catch( ... ) { } }
    inline bool isV2Plus( void ) {  try { if( m_CardModule.get( ) ) { return m_CardModule->IsV2Plus(); } } catch( ... ) { } return false; }

	inline bool beginTransaction( bool& bCardReset, bool& bCardRemoved ) { 
        bool bTransactionTaken = false;
		bCardReset = false;
        bCardRemoved = false;

		/***** CC TODO : Manage the transaction based on the original one in the Minidriver.hpp file *****/ 

		Log::begin("beginTransaction");
		try
		{
			CardManager::getInstance ()->beginTransaction ();
			bTransactionTaken = true;
		}
		catch (...) {
		}

		Log::end("beginTransaction");

        return bTransactionTaken;
    }

	inline void endTransaction( void ) {
		try
		{
			CardManager::getInstance ()->endTransaction ();
		}
		catch (...) {
		}
	}

    inline bool isReadOnly( void ) { bool bRet = false; u1Array* a = getCardProperty( CARD_READ_ONLY, 0 ); if( a ) { bRet = ( 1 == a->ReadU1At( 0 ) ); delete a;} return bRet; } 
    inline bool isECC( void ) { if( m_CardModule.get( ) ) { return m_CardModule->IsECC(); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
    inline bool IsSha1Disabled( void ) { if( m_CardModule.get( ) ) { return m_CardModule->IsSha1Disabled(); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
    inline bool hasOAEP_PSS( void ) { if( m_CardModule.get( ) ) { return m_CardModule->hasOAEP_PSS(); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
	inline void getRSAMinMax( int &minRsa, int& maxRsa, int &minRsaGen, int &maxRsaGen, MiniDriverAuthentication::ROLES role ) { if( m_CardModule.get( ) ) { m_CardModule->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, (u1) role); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
	inline void getECCMinMax( int &minEcc, int& maxEcc, int &minEccGen, int &maxEccGen, MiniDriverAuthentication::ROLES role ) { if( m_CardModule.get( ) ) { m_CardModule->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, (u1) role); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
	inline bool IsLastHashRoundSupported( CDigest::HASH_TYPE hashType ) { if( m_CardModule.get( ) ) { return m_CardModule->IsLastHashRoundSupported( hashType); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
	inline void GetRandom(unsigned char* pRnd, unsigned int rndLength)  { if( m_CardModule.get( ) ) { m_CardModule->GetRandom( (u1*) pRnd, (u4) rndLength); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 

    // Authentification management
    inline unsigned char getPinMaxPinLength( MiniDriverAuthentication::ROLES role ) { return m_Authentication.getPinMaxPinLength( role ); }
    inline unsigned char getPinMinPinLength( MiniDriverAuthentication::ROLES role ) { return m_Authentication.getPinMinPinLength( role ); }
    inline bool isPinInitialized( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isPinInitialized( role ); } 
    inline bool isSSO( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isSSO( role ); }
    inline bool isNoPin( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isNoPin( role ); }
    inline bool isAuthenticated( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isAuthenticated( role ); }
	inline bool IsPinSMRequiredForVerify (MiniDriverAuthentication::ROLES role ) { if( m_CardModule.get( ) ) { return m_CardModule->IsPinSMRequiredForVerify( (u1) role ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); } 
    inline bool isPinExpired(MiniDriverAuthentication::ROLES role ) { return m_Authentication.isPinExpired( role ); }
    inline bool isExternalPin( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isExternalPin( role ); }
    inline bool isRegularPin( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isRegularPin( role ); }
    inline bool isModePinOnly( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isModePinOnly( role ); }
    inline bool isModeNotPinOnly( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isModeNotPinOnly( role ); }
    inline bool isModePinOrBiometry( MiniDriverAuthentication::ROLES role ) { return m_Authentication.isModePinOrBiometry( role ); }
	inline unsigned char getPinCacheType( MiniDriverAuthentication::ROLES role ) { return m_Authentication.getPinCacheType( role ); }
	inline MiniDriverAuthentication::ROLES getPinUnblockRole( MiniDriverAuthentication::ROLES role ) { return m_Authentication.getPinUnblockRole(role); }
    void changePin( MiniDriverAuthentication::ROLES role, u1Array* a_pOldPIN, u1Array* a_pNewPIN );
    void unblockPin( MiniDriverAuthentication::ROLES role, u1Array* a_PinSo, u1Array* a_PinUser);
    inline void verifyPin( MiniDriverAuthentication::ROLES role, u1Array* a_Pin ) { m_Authentication.login( role, a_Pin ); }
    inline void logOut( MiniDriverAuthentication::ROLES role ) { m_Authentication.logOut( role ); }
    inline int getTriesRemaining( MiniDriverAuthentication::ROLES role ) { return m_Authentication.getTriesRemaining( role ); }
    inline void administratorLogin( u1Array* a_pAdministratorKey ) { m_Authentication.administratorLogin( a_pAdministratorKey ); }
    inline void administratorLogout( void ) { m_Authentication.administratorLogout( ); }
    void administratorChangeKey( u1Array* a_OldKey, u1Array* a_NewKey );
    inline unsigned char administratorGetTriesRemaining( void ) { return m_Authentication.administratorGetTriesRemaining( ); }
    inline bool administratorIsAuthenticated( void ) { return m_Authentication.administratorIsAuthenticated( ); }
	inline const std::list<MiniDriverAuthentication::ROLES>& getStaticRoles() const { return m_Authentication.getStaticRoles(); }

    // Files management
    inline void hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files ) { m_Files.hasChanged( a_Pins, a_Containers, a_Files ); m_Authentication.read( );}
    inline MiniDriverFiles::FILES_NAME& enumFiles( const std::string& a_DirectoryPath ) { return m_Files.enumFiles( a_DirectoryPath ); }
    inline u1Array* readFile( const std::string& a_stDirectory, const std::string& a_stFile ) { return m_Files.readFile( a_stDirectory, a_stFile ); }
    inline void writeFile( const std::string& a_stDirectory, const std::string& a_stFile, u1Array* a_FileData, const bool& a_bAddToCache = true ) { { Log::begin( "MiniDriver::writeFile" ); Log::log( "Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) ); m_Files.writeFile( a_stDirectory, a_stFile, a_FileData, a_bAddToCache ); cacheSerialize( ); Log::end( "MiniDriver::writeFile" ); } }
    void createFile( const std::string&, const std::string&, const bool& );
    inline void deleteFile( const std::string& a_stDirectory, const std::string& a_stFile ) { { Log::begin( "MiniDriver::deleteFile" ); Log::log( "Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) ); m_Files.deleteFile( a_stDirectory, a_stFile ); cacheSerialize( ); Log::end( "MiniDriver::deleteFile" ); } }
    inline void createDirectory( const std::string& a_stDirectoryParent, const std::string& a_stDirectory ) { { Log::begin( "MiniDriver::createDirectory" ); Log::log( "Directory <%s> - Parent <%s>", a_stDirectory.c_str( ), a_stDirectoryParent.c_str( ) ); m_Files.createDirectory( a_stDirectoryParent, a_stDirectory ); cacheSerialize( ); Log::end( "MiniDriver::createDirectory" ); } }
    void createCertificate( MiniDriverAuthentication::ROLES, unsigned char&, unsigned char&, std::string&, u1Array*, u1Array*, const bool& );
    void createCertificateRoot( std::string& a_stCertificateName, u1Array* a_pValue );
    void deleteCertificateRoot( u1Array* a_pValue );
    void readCertificate( const std::string&, boost::shared_ptr< u1Array >& );
    inline void deleteFileStructure( void ) { m_Files.deleteFileStructure( ); }
    inline void certificateDelete( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec ) { m_Files.certificateDelete( a_ucContainerIndex, a_ucKeySpec ); }
    inline void cacheDisable( const std::string& a_stFileName ) { m_Files.cacheDisable( a_stFileName ); }
    inline void renameFile( const std::string& a_stOldFileDirectory, const std::string& a_stOldFileName, const std::string& a_stNewFileDirectory, const std::string& a_stNewFileName ) { m_Files.renameFile( a_stOldFileDirectory, a_stOldFileName, a_stNewFileDirectory, a_stNewFileName ); } 

    // Containers management
    inline MiniDriverContainer& containerGet( const unsigned char& a_ucContainerIndex ) { return m_Files.containerGet( a_ucContainerIndex ); }
	inline void containerDelete( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec ) { m_Files.containerDelete( a_ucContainerIndex, a_ucKeySpec ); }
    inline bool containerReadOnly( const unsigned char& a_ucContainerIndex ) { return m_Files.containerReadOnly( a_ucContainerIndex ); }
    void containerCreate( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, u1Array* a_pPublicKeyModulus, const int& a_KeySize, u1Array* a_pKeyValue ) ;
    inline unsigned char containerCount( void ) { return m_Files.containerCount( ); }
    inline bool containerGetMatching( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stFileName, const u1Array* a_pPublicKeyModulus ) { return m_Files.containerGetMatching( role, a_ucContainerIndex, a_ucKeySpec, a_stFileName, a_pPublicKeyModulus ); }
    inline bool containerIsImportedExchangeKey( const unsigned char& a_ucContainerIndex ) { return m_Files.containerIsImportedExchangeKey( a_ucContainerIndex ); }
    inline bool containerIsImportedSignatureKey( const unsigned char& a_ucContainerIndex ) { return m_Files.containerIsImportedSignatureKey( a_ucContainerIndex ); }
    inline unsigned char containerGetFree( void ) { return m_Files.containerGetFree( ); }
    
    // Cryptography management
    inline boost::shared_ptr< u1Array > privateKeyDecrypt( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, u1Array* a_pDataToDecrypt ) { if( m_CardModule.get( ) ) { /*m_CardModule->manageGarbageCollector( ); */m_pDataDecrypted.reset( m_CardModule->privateKeyDecrypt( a_ucContainerIndex, a_ucKeySpec, a_pDataToDecrypt ) ); return m_pDataDecrypted; } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    inline boost::shared_ptr< u1Array > privateKeyDecryptEx( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, const unsigned char& a_ucPaddingType, const unsigned char& a_ucAlgo, u1Array* a_pDataToDecrypt ) { if( m_CardModule.get( ) ) { /*m_CardModule->manageGarbageCollector( ); */m_pDataDecrypted.reset( m_CardModule->privateKeyDecryptEx( a_ucContainerIndex, a_ucKeySpec, a_ucPaddingType, a_ucAlgo, a_pDataToDecrypt ) ); return m_pDataDecrypted; } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    inline boost::shared_ptr< u1Array > privateKeySign( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, unsigned char a_ucPaddingType, unsigned char a_ucAlgo, u1Array* a_pDataToSign, u1Array* a_pIntermediateHash, u1Array* a_pHashCounter ) { if( m_CardModule.get( ) ) { m_pDataSigned.reset( m_CardModule->privateKeySign( a_ucContainerIndex, a_ucKeySpec, a_ucPaddingType, a_ucAlgo, a_pDataToSign, a_pIntermediateHash, a_pHashCounter ) ); return m_pDataSigned; } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    inline boost::shared_ptr< u1Array > constructDHAgreement( const unsigned char& a_ucContainerIndex, u1Array* a_pDataQx, u1Array* a_pDataQy ) { if( m_CardModule.get( ) ) { m_pDHAgreement.reset( m_CardModule->constructDHAgreement( a_ucContainerIndex, a_pDataQx, a_pDataQy ) ); return m_pDHAgreement; } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    // Property management
    inline u1Array* getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags ) { if( m_CardModule.get( ) ) { return m_CardModule->getCardProperty( a_ucProperty, a_ucFlags ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    inline void setCardProperty( const unsigned char& a_ucProperty, u1Array* a_Data, const unsigned char& a_ucFlags ) { if( m_CardModule.get( ) ) { m_CardModule->setCardProperty( a_ucProperty, a_Data, a_ucFlags ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    inline DWORD GetCardModel( void ) { if( m_CardModule.get( ) ) { return m_CardModule->GetCardModel(); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    inline bool isStaticProfile( void ) { return m_bIsStaticProfile;}
	inline u1Array* getContainer(unsigned char ctrIndex) { if( m_CardModule.get( ) ) { return m_CardModule->getContainer(ctrIndex); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
	inline bool Validate () { return m_Files.Validate (); }
    inline bool supportsDualKeyContainers( void ) { if( m_CardModule.get( ) ) { return m_CardModule->supportsDualKeyContainers(); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

private:    

    void toString( const unsigned char* buffer, std::size_t size, std::string &result );

    boost::shared_ptr< u1Array > m_pDataDecrypted;
    boost::shared_ptr< u1Array > m_pDataSigned;
    boost::shared_ptr< u1Array > m_pDHAgreement;
    boost::shared_ptr< u1Array > m_u1aSerialNumber;
    boost::shared_ptr< MiniDriverModuleService > m_CardModule;
    MiniDriverAuthentication m_Authentication;
    MiniDriverFiles m_Files;    

    // Name of the file on the computer disk containing the image of the cache
    std::string m_stFileName;

    bool m_bIsStaticProfile;

	// Enable/disable the on disk serialization/deserialization
    bool m_bEnableDiskCache;
    void cacheSerialize( void );

#ifndef NO_FILESYSTEM

    void cacheDeserialize( void );

    // Disk serialization and deserialization
    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int version ) {

        //Log::begin( "MiniDriver::serialize" );

       if (version != 128)
          throw boost::archive::archive_exception(boost::archive::archive_exception::unsupported_class_version);

        // Append the files information
        ar & m_Files;

		//Log::end( "MiniDriver::serialize" );
    }

#endif
};

#ifndef NO_FILESYSTEM
BOOST_CLASS_VERSION( MiniDriver, 128 )
#endif

#endif // __GEMALTO_MINIDRIVER__
