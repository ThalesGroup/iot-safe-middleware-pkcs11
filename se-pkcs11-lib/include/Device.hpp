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
#ifndef __GEMALTO_READER__
#define __GEMALTO_READER__

#include <stdio.h>
#include <string>
#include <boost/shared_ptr.hpp>
#include "CardManager.hpp"
#include "MiniDriver.hpp"
#include "MiniDriverException.hpp"
#include "Timer.hpp"
#include "PCSCMissing.h"

#define EMPTY_READER_NAME   "empty"


class CardDesc
{
public:
	u1Array m_atr;
	u1Array m_mask;

	CardDesc() : m_atr(38), m_mask(38) {}
	~CardDesc() {}
};

/* This class is a facade exporting all smart card & reader features
*/
class Device {

public:

    static bool s_bEnableDiskCache;
	static std::vector<CardDesc> s_vAdditionalAtrs;

    Device (const DEVICEINFO&, const unsigned char&);

    virtual ~Device ();

    unsigned char getDeviceID( void ) { return m_ucDeviceID; }

    void clear( void );

    inline void saveCache( void ) { if( Device::s_bEnableDiskCache && m_MiniDriver.get( ) ) { m_MiniDriver->saveCache( ); } }

    // Smart card reader operations

    inline const std::string getReaderName (void) {return m_stDeviceInfo.szDeviceName;}

	/****** CC TODO - Remove this method !!! *****/
	inline bool isSmartCardPresent( void ) { return (true); }

     // inline bool isSmartCardMute( void ) { return ( ( m_DeviceInfo.dwCurrentState & SCARD_STATE_MUTE ) ? true : false ); }

    inline bool isSmartCardRecognized( void ) { if ( m_MiniDriver.get( ) ) return true; else return false;}
        
    //inline const SCARD_READERSTATE& getReaderState( void ) { return m_DeviceState; }

    void set (const DEVICEINFO&);

    // void put( SCARD_READERSTATE& );

    // void update( const SCARD_READERSTATE& );

    void addMiniDriver( void );

    void removeMiniDriver( void );

    unsigned long getHandle( void );

    inline bool isVerifyPinSecured( void ) { return false; }

	inline bool IsMultiPinSupported(void) const { if( m_MiniDriver.get( ) ) return m_MiniDriver->IsMultiPinSupported(); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline bool IsGCEnabled(void) const { if( m_MiniDriver.get( ) ) return m_MiniDriver->IsGCEnabled(); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isV2Plus( void ) {  if( m_MiniDriver.get( ) ) { return m_MiniDriver->isV2Plus( ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline bool isDotNetCard( void ) { if( m_MiniDriver.get( ) ) { return (m_MiniDriver->GetCardModel() == NET_STUB); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }
    
	bool beginTransaction();

    inline void endTransaction( void ) { if( m_MiniDriver.get( ) ) { m_MiniDriver->endTransaction( ); } }

    // Smart card operations

    void hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files );

    u1Array* getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags );

    void setCardProperty( const unsigned char& a_ucProperty, u1Array* a_Data, const unsigned char& a_ucFlags );

    inline const u1Array* getSerialNumber( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getSerialNumber( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    boost::shared_ptr< u1Array > privateKeyDecrypt( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, u1Array* a_pDataToDecrypt ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->privateKeyDecrypt( a_ucContainerIndex, a_ucKeySpec, a_pDataToDecrypt ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    boost::shared_ptr< u1Array > privateKeyDecryptEx( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, const unsigned char& a_ucPaddingType, const unsigned char& a_ucAlgo, u1Array* a_pDataToDecrypt ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->privateKeyDecryptEx( a_ucContainerIndex, a_ucKeySpec, a_ucPaddingType, a_ucAlgo, a_pDataToDecrypt ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    boost::shared_ptr< u1Array > privateKeySign( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, unsigned char a_ucPaddingType, unsigned char a_ucAlgo, u1Array* a_pDataToSign, u1Array* a_pIntermediateHash, u1Array* a_pHashCounter ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->privateKeySign( a_ucContainerIndex, a_ucKeySpec, a_ucPaddingType, a_ucAlgo, a_pDataToSign, a_pIntermediateHash, a_pHashCounter ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    boost::shared_ptr< u1Array > constructDHAgreement( const unsigned char& a_ucContainerIndex, u1Array* a_pDataQx, u1Array* a_pDataQy ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->constructDHAgreement( a_ucContainerIndex, a_pDataQx, a_pDataQy ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline const MiniDriverModuleService* getCardModule( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getCardModule( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void forceGarbageCollection( void ) { try { if( m_MiniDriver.get( ) ) { m_MiniDriver->forceGarbageCollection( ); } } catch( ... ) { } }

    inline bool isReadOnly( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isReadOnly( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isECC( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isECC( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool IsSha1Disabled( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->IsSha1Disabled( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool hasOAEP_PSS( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->hasOAEP_PSS( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline void getRSAMinMax( int &minRsa, int& maxRsa, int &minRsaGen, int &maxRsaGen, MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) m_MiniDriver->getRSAMinMax( minRsa, maxRsa, minRsaGen, maxRsaGen, role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline void getECCMinMax( int &minEcc, int& maxEcc, int &minEccGen, int &maxEccGen, MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) m_MiniDriver->getECCMinMax( minEcc, maxEcc, minEccGen, maxEccGen, role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline bool IsLastHashRoundSupported( CDigest::HASH_TYPE hashType ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->IsLastHashRoundSupported( hashType ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isPinInitialized( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isPinInitialized( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	 inline void GetRandom(unsigned char* pRnd, unsigned int rndLength) { if( m_MiniDriver.get( ) ) m_MiniDriver->GetRandom( pRnd, rndLength ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    // PIN operations

    inline unsigned char getPinMaxPinLength( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getPinMaxPinLength( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char getPinMinPinLength( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getPinMinPinLength( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isSSO( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isSSO( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isNoPin( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isNoPin( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    bool isAuthenticated( MiniDriverAuthentication::ROLES role );

	inline bool IsPinSMRequiredForVerify(MiniDriverAuthentication::ROLES role) { if (m_MiniDriver.get( ) ) return m_MiniDriver->IsPinSMRequiredForVerify( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isPinExpired(MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isPinExpired( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isExternalPin( MiniDriverAuthentication::ROLES role ) {if( m_MiniDriver.get( ) ) return m_MiniDriver->isExternalPin( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isRegularPin( MiniDriverAuthentication::ROLES role ) {if( m_MiniDriver.get( ) ) return m_MiniDriver->isRegularPin( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isModePinOnly( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isModePinOnly( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isModeNotPinOnly( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isModeNotPinOnly( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isModePinOrBiometry( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isModePinOrBiometry( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline unsigned char getPinCacheType(MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getPinCacheType( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline MiniDriverAuthentication::ROLES getPinUnblockRole( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getPinUnblockRole(role); else throw MiniDriverException( SCARD_E_NO_SMARTCARD );}

    void changePin( MiniDriverAuthentication::ROLES role, u1Array* a_pOldPIN, u1Array* a_pNewPIN );

    inline void unblockPin( MiniDriverAuthentication::ROLES role, u1Array* a_PinSo, u1Array* a_PinUser ) { if( m_MiniDriver.get( ) ) m_MiniDriver->unblockPin( role, a_PinSo, a_PinUser ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void verifyPin( MiniDriverAuthentication::ROLES role, u1Array* a_Pin );

    void logOut( MiniDriverAuthentication::ROLES role, bool bClearCache );

    inline int getTriesRemaining( MiniDriverAuthentication::ROLES role ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getTriesRemaining( role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    inline void administratorLogin( u1Array* a_pAdministratorKey ) { if( m_MiniDriver.get( ) ) m_MiniDriver->administratorLogin( a_pAdministratorKey ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void administratorLogout( void ) { if( m_MiniDriver.get( ) ) m_MiniDriver->administratorLogout( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void administratorChangeKey( u1Array* a_OldKey, u1Array* a_NewKey ) {  if( m_MiniDriver.get( ) ) m_MiniDriver->administratorChangeKey( a_OldKey, a_NewKey ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char administratorGetTriesRemaining( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->administratorGetTriesRemaining( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool administratorIsAuthenticated( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->administratorIsAuthenticated( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline CSecureString& getSecuredPin( MiniDriverAuthentication::ROLES role) { return m_securedPin[ MiniDriverAuthentication::getRoleIndex(role)];}

    inline void clearPinCache( void ) { for (int i = 0; i < 6; i++) m_securedPin[i].Reset();}
    inline void clearPinCache( MiniDriverAuthentication::ROLES role ) { if (role != MiniDriverAuthentication::PIN_NONE) m_securedPin[MiniDriverAuthentication::getRoleIndex(role)].Reset();}

	inline const std::list<MiniDriverAuthentication::ROLES>& getStaticRoles() const { if( m_MiniDriver.get( ) ) return m_MiniDriver->getStaticRoles( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    // Files operations

    inline void createDirectory( const std::string& a_stDirectoryParent, const std::string& a_stDirectory ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->createDirectory( a_stDirectoryParent, a_stDirectory ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void createFile(  const std::string& a_stDirectory, const std::string& a_stFile, const bool& a_bIsReadProtected ) { if( m_MiniDriver.get( ) ) m_MiniDriver->createFile( a_stDirectory, a_stFile, a_bIsReadProtected ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void deleteFile( const std::string& a_stDirectory, const std::string& a_stFile ) { if( m_MiniDriver.get( ) ) m_MiniDriver->deleteFile( a_stDirectory, a_stFile ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void readCertificate( const std::string& a_stPath, boost::shared_ptr< u1Array >& a_pCertificateValue ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->readCertificate( a_stPath, a_pCertificateValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline MiniDriverFiles::FILES_NAME& enumFiles( const std::string& a_DirectoryPath ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->enumFiles( a_DirectoryPath ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline u1Array* readFile( const std::string& a_stDirectory, const std::string& a_stFile ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->readFile( a_stDirectory, a_stFile ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void writeFile( const std::string& a_stDirectory, const std::string& a_stFile, u1Array* a_FileData, const bool& a_bAddToCache = true ) { if( m_MiniDriver.get( ) ) m_MiniDriver->writeFile( a_stDirectory, a_stFile, a_FileData, a_bAddToCache ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void createCertificate( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stCertificateName, u1Array* a_pValue, u1Array* a_pModulus, const bool& a_bSmartCardLogon ) { if( m_MiniDriver.get( ) ) m_MiniDriver->createCertificate( role, a_ucContainerIndex, a_ucKeySpec, a_stCertificateName, a_pValue, a_pModulus, a_bSmartCardLogon ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void createCertificateRoot( std::string& a_stCertificateName, u1Array* a_pValue ) { if( m_MiniDriver.get( ) ) m_MiniDriver->createCertificateRoot( a_stCertificateName, a_pValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void deleteCertificateRoot( u1Array* a_pValue ) { if( m_MiniDriver.get( ) ) m_MiniDriver->deleteCertificateRoot( a_pValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void deletePrivateKey( const unsigned char& a_ucContainerIndex );

    inline void deleteFileStructure( void ) { if( m_MiniDriver.get( ) ) m_MiniDriver->deleteFileStructure( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void certificateDelete( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec ) { if( m_MiniDriver.get( ) ) m_MiniDriver->certificateDelete( a_ucContainerIndex, a_ucKeySpec ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void cacheDisable( const std::string& a_stFileName ) { if( m_MiniDriver.get( ) ) m_MiniDriver->cacheDisable( a_stFileName ); }

    inline void renameFile( const std::string& a_stOldFileDirectory, const std::string& a_stOldFileName, const std::string& a_stNewFileDirectory, const std::string& a_stNewFileName ) { if( m_MiniDriver.get( ) ) m_MiniDriver->renameFile( a_stOldFileDirectory, a_stOldFileName, a_stNewFileDirectory, a_stNewFileName ); } 


    // Container operations
    inline void containerCreate( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, u1Array* a_pPublicKeyModulus, const int& a_KeySize, u1Array* a_pKeyValue ) { if( m_MiniDriver.get( ) ) m_MiniDriver->containerCreate( role, a_ucContainerIndex, a_bKeyImport, a_ucKeySpec, a_pPublicKeyModulus, a_KeySize, a_pKeyValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline void containerDelete( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec) { if( m_MiniDriver.get( ) ) m_MiniDriver->containerDelete( a_ucContainerIndex, a_ucKeySpec ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerReadOnly( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerReadOnly( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline MiniDriverContainer& containerGet( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerGet( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char containerCount( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerCount( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerGetMatching( MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stFileName, const u1Array* a_pPublicKeyModulus ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerGetMatching( role, a_ucContainerIndex, a_ucKeySpec, a_stFileName, a_pPublicKeyModulus ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerIsImportedExchangeKey( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerIsImportedExchangeKey( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerIsImportedSignatureKey( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerIsImportedSignatureKey( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char containerGetFree( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerGetFree( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isStaticProfile( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isStaticProfile( ); else return false; /* if there is no card, just return false*/ }

	inline u1Array* getContainer(unsigned char ctrIndex) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getContainer( ctrIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	inline bool supportsDualKeyContainers( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->supportsDualKeyContainers( ); else return false; /* if there is no card, just return false*/ }

private:
    DEVICEINFO m_stDeviceInfo;

    boost::shared_ptr<MiniDriver> m_MiniDriver;

    // boost::shared_ptr <PCSC> m_PCSC;

    unsigned char m_ucDeviceID;

    Timer m_TimerLastChange;
    
    std::map<MiniDriverAuthentication::ROLES, Timer> m_TimerLastAuth;

    std::map<MiniDriverAuthentication::ROLES, bool> m_AuthRoles;

    CSecureString m_securedPin[6];
};

#endif // __GEMALTO_READER__
