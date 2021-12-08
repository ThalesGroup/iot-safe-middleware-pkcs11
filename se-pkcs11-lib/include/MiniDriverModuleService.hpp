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
#ifndef __GEMALTO_MINIDRIVER_MODULE_SERVICE_FILE_
#define __GEMALTO_MINIDRIVER_MODULE_SERVICE_FILE_

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/shared_ptr.hpp>
#include "MiniDriverException.hpp"
#include "CardModuleAPI.h"
#include "Except.h"
#include "Timer.hpp"
#include "util.h"

const unsigned char CARD_PROPERTY_PIN_INFO_EX = 0x87;
const unsigned char CARD_FREE_SPACE  = 0x00; //Returns a byte array blob of 12 bytes
const unsigned char CARD_KEYSIZES = 0x02; // Returns a byte array blob of 16 bytes 
const unsigned char CARD_READ_ONLY = 0x03; // Returns a byte array blob of 1 byte
const unsigned char CARD_CACHE_MODE = 0x04; // Returns a byte array blob of 1 byte
const unsigned char CARD_GUID = 0x05; // Returns a byte array blob of 16 bytes
const unsigned char CARD_SERIAL_NUMBER = 0x06; // Returns a byte array blob of 12 bytes
const unsigned char CARD_PIN_INFO = 0x07; // Returns a byte array blob of 12 bytes
const unsigned char CARD_ROLES_LIST = 0x08; // Returns a byte array blob of 1 byte
const unsigned char CARD_AUTHENTICATED_ROLES = 0x09; // Returns a byte array blob of 1 byte 
const unsigned char CARD_PIN_STRENGTH = 0x0A; // Returns a byte array blob of 1 byte
const unsigned char CARD_X509_ENROLL = 0x0D; // Returns a byte array blob of 1 byte
const unsigned char CARD_PIN_POLICY = 0x80; // Returns a byte array blob of 14 bytes
const unsigned char CARD_CHANGE_PIN_FIRST = 0xFA; // Returns a byte array blob of 1 byte
const unsigned char CARD_VERSION_INFO = 0xFF; // Returns a byte array blob of 4 bytes

/*
*/
class MiniDriverModuleService {

public:

   typedef std::map< unsigned char, u1Array* > PROPERTIES;
    typedef enum { SMART_CARD_TYPE_V1 = 0x00, SMART_CARD_TYPE_V2 = 0x01, SMART_CARD_TYPE_V2PLUS = 0x02 } SMARTCARD_TYPE;
    MiniDriverModuleService(CardModuleAPI* pCardModService);
    ~MiniDriverModuleService();

    void CheckSmartCardType(void);

	inline bool IsMultiPinSupported( void ) const { return m_bMultiPinSupported; }

	inline bool IsGCEnabled( void ) { return m_bEnableGC; }

    inline bool IsV2Plus( void ) { return ( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ); }

    inline bool IsV2( void ) { return ( SMART_CARD_TYPE_V2 == m_ucSmartCardType ); }

    inline bool IsECC( void ) { return (m_pCardMod->IsECC() != 0); }

    inline bool IsSha1Disabled (void) { return (m_pCardMod->IsSha1Disabled() != 0); }

    inline bool hasOAEP_PSS( void ) { return (m_pCardMod->hasOAEP_PSS() != 0); }

	inline void getRSAMinMax( int &minRsa, int& maxRsa, int &minRsaGen, int &maxRsaGen, u1 role ) { m_pCardMod->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, role); }

	inline void getECCMinMax( int &minEcc, int& maxEcc, int &minEccGen, int &maxEccGen, u1 role ) { m_pCardMod->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, role); }

	inline bool IsLastHashRoundSupported( CDigest::HASH_TYPE hashType ) { return (m_pCardMod->IsLastHashRoundSupported(hashType) != 0); }

	inline void GetRandom(u1* pRnd, u4 rndLength) { m_pCardMod->GetRandom(pRnd, rndLength); }

    inline bool IsPlusCard( void ) { return (m_pCardMod->IsPlusCard() != 0); }

    inline DWORD GetCardModel( void ) { return m_pCardMod->GetCardModel();}

	inline bool HasMemoryBug( void ) { return m_pCardMod->HasMemoryBug(); }

    inline BYTE GetPinId( u1 role ) { return m_pCardMod->GetPinId( role );}

	inline BYTE GetCardPinId( u1 role ) { return m_pCardMod->GetCardPinId( role );}

	inline void getStaticRoles(std::list<u1>& roles) { m_pCardMod->getStaticRoles(roles); }

	inline bool IsPinSMRequiredForVerify(u1 role) { return m_pCardMod->IsPinSMRequiredForVerify(role); }
	inline bool IsPinSMRequiredForUnblock(u1 role) { return m_pCardMod->IsPinSMRequiredForUnblock(role); }
	inline bool IsPinSMRequiredForChange(u1 role) { return m_pCardMod->IsPinSMRequiredForChange(role); }

    inline bool IsReadOnly (u1 index) { return m_pCardMod->IsReadOnly (index); }

    inline bool HasSSO () { return m_pCardMod->HasSSO (); }

    void manageGarbageCollector( void );

    inline bool GetPinPadSupported () { return m_pCardMod->GetPinPadSupported(); }
    inline void SetPinPadSupported (bool bIsPinPad) { m_pCardMod->SetPinPadSupported(bIsPinPad);}
	unsigned int GetMemory();
	void ForceGarbageCollector();

	void RestoreContext( void ) { m_pCardMod->RestoreContext(); }
	void VerifyContext( void ) { m_pCardMod->VerifyContext(); }

	// Exposed methods
	
	
	void createContainer(u1 ctrIndex,u1 keyImport,u1 keySpec,s4 keySize,u1Array* keyValue, u1 role);
	void deleteContainer(u1 ctrIndex, u1 keySpec);
	u1Array* getContainer(u1 ctrIndex);
   u1Array* getContainerProperty(u1 ctrIndex,u1 property,u1 flags);
   void setContainerProperty(u1 ctrIndex,u1 property,u1Array* data,u1 flags);
	u1Array* privateKeyDecrypt(u1 ctrIndex,u1 keyType,u1Array* encryptedData);
    u1Array* privateKeyDecryptEx(u1 ctrIndex,u1 keyType,u1 paddingType, u1 algo, u1Array* encryptedData);
    u1Array* privateKeySign(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter);
    u1Array* constructDHAgreement(u1 ctrIndex, u1Array* dataQx, u1Array* dataQy);
	bool supportsDualKeyContainers (void);

	void createFile(string* path,u1Array* acls,s4 initialSize);
   void createDirectory(string* path,u1Array* acls);
	void writeFile(string* path,u1Array* data);

	u1Array* readFile(string* path);
   u1Array* readFileWithoutMemoryCheck(string* path);

	void deleteFile(string* path);
	void deleteDirectory(string* path);

	StringArray* getFiles(string* path);
	u1Array* getFileProperties(string* path);

   s4 getTriesRemaining(u1 role);
   bool generateSessionPinEx(u1 role, u1Array* pPin, u1ArraySecure& sbSessionPin,s4* pcAttemptsRemaining);
   void changeReferenceData(u1 mode,u1 role,u1Array* oldPin,u1Array* newPin,s4 maxTries);
	void changeAuthenticatorEx(u1 mode,u1 oldRole,u1Array* oldPin,u1 newRole,u1Array* newPin,s4 maxTries);

	void SetPinInitialized(u1 role);
	
	bool isAuthenticated(u1 role, bool bForceRequest = false);
   bool isPinExpired(u1 role);
	void SetAuthenticated(u1 role);
	void SetDeauthenticated(u1 role);

   u1Array* getCardProperty(u1 property,u1 flags);
	void setCardProperty(u1 property,u1Array* data,u1 flags);

   u1Array* authenticateEx(u1 mode,u1 role,u1Array* pin);
   void verifyPin(u1 role,u1Array* pin);

   void deauthenticateEx(u1 roles);
   void logOut(u1 role);

   u1Array* getChallenge();
   void externalAuthenticate(u1Array* response);

   s4Array* getKeySizes();
   u1Array* getSerialNumber();

private:
   LONG AnalyseExceptionString(Exception& ex);
   void checkException( Exception & );
   CardModuleAPI* m_pCardMod;
    SMARTCARD_TYPE m_ucSmartCardType;
	bool m_bMultiPinSupported;
	bool m_bEnableGC;
    Timer m_Timer;
    PROPERTIES m_Properties;

};


#endif // __GEMALTO_MINIDRIVER_CARD_CACHE_FILE_
