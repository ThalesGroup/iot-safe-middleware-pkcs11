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
#ifndef __GEMALTO_TOKEN__
#define __GEMALTO_TOKEN__


#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/ptr_container/ptr_set.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/random.hpp>
#include <string>
#include <vector>
#include <list>
#include "MiniDriver.hpp"
#include "Device.hpp"
#include "Session.hpp"
#include "Pkcs11ObjectStorage.hpp"
#include "Pkcs11ObjectKeyPrivateRSA.hpp"
#include "Pkcs11ObjectCertificateX509PublicKey.hpp"
#include "MiniDriverException.hpp"
#include "Pkcs11ObjectKeyPublicRSA.hpp"

class Slot;


/*
*/
class Token {

public:

	class CAtomicLogin
	{
	public:
		Token* m_pToken;
        bool m_bIsForWriteOperation;
		std::vector<MiniDriverAuthentication::ROLES> m_vecAuthenticatedRoles;

		CAtomicLogin(Token* pToken, MiniDriverAuthentication::ROLES unblockRole );
        CAtomicLogin(Token* pToken, bool bIsForWriteOperation = false, CK_BYTE specificRole = 0 );

		bool authenticateRole(MiniDriverAuthentication::ROLES role);

		~CAtomicLogin()
		{
			try
			{
				if (m_pToken->m_Device)
				{
					for (std::vector<MiniDriverAuthentication::ROLES>::iterator It = m_vecAuthenticatedRoles.begin();
						It != m_vecAuthenticatedRoles.end(); It++)
					{
						m_pToken->m_Device->logOut( *It, false);
						if ( m_pToken->IsPinCacheDisabled (*It) )
						{
							m_pToken->m_Device->clearPinCache(*It);
						}
					}

				}
			}
			catch(...) {}
		}
	};

    typedef boost::ptr_map< CK_OBJECT_HANDLE, StorageObject > TOKEN_OBJECTS;

    static const unsigned long FLAG_OBJECT_TOKEN = 0x00000000;

    static const unsigned long MASK_OBJECT_TOKEN = 0x00FF0000;

    static bool s_bForcePinUser;

    Token( Slot*, Device* );

    inline virtual ~Token( ) { clear( ); }


    void login( const CK_ULONG&, u1Array* );

    void logout( void );

	bool IsPinCacheDisabled(MiniDriverAuthentication::ROLES role)
	{
		if (!m_Device)
			return false;
		else
			return (m_Device->getPinCacheType(role) == MiniDriverAuthentication::PIN_CACHE_NONE)
				  ||(m_Device->getPinCacheType(role) == MiniDriverAuthentication::PIN_CACHE_ALWAYS_PROMPT);
	}

    void generateRandom( CK_BYTE_PTR, const CK_ULONG& );

    void addObject( StorageObject*, CK_OBJECT_HANDLE_PTR, const bool& a_bRegisterObject = true );

    void addObjectPrivateKey( PrivateKeyObject*, CK_OBJECT_HANDLE_PTR );

    void addObjectCertificate( X509PubKeyCertObject*, CK_OBJECT_HANDLE_PTR );

    void addObjectPublicKey( Pkcs11ObjectKeyPublic*, CK_OBJECT_HANDLE_PTR );

    void deleteObject( const CK_OBJECT_HANDLE& );

    // === TEST
    //inline void findObjectsInit( void ) { m_TokenObjectsReturnedInSearch.clear( ); synchronizeIfSmartCardContentHasChanged( ); }
    inline void findObjectsInit( Session* a_pSession ) { a_pSession->m_TokenObjectsReturnedInSearch.clear( ); try{ synchronizeIfSmartCardContentHasChanged( ); } catch( ... ){} }

    void findObjects( Session*, CK_OBJECT_HANDLE_PTR, const CK_ULONG&, CK_ULONG_PTR );

    void getAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    void setAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    void generateKeyPair( Pkcs11ObjectKeyPublic*, PrivateKeyObject*, CK_OBJECT_HANDLE_PTR , CK_OBJECT_HANDLE_PTR );

    void deriveKey( PrivateKeyObject*, CK_ECDH1_DERIVE_PARAMS_PTR, SecretKeyObject*, CK_OBJECT_HANDLE_PTR );

    StorageObject* getObject( const CK_OBJECT_HANDLE& );

    void sign( const KeyObject*, u1Array*, u1Array*, u1Array* , const CK_ULONG&, CK_BYTE_PTR );

    void decrypt( const StorageObject*, u1Array*, const CK_ULONG&, unsigned char, CK_BYTE_PTR , CK_ULONG_PTR );

    void verify( const StorageObject*, u1Array*, const CK_ULONG&, u1Array* );

    void encrypt( const StorageObject*, u1Array*, const CK_ULONG&, CK_VOID_PTR, CK_BYTE_PTR );

    void initToken( u1Array*, u1Array* );

    void initPIN( u1Array*, u1Array* );

    void setPIN( u1Array*, u1Array* );

    inline const CK_ULONG& getLoggedRole( void ) { return m_RoleLogged; }

    inline void setLoggedRole( const CK_ULONG& r ) { m_RoleLogged = r; }

    inline CK_TOKEN_INFO& getTokenInfo( void ) { return m_TokenInfo; }

    inline bool isToken( const CK_OBJECT_HANDLE& a_hObject ) { return ( ( a_hObject & MASK_OBJECT_TOKEN ) == FLAG_OBJECT_TOKEN ); }

    bool synchronizeIfSmartCardContentHasChanged( void );

	inline void forceSynchronizePrivateObjects(void) { m_bSynchronizeObjectsPrivate = true; synchronizePrivateObjects(); }
        
    static CK_RV checkException( MiniDriverException& );

    MiniDriverAuthentication::ROLES getUserRole() const;

    void updatePinFlags();

private:

    typedef std::vector< StorageObject* > OBJECTS;

    std::string g_stPathPKCS11;

    std::string g_stPathTokenInfo;

    std::string g_stPrefixData;

    std::string g_stPrefixKeyPublic;

    std::string g_stPrefixKeyPrivate;

    std::string g_stPrefixKeySecret;

    std::string g_stPrefixPublicObject;

    std::string g_stPrefixPrivateObject;

    std::string g_stPrefixRootCertificate;

    bool checkSmartCardContent( void );
    bool m_bCheckSmartCardContentDone;

    void initializeObjectIndex( void );

    void checkTokenInfo( void );

    void setTokenInfo( void );

    void writeTokenInfo( void );

    void readTokenInfo( void );

    void createTokenInfo( void );

    //void initializeTokenInfo( void );

    CK_OBJECT_HANDLE computeObjectHandle( const CK_OBJECT_CLASS&, const bool& );

    inline void clear( void ) { m_Objects.clear( ); if (m_Device && m_pSlot) m_Device->clearPinCache(getUserRole()); }

    void authenticateUser( u1Array* );

    void authenticateAdmin( u1Array* );

    void deleteObjectFromCard( StorageObject* );

    void computeObjectFileName( StorageObject*, std::string& );

    void writeObject( StorageObject* );

    CK_OBJECT_HANDLE registerStorageObject( StorageObject* , bool bCheckExistence = true);

    void unregisterStorageObject( const CK_OBJECT_HANDLE& );

	bool CheckStorageObjectExisting( StorageObject* );

    CK_OBJECT_HANDLE computeObjectHandle( void );

    void synchronizeObjects( void );

    void synchronizePublicObjects( void );

    void synchronizePrivateObjects( void );

    void synchronizePIN( void );

    void synchronizePublicCertificateAndKeyObjects( void );

    void synchronizePrivateCertificateAndKeyObjects( void );

    void synchronizePublicDataObjects( void );

    void synchronizePrivateDataObjects( void );

    void synchronizePrivateKeyObjects( void );

    void synchronizeSecretKeyObjects( void );

    void synchronizeRootCertificateObjects( void );

    void synchronizeEmptyContainers( void );

    void createCertificateFromMiniDriverFile( const std::string&, const unsigned char&, const unsigned char&, boost::shared_ptr<u1Array>& );

    void createRootCertificateFromValue( unsigned char* , unsigned int , const unsigned char& );

    bool createCertificateFromPKCS11ObjectFile( const std::string&, const std::string& );

    void createPublicKeyFromPKCS11ObjectFile( const std::string& );

    void createPublicKeyFromMiniDriverFile( const std::string&, const unsigned char& a_ucIndex, const unsigned int& a_ucKeySpec, u1Array*, u1Array*, boost::shared_ptr<u1Array> );

    void createPrivateKeyFromPKCS11ObjectFile( const std::string& );

    void createPrivateKeyFromMiniDriverFile( const std::string&, const unsigned char&, const unsigned int&, u1Array*, u1Array* );

    void createSecretKeyFromPKCS11ObjectFile( const std::string&, u1 );

    bool isPrivate( const CK_OBJECT_HANDLE& a_ObjectHandle ) { return ( ( ( a_ObjectHandle >> 8 ) & 0x000000FF ) >= 0x00000010 ); }

    void checkAuthenticationStatus( CK_ULONG, MiniDriverException& );

    void printObject( StorageObject* );

    boost::mt19937 m_RandomNumberGenerator;

    Device* m_Device;

    TOKEN_OBJECTS m_Objects;

    std::vector< StorageObject* > m_ObjectsToCreate;

    //std::vector< std::string > m_ObjectsToDelete;

    CK_TOKEN_INFO m_TokenInfo;

    CK_ULONG m_RoleLogged;

    unsigned char m_uiObjectIndex;

    bool m_bCreateDirectoryP11;

    bool m_bCreateTokenInfoFile;

    bool m_bWriteTokenInfoFile;

    bool m_bSynchronizeObjectsPublic;

    bool m_bSynchronizeObjectsPrivate;

    Slot* m_pSlot;

    unsigned char computeIndex( const std::string& );

    void generateDefaultAttributesCertificate( X509PubKeyCertObject* );

    void generateDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublic* );

    void generateDefaultAttributesKeyPrivate( PrivateKeyObject* );

    void generateLabel( boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    void generateID(boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    void generateSubject( boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    void generateSerialNumber( boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    void generateIssuer( boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    void generatePublicKeyValue( boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>&, bool&, unsigned char &,u8& , boost::shared_ptr<u1Array>&);

    void generateRootAndSmartCardLogonFlags( boost::shared_ptr< u1Array>&, bool&, unsigned long&, bool& );

    void searchContainerIndex( boost::shared_ptr< u1Array>&, unsigned char&, unsigned char& );

    void setDefaultAttributesCertificate( X509PubKeyCertObject* );

    void setDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublic* );

    void setDefaultAttributesKeyPrivate( PrivateKeyObject* );

    void setContainerIndexToCertificate( boost::shared_ptr< u1Array>&, const unsigned char&, const unsigned char& );

    void setContainerIndexToKeyPublic( boost::shared_ptr< u1Array>&, const unsigned char&, const unsigned char& );

    void computeObjectNameData( std::string&, /*const*/ StorageObject* );

    void computeObjectNamePublicKey( std::string&, /*const*/ StorageObject* );
    
    void computeObjectNamePrivateKey( std::string&, /*const*/ StorageObject* );

    void computeObjectNameCertificate( std::string&, /*const*/ StorageObject* );

    void incrementObjectIndex( void );

    bool isObjectNameValid( const std::string&, const MiniDriverFiles::FILES_NAME& );

	bool isRoleUsingProtectedAuthenticationPath(MiniDriverAuthentication::ROLES role);
 };


#endif // __GEMALTO_TOKEN__
