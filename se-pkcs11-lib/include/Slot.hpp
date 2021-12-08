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
#ifndef __GEMALTO_SLOT__
#define __GEMALTO_SLOT__

#include <boost/shared_ptr.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <string>
#include "Device.hpp"
#include "Session.hpp"
#include "Token.hpp"
#include "PKCS11Exception.hpp"
#include "Pkcs11ObjectStorage.hpp"

#define ALGO_SHA_1                      (0x04)
#define ALGO_SHA_256                    (0x05)
#define ALGO_SHA_384                    (0x06)
#define ALGO_SHA_512                    (0x07)

#define PADDING_NONE                    (0x01)
#define PADDING_PKCS1                   (0x02)
#define PADDING_PSS                     (0x04)
#define PADDING_OAEP                    (0x08)

#define SLOT_MAX_SESSIONS_COUNT	255

/*
*/
class Slot {


public:

	typedef boost::ptr_map< CK_SESSION_HANDLE, Session > MAP_SESSIONS;
    typedef boost::ptr_map< CK_OBJECT_HANDLE, StorageObject > SESSION_OBJECTS;

    Slot( const boost::shared_ptr < Device >& , CK_SLOT_ID, MiniDriverAuthentication::ROLES userRole, bool bIsVirtual = false);

    inline virtual ~Slot( ) { try { closeAllSessions( ); } catch( ... ) { } }


	/* =========== PKCS11 INTERFACE ===========  */

    void finalize( bool bPcscValid );
	
	void getInfo( CK_SLOT_INFO_PTR );

	void getTokenInfo( CK_TOKEN_INFO_PTR );

	void getMechanismList( CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR );

	void getMechanismInfo( const CK_MECHANISM_TYPE&, CK_MECHANISM_INFO_PTR );

	void initToken( CK_UTF8CHAR_PTR, const CK_ULONG&, CK_UTF8CHAR_PTR );

	void closeAllSessions( bool bPcscValid = true );

	void openSession( const CK_FLAGS&, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR );

	void closeSession( const CK_SESSION_HANDLE& );
	
	void getSessionInfo( const CK_SESSION_HANDLE&, CK_SESSION_INFO_PTR );

	void login( const CK_SESSION_HANDLE&, const CK_USER_TYPE&, CK_UTF8CHAR_PTR, const CK_ULONG& );

	void logout( const CK_SESSION_HANDLE& );

	void initPIN( const CK_SESSION_HANDLE&, CK_UTF8CHAR_PTR, const CK_ULONG& );

	void setPIN( const CK_SESSION_HANDLE&, CK_UTF8CHAR_PTR, const CK_ULONG&, CK_UTF8CHAR_PTR, const CK_ULONG& );

	void createObject( const CK_SESSION_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG&, CK_OBJECT_HANDLE_PTR );

	void destroyObject( const CK_SESSION_HANDLE&, const CK_OBJECT_HANDLE& );

	void getAttributeValue( const CK_SESSION_HANDLE&, const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

	void setAttributeValue( const CK_SESSION_HANDLE&, const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

	void findObjectsInit( const CK_SESSION_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

	void findObjects( const CK_SESSION_HANDLE&, CK_OBJECT_HANDLE_PTR, const CK_ULONG&, CK_ULONG_PTR );

	void findObjectsFinal( const CK_SESSION_HANDLE& );

    inline void generateRandom( const CK_SESSION_HANDLE&, CK_BYTE_PTR a_pRandomData, const CK_ULONG& a_ulRandomLen ) { if( m_Token.get( ) ) { m_Token->generateRandom( a_pRandomData, a_ulRandomLen ); } }

	void generateKeyPair( const CK_SESSION_HANDLE&, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, const CK_ULONG&, CK_ATTRIBUTE_PTR, const CK_ULONG&, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR );

    void deriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
	
	void encryptInit( const CK_SESSION_HANDLE&, CK_MECHANISM_PTR, const CK_OBJECT_HANDLE& );

	void encrypt( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG&, CK_BYTE_PTR, CK_ULONG_PTR );

	void decryptInit( const CK_SESSION_HANDLE&, CK_MECHANISM_PTR, const CK_OBJECT_HANDLE& );

	void decrypt( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG&, CK_BYTE_PTR, CK_ULONG_PTR );

	void signInit( const CK_SESSION_HANDLE&, CK_MECHANISM_PTR, const CK_OBJECT_HANDLE& );

	void sign( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG&, CK_BYTE_PTR, CK_ULONG_PTR );

	void signUpdate( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG& );

	void signFinal( const CK_SESSION_HANDLE&, CK_BYTE_PTR, CK_ULONG_PTR );

	void digestInit( const CK_SESSION_HANDLE&, CK_MECHANISM_PTR );

	void digest( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG&, CK_BYTE_PTR, CK_ULONG_PTR );

	void digestUpdate( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG& );

	void digestFinal( const CK_SESSION_HANDLE&, CK_BYTE_PTR, CK_ULONG_PTR );

	void verifyInit( const CK_SESSION_HANDLE&, CK_MECHANISM_PTR, const CK_OBJECT_HANDLE& );

	void verify( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG&, CK_BYTE_PTR, const CK_ULONG ); 

	void verifyUpdate( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG& );

	void verifyFinal( const CK_SESSION_HANDLE&, CK_BYTE_PTR, const CK_ULONG& );


	inline bool getEvent( void ) { return m_bEvent; }

    inline CK_SLOT_ID getEventSlotId( void ) { return m_ucEventSlotId; }

	inline void setEvent( const bool& a_bEventState, const unsigned char& a_SlotId ) { m_bEvent = a_bEventState; m_ucEventSlotId = a_SlotId; }

	inline const boost::shared_ptr< Token >& getToken( void ) { return m_Token; }

	bool isSessionOwner( const CK_SESSION_HANDLE& a_hSession );

    inline bool isCardPresent( void ) { try { if( m_Device.get( ) ) { return m_Device->isSmartCardPresent( ); } } catch( MiniDriverException& ) { } return false; }

    inline const std::string getReaderName( void ) { try { if( m_Device.get( ) ) { return m_Device->getReaderName( ); } } catch( MiniDriverException& ) { } return m_stEmpty; }

    inline CK_SLOT_ID getSlotId( void ) { try { if( m_Device.get( ) ) { return m_slotID; } } catch( MiniDriverException& ) { } return 0xFF; }

// LCA: Card insertion notif
    inline void tokenInserted( void ) { Log::log( "SLot::tokenInserted" ); m_isTokenInserted = true; }

    void tokenCreate( void );
    //inline void tokenCreate( void ) { m_ulUserType = CK_UNAVAILABLE_INFORMATION; m_Token.reset( new Token( this, m_Device.get( ) ) ); try { if( !Device::s_bEnableCache && m_Device.get( ) ) { m_Device->forceGarbageCollection( ); } updateAllSessionsState( ); } catch( ... ) { } }
	
    inline void tokenDelete( void ) { m_ulUserType = CK_UNAVAILABLE_INFORMATION; m_isTokenRemoved = true; m_Token.reset( ); try { updateAllSessionsState( ); } catch( ... ) { } }

    void tokenUpdate( void );

  	boost::shared_ptr< Device > m_Device;

    inline bool isAuthenticated( void ) { return ( CKU_USER == m_ulUserType ); }

    inline bool administratorIsAuthenticated( void ) { return ( CKU_SO == m_ulUserType ); }

    inline CK_USER_TYPE getUserType( void ) { return m_ulUserType; }

    inline void setUserType( const CK_USER_TYPE& a_ulUserType ) { m_ulUserType = a_ulUserType; }

    void getCardProperty( CK_BYTE, CK_BYTE, CK_BYTE_PTR, CK_ULONG_PTR );

    void setCardProperty( CK_BYTE, CK_BYTE, CK_BYTE_PTR, CK_ULONG );

    inline bool isTokenInserted( ) { return m_isTokenInserted; }
    inline bool isTokenRemoved( ) { return m_isTokenRemoved; }

    inline MiniDriverAuthentication::ROLES getUserRole() const { return m_userRole;}

    inline bool isVirtual() const { return m_bIsVirtual;}
    inline void setVirtual(bool bIsVirtual) { m_bIsVirtual = bIsVirtual;}

    inline bool isStaticProfile( void ) const { try { if( m_Device.get( ) ) { return m_Device->isStaticProfile( ); } } catch( MiniDriverException& ) { } return false; }

	inline bool isAuthenticationLost( void ) const { return m_bAuthenticationLost; }
	inline void setAuthenticationLost( bool bLost ) { m_bAuthenticationLost = bLost; }

    StorageObject* getSessionObject( const CK_OBJECT_HANDLE& a_hObject );
    void removeSessionObject( const CK_OBJECT_HANDLE& a_hObject );
    SESSION_OBJECTS m_SessionObjects;

private:

    void checkAccessException( const PKCS11Exception& );

    Session* getSession( const CK_SESSION_HANDLE& a_hSession );
    
    void updateAllSessionsState( void );

	void clearCache( void );

	void isValidMechanism( const CK_ULONG&, const CK_ULONG& );

    void isValidCryptoOperation( StorageObject*, const CK_ULONG& , CK_MECHANISM_TYPE);

	inline void clear( void ) { closeAllSessions( ); m_Token.reset( ); }

	CK_SESSION_HANDLE addSession( const bool& );

	void removeSession( const CK_SESSION_HANDLE& );

	bool hasReadOnlySession( void );

	CK_SESSION_HANDLE computeSessionHandle( const bool& );
    
	void createToken( void ) { m_Token.reset( new Token( this, m_Device.get( ) ) ); }

    void checkTokenInsertion( void );

	bool m_bEvent;
    
    unsigned char m_ucEventSlotId;

	CK_SLOT_INFO m_SlotInfo;

	MAP_SESSIONS m_Sessions;
	
	boost::shared_ptr< Token > m_Token;

	static unsigned char s_ucSessionIndex;

    std::string m_stEmpty;

    CK_USER_TYPE m_ulUserType;
    MiniDriverAuthentication::ROLES m_userRole;
    CK_SLOT_ID m_slotID;
    bool m_bIsVirtual;
	bool m_bAuthenticationLost;
// LCA: used to remember token insertion
    bool m_isTokenInserted;
    bool m_isTokenRemoved;
};

#endif // __GEMALTO_SLOT__
