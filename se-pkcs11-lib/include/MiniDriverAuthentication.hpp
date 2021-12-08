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
#ifndef __GEMALTO_MINIDRIVER_AUTHENTICATION__
#define __GEMALTO_MINIDRIVER_AUTHENTICATION__


#include <boost/serialization/serialization.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/archive/archive_exception.hpp>
#include <boost/shared_ptr.hpp>
#include "MiniDriverPinPolicy.hpp"
#include "Array.h"
#include "MiniDriverException.hpp"
#include "PCSCMissing.h"

/*
*/
class MiniDriverAuthentication {

public:

    typedef enum { PIN_NONE = 0x00, PIN_USER = 0x01, PIN_ADMIN = 0x02, PIN_3 = 0x04, PIN_4 = 0x08, PIN_5 = 0x10, PIN_6 = 0x20, PIN_7 = 0x40 } ROLES;

    typedef enum { MODE_CHANGE_PIN = 0x00, MODE_UNBLOCK_PIN = 0x01 } CHANGE_REFERENCE_DATA_MODES;

    typedef enum { UVM_PIN_ONLY = 1, UVM_FP_ONLY, UVM_PIN_OR_FP, UVM_PIN_AND_FP } UVM_MODES;

    typedef enum { PIN_TYPE_REGULAR = 0, PIN_TYPE_EXTERNAL, PIN_TYPE_CHALLENGE_RESPONSE, PIN_TYPE_NO_PIN } PIN_TYPES;

	typedef enum { PIN_CACHE_NORMAL = 0, PIN_CACHE_TIMED, PIN_CACHE_NONE, PIN_CACHE_ALWAYS_PROMPT } PIN_CACHE_TYPES;

    static const unsigned char g_ucAuthenticateError = 0;
    static const unsigned char g_ucAuthenticateRegular = 1;
    static const unsigned char g_ucAuthenticateSecure = 2;
    static const unsigned char g_AuthenticateBiometry = 3;

	static std::string g_sPinUserLabel;
	static std::string g_sPinAdminLabel;
	static std::string g_sPin3Label;
	static std::string g_sPin4Label;
	static std::string g_sPin5Label;
	static std::string g_sPin6Label;
	static std::string g_sPin7Label;


    MiniDriverAuthentication( );

    inline void setCardModule( MiniDriverModuleService* a_pCardModule ) { m_CardModule = a_pCardModule; for (int i=0; i < 6; i++) m_PinPolicyForRole[i].setCardModuleService( m_CardModule ); }

    void read( void );

	void setStaticRoles(std::list<u1> roles);
	const std::list<MiniDriverAuthentication::ROLES>& getStaticRoles() const { return m_listStaticRoles; }


    // User role management

    bool isSSO( MiniDriverAuthentication::ROLES role );

    inline bool isNoPin( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return true; else return ( m_ucTypePINForRole[getRoleIndex(role)] == PIN_TYPE_NO_PIN );}

    inline bool isAuthenticated( MiniDriverAuthentication::ROLES role ) { if( m_CardModule ) return m_CardModule->isAuthenticated( (u1) role, true ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isPinExpired( MiniDriverAuthentication::ROLES role ) { if( m_CardModule ) return m_CardModule->isPinExpired( (u1) role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isPinInitialized( MiniDriverAuthentication::ROLES role ) { if (PIN_NONE == role) return false; bool bRet = true; u1Array* a = 0; if( m_CardModule ) { try { a = m_CardModule->getCardProperty( CARD_CHANGE_PIN_FIRST, (u1) role ); } catch( ... ) { a = 0; } if( a ) { bRet = ( 0 == a->ReadU1At( 0 ) ); delete a;} } return bRet; }

    inline bool isExternalPin( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return (m_ucTypePINForRole[getRoleIndex(role)] == PIN_TYPE_EXTERNAL);}

    inline bool isRegularPin( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return (m_ucTypePINForRole[getRoleIndex(role)] == PIN_TYPE_REGULAR);}

    inline bool isModePinOnly( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_wActiveModeForRole[getRoleIndex(role)] == UVM_PIN_ONLY );}

    inline bool isModeNotPinOnly( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_wActiveModeForRole[getRoleIndex(role)] != UVM_PIN_ONLY );}

    inline bool isModePinOrBiometry( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_wActiveModeForRole[getRoleIndex(role)] == UVM_PIN_OR_FP );}

	inline bool isPinCacheNormal( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_ucCachePINForRole[getRoleIndex(role)] == PIN_CACHE_NORMAL );}

	inline bool isPinCacheTimed( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_ucCachePINForRole[getRoleIndex(role)] == PIN_CACHE_TIMED );}

	inline bool isPinCacheNone( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_ucCachePINForRole[getRoleIndex(role)] == PIN_CACHE_NONE );}

	inline bool isPinCacheAlwaysPrompt( MiniDriverAuthentication::ROLES role ) const { if (PIN_NONE == role) return false; return ( m_ucCachePINForRole[getRoleIndex(role)] == PIN_CACHE_ALWAYS_PROMPT );}

    void login( MiniDriverAuthentication::ROLES role, u1Array* );

    inline void verifyPin( MiniDriverAuthentication::ROLES role, u1Array* a_Pin) { if( m_CardModule ) m_CardModule->verifyPin( (u1) role, a_Pin ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

	bool generateSessionPinEx(MiniDriverAuthentication::ROLES role, u1Array* pPin, u1ArraySecure& sbSessionPin,s4* pcAttemptsRemaining) { if( m_CardModule ) return m_CardModule->generateSessionPinEx( (u1) role, pPin, sbSessionPin, pcAttemptsRemaining ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void changePin( MiniDriverAuthentication::ROLES role, u1Array* a_pOldPIN, u1Array* a_pNewPIN );

	inline void logOut( MiniDriverAuthentication::ROLES role ) { if( m_CardModule ) { if (PIN_NONE != role) m_CardModule->logOut( (u1) role );} else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void unblockPin( MiniDriverAuthentication::ROLES role, u1Array*, u1Array* );

    bool isLoggedIn( MiniDriverAuthentication::ROLES role );

	bool isPinPadSupported();

	bool isSessionPinSupported(MiniDriverAuthentication::ROLES role);

    void synchronizePIN( void );

    inline unsigned char getPinMinPinLength( MiniDriverAuthentication::ROLES role ) { int i = getRoleIndex(role); if (m_PinPolicyForRole[i].empty()) read(); return m_PinPolicyForRole[i].getPinMinLength( ); }

    inline unsigned char getPinMaxPinLength( MiniDriverAuthentication::ROLES role ) { int i = getRoleIndex(role); if (m_PinPolicyForRole[i].empty()) read(); return m_PinPolicyForRole[i].getPinMaxLength( ); }

    inline unsigned char getPinMaxAttempts( MiniDriverAuthentication::ROLES role ) { int i = getRoleIndex(role); if (m_PinPolicyForRole[i].empty()) read(); return m_PinPolicyForRole[i].getMaxAttemps( ); }

    inline unsigned char getPinType( MiniDriverAuthentication::ROLES role ) { return m_ucTypePINForRole[getRoleIndex(role)]; }

    // Get the card mode (1=PIN, 2=FingerPrint, 3=PIN or FP, 4=PIN and FP). The default mode is PIN
    inline unsigned short getPinMode( MiniDriverAuthentication::ROLES role ) { return m_wActiveModeForRole[getRoleIndex(role)]; }

	inline unsigned char getPinCacheType( MiniDriverAuthentication::ROLES role ) { return m_ucCachePINForRole[getRoleIndex(role)]; }

	inline ROLES getPinUnblockRole( MiniDriverAuthentication::ROLES role ) { return m_unblockForRole[getRoleIndex(role)]; }

    inline unsigned char getTriesRemaining( MiniDriverAuthentication::ROLES role ) { if( m_CardModule ) return (unsigned char)m_CardModule->getTriesRemaining( (u1) role ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    // Administrator key management

    void administratorLogin( u1Array* );

    inline void administratorLogout( void ) {if( m_CardModule ) m_CardModule->logOut( PIN_ADMIN ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void administratorChangeKey( u1Array*, u1Array* );

    inline unsigned char administratorGetTriesRemaining( void ) { if( m_CardModule ) return (unsigned char)m_CardModule->getTriesRemaining( PIN_ADMIN ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    bool administratorIsAuthenticated( void );

    void print( void );

    static const char* getRoleDescription(ROLES role);
    static int getRoleIndex(ROLES role);
	static int getRolePinID(ROLES role);
    static MiniDriverAuthentication::ROLES getRoleFromIndex( int index);
	static MiniDriverAuthentication::ROLES getRoleFromDesc( const char* szDesc);
    
private:

    // void verifyPinWithBio( void );

    void computeCryptogram( u1Array*, u1Array* );

    unsigned char howToAuthenticate( MiniDriverAuthentication::ROLES role, unsigned char bPinLen );

	unsigned char howToChangePin( MiniDriverAuthentication::ROLES role, unsigned char bOldPinLen, unsigned char bNewPinLen );

	unsigned char howToUnblock( MiniDriverAuthentication::ROLES role, unsigned char bPinLen ) { return howToAuthenticate(role, bPinLen); }

    void authenticateAdmin( u1Array* );

    MiniDriverModuleService* m_CardModule;

    u1ArraySerializable m_Cryptogram;

    ROLES m_AuthenticatedRole;

    bool m_bIsAdministratorLogged;

    // handle roles PIN_USER and PIN_3 to PIN_7
    unsigned short m_wActiveModeForRole[6];
    unsigned char m_ucTypePINForRole[6];
	unsigned char m_ucCachePINForRole[6];
	MiniDriverAuthentication::ROLES m_unblockForRole[6];
    u1ArraySerializable m_PinInfoExForRole[6];
    MiniDriverPinPolicy m_PinPolicyForRole[6];
	std::list<MiniDriverAuthentication::ROLES> m_listStaticRoles;

};


#endif // __GEMALTO_MINIDRIVER_AUTHENTICATION__
