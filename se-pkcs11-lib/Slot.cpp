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

#include "Slot.hpp"
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include "cryptoki.h"
#include "Template.hpp"
#include "digest.h"
#include "Pkcs11ObjectData.hpp"
#include "Pkcs11ObjectKeyPrivateRSA.hpp"
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "Pkcs11ObjectKeyPrivateECC.hpp"
#include "Pkcs11ObjectKeyPublicECC.hpp"
#include "Pkcs11ObjectCertificateX509PublicKey.hpp"
#include "Pkcs11ObjectKeyGenericSecret.hpp"
#include "Log.hpp"
#include "Application.hpp"


CK_MECHANISM_TYPE g_mechanismList[ ] = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, // 0
    CKM_RSA_PKCS,              // 1
    CKM_RSA_X_509,             // 2
    CKM_MD5_RSA_PKCS,          // 3
    CKM_SHA1_RSA_PKCS,         // 4
    CKM_SHA256_RSA_PKCS,       // 5
	CKM_SHA384_RSA_PKCS,       // 6
	CKM_SHA512_RSA_PKCS,       // 7
    CKM_MD5,                   // 8
    CKM_SHA_1,                 // 9
    CKM_SHA256,                 // 10
    CKM_SHA384,                 // 11
    CKM_SHA512,                 // 12
    CKM_AES_CMAC_GENERAL,       // 13
    CKM_AES_CMAC                // 14
};

CK_MECHANISM_TYPE g_mechanismListRsaEx[ ] = {
    CKM_RSA_PKCS_OAEP,    
    CKM_RSA_PKCS_PSS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS
};

CK_MECHANISM_TYPE g_mechanismListECC[ ] = {
    CKM_ECDSA_KEY_PAIR_GEN,    
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_ECDSA,                 
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_ECDH1_DERIVE
};

CK_MECHANISM_INFO g_mechanismInfo[] = {
    {/* 0 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_GENERATE_KEY_PAIR },
    {/* 1 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT },
    {/* 2 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT },
    {/* 3 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {/* 4 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {/* 5 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
	{/* 6 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
	{/* 7 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {/* 8 */  0,0, CKF_DIGEST },
    {/* 9 */  0,0, CKF_DIGEST },
    {/* 10 */  0,0, CKF_DIGEST },
    {/* 11 */  0,0, CKF_DIGEST },
    {/* 12 */  0,0, CKF_DIGEST },
    {/* 13 */ 128, 128, CKF_SIGN | CKF_VERIFY },
    {/* 14 */ 128, 128, CKF_SIGN | CKF_VERIFY }
};

CK_MECHANISM_INFO g_mechanismInfoRsaEx[] = {
    {MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT },
    {MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY }
};

CK_MECHANISM_INFO g_mechanismInfoECC[] = {
    {MiniDriver::s_iMinLengthKeyECC, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
    {MiniDriver::s_iMinLengthKeyECC, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
    {MiniDriver::s_iMinLengthKeyECC, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
    {MiniDriver::s_iMinLengthKeyECC, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
    {384, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
    {521, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
    {MiniDriver::s_iMinLengthKeyECC, MiniDriver::s_iMaxLengthKeyECC, CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
};

const int g_iLabelSize = 32;

// Index used to compute the session handle. The first session handle must start from 1 because 0 is used for an unvalid handle
unsigned char Slot::s_ucSessionIndex = 0;


/*
*/
Slot::Slot( const boost::shared_ptr < Device >& a_pDevice, CK_SLOT_ID slotID, MiniDriverAuthentication::ROLES userRole, bool bIsVirtual ) {

    Log::begin( "Slot::Slot" ); 

    // LCA: used to remember card insertion
    m_isTokenInserted = false;
    m_isTokenRemoved = false;

    //m_SessionState = CKS_RO_PUBLIC_SESSION;

    m_ulUserType = CK_UNAVAILABLE_INFORMATION;
    m_userRole = userRole;
    m_slotID = slotID;
    m_bIsVirtual = bIsVirtual;

    m_stEmpty = "";

    m_ucEventSlotId = 0xFF;

    m_bEvent = false;

	m_bAuthenticationLost = false;

    // Store a pointer to the device instance
    m_Device = a_pDevice;

    try {

        // Create a token instance if a smart card is present into the reader
        if( m_Device.get( ) && m_Device->isSmartCardPresent( ) && m_Device->isSmartCardRecognized( ) ) {

            Log::log( "Slot::Slot - Reader Name <%s> - SmartCard present <%d>", m_Device->getReaderName( ).c_str( ), m_Device->isSmartCardPresent( ) );

            //m_Token.reset( new Token( this, m_Device.get( ) ) );

            //// Analyse the current state of the smart card to consider the slot as connected or not
            //if( m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_Device->isAuthenticated( ) ) ) {

            //    Log::log( "Slot::Slot - No PIN or SSO activated" );

            //    m_ulUserType = CKU_USER;
            //}

            tokenInserted( );
        }

    } catch( MiniDriverException& ) {

        m_Token.reset( );

        Log::error( "Slot::Slot", "MiniDriverException" );
    }

    // Initialize the slot info
    memset( &m_SlotInfo, 0, sizeof( CK_SLOT_INFO ) );

    m_SlotInfo.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;

    memset( m_SlotInfo.slotDescription, ' ', sizeof( m_SlotInfo.slotDescription ) );

    if( m_Device.get( ) ) {

        std::string slotDescription = m_Device->getReaderName( );
        
        // Add PIN information if associated with PIN different from USER
        if (m_userRole != MiniDriverAuthentication::PIN_USER)
        {
            slotDescription += " (";
            slotDescription += MiniDriverAuthentication::getRoleDescription(m_userRole);
            slotDescription += ")";
        }
        memcpy( m_SlotInfo.slotDescription, slotDescription.c_str( ), min((int) slotDescription.length( ), 64) );
    }

    memset( m_SlotInfo.manufacturerID, ' ', sizeof( m_SlotInfo.manufacturerID ) );

    m_SlotInfo.manufacturerID[0] = 'U';
    m_SlotInfo.manufacturerID[1] = 'n';
    m_SlotInfo.manufacturerID[2] = 'k';
    m_SlotInfo.manufacturerID[3] = 'n';
    m_SlotInfo.manufacturerID[4] = 'o';
    m_SlotInfo.manufacturerID[5] = 'w';
    m_SlotInfo.manufacturerID[6] = 'n';

    Log::end( "Slot::Slot" ); 
}


/*
*/
inline void Slot::tokenCreate( void ) { 
        
    m_ulUserType = CK_UNAVAILABLE_INFORMATION; 
            
   
    try { 

		  m_Token.reset( new Token( this, m_Device.get( ) ) ); 

        // Analyse the current state of the smart card to consider the slot as connected or not
        if( m_Device->isNoPin( m_userRole) || ( m_Device->isSSO( m_userRole) && m_Device->isAuthenticated( m_userRole) ) ) {

            Log::log( "Slot::Slot - No PIN or SSO activated" );

            m_ulUserType = CKU_USER;

			m_Token->forceSynchronizePrivateObjects();
        }
                    
        if( !Device::s_bEnableDiskCache && m_Device.get( ) ) { 
                
            m_Device->forceGarbageCollection( ); 
        } 
            
        updateAllSessionsState( ); 
        
    } catch( ... ) { } 
}

/*
*/
void Slot::tokenUpdate( void ) { 
    try { 
        if( m_Token.get( ) ) 
        { 
            m_Token->synchronizeIfSmartCardContentHasChanged( ); 

            if (m_ulUserType == CK_UNAVAILABLE_INFORMATION)
            {
                // Analyse the current state of the smart card to consider the slot as connected or not
                if( m_Device->isNoPin( m_userRole) || ( m_Device->isSSO( m_userRole) && m_Device->isAuthenticated( m_userRole) ) ) {

                    Log::log( "Slot::tokenUpdate - No PIN or SSO activated" );

                    m_ulUserType = CKU_USER;

                    m_Token->forceSynchronizePrivateObjects();
                }
            }
        } 
        updateAllSessionsState( ); 
    } catch( ... ) { } 
}

	
/*
*/
void Slot::finalize( bool bPcscValid ) {

    Log::begin( "Slot::finalize" ); 

    //m_SessionState = CKS_RO_PUBLIC_SESSION;

    m_ulUserType = CK_UNAVAILABLE_INFORMATION;

    try {

        closeAllSessions( bPcscValid );

        if( m_Device.get( ) ) {

            if( bPcscValid && m_Device->isSmartCardPresent( ) ) {

                m_Device->logOut( m_userRole, true);

                m_Device->administratorLogout( );

                if( !Device::s_bEnableDiskCache ) {

                    m_Device->forceGarbageCollection( );
                }
            }

            if (!isVirtual())
            {
                m_Device->saveCache( );
            }
        }

    } catch( ... ) { }

    Log::end( "Slot::finalize" ); 
}


/*
*/
void Slot::checkTokenInsertion( void ) {

    if( m_isTokenInserted ) {

        tokenCreate( );

        m_isTokenInserted = false;
        m_isTokenRemoved = false;

        if (!isVirtual())
        {
            m_Device->saveCache( );
        }
    }
    else
        tokenUpdate();
}


/*
*/
void Slot::getInfo( CK_SLOT_INFO_PTR p ) {

    if( !p ) {

        return;
    }

    memcpy( p->slotDescription, m_SlotInfo.slotDescription, sizeof( p->slotDescription ) );

    memcpy( p->manufacturerID, m_SlotInfo.manufacturerID, sizeof( p->manufacturerID ) );

    p->hardwareVersion.major = m_SlotInfo.hardwareVersion.major;

    p->hardwareVersion.minor = m_SlotInfo.hardwareVersion.minor;

    p->firmwareVersion.major = m_SlotInfo.firmwareVersion.major;

    p->firmwareVersion.minor = m_SlotInfo.firmwareVersion.minor;

    // No card in reader
    m_SlotInfo.flags &= ~CKF_TOKEN_PRESENT;


// LCA: Token inserted?
    checkTokenInsertion( );

    try {

        if( getToken( ).get( ) ) { //m_Device.get( ) && m_Device->isSmartCardPresent( ) ) {

            // we found a card in this reader
            m_SlotInfo.flags |= CKF_TOKEN_PRESENT;
        } 

    } catch( ... ) { }

    p->flags = m_SlotInfo.flags;
}


/*
*/
void Slot::getTokenInfo( CK_TOKEN_INFO_PTR p ) {

    if( !p ) {

        return;
    }

    // LCA: Token inserted?
    checkTokenInsertion( );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    //Log::begin( "Slot::GetTokenInfo" );

    try {

        p->firmwareVersion.major = m_Token->getTokenInfo( ).firmwareVersion.major;
        p->firmwareVersion.minor = m_Token->getTokenInfo( ).firmwareVersion.minor;
        p->hardwareVersion.major = m_Token->getTokenInfo( ).hardwareVersion.major;
        p->hardwareVersion.minor = m_Token->getTokenInfo( ).hardwareVersion.minor;

        memcpy( p->label, m_Token->getTokenInfo( ).label, sizeof( p->label ) );

        if (m_userRole != MiniDriverAuthentication::PIN_USER)
        {
            std::string szPinId = " (";
            szPinId += MiniDriverAuthentication::getRoleDescription(m_userRole);
            szPinId += ")";

            memcpy( & p->label[32 - szPinId.length()], szPinId.c_str(), szPinId.length());
        }

        memcpy( p->manufacturerID, m_Token->getTokenInfo( ).manufacturerID, sizeof( p->manufacturerID ) );

        memcpy( p->model, m_Token->getTokenInfo( ).model, sizeof( p->model ) );

        memcpy( p->serialNumber, m_Token->getTokenInfo( ).serialNumber, sizeof( p->serialNumber ) );

        //Log::logCK_UTF8CHAR_PTR( "Slot::GetTokenInfo - m_TokenInfo.serialNumber", m_Token->getTokenInfo( ).serialNumber, sizeof( m_Token->getTokenInfo( ).serialNumber ) );

        p->ulFreePrivateMemory  = m_Token->getTokenInfo( ).ulFreePrivateMemory;
        p->ulFreePublicMemory   = m_Token->getTokenInfo( ).ulFreePublicMemory;
        p->ulMaxPinLen          = m_Token->getTokenInfo( ).ulMaxPinLen;
        p->ulMinPinLen          = m_Token->getTokenInfo( ).ulMinPinLen;
        p->ulMaxRwSessionCount  = SLOT_MAX_SESSIONS_COUNT;
        p->ulSessionCount       = 0;
        p->ulMaxSessionCount    = SLOT_MAX_SESSIONS_COUNT;
        p->ulRwSessionCount     = 0;
        p->ulTotalPrivateMemory = m_Token->getTokenInfo( ).ulTotalPrivateMemory;
        p->ulTotalPublicMemory  = m_Token->getTokenInfo( ).ulTotalPublicMemory;

        BOOST_FOREACH( const MAP_SESSIONS::value_type& s, m_Sessions ) {

            // Count the number of opened sessions
            ++p->ulSessionCount;

            if( s.second->isReadWrite( ) ) {

                ++p->ulRwSessionCount;
            }
        }

        memcpy( p->utcTime, m_Token->getTokenInfo( ).utcTime, sizeof( p->utcTime ) );

        if( !m_Device.get( ) ) {

            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
        }

        try {

            //Log::log( "Slot::GetTokenInfo - isNoPinSupported <%d>", m_Device->isNoPin( ) );
            //Log::log( "Slot::GetTokenInfo - IsSSO <%d>", m_Device->isSSO( ) );
            //Log::log( "Slot::GetTokenInfo - IsAuthenticated <%d>", bIsAuthenticated );

            // Check if the smart card is in SSO mode
            if(  m_Device->isNoPin( m_userRole) || ( m_Device->isSSO( m_userRole) && isAuthenticated( ) ) ) {

                m_Token->getTokenInfo( ).flags &= ~CKF_LOGIN_REQUIRED;
                //Log::log( "Slot::GetTokenInfo - No login required" );

            } else {

                m_Token->getTokenInfo( ).flags |= CKF_LOGIN_REQUIRED;
                //Log::log( "Slot::GetTokenInfo - Login required" );
            }

            if( m_Device->isPinInitialized( m_userRole ) ) {
                Log::log( "Slot::getTokenInfo - Enable CKF_USER_PIN_INITIALIZED" );
                m_Token->getTokenInfo( ).flags |= CKF_USER_PIN_INITIALIZED;
            }
            else
            {
                Log::log( "Slot::getTokenInfo - Disable CKF_USER_PIN_INITIALIZED" );
                m_Token->getTokenInfo( ).flags &= ~CKF_USER_PIN_INITIALIZED;
            }

        } catch( MiniDriverException& x ) {

            Log::error( "Slot::getTokenInfo", "MiniDriverException" );
            throw PKCS11Exception( Token::checkException( x ) );
        }

        p->flags = m_Token->getTokenInfo( ).flags;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    //Log::end( "Slot::GetTokenInfo" );
}


/*
*/
void Slot::getMechanismList( CK_MECHANISM_TYPE_PTR a_pMechanismList, CK_ULONG_PTR a_pulCount ) {

    // LCA: Token inserted?
    checkTokenInsertion( );

    if( !m_Token || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

   bool bSha1Disabled = m_Device->IsSha1Disabled();
	bool bIsRsa = true;
    bool bIsECC = m_Device->isECC();
    bool bIsRsaEx = m_Device->hasOAEP_PSS();
	int minRsa = 0, maxRsa = 0, minRsaGen = 0, maxRsaGen = 0, minEcc = 0, maxEcc = 0, minEccGen = 0, maxEccGen = 0;
	m_Device->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, m_userRole);
	if (bIsECC)
	{
		m_Device->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, m_userRole);

		if (!minEcc || !maxEcc)
		{
			// No ECC key size supported (can happen on static profiles)
			// disable Ecc
			bIsECC = false;
		}
	}

	if (!minRsa || !maxRsa)
	{
		// No RSa key size supported (can happen on static profiles)
		// disable RSA
		bIsRsa = false;
		bIsRsaEx = false;
	}

    size_t lStandard = (bIsRsa)? sizeof( g_mechanismList ) / sizeof( CK_ULONG ) : 5 /* only hash mechanisms */;
    size_t lEcc = (bIsECC)? sizeof( g_mechanismListECC ) / sizeof( CK_ULONG ) : 0;
    size_t lRsaEx = (bIsRsaEx)? sizeof( g_mechanismListRsaEx ) / sizeof( CK_ULONG ) : 0;

    size_t lTotal = lStandard + lEcc + lRsaEx;
    if (bSha1Disabled)
    {
       // remove SHA-1 mechanisms
       if (bIsRsa) lTotal--;
       if (bIsECC) lTotal--;
       if (bIsRsaEx) lTotal--;
    }

    if( a_pMechanismList ) {

       if( *a_pulCount < lTotal ) {

           *a_pulCount = lTotal;
        
           throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
       }
    
       size_t index = 0;
        for( size_t i = 0 ; i < lStandard ; ++i ) {
           CK_MECHANISM_TYPE mechType = g_mechanismList[ i + sizeof( g_mechanismList ) / sizeof( CK_ULONG ) - lStandard];
           if (bSha1Disabled && (mechType == CKM_SHA1_RSA_PKCS))
              continue;
            a_pMechanismList[ index++ ] = mechType;
        }

        for( size_t i = 0 ; i < lEcc ; ++i ) {
           CK_MECHANISM_TYPE mechType = g_mechanismListECC[ i ];
           if (bSha1Disabled && (mechType == CKM_ECDSA_SHA1))
              continue;
            a_pMechanismList[ index++ ] = mechType;
        }

        for( size_t i = 0 ; i < lRsaEx ; ++i ) {
           CK_MECHANISM_TYPE mechType = g_mechanismListRsaEx[ i ];
           if (bSha1Disabled && (mechType == CKM_SHA1_RSA_PKCS_PSS))
              continue;
            a_pMechanismList[ index++ ] = mechType;
        }
     }
  
    *a_pulCount = lTotal;
}


/*
*/
void Slot::getMechanismInfo( const CK_MECHANISM_TYPE& t, CK_MECHANISM_INFO_PTR p ) {

    //if( !p ) {

    //    return;
    //}

    // LCA: Token inserted?
    checkTokenInsertion( );

    if( !m_Token || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    size_t i = 0;

    CK_MECHANISM_INFO_PTR pMechInfo = NULL;
    bool found = false;
    bool bSha1Disabled = m_Device->IsSha1Disabled();
	bool bIsRsa = true;
    bool bIsECC = m_Device->isECC();
    bool bIsRsaEx = m_Device->hasOAEP_PSS();
	int minRsa = 0, maxRsa = 0, minRsaGen = 0, maxRsaGen = 0, minEcc = 0, maxEcc = 0, minEccGen = 0, maxEccGen = 0;

   if (bSha1Disabled && (t == CKM_SHA1_RSA_PKCS || t == CKM_ECDSA_SHA1 || t == CKM_SHA1_RSA_PKCS_PSS))
   {
      throw PKCS11Exception( CKR_MECHANISM_INVALID );
   }

	m_Device->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, m_userRole);
	if (bIsECC)
	{
		m_Device->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, m_userRole);

		if (!minEcc || !maxEcc)
		{
			// No ECC key size supported (can happen on static profiles)
			// disable Ecc
			bIsECC = false;
		}
	}

	if (!minRsa || !maxRsa)
	{
		// No RSa key size supported (can happen on static profiles)
		// disable RSA
		bIsRsa = false;
		bIsRsaEx = false;
	}

    size_t lStandard = (bIsRsa)? sizeof( g_mechanismList ) / sizeof( CK_ULONG ) : 5;
    size_t lEcc = sizeof( g_mechanismListECC ) / sizeof( CK_ULONG );
    size_t lRsaEx = sizeof( g_mechanismListRsaEx ) / sizeof( CK_ULONG );

    for( i = 0 ; i < lStandard ; ++i ) {

        if( g_mechanismList[ i  + sizeof( g_mechanismList ) / sizeof( CK_ULONG ) - lStandard] == t ) {

            found = true;
            pMechInfo = &g_mechanismInfo[ i ];
			switch(t)
			{
			case CKM_RSA_PKCS_KEY_PAIR_GEN:
				pMechInfo->ulMinKeySize = minRsaGen;
				pMechInfo->ulMaxKeySize = maxRsaGen;
				break;
			case CKM_RSA_PKCS : 
			case CKM_RSA_X_509: 
			case CKM_MD5_RSA_PKCS: 
			case CKM_SHA1_RSA_PKCS: 
			case CKM_SHA256_RSA_PKCS: 
			case CKM_SHA384_RSA_PKCS:
			case CKM_SHA512_RSA_PKCS:
				pMechInfo->ulMinKeySize = minRsa;
				pMechInfo->ulMaxKeySize = maxRsa;			
				break;
			}
        }
    }

    if (!found && bIsECC)
    {
        for( i = 0 ; i < lEcc ; ++i ) {

            if( g_mechanismListECC[ i ] == t ) {

                found = true;
                pMechInfo = &g_mechanismInfoECC[ i ];
				if (CKM_ECDSA_KEY_PAIR_GEN == t)
				{
					pMechInfo->ulMinKeySize = minEccGen;
					pMechInfo->ulMaxKeySize = maxEccGen;
				}
				else
				{
               if (pMechInfo->ulMinKeySize < (CK_ULONG)minEcc)
					   pMechInfo->ulMinKeySize = minEcc;
               if (pMechInfo->ulMaxKeySize > (CK_ULONG)maxEcc)
					   pMechInfo->ulMaxKeySize = maxEcc;
				}
                break;
            }
        }
    }

    if (!found && bIsRsaEx)
    {
        for( i = 0 ; i < lRsaEx ; ++i ) {

            if( g_mechanismListRsaEx[ i ] == t ) {

                found = true;
                pMechInfo = &g_mechanismInfoRsaEx[ i ];
				pMechInfo->ulMinKeySize = minRsa;
				pMechInfo->ulMaxKeySize = maxRsa;
                break;
            }
        }
    }

    if( !found ) {

        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }

    p->ulMinKeySize = pMechInfo->ulMinKeySize;

    p->ulMaxKeySize = pMechInfo->ulMaxKeySize;

    p->flags = pMechInfo->flags;
}


/*
*/
void Slot::initToken( CK_UTF8CHAR_PTR pPin, const CK_ULONG& ulPinLen, CK_UTF8CHAR_PTR pLabel ) {

    checkTokenInsertion( );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check if we have an open session
    if( m_Sessions.size( ) ) {

        throw PKCS11Exception( CKR_SESSION_EXISTS );
    }

    u1ArraySecure p( ulPinLen );
    p.SetBuffer( pPin );

    u1Array l( g_iLabelSize );
    l.SetBuffer( pLabel );

    try {

        m_Token->initToken( &p, &l );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::checkAccessException( const PKCS11Exception& a_Exception ) {

    if( CKR_USER_NOT_LOGGED_IN == a_Exception.getError( ) ) {

        Log::log( "Slot::checkAccessException - !! User desauthenticated !!" );

        m_ulUserType = CK_UNAVAILABLE_INFORMATION;

        // Update the state of all sessions because write access is no more allowed
        updateAllSessionsState( );
    }
}


/*
*/
void Slot::openSession( const CK_FLAGS& flags, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR phSession ) {

    bool bIsReadWrite = ( ( flags & CKF_RW_SESSION ) == CKF_RW_SESSION );


// LCA: Token inserted?
    checkTokenInsertion( );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }


    // if admin is logged we can not open R/O session because R/O session is not allowed for SO
    if( administratorIsAuthenticated( ) && !bIsReadWrite ) {

        throw PKCS11Exception( CKR_SESSION_READ_WRITE_SO_EXISTS );
    }

    // Create the session
    *phSession = addSession( bIsReadWrite );
}


/*
*/
void Slot::closeAllSessions( bool bPcscValid ) {

    bool bIsSSOMode = false;
    
    if (m_Device.get( ) && m_Device->isSmartCardRecognized( ) && 
        (m_Device->isNoPin( m_userRole ) || ( m_Device->isSSO( m_userRole) && isAuthenticated( ) ))
       )
    {
        bIsSSOMode = true;
    }

    try {

        // The user or SO must be desauthenticated
        if( (isAuthenticated( ) || administratorIsAuthenticated( ) ) 
            && !bIsSSOMode                
          ){
        
            if( bPcscValid && m_Device.get( ) && m_Device->isSmartCardPresent( ) ) {

                if( m_Token.get( ) ) {

                    m_Token->logout( );
                }
            }
        }

		setAuthenticationLost(false);

    } catch( ... ) { }

	if (!m_Sessions.empty())
		m_Sessions.clear( );
	if (!m_SessionObjects.empty())
    m_SessionObjects.clear();

    if( !bIsSSOMode ) // not in SSO mode
    {
        //m_SessionState = CKS_RO_PUBLIC_SESSION;
        m_ulUserType = CK_UNAVAILABLE_INFORMATION;
    }
}


/*
*/
void Slot::closeSession( const CK_SESSION_HANDLE& a_hSession ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    getSession( a_hSession );

    m_Sessions.erase( a_hSession );

    try {

        // Last session ? The user or SO must be desauthenticated
        if( !m_Sessions.size( ) ) {

			if (( isAuthenticated( ) || administratorIsAuthenticated( ) )
                && m_Device.get( ) && m_Device->isSmartCardRecognized( )
                && !m_Device->isNoPin( m_userRole)
                && !m_Device->isSSO( m_userRole)                               
               )
			{
				m_Token->logout( );
				//m_SessionState = CKS_RO_PUBLIC_SESSION;
				m_ulUserType = CK_UNAVAILABLE_INFORMATION;
			}

			setAuthenticationLost(false);
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::getSessionInfo( const CK_SESSION_HANDLE& a_hSession, CK_SESSION_INFO_PTR a_pInfo ) {

    Session* s = getSession( a_hSession );

    // Return the session information

    if( !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    a_pInfo->slotID = m_slotID;

    //// Lead Firefox to crash when it is called from the "Certificate Manager"
    //// when the smart card was previously logged in by Firefox but is now logged 
    //// out by another application than Firefox:
    //// Check that the user is still logged in
    //if( m_ulUserType == CKU_USER ) {

    //    if ( m_Device.get( ) && !m_Device->isAuthenticated( ) ) {
    //    
    //        m_ulUserType = CK_UNAVAILABLE_INFORMATION;

    //        // Update the state of all sessions because write access is no more allowed
    //        updateAllSessionsState( );
    //    }
    //}

    //        // Update the state of all sessions because write access is no more allowed
    //        updateAllSessionsState( );
    //    }
    //}

    a_pInfo->state = s->getState( );

    a_pInfo->flags = s->getFlags( );

    a_pInfo->ulDeviceError = CKR_OK;
}


/*
*/
void Slot::login( const CK_SESSION_HANDLE& a_hSession, const CK_USER_TYPE& a_UserType, CK_UTF8CHAR_PTR a_pPin, const CK_ULONG& a_ulPinLen ) {

    if( !m_Token.get(  ) || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    try {

        // The smart card is configured in "no pin" mode
        if( m_Device->isNoPin( m_userRole) && !administratorIsAuthenticated( ) ) {

            //m_SessionState = s->isReadWrite( ) ? ( ( CKU_USER == a_UserType ) ? CKS_RW_USER_FUNCTIONS : CKS_RW_SO_FUNCTIONS ) : ( ( CKU_USER == a_UserType ) ? CKS_RO_USER_FUNCTIONS : CKS_RW_SO_FUNCTIONS );

            m_ulUserType = a_UserType;

            updateAllSessionsState( );

            return;
        }

        // The smart card is configured in "sso" mode and the end-user is already logged in
        if( m_Device->isSSO( m_userRole ) && isAuthenticated( ) ) {

            m_ulUserType = a_UserType;

            updateAllSessionsState( );

            return;
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::login", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );
    }

    // The SO wants to log in but a session exists
    if( ( CKU_SO == a_UserType ) && hasReadOnlySession( ) ) {

        throw PKCS11Exception( CKR_SESSION_READ_ONLY_EXISTS );
    }

    u1ArraySecure pPin( a_ulPinLen );

    pPin.SetBuffer( a_pPin );

    try {

        m_Token->login( a_UserType, &pPin );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::login", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if( CKU_SO == a_UserType ) {

        // cache SO PIN for the duration of this session        
        if( s ) {

            s->setPinSO( pPin );
        }
    }

    m_ulUserType = a_UserType;

    // Update the state of all sessions because write access is now allowed
    updateAllSessionsState( );

	setAuthenticationLost(false);
}


/*
*/
void Slot::logout( const CK_SESSION_HANDLE& a_hSession ) {

    if( !m_Device.get( ) || !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    getSession( a_hSession );

    try {

        // Log out from the smart card
        m_Token->logout( );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    m_ulUserType = CK_UNAVAILABLE_INFORMATION;

	setAuthenticationLost(false);

    // Analyse the current stae of the smart card to consider the slot as connected or not
    if( m_Device->isNoPin( m_userRole) || ( m_Device->isSSO( m_userRole ) && m_Device->isAuthenticated( m_userRole) ) ) {

        m_ulUserType = CKU_USER;
    }

    // Update the state of all sessions because write access is no more allowed
    updateAllSessionsState( );
}


/*
*/
void Slot::updateAllSessionsState( void ) {

    //CK_ULONG ulRole = CK_UNAVAILABLE_INFORMATION;
    //
    //    if( isAuthenticated( ) ) {

    //        ulRole = CKU_USER;

    //    } else if( administratorIsAuthenticated( ) ) {

    //        ulRole = CKU_SO;
    //    }

    BOOST_FOREACH( const MAP_SESSIONS::value_type& i, m_Sessions ) {

        if( i.second ) {

            i.second->updateState( m_ulUserType );
        }
    }
}


/*
*/
void Slot::initPIN( const CK_SESSION_HANDLE& a_hSession, CK_UTF8CHAR_PTR a_pPin, const CK_ULONG& a_ulPinLen ) {

    Session* s = getSession( a_hSession );

    if( CKS_RW_SO_FUNCTIONS != s->getState( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    u1ArraySecure p( a_ulPinLen );
    p.SetBuffer( a_pPin );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if (    (a_ulPinLen > m_Token->getTokenInfo().ulMaxPinLen)
        ||  ((a_ulPinLen != 0) && a_ulPinLen < m_Token->getTokenInfo().ulMinPinLen)
		||  ((a_ulPinLen == 0) && !(m_Token->getTokenInfo().flags & CKF_PROTECTED_AUTHENTICATION_PATH))
       )
    {
        throw PKCS11Exception( CKR_PIN_LEN_RANGE );
    }

    try {
        u1ArraySecure soPin(s->getPinSO()->GetLength());
        s->getPinSO()->CopyTo(soPin.GetBuffer());
        m_Token->initPIN( &soPin, &p );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::setPIN( const CK_SESSION_HANDLE& a_hSession, CK_UTF8CHAR_PTR a_pOldPin, const CK_ULONG& a_ulOldLen, CK_UTF8CHAR_PTR a_pNewPin, const CK_ULONG& a_ulNewLen ) {

    Session* s = getSession( a_hSession );

    CK_ULONG ulState = s->getState( );

    if( ( CKS_RW_PUBLIC_SESSION != ulState ) && ( CKS_RW_SO_FUNCTIONS != ulState ) && ( CKS_RW_USER_FUNCTIONS != ulState ) ) {

        throw PKCS11Exception( CKR_SESSION_READ_ONLY );
    }

    u1ArraySecure o( a_ulOldLen );
    o.SetBuffer( a_pOldPin );

    u1ArraySecure n( a_ulNewLen );
    n.SetBuffer( a_pNewPin );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check pin length range only for CKU_USER
    if (    (CKS_RW_SO_FUNCTIONS != ulState) &&
            (	(a_ulNewLen > m_Token->getTokenInfo().ulMaxPinLen) 
			||  (a_ulNewLen != 0 && a_ulNewLen < m_Token->getTokenInfo().ulMinPinLen)
			||	((a_ulNewLen == 0) && !(m_Token->getTokenInfo().flags & CKF_PROTECTED_AUTHENTICATION_PATH))
			)
       )
    {
        throw PKCS11Exception( CKR_PIN_LEN_RANGE );
    }

    try {

        m_Token->setPIN( &o, &n );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::setPIN", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::findObjectsInit( const CK_SESSION_HANDLE& a_hSession, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    Session* s = getSession( a_hSession );

    // check if search is active for this session or not
    if( s->isSearchActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    Template* searchTmpl = NULL_PTR;

    if( a_ulCount ) {

        searchTmpl = new Template( a_pTemplate, a_ulCount );
    }

    s->removeSearchTemplate( );

    s->setSearchTemplate( searchTmpl );

    if( !m_Token ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Token->findObjectsInit( s );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::findObjects( const CK_SESSION_HANDLE& a_hSession, CK_OBJECT_HANDLE_PTR a_phObject, const CK_ULONG& a_ulMaxObjectCount, CK_ULONG_PTR a_pulObjectCount ) {

    Session* s = getSession( a_hSession );

    // check if search is active for this session or not
    if( !s->isSearchActive( )  ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    *a_pulObjectCount = 0;

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Find the token objects matching the template
        m_Token->findObjects( s, a_phObject, a_ulMaxObjectCount, a_pulObjectCount );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Find the session objects matching the template
    s->findObjects( a_phObject, a_ulMaxObjectCount, a_pulObjectCount );
}


/*
*/
void Slot::findObjectsFinal( const CK_SESSION_HANDLE& a_hSession ) {

    Session* s = getSession( a_hSession );

    // check if search is active for this session or not
    if( !s->isSearchActive( )  ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    s->removeSearchTemplate( );
}


/*
*/
void Slot::createObject( const CK_SESSION_HANDLE& a_hSession, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount, CK_OBJECT_HANDLE_PTR a_phObject ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check template consistency
    Template t;
    t.checkTemplate( a_pTemplate, a_ulCount, Template::MODE_CREATE );

    bool bIsToken = t.isToken( a_pTemplate, a_ulCount );
    bool bIsPrivate = t.isPrivate( a_pTemplate, a_ulCount );

    // if this is a readonly session and user is not logged 
    // then only public session objects can be created
    Session* s = getSession( a_hSession );

    if( !s->isReadWrite( ) && bIsToken ) {

        throw PKCS11Exception( CKR_SESSION_READ_ONLY );
    }

    if( !isAuthenticated( ) && bIsPrivate ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    StorageObject* o = 0;

    CK_ULONG ulClass = t.getClass( a_pTemplate, a_ulCount );
    bool bIsRSA = (ulClass == CKO_PUBLIC_KEY || ulClass == CKO_PRIVATE_KEY) && (CKK_RSA == t.getKeyType(a_pTemplate, a_ulCount));
    bool bIsECC = (ulClass == CKO_PUBLIC_KEY || ulClass == CKO_PRIVATE_KEY) && (CKK_EC == t.getKeyType(a_pTemplate, a_ulCount));

    switch( ulClass ) {

    case CKO_DATA:
        if (isVirtual())
        {
            // data object only supported on the USER PIN slot
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        o = new DataObject( );
        break;

    case CKO_PUBLIC_KEY:
        if (bIsRSA)
            o = new Pkcs11ObjectKeyPublicRSA( );
        else if (bIsECC)
            o = new Pkcs11ObjectKeyPublicECC( );
        else
            throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
        break;

    case CKO_PRIVATE_KEY:
        if (bIsRSA)
            o = new RSAPrivateKeyObject( );
        else if (bIsECC)
            o = new ECCPrivateKeyObject( );
        else
            throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
        break;

    case CKO_CERTIFICATE:
        o = new X509PubKeyCertObject( );
        break;

    default:
        throw PKCS11Exception( CKR_TEMPLATE_INCONSISTENT );
    }

    try
    {
        for( CK_BYTE idx = 0; idx < a_ulCount; ++idx ) {

            o->setAttribute( a_pTemplate[ idx ], true );
        }

        // check certificate attributes coherance
        if (ulClass == CKO_CERTIFICATE)
        {
           if (!Application::g_DisableCertificateValidation && !((X509PubKeyCertObject*) o)->validate())
              throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;

        if( bIsToken ) {
			Token::CAtomicLogin atomicLogin(m_Token.get(), true, ((CKO_PRIVATE_KEY == ulClass) && (m_Token->getUserRole() != MiniDriverAuthentication::PIN_USER))? m_Token->getUserRole() : 0 );
            switch( ulClass ) {

            case CKO_PUBLIC_KEY:
                m_Token->addObjectPublicKey( (Pkcs11ObjectKeyPublic*)o, &hObject );
                break;

            case CKO_PRIVATE_KEY:
                m_Token->addObjectPrivateKey( (PrivateKeyObject*)o, &hObject );
                break;

            case CKO_CERTIFICATE:
                m_Token->addObjectCertificate( (X509PubKeyCertObject*)o, &hObject );
                break;

            default:
                m_Token->addObject( o, &hObject );
                break;
            }

            o = NULL; // now owned by the token

        } else {

            s->addObject( o, &hObject );
            o = NULL; // now owned by the session
        }

        *a_phObject = hObject;
    }
    catch(...)
    {
        if (o) delete o; // free pointer if something wrong happened
        throw;
    }
}


/*
*/
void Slot::destroyObject( const CK_SESSION_HANDLE& a_hSession, const CK_OBJECT_HANDLE& a_hObject ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    try {

        // from object handle we can determine if it is a token object or session object
        if( m_Token->isToken( a_hObject ) ) {

            // if this is a readonly session and user is not logged then only public session objects can be created
            if( !s->isReadWrite( ) ) {

                throw PKCS11Exception( CKR_SESSION_READ_ONLY );
            }

            m_Token->deleteObject( a_hObject );

        } else {

            s->deleteObject( a_hObject );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::getAttributeValue( const CK_SESSION_HANDLE& a_hSession, const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        if( m_Token->isToken( a_hObject ) ) {

            m_Token->getAttributeValue( a_hObject, a_pTemplate, a_ulCount );

        } else {

            m_Sessions.at( a_hSession ).getAttributeValue( a_hObject, a_pTemplate, a_ulCount );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::setAttributeValue( const CK_SESSION_HANDLE& a_hSession, const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    try {

        if( m_Token->isToken( a_hObject ) ) {

            if( !s->isReadWrite( ) ) {

                throw PKCS11Exception( CKR_SESSION_READ_ONLY );
            }

            m_Token->setAttributeValue( a_hObject, a_pTemplate, a_ulCount );

        } else {

            s->setAttributeValue( a_hObject, a_pTemplate, a_ulCount );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::generateKeyPair( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, CK_ATTRIBUTE_PTR a_pPublicKeyTemplate, const CK_ULONG& a_ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR a_pPrivateKeyTemplate, const CK_ULONG& a_ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR a_phPublicKey,CK_OBJECT_HANDLE_PTR a_phPrivateKey ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    // Check Public Template Consitency
    Template t;
    t.checkTemplate( a_pPublicKeyTemplate, a_ulPublicKeyAttributeCount, Template::MODE_GENERATE_PUB );

    // Check Private Template Consitency
    t.checkTemplate( a_pPrivateKeyTemplate, a_ulPrivateKeyAttributeCount, Template::MODE_GENERATE_PRIV );

    Pkcs11ObjectKeyPublic* pubKey = NULL;
    PrivateKeyObject* privKey = NULL;
    bool bIsRSA = false;

    if (a_pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
    {
        bIsRSA = true;

        // Create the PKCS11 public key
        pubKey = new Pkcs11ObjectKeyPublicRSA( );

        // Create the PKCS11 private key
        privKey = new RSAPrivateKeyObject( );
    }
    else
    {
        // Create the PKCS11 public key
        pubKey = new Pkcs11ObjectKeyPublicECC( );

        // Create the PKCS11 private key
        privKey = new ECCPrivateKeyObject( );
    }

    // Populate the PKCS11 public key
    try {

        for( unsigned long i = 0 ; i < a_ulPublicKeyAttributeCount ; ++i ) {

            pubKey->setAttribute( a_pPublicKeyTemplate[ i ], true );
        }

        // Populate the PKCS11 private key
        for( unsigned long i = 0 ; i < a_ulPrivateKeyAttributeCount ; ++i ) {

            privKey->setAttribute( a_pPrivateKeyTemplate[ i ], true );
        }

        // Generate the key pair on cars
        if( privKey->isToken( ) ) {
            //disable signature in case of gen key pair is for DH purpose
            if(a_pMechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN) 
            {
                privKey->_sign = FALSE;
                privKey->_derive = TRUE;
            }
                 
            m_Token->generateKeyPair( pubKey, privKey, a_phPublicKey, a_phPrivateKey );

        } else if (bIsRSA) {

            // We do not support generation of RSA key pair in the session
            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }
        else
        {

            if( !isAuthenticated( ) && ( privKey->isPrivate() ||  pubKey->isPrivate())) {

                throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
            }

            if (pubKey->isToken())
            {
               // We do not support public key in token if private key is in token
               throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
            }

            s->generateKeyPair(pubKey, privKey, a_phPublicKey, a_phPrivateKey );
        }

        // Create the PKCS11 public key object on cache if it is not a token object
        if( pubKey && !pubKey->isToken( ) ) {

            s->addObject( pubKey, a_phPublicKey );
        }

        if( privKey && !privKey->isToken( ) ) {

            s->addObject( privKey, a_phPrivateKey );
        }

    } catch( MiniDriverException& x ) {

        // the generation failed
        delete privKey;
        delete pubKey;
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        // We do not support generation of key pair in the session
        delete privKey;
        delete pubKey;
        throw;

    } catch( ... ) {

        delete privKey;
        delete pubKey;
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}

/*
*/
void Slot::deriveKey(CK_SESSION_HANDLE a_hSession, CK_MECHANISM_PTR a_pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR a_pTemplate, CK_ULONG a_ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    if( !m_Token.get( ) || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if (!m_Device->isECC())
    {
        throw PKCS11Exception( CKR_FUNCTION_NOT_SUPPORTED );
    }

    Session* s = getSession( a_hSession );

    // Check secret key Template Consitency
    Template t;
    t.checkTemplate( a_pTemplate, a_ulAttributeCount, Template::MODE_GENERATE_SECRET );

    if (a_pMechanism->mechanism != CKM_ECDH1_DERIVE)
    {
        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }

    CK_ECDH1_DERIVE_PARAMS_PTR pEcdhParams = (CK_ECDH1_DERIVE_PARAMS_PTR) a_pMechanism->pParameter;
    if (!pEcdhParams || (pEcdhParams->kdf != CKD_NULL && pEcdhParams->kdf != CKD_SHA1_KDF))
    {
        throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
    }

    if ((pEcdhParams->kdf == CKD_NULL) && (pEcdhParams->pSharedData != NULL || pEcdhParams->ulSharedDataLen != 0))
    {
        throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
    }

    if (CKO_SECRET_KEY != t.getClass(a_pTemplate, a_ulAttributeCount))
        throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );

    if (CKK_GENERIC_SECRET != t.getKeyType(a_pTemplate, a_ulAttributeCount))
        throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );    

    isValidMechanism( a_pMechanism->mechanism, CKF_DERIVE );

    // get the corresponding object
    StorageObject* o = 0;

    try {

        // from object handle we can determine
        // if it is a token object or session object
        if( m_Token->isToken( hBaseKey ) ) {

            o = m_Token->getObject( hBaseKey );

        } else {

            o = s->getObject( hBaseKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if( !isAuthenticated( ) && (o->isToken() || o->isPrivate())) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }  
    //isValidCryptoOperation( o, CKF_DERIVE, a_pMechanism->mechanism );

    GenericSecretKeyObject* derivedKey = new GenericSecretKeyObject();

    // Populate the PKCS11 public key
    try {

        /*for( unsigned long i = 0 ; i < a_ulAttributeCount ; ++i ) {
            derivedKey->setAttribute( a_pTemplate[ i ], true );
        }*/     
    
        if (derivedKey->isToken())
        {
            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( !isAuthenticated( ) && derivedKey->isPrivate()) {

            throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
        }

        // Generate the key pair on cars
        if( o->isToken( ) ) {
            m_Token->deriveKey((PrivateKeyObject*) o, pEcdhParams, derivedKey, phKey );   
        }
        else
        {
            s->deriveKey((PrivateKeyObject*) o, pEcdhParams, derivedKey, phKey );
        }

        // Create the PKCS11 public key object on cache if it is not a token object
        if( derivedKey && !derivedKey->isToken( ) ) {

            s->addObject( derivedKey, phKey );
        }

        derivedKey->print();


    } catch( MiniDriverException& x ) {

        // the generation failed
        delete derivedKey;
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        // We do not support generation of key pair in the session
        delete derivedKey;
        throw;

    } catch( ... ) {

        delete derivedKey;
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}

/*
*/
void Slot::digestInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    switch( a_pMechanism->mechanism ) {

    case CKM_SHA_1:
        s->setDigest( CDigest::getInstance(CDigest::SHA1) );
        break;

    case CKM_SHA256:
        s->setDigest( CDigest::getInstance(CDigest::SHA256) );
        break;

    case CKM_SHA384:
        s->setDigest( CDigest::getInstance(CDigest::SHA384) );
        break;

    case CKM_SHA512:
        s->setDigest( CDigest::getInstance(CDigest::SHA512) );
        break;

    case CKM_MD5:
        s->setDigest( CDigest::getInstance(CDigest::MD5) );
        break;

    default:
        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }
}


/*
*/
void Slot::digest( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pDigest, CK_ULONG_PTR a_pulDigestLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CDigest* digest = s->getDigest( );
    if( !digest ) {
        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }


    if((*a_pulDigestLen < (CK_ULONG)digest->hashLength( )) && a_pDigest ) {

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );

    } else if(!a_pDigest) {

        *a_pulDigestLen = digest->hashLength( );

    } else {

        digest->hashUpdate(a_pData, 0, a_ulDataLen);

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        if( a_pDigest ) {
            digest->hashFinal(a_pDigest);
	    s->removeDigestKeyOp(); /* Needed to avoid double hash of data in SignUpdate function */
            s->removeDigest( );
        }
    }
}


/*
*/
void Slot::digestUpdate( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pPart, const CK_ULONG& a_ulPartLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    s->getDigest( )->hashUpdate( a_pPart, 0, a_ulPartLen );
}


/*
*/
void Slot::digestFinal( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pDigest, CK_ULONG_PTR a_pulDigestLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CDigest* digest = s->getDigest( );
    if( !digest ) {
        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if((*a_pulDigestLen < (CK_ULONG)digest->hashLength( )) && a_pDigest ) {

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );

    } else if( !a_pDigest ) {

        *a_pulDigestLen = digest->hashLength( );

    } else {

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        if ( a_pDigest ){

            digest->hashFinal( a_pDigest );

            s->removeDigest( );
        }
    }
}


/*
*/
void Slot::signInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    Session* s = getSession( a_hSession );

    if( s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    CK_MECHANISM_TYPE t = a_pMechanism->mechanism;
    bool bSha1Disabled = m_Device->IsSha1Disabled();
    if (bSha1Disabled && (t == CKM_SHA1_RSA_PKCS || t == CKM_ECDSA_SHA1 || t == CKM_SHA1_RSA_PKCS_PSS))
    {
        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_SIGN );

    if (    a_pMechanism->mechanism == CKM_RSA_PKCS_PSS 
        ||  a_pMechanism->mechanism == CKM_SHA1_RSA_PKCS_PSS
        ||  a_pMechanism->mechanism == CKM_SHA256_RSA_PKCS_PSS
        ||  a_pMechanism->mechanism == CKM_SHA384_RSA_PKCS_PSS
        ||  a_pMechanism->mechanism == CKM_SHA512_RSA_PKCS_PSS
       )
    {
        CK_RSA_PKCS_PSS_PARAMS_PTR pParams = (CK_RSA_PKCS_PSS_PARAMS_PTR) a_pMechanism->pParameter;
        if (!pParams
            ||(pParams->hashAlg != CKM_SHA_1 && pParams->hashAlg != CKM_SHA256 && pParams->hashAlg != CKM_SHA384 && pParams->hashAlg != CKM_SHA512)
            ||(pParams->hashAlg == CKM_SHA_1 && ((pParams->mgf != CKG_MGF1_SHA1) || (pParams->sLen != 20)))
            ||(pParams->hashAlg == CKM_SHA256 && ((pParams->mgf != CKG_MGF1_SHA256) || (pParams->sLen != 32)))
            ||(pParams->hashAlg == CKM_SHA384 && ((pParams->mgf != CKG_MGF1_SHA384) || (pParams->sLen != 48)))
            ||(pParams->hashAlg == CKM_SHA512 && ((pParams->mgf != CKG_MGF1_SHA512) || (pParams->sLen != 64)))
           )
        {
            throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
        }

        switch(a_pMechanism->mechanism)
        {
        case CKM_SHA1_RSA_PKCS_PSS :
            if (pParams->hashAlg != CKM_SHA_1)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            if (pParams->hashAlg != CKM_SHA256)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        case CKM_SHA384_RSA_PKCS_PSS :
            if (pParams->hashAlg != CKM_SHA384)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        case CKM_SHA512_RSA_PKCS_PSS:
            if (pParams->hashAlg != CKM_SHA512)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        }
    }
    else if ( a_pMechanism->mechanism == CKM_AES_CMAC_GENERAL )
    {
        CK_MAC_GENERAL_PARAMS_PTR pParams = (CK_MAC_GENERAL_PARAMS_PTR) a_pMechanism->pParameter;

        // Output signature length for this mechanism must be 8-16 bytes
        if ( !pParams ||
             ( *pParams > 16 &&
               *pParams < 8 )
            )
        {
            throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
        }
    }

    // get the corresponding object
    StorageObject* o = 0;

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // from object handle we can determine
        // if it is a token object or session object
        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey );

        } else {

            o = s->getObject( a_hKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if( !isAuthenticated( ) && (o->isToken() || o->isPrivate())) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    isValidCryptoOperation( o, CKF_SIGN, a_pMechanism->mechanism );

    // Initialize this crypto operation
    boost::shared_ptr< CryptoOperation > co( new CryptoOperation( a_pMechanism, a_hKey ) );

    s->setSignatureOperation( co );

    if( CKM_SHA1_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA1 == a_pMechanism->mechanism || CKM_SHA1_RSA_PKCS_PSS == a_pMechanism->mechanism ){

        s->setDigestKeyOp( CDigest::getInstance(CDigest::SHA1) );

    } else if( CKM_SHA256_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA256 == a_pMechanism->mechanism || CKM_SHA256_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyOp( CDigest::getInstance(CDigest::SHA256) );

    } else if( CKM_SHA384_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA384 == a_pMechanism->mechanism || CKM_SHA384_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyOp( CDigest::getInstance(CDigest::SHA384) );

    } else if( CKM_SHA512_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA512 == a_pMechanism->mechanism || CKM_SHA512_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyOp( CDigest::getInstance(CDigest::SHA512) );

    } else if( CKM_MD5_RSA_PKCS == a_pMechanism->mechanism ){

        s->setDigestKeyOp( CDigest::getInstance(CDigest::MD5) );

    } else if( CKM_AES_CMAC_GENERAL == a_pMechanism->mechanism || CKM_AES_CMAC == a_pMechanism->mechanism ) {

        s->removeDigestKeyOp( );

    }
}


/*
*/
void Slot::sign( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pSignature, CK_ULONG_PTR a_pulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    StorageObject* obj = 0;
    try {
       CK_OBJECT_HANDLE a_hKey = s->getSignature()->getObject();
       if( m_Token->isToken( a_hKey ) ) {
          obj = m_Token->getObject( a_hKey );
       } else {
          obj = s->getObject( a_hKey );
       }
    }
    catch( ... ) {}
    
    // Get the key object to perform the signature
    KeyObject *o = (KeyObject*) obj;
    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    // Get the PKCS11 mechanism to use
    CK_ULONG m = s->getSignature( )->getMechanism( );

    // Check the output signature buffer length
    u4 ulExpectedSigLen;
    if (o->_keyType == CKK_AES) {

        if (m == CKM_AES_CMAC_GENERAL) {

            // The mechanism data for CKM_AES_CMAC_GENERAL is the intended output signature length
            ulExpectedSigLen = *( (CK_MAC_GENERAL_PARAMS_PTR) ( s->getSignature( )->getParameters( ) ) );
        }
        else {

            // There is no mechanism data for CKM_AES_CMAC, the output signature length is always 128-bit / 16-byte
            ulExpectedSigLen = 16;
        }

        if( !a_pSignature ) {

            *a_pulSignatureLen = ulExpectedSigLen;

            return;

        } else if( *a_pulSignatureLen < ulExpectedSigLen ) {

            *a_pulSignatureLen = ulExpectedSigLen;

            throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
        }
    }
    else {

        // TBD : Private key may not necessarily have the modulus or modulus bits
        // if that is the case then we need to locate the corresponding public key
        // or may be I should always put the modulus bits in private key attributes

        // This PKCS#11 library does not support RSA and ECDSA with 0 length input data
        if (a_ulDataLen == 0) {
            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        bool bIsRSA = (o->_keyType == CKK_RSA);
        if (bIsRSA)
        {
            if( !((RSAPrivateKeyObject*)o)->m_pModulus.get() ) {

                s->removeSignatureOperation( );
                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }
            ulExpectedSigLen = ((RSAPrivateKeyObject*)o)->m_pModulus->GetLength();
        }
        else
        {
            if( !((ECCPrivateKeyObject*)o)->m_pParams.get() ) {

                s->removeSignatureOperation( );
                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }
            ulExpectedSigLen = 2 * ((((ECCPrivateKeyObject*)o)->getOrderBitLength() + 7) / 8);
        }

        if( ( ( m == CKM_RSA_PKCS ) && ( a_ulDataLen > ulExpectedSigLen - 11 ) ) || ( ( m == CKM_RSA_X_509 ) && ( a_ulDataLen > ulExpectedSigLen ) ) ) {

            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        // check PSS case : input length must be the same as the length of the hash specified in parameters
        if (m == CKM_RSA_PKCS_PSS)
        {
            CK_RSA_PKCS_PSS_PARAMS_PTR pParams = (CK_RSA_PKCS_PSS_PARAMS_PTR) s->getSignature( )->getParameters();
            CK_ULONG hLen = 0;
            switch(pParams->hashAlg)
            {
                case CKM_SHA_1 : hLen = 20; break;
                case CKM_SHA256: hLen = 32; break;
                case CKM_SHA384 : hLen = 48; break;
                case CKM_SHA512: hLen = 64; break;
            }

            if (hLen != a_ulDataLen)
            {
                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
            }
        }

        if (m == CKM_ECDSA)
        {
            if (a_ulDataLen != 20 && a_ulDataLen != 32 && a_ulDataLen != 48 && a_ulDataLen != 64)
            {
                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
            }
        }

        if( !a_pSignature ) {

            *a_pulSignatureLen = ulExpectedSigLen;

            return;

        } else if( *a_pulSignatureLen < ulExpectedSigLen ) {

            *a_pulSignatureLen = ulExpectedSigLen;

            throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
        }
    }

    // Compute hash if applicable
    boost::shared_ptr< u1Array > dataToSign;
    boost::shared_ptr< u1Array > intermediateHash;
    boost::shared_ptr< u1Array > hashCounter;

    if( s->isDigestActiveKeyOp( ) ) {

        if( !s->_digestKeyOp ) {

            s->removeSignatureOperation( );
            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        // require hashing also
        CDigest* d = s->_digestKeyOp.get( );

        if( !d ) {

            s->removeSignatureOperation( );
            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if (!o->isToken() || !m_Device->IsLastHashRoundSupported(s->_digestKeyOp->hashType()) || (s->_digestKeyOp->hashType() == CDigest::MD5) )
        {
            dataToSign.reset( new u1Array( d->hashLength( ) ) );
            d->hashUpdate( a_pData, 0, a_ulDataLen );
            d->hashFinal( dataToSign->GetBuffer() );
        }
        else
        {
            CK_ULONG ulDataBlock = d->hashBlock(); 
            CK_ULONG ulBlockNumber = (a_ulDataLen + ulDataBlock - 1) / ulDataBlock;
            CK_ULONG ulLastBlockByteLength = a_ulDataLen - (ulBlockNumber - 1) * ulDataBlock;

            d->hashUpdate( a_pData, 0, (ulBlockNumber - 1) * ulDataBlock );

            dataToSign.reset( new u1Array( ulLastBlockByteLength ) );

            dataToSign->SetBuffer( a_pData + ((ulBlockNumber) - 1) * ulDataBlock );

            intermediateHash.reset(new u1Array(0));
            hashCounter.reset(new u1Array(0));

            d->getHashContext(*intermediateHash.get(), *hashCounter.get());
        }


    } else {

        // Sign Only
        dataToSign.reset( new u1Array( a_ulDataLen ) );

        // Need to check because a_pData maybe NULL if a_ulDataLen is 0
        if (a_ulDataLen > 0) {
            dataToSign->SetBuffer( a_pData );
        }
    }

    // Allocate output signature buffer
    CK_BYTE_PTR a_pSignature_temp = nullptr;
    // The card applet can only do 128-bit / 16-byte CMAC, so truncate excess length later
    a_pSignature_temp = m == CKM_AES_CMAC_GENERAL ? new CK_BYTE[16] : new CK_BYTE[ulExpectedSigLen];
    if ( !a_pSignature_temp ) {

        s->removeSignatureOperation( );
        throw PKCS11Exception( CKR_HOST_MEMORY );
    }

    // Perform signature
    try {
        if (o->isToken())
            m_Token->sign( o, dataToSign.get( ), intermediateHash.get(), hashCounter.get(), m, a_pSignature_temp );
        else
            s->sign( o, dataToSign.get( ), m, a_pSignature_temp );

    } catch( MiniDriverException& x ) {
        delete[] a_pSignature_temp;
        s->removeDigestKeyOp( );
        s->removeSignatureOperation( );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {
        delete[] a_pSignature_temp;
        s->removeDigestKeyOp( );
        s->removeSignatureOperation( );
        checkAccessException( x );
        throw;

    } catch( ... ) {
        delete[] a_pSignature_temp;
        s->removeDigestKeyOp( );
        s->removeSignatureOperation( );
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Place signature to the output parameter, also truncate excess length if applicable
    *a_pulSignatureLen = ulExpectedSigLen;
    memcpy(a_pSignature, a_pSignature_temp, ulExpectedSigLen);

    delete[] a_pSignature_temp;

    s->removeDigestKeyOp( );

    s->removeSignatureOperation( );
}


/* update the hash or if hashing is not getting used we just accumulate it
*/
void Slot::signUpdate( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pPart, const CK_ULONG& a_ulPartLen ) {

    if( !m_Token.get( ) || !m_Device.get( )) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    StorageObject* o = NULL;

    try {
        CK_OBJECT_HANDLE a_hKey = s->getSignature()->getObject();
        if( m_Token->isToken( a_hKey ) ) {
            o = m_Token->getObject( a_hKey );
        } else {
            o = s->getObject( a_hKey );
        }
    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( s->isDigestActiveKeyOp( ) ) {

        if( !s->_digestKeyOp ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if (!o->isToken() || !m_Device->IsLastHashRoundSupported(s->_digestKeyOp->hashType()) || (s->_digestKeyOp->hashType() == CDigest::MD5) )
        {
            s->_digestKeyOp->hashUpdate( a_pPart, 0, a_ulPartLen );
        }
        else
        {
            CK_ULONG ulDataBlock = s->_digestKeyOp->hashBlock(); 
            CK_ULONG ulBlockNumber = (a_ulPartLen + ulDataBlock - 1) / ulDataBlock;
            CK_ULONG ulLastBlockByteLength = a_ulPartLen - (ulBlockNumber - 1) * ulDataBlock;

            if( s->m_LastBlockToSign )
            {
                s->_digestKeyOp->hashUpdate( s->m_LastBlockToSign->GetBuffer(), 0, s->m_LastBlockToSign->GetLength());
            }

            s->_digestKeyOp->hashUpdate( a_pPart, 0, (ulBlockNumber - 1) * ulDataBlock );

            s->m_LastBlockToSign.reset( new u1Array( ulLastBlockByteLength ) );

            s->m_LastBlockToSign->SetBuffer( a_pPart + ((ulBlockNumber) - 1) * ulDataBlock );
        }

    } else { // Sign Only

        if( s->m_AccumulatedDataToSign ) {

            // just accumulate the data
            u1Array* updatedData = new u1Array( s->m_AccumulatedDataToSign->GetLength() + a_ulPartLen);

            memcpy(updatedData->GetBuffer(),s->m_AccumulatedDataToSign->GetBuffer(),s->m_AccumulatedDataToSign->GetLength());

            memcpy((u1*)&updatedData->GetBuffer()[s->m_AccumulatedDataToSign->GetLength()], a_pPart, a_ulPartLen);

            s->m_AccumulatedDataToSign.reset( updatedData );

        } else {

            s->m_AccumulatedDataToSign.reset( new u1Array( a_ulPartLen ) );

            s->m_AccumulatedDataToSign->SetBuffer( a_pPart );
        }

        CK_ULONG m = s->getSignature( )->getMechanism( );

        PrivateKeyObject* prvKey = (PrivateKeyObject*) o;
        if (prvKey->_keyType == CKK_RSA)
        {
            u1Array* u = ((RSAPrivateKeyObject*)o)->m_pModulus.get( );

            if( !u ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }

            if( ( ( m == CKM_RSA_PKCS ) && ( s->m_AccumulatedDataToSign->GetLength( ) > u->GetLength( ) - 11 ) ) ||
                ( ( m == CKM_RSA_X_509 ) && ( s->m_AccumulatedDataToSign->GetLength( ) > u->GetLength( ) ) ) ) {

                    throw PKCS11Exception( CKR_DATA_LEN_RANGE );
            }
        }

        if ( (m == CKM_ECDSA) && ( s->m_AccumulatedDataToSign->GetLength() > 64) )
        {
            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }
    }
}


/*
*/
void Slot::signFinal( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pSignature, CK_ULONG_PTR a_pulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }
    
    StorageObject* obj = 0;
    try {
       CK_OBJECT_HANDLE a_hKey = s->getSignature()->getObject();
       if( m_Token->isToken( a_hKey ) ) {
          obj = m_Token->getObject( a_hKey );
       } else {
          obj = s->getObject( a_hKey );
       }
    }
    catch( ... ) {}

    PrivateKeyObject* o = (PrivateKeyObject*) obj;
    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    // TBD : Private key may not necessarily have the modulus or modulus bits
    // if that is the case then we need to locate the corresponding public key
    // or may be I should always put the modulus bits in private key attributes
    bool bIsRSA = (o->_keyType == CKK_RSA);
    u4 ulExpectedSigLen;
    if (bIsRSA)
    {
        if( !((RSAPrivateKeyObject*)o)->m_pModulus.get() ) {
            s->removeDigestKeyOp( );
            s->removeSignatureOperation( );
            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }
        ulExpectedSigLen = ((RSAPrivateKeyObject*)o)->m_pModulus->GetLength();
    }
    else
    {
        if( !((ECCPrivateKeyObject*)o)->m_pParams.get() ) {
            s->removeDigestKeyOp( );
            s->removeSignatureOperation( );
            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }
        ulExpectedSigLen = 2 * ((((ECCPrivateKeyObject*)o)->getOrderBitLength() + 7) / 8);
    }

    if( !a_pSignature ) {

        *a_pulSignatureLen = ulExpectedSigLen;

        return;

    } else if( *a_pulSignatureLen < ulExpectedSigLen ) {

        *a_pulSignatureLen = ulExpectedSigLen;

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }


    if( !s->m_Signature ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    boost::shared_ptr< u1Array > dataToSign;
    boost::shared_ptr< u1Array > intermediateHash;
    boost::shared_ptr< u1Array > hashCounter;

    if( s->isDigestActiveKeyOp( ) ) {

        if( !s->_digestKeyOp ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        // require hashing also
        CDigest* d = s->_digestKeyOp.get( );
        if( !d ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if (!s->m_LastBlockToSign)
        {
            dataToSign.reset( new u1Array( d->hashLength( ) ) );

            d->hashFinal( dataToSign->GetBuffer() );
        }
        else
        {
            // last round of hash in card supported.
            dataToSign = s->m_LastBlockToSign;

            intermediateHash.reset(new u1Array(0));
            hashCounter.reset(new u1Array(0));

            d->getHashContext(*intermediateHash.get(), *hashCounter.get());
        }

    } else {
        CK_ULONG m = s->getSignature( )->getMechanism( );
        CK_ULONG ulDataLen = s->m_AccumulatedDataToSign->GetLength();
        if ((m == CKM_ECDSA) && ulDataLen != 20 && ulDataLen != 32 && ulDataLen != 48 && ulDataLen != 64)
        {
            s->removeSignatureOperation( );
            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        // Sign Only
        dataToSign = s->m_AccumulatedDataToSign;
    }

    if (o->isToken())
        m_Token->sign( o, dataToSign.get( ), intermediateHash.get(), hashCounter.get(), s->m_Signature->getMechanism( ), a_pSignature );
    else
        s->sign(o, dataToSign.get( ), s->m_Signature->getMechanism( ), a_pSignature );

    *a_pulSignatureLen = ulExpectedSigLen;

    s->removeDigestKeyOp( );

    s->removeSignatureOperation( );

    s->m_AccumulatedDataToSign.reset( );

    s->m_LastBlockToSign.reset( );
}


/*
*/
void Slot::encryptInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isEncryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_ENCRYPT );

    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    try {

        // from object handle we can determine
        // if it is a token object or session object
        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey );

        } else {

            o = s->getObject( a_hKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_ENCRYPT, a_pMechanism->mechanism );

    // check the OAEP parameters
    if (a_pMechanism->mechanism == CKM_RSA_PKCS_OAEP)
    {
        // we only support MGF1 based on the same specified hash
        CK_RSA_PKCS_OAEP_PARAMS_PTR pParams = (CK_RSA_PKCS_OAEP_PARAMS_PTR) a_pMechanism->pParameter;
        if (   !pParams || (pParams->pSourceData != NULL) || (pParams->ulSourceDataLen != 0) 
            ||(pParams->hashAlg != CKM_SHA_1 && pParams->hashAlg != CKM_SHA256 && pParams->hashAlg != CKM_SHA384 && pParams->hashAlg != CKM_SHA512)
            ||(pParams->hashAlg == CKM_SHA_1 && pParams->mgf != CKG_MGF1_SHA1)
            ||(pParams->hashAlg == CKM_SHA256 && pParams->mgf != CKG_MGF1_SHA256)
            ||(pParams->hashAlg == CKM_SHA384 && pParams->mgf != CKG_MGF1_SHA384)
            ||(pParams->hashAlg == CKM_SHA512 && pParams->mgf != CKG_MGF1_SHA512)
           )
        {
            throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
        }

        // check that the modulus length is compatibile with the selected hash
        u1Array* u = ( (Pkcs11ObjectKeyPublicRSA*) o)->m_pModulus.get();
        if (!u)
        {
            throw PKCS11Exception( CKR_FUNCTION_FAILED );
        }

        int modulusLength = u->GetLength();
        int hLen = 0;
        switch(pParams->hashAlg)
        {
            case CKM_SHA_1: hLen = 20; break;
            case CKM_SHA256: hLen = 32; break;
            case CKM_SHA384: hLen = 48; break;
            case CKM_SHA512: hLen = 64; break;
        }
        
        if ( modulusLength < 2 + 2*hLen )
        {
            throw PKCS11Exception( CKR_KEY_SIZE_RANGE );
        }
    }

    // let's initialize this crypto operation
    s->setEncryptionOperation( new CryptoOperation( a_pMechanism, a_hKey ) );
}


/*
*/
void Slot::encrypt( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pEncryptedData, CK_ULONG_PTR a_pulEncryptedDataLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isEncryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }  

    u1Array* u = NULL;
    StorageObject* o = NULL;

    try {

        if( !s->_encryption ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        try
        {
            CK_OBJECT_HANDLE hKey = s->_encryption->getObject( );
            if( m_Token->isToken( hKey ) ) {
                o = m_Token->getObject( hKey );
            } else {
                o = s->getObject( hKey );
            }
        }
        catch(...)
        {
        }

        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        u = ((Pkcs11ObjectKeyPublicRSA*)o)->m_pModulus.get( );
        if( !u ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if( !a_pEncryptedData ) {

            *a_pulEncryptedDataLen = u->GetLength();

            return;

        } else {

            if( *a_pulEncryptedDataLen < u->GetLength( ) ) {

                *a_pulEncryptedDataLen = u->GetLength();

                throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
            }
        }

        boost::shared_ptr< u1Array > dataToEncrypt( new u1Array( a_ulDataLen ) );
        dataToEncrypt->SetBuffer( a_pData );

        m_Token->encrypt( o, dataToEncrypt.get( ), s->_encryption->getMechanism( ), s->_encryption->getParameters(), a_pEncryptedData );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    *a_pulEncryptedDataLen = u->GetLength( );

    s->removeEncryptionOperation( );
}


/*
*/
void Slot::decryptInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    if( !m_Token.get( ) /*|| !m_Device.get( )*/ ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isDecryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_DECRYPT );

    //try {

    //    if( !m_Device->isAuthenticated( ) ) {

    //        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    //    }

    //} catch( MiniDriverException& x ) {

    //    Log::error( "Slot::decryptInit", "MiniDriverException" );
    //    throw PKCS11Exception( Token::checkException( x ) );
    //}
    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    // from object handle we can know if it is a token or session object
    try {

        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey );

        } else {

            o = s->getObject( a_hKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_DECRYPT, a_pMechanism->mechanism );

    // check the OAEP parameters
    if (a_pMechanism->mechanism == CKM_RSA_PKCS_OAEP)
    {
        // we only support MGF1 with the same hash as the one specified
        CK_RSA_PKCS_OAEP_PARAMS_PTR pParams = (CK_RSA_PKCS_OAEP_PARAMS_PTR) a_pMechanism->pParameter;
        if (   !pParams || (pParams->pSourceData != NULL) || (pParams->ulSourceDataLen != 0) 
            || (pParams->hashAlg != CKM_SHA_1 && pParams->hashAlg != CKM_SHA256 && pParams->hashAlg != CKM_SHA384 && pParams->hashAlg != CKM_SHA512)
            || (pParams->hashAlg == CKM_SHA_1 && pParams->mgf != CKG_MGF1_SHA1)
            || (pParams->hashAlg == CKM_SHA256 && pParams->mgf != CKG_MGF1_SHA256)
            || (pParams->hashAlg == CKM_SHA384 && pParams->mgf != CKG_MGF1_SHA384)
            || (pParams->hashAlg == CKM_SHA512 && pParams->mgf != CKG_MGF1_SHA512)
           )
        {
            throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
        }

        // check that the modulus length is compatibile with the selected hash
        u1Array* u = ( (RSAPrivateKeyObject*) o)->m_pModulus.get();
        if (!u)
        {
            throw PKCS11Exception( CKR_FUNCTION_FAILED );
        }

        int modulusLength = u->GetLength();
        int hLen = 0;
        switch(pParams->hashAlg)
        {
            case CKM_SHA_1: hLen = 20; break;
            case CKM_SHA256: hLen = 32; break;
            case CKM_SHA384: hLen = 48; break;
            case CKM_SHA512: hLen = 64; break;
        }
        
        if ( modulusLength < 2 + 2*hLen )
        {
            throw PKCS11Exception( CKR_KEY_SIZE_RANGE );
        }
    }

    // let's initialize this crypto operation
    s->setDecryptionOperation( new CryptoOperation( a_pMechanism, a_hKey ) );
}


/*
*/
void Slot::decrypt( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pEncryptedData, const CK_ULONG& a_ulEncryptedDataLen, CK_BYTE_PTR a_pData, CK_ULONG_PTR a_pulDataLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDecryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( !s->_decryption ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    StorageObject* o = NULL;

    try
    {
        CK_OBJECT_HANDLE hKey = s->_decryption->getObject( );
        if( m_Token->isToken( hKey ) ) {
            o = m_Token->getObject( hKey );
        } else {
            o = s->getObject( hKey );
        }
    }
    catch(...)
    {
    }

    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CK_ULONG m = s->_decryption->getMechanism( );

    u1Array* u = ( (RSAPrivateKeyObject*) o)->m_pModulus.get( );
    if( !u ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    unsigned long l = (unsigned long)u->GetLength( );

    // The following variables are used only in OAEP case
    unsigned char algo = 0;

    if( m == CKM_RSA_PKCS ) {

        // Can't know exact size of returned value before decryption has been done
        if( !a_pData ) {

            *a_pulDataLen = l - 11;

            return;
        }
    } else if( m == CKM_RSA_X_509 ) {

        if( !a_pData ) {

            *a_pulDataLen = l;

            return;

        } else {

            if( *a_pulDataLen < l ) {

                *a_pulDataLen = l;

                throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
            }
        }
    }
    else if (m == CKM_RSA_PKCS_OAEP ) {
        unsigned long hLen = 0;
        CK_RSA_PKCS_OAEP_PARAMS_PTR pParams = (CK_RSA_PKCS_OAEP_PARAMS_PTR) s->_decryption->getParameters();

        switch(pParams->hashAlg)
        {
            case CKM_SHA_1: hLen = 20; algo = ALGO_SHA_1; break;
            case CKM_SHA256: hLen = 32; algo = ALGO_SHA_256; break;
            case CKM_SHA384: hLen = 48; algo = ALGO_SHA_384; break;
            case CKM_SHA512: hLen = 64; algo = ALGO_SHA_512; break;
        }
        
        // Can't know exact size of returned value before decryption has been done
        if( !a_pData ) {

            *a_pulDataLen = l - 2 - 2*hLen;

            return;
        }

    } else {

        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }

    if( a_ulEncryptedDataLen != l ) {

        throw PKCS11Exception( CKR_ENCRYPTED_DATA_LEN_RANGE );
    }

    boost::shared_ptr< u1Array > dataToDecrypt( new u1Array( a_ulEncryptedDataLen ) );

    dataToDecrypt->SetBuffer( a_pEncryptedData );

    try {

        if (o->isToken())
            m_Token->decrypt( o, dataToDecrypt.get( ), m, algo, a_pData, a_pulDataLen );
        else
            s->decrypt( o, dataToDecrypt.get( ), m, algo, a_pData, a_pulDataLen );

    } catch( MiniDriverException& x ) {

        s->removeDecryptionOperation( );

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        s->removeDecryptionOperation( );

        checkAccessException( x );

        throw;

    } catch( ... ) {

        s->removeDecryptionOperation( );

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    s->removeDecryptionOperation( );
}


/*
*/
void Slot::verifyInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    if( !m_Token.get( )/* || !m_Device.get( )*/ ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isVerificationActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_VERIFY );

    if (    a_pMechanism->mechanism == CKM_RSA_PKCS_PSS 
        ||  a_pMechanism->mechanism == CKM_SHA1_RSA_PKCS_PSS
        ||  a_pMechanism->mechanism == CKM_SHA256_RSA_PKCS_PSS
        ||  a_pMechanism->mechanism == CKM_SHA384_RSA_PKCS_PSS
        ||  a_pMechanism->mechanism == CKM_SHA512_RSA_PKCS_PSS
       )
    {
        CK_RSA_PKCS_PSS_PARAMS_PTR pParams = (CK_RSA_PKCS_PSS_PARAMS_PTR) a_pMechanism->pParameter;
        if (!pParams
            ||(pParams->hashAlg != CKM_SHA_1 && pParams->hashAlg != CKM_SHA256 && pParams->hashAlg != CKM_SHA384 && pParams->hashAlg != CKM_SHA512)
            ||(pParams->hashAlg == CKM_SHA_1 && ((pParams->mgf != CKG_MGF1_SHA1) || (pParams->sLen != 20)))
            ||(pParams->hashAlg == CKM_SHA256 && ((pParams->mgf != CKG_MGF1_SHA256) || (pParams->sLen != 32)))
            ||(pParams->hashAlg == CKM_SHA384 && ((pParams->mgf != CKG_MGF1_SHA384) || (pParams->sLen != 48)))
            ||(pParams->hashAlg == CKM_SHA512 && ((pParams->mgf != CKG_MGF1_SHA512) || (pParams->sLen != 64))) 
           )
        {
            throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
        }

        switch(a_pMechanism->mechanism)
        {
        case CKM_SHA1_RSA_PKCS_PSS :
            if (pParams->hashAlg != CKM_SHA_1)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            if (pParams->hashAlg != CKM_SHA256)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        case CKM_SHA384_RSA_PKCS_PSS :
            if (pParams->hashAlg != CKM_SHA384)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        case CKM_SHA512_RSA_PKCS_PSS:
            if (pParams->hashAlg != CKM_SHA512)
                throw PKCS11Exception( CKR_MECHANISM_PARAM_INVALID );
            break;
        }
    }

    /*   try {

    if( !m_Device->isAuthenticated( ) ) {

    throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    } catch( MiniDriverException& x ) {

    Log::error( "Slot::verifyInit", "MiniDriverException" );
    throw PKCS11Exception( Token::checkException( x ) );
    }*/
    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    try {

        // from object handle we can know if it is a token or session object
        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey);

        } else {

            o = s->getObject( a_hKey );

        }

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_VERIFY, a_pMechanism->mechanism );

    // Initialize this crypto operation
    s->setVerificationOperation( new CryptoOperation( a_pMechanism, a_hKey ) );

    if( CKM_SHA1_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA1 == a_pMechanism->mechanism || CKM_SHA1_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyVerification( CDigest::getInstance(CDigest::SHA1) );

    } else if( CKM_SHA256_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA256 == a_pMechanism->mechanism || CKM_SHA256_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyVerification( CDigest::getInstance(CDigest::SHA256) );

    } else if( CKM_SHA384_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA384 == a_pMechanism->mechanism || CKM_SHA384_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyVerification( CDigest::getInstance(CDigest::SHA384) );

    } else if( CKM_SHA512_RSA_PKCS == a_pMechanism->mechanism || CKM_ECDSA_SHA512 == a_pMechanism->mechanism || CKM_SHA512_RSA_PKCS_PSS == a_pMechanism->mechanism){

        s->setDigestKeyVerification( CDigest::getInstance(CDigest::SHA512) );

    } else if( CKM_MD5_RSA_PKCS == a_pMechanism->mechanism ){

        s->setDigestKeyVerification( CDigest::getInstance(CDigest::MD5) );
    }
}


/*
*/
void Slot::verify( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pSignature, const CK_ULONG a_ulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isVerificationActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( !s->_verification ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CK_ULONG m = s->_verification->getMechanism( );

    try {
        StorageObject* o = 0;
        try {
           CK_OBJECT_HANDLE a_hKey = s->_verification->getObject();
           if( m_Token->isToken( a_hKey ) ) {
              o = m_Token->getObject( a_hKey );
           } else {
              o = s->getObject( a_hKey );
           }
        }
        catch( ... ) {}
    
        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        Pkcs11ObjectKeyPublic* pubKey = (Pkcs11ObjectKeyPublic*) o;
        bool bIsRSA = (pubKey->_keyType == CKK_RSA);
        u4 ulExpectedSigLen;
        if (bIsRSA)
        {
            if( !((Pkcs11ObjectKeyPublicRSA*)o)->m_pModulus.get() ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }
            ulExpectedSigLen = ((Pkcs11ObjectKeyPublicRSA*)o)->m_pModulus->GetLength();
        }
        else
        {
            if( !((Pkcs11ObjectKeyPublicECC*)o)->m_pParams.get() ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }
            ulExpectedSigLen = 2 * ((((Pkcs11ObjectKeyPublicECC*)o)->getOrderBitLength() + 7) / 8);
        }

        if( ( ( m == CKM_RSA_PKCS ) && ( a_ulDataLen > ulExpectedSigLen - 11 ) ) || ( ( m == CKM_RSA_X_509 ) && ( a_ulDataLen > ulExpectedSigLen ) ) ) {

            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        // check PSS case : input length must be the same as the length of the hash specified in parameters
        if (m == CKM_RSA_PKCS_PSS)
        {
            CK_RSA_PKCS_PSS_PARAMS_PTR pParams = (CK_RSA_PKCS_PSS_PARAMS_PTR) s->_verification->getParameters();
            CK_ULONG hLen = 0;
            switch(pParams->hashAlg)
            {
                case CKM_SHA_1 : hLen = 20; break;
                case CKM_SHA256: hLen = 32; break;
                case CKM_SHA384 : hLen = 48; break;
                case CKM_SHA512: hLen = 64; break;
            }

            if (hLen != a_ulDataLen)
            {
                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
            }
        }

        if (m == CKM_ECDSA)
        {
            if (a_ulDataLen != 20 && a_ulDataLen != 32 && a_ulDataLen != 48 && a_ulDataLen != 64)
            {
                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
            }
        }

        boost::shared_ptr< u1Array > dataToVerify;

        if( s->isDigestVerificationActiveKeyOp( ) ) {

            if( !s->_digestKeyVerification ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }

            // require hashing also
            CDigest* d = s->_digestKeyVerification.get( );
            if( !d ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }

            CK_BYTE_PTR h = new CK_BYTE[ d->hashLength( ) ];

            d->hashUpdate( a_pData, 0, a_ulDataLen );

            d->hashFinal( h );

            dataToVerify.reset( new u1Array( d->hashLength( ) ) );

            dataToVerify->SetBuffer( h );

            delete[ ] h;

        } else { // Sign Only

            dataToVerify.reset( new u1Array( a_ulDataLen ) );

            dataToVerify->SetBuffer( a_pData );
        }

        boost::shared_ptr< u1Array > signature( new u1Array( a_ulSignatureLen ) );

        signature->SetBuffer( a_pSignature );

        if (pubKey->isToken() || bIsRSA)
            m_Token->verify( o, dataToVerify.get( ), m, signature.get( ) );
        else
            s->verify(o, dataToVerify.get( ), m, signature.get( ) );

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

    } catch( MiniDriverException& x ) {

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

        throw;

    } catch( ... ) {

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*	Update the hash or if hashing is not getting used we just accumulate it
*/
void Slot::verifyUpdate( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pPart, const CK_ULONG& a_ulPartLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isVerificationActive( ) ){

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( s->isDigestVerificationActiveKeyOp( ) ) {

        if( !s->_digestKeyVerification ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CDigest* digest = s->_digestKeyVerification.get( );
        if( !digest ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        digest->hashUpdate( a_pPart, 0, a_ulPartLen );

    } else { 

        // Sign Only

        if( s->m_AccumulatedDataToVerify.get( ) ) { 

            // just accumulate the data
            u1Array* pAccumulatedDataToVerify = s->m_AccumulatedDataToVerify.get( );

            u1Array* updatedData = new u1Array( pAccumulatedDataToVerify->GetLength( ) + a_ulPartLen );

            memcpy( updatedData->GetBuffer( ), pAccumulatedDataToVerify->GetBuffer( ), pAccumulatedDataToVerify->GetLength( ) );

            memcpy( (u1*)&updatedData->GetBuffer()[ pAccumulatedDataToVerify->GetLength( )], a_pPart, a_ulPartLen );

            s->m_AccumulatedDataToVerify.reset( updatedData );

        } else {

            s->m_AccumulatedDataToVerify.reset( new u1Array( a_ulPartLen ) );

            s->m_AccumulatedDataToVerify->SetBuffer( a_pPart );
        }

        if( !s->_verification ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CK_ULONG m = s->_verification->getMechanism( );

        StorageObject* o = NULL;

        try {

            o = m_Token->getObject( s->_verification->getObject( ) );

        } catch( MiniDriverException& x ) {

            throw PKCS11Exception( Token::checkException( x ) );

        } catch( PKCS11Exception& x ) {

            checkAccessException( x );

            throw;

        } catch( ... ) {

            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
        }

        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        u1Array* u = ( (Pkcs11ObjectKeyPublicRSA*) o )->m_pModulus.get( );

        if( !u ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if((( m == CKM_RSA_PKCS) && (s->m_AccumulatedDataToVerify->GetLength() > u->GetLength() - 11)) ||
            (( m == CKM_RSA_X_509) && (s->m_AccumulatedDataToVerify->GetLength() > u->GetLength())))
        {
            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }
    }
}


/*
*/
void Slot::verifyFinal( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pSignature, const CK_ULONG& a_ulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isVerificationActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    boost::shared_ptr< u1Array > dataToVerify;

    if( s->isDigestVerificationActiveKeyOp( ) ) {

        if( !s->_digestKeyVerification ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        // require hashing also
        CDigest* digest = s->_digestKeyVerification.get( );

        if( !digest ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CK_BYTE_PTR hash = new CK_BYTE[ digest->hashLength( ) ];

        digest->hashFinal( hash );

        dataToVerify.reset( new u1Array( digest->hashLength( ) ) );

        dataToVerify->SetBuffer( hash );

        delete[ ] hash;

    } else {

        // Sign Only
        dataToVerify = s->m_AccumulatedDataToVerify;
    }

    boost::shared_ptr< u1Array > signature( new u1Array( a_ulSignatureLen ) );

    signature->SetBuffer( a_pSignature );

    if( !s->_verification ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    try {

        StorageObject* o = m_Token->getObject( s->_verification->getObject( ) );

        m_Token->verify( o, dataToVerify.get( ), s->_verification->getMechanism( ), signature.get( ) );

    } catch( MiniDriverException& x ) {

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

        s->m_AccumulatedDataToVerify.reset( );

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

        s->m_AccumulatedDataToVerify.reset( );

        checkAccessException( x );

        throw;

    } catch( ... ) {

        s->removeDigestKeyVerification( );

        s->removeVerificationOperation( );

        s->m_AccumulatedDataToVerify.reset( );

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    s->removeDigestKeyVerification( );

    s->removeVerificationOperation( );

    s->m_AccumulatedDataToVerify.reset( );
}


/*
*/
CK_SESSION_HANDLE Slot::addSession( const bool& a_bIsReadWrite ) {

    // Prepare a unique session id
    CK_SESSION_HANDLE h = computeSessionHandle( a_bIsReadWrite );

    // Create & store the session instance
    m_Sessions.insert( h, new Session( this, h, a_bIsReadWrite ) );

    // Return the session handle
    return h;
}


/*
*/
CK_SESSION_HANDLE Slot::computeSessionHandle( const bool& a_bIsReadWrite ) {

    if( !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

	if (m_Sessions.size() >= SLOT_MAX_SESSIONS_COUNT)
	{
		throw PKCS11Exception( CKR_SESSION_COUNT );
	}

    // A session handle is a 4 or more bytes long unsigned data.
    CK_SESSION_HANDLE h = 0x00000000;
	unsigned int counter = 0;

    unsigned char ucSlotID = 0xFF;

    if (m_Device)
       ucSlotID = (unsigned char) m_slotID;
    else
       throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );

	do
	{
		counter = ++s_ucSessionIndex;
		h = ( ucSlotID << 16 ) | ( (a_bIsReadWrite?1:0) << 8 ) | counter;
	} while ((counter == 0) || isSessionOwner(h));
	

    return h;
}


/*
*/
void Slot::removeSession( const CK_SESSION_HANDLE& a_ulSessionId ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    m_Sessions.erase( a_ulSessionId );

    try {

        // if this was the last session to be removed then the login 
        // state of token for application returns to public sessions
        if( !m_Sessions.size( ) ) {

            m_Token->setLoggedRole( CK_UNAVAILABLE_INFORMATION );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
bool Slot::hasReadOnlySession( void ) {

    BOOST_FOREACH( const MAP_SESSIONS::value_type& i, m_Sessions ) {

        if( i.second && !i.second->isReadWrite( ) ) {

            return true;
        }
    }

    return false;
}


/*
*/
void Slot::isValidMechanism( const CK_ULONG& a_mechanism, const CK_ULONG& a_Operation )
{
    if( !m_Token || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    bool bFound = false;
    bool bIsECC = m_Device->isECC();
    bool bIsRsaEx = m_Device->hasOAEP_PSS();

    size_t lStandard = sizeof( g_mechanismList ) / sizeof( CK_ULONG );
    size_t lEcc = sizeof( g_mechanismListECC ) / sizeof( CK_ULONG );
    size_t lRsaEx = sizeof( g_mechanismListRsaEx ) / sizeof( CK_ULONG );

    for( size_t i = 0; i < lStandard ; ++i ) {

        if( g_mechanismList[ i ] == a_mechanism ){

            if( ( g_mechanismInfo[ i ].flags & a_Operation ) != a_Operation ) {

                throw PKCS11Exception( CKR_MECHANISM_INVALID );
            }

            bFound = true;

            break;
        }
    }

    if (!bFound && bIsECC)
    {
        for( size_t i = 0; i < lEcc ; ++i ) {

            if( g_mechanismListECC[ i ] == a_mechanism ){

                if( ( g_mechanismInfoECC[ i ].flags & a_Operation ) != a_Operation ) {

                    throw PKCS11Exception( CKR_MECHANISM_INVALID );
                }

                bFound = true;

                break;
            }
        }
    }

    if (!bFound && bIsRsaEx)
    {
        for( size_t i = 0; i < lRsaEx ; ++i ) {

            if( g_mechanismListRsaEx[ i ] == a_mechanism ){

                if( ( g_mechanismInfoRsaEx[ i ].flags & a_Operation ) != a_Operation ) {

                    throw PKCS11Exception( CKR_MECHANISM_INVALID );
                }

                bFound = true;

                break;
            }
        }
    }

    if( !bFound ) {

        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }
}


/*
*/
void Slot::isValidCryptoOperation( StorageObject* a_pObject, const CK_ULONG& a_ulOperation, CK_MECHANISM_TYPE mech ) {

    if( !a_pObject ) {

        throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
    }

    CK_OBJECT_CLASS c = a_pObject->getClass( );

    // Check if key is consistent
    switch( a_ulOperation ) {
    case CKF_ENCRYPT:
    case CKF_VERIFY:
    case CKF_VERIFY_RECOVER:
        if(c != CKO_PUBLIC_KEY && c != CKO_SECRET_KEY){
            throw PKCS11Exception(  CKR_KEY_TYPE_INCONSISTENT );
        }
        break;

    case CKF_DECRYPT:
    case CKF_SIGN:
    case CKF_SIGN_RECOVER:
    case CKF_DERIVE:
        if( ( c != CKO_PRIVATE_KEY ) && ( c != CKO_SECRET_KEY ) ) {

            throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
        }
        break;
    }

    // Check if key supports the operation
    switch( a_ulOperation )
    {
    case CKF_ENCRYPT:
        if(((c == CKO_PUBLIC_KEY)&&(!((Pkcs11ObjectKeyPublic*)a_pObject)->_encrypt)) ){
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        if (((Pkcs11ObjectKeyPublic*)a_pObject)->_keyType == CKK_EC)
        {
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_DECRYPT:
        if(((c == CKO_PRIVATE_KEY)&&(!((PrivateKeyObject*)a_pObject)->_decrypt))	){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        if (((PrivateKeyObject*)a_pObject)->_keyType == CKK_EC)
        {
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_VERIFY:
        if (c == CKO_PUBLIC_KEY)
        {
            if (!((Pkcs11ObjectKeyPublic*)a_pObject)->_verify)
            {
                throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
            }

            if (    (((Pkcs11ObjectKeyPublic*)a_pObject)->_keyType == CKK_EC) 
                &&  (mech != CKM_ECDSA)
                &&  (mech != CKM_ECDSA_SHA1)
                &&  (mech != CKM_ECDSA_SHA256)
                &&  (mech != CKM_ECDSA_SHA384)
                &&  (mech != CKM_ECDSA_SHA512)
            )
            {
                throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
            }
        }
        else if (c == CKO_SECRET_KEY)
        {
            if (!((SecretKeyObject*)a_pObject)->_verify)
            {
                throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
            }

            if (    (((SecretKeyObject*)a_pObject)->_keyType == CKK_AES)
                &&  (mech != CKM_AES_CMAC_GENERAL)
                &&  (mech != CKM_AES_CMAC)
            )
            {
                throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
            }
        }
        break;

    case CKF_VERIFY_RECOVER:
        if(((c == CKO_PUBLIC_KEY)&&(!((Pkcs11ObjectKeyPublic*)a_pObject)->_verifyRecover))){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        if (((Pkcs11ObjectKeyPublic*)a_pObject)->_keyType == CKK_EC)
        {
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_SIGN:
        if (c == CKO_PRIVATE_KEY)
        {
            if (!((PrivateKeyObject*)a_pObject)->_sign)
            {
                throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
            }

            if (    (((PrivateKeyObject*)a_pObject)->_keyType == CKK_EC)
                &&  (mech != CKM_ECDSA)
                &&  (mech != CKM_ECDSA_SHA1)
                &&  (mech != CKM_ECDSA_SHA256)
                &&  (mech != CKM_ECDSA_SHA384)
                &&  (mech != CKM_ECDSA_SHA512)
            )
            {
                throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
            }
        }
        else if (c == CKO_SECRET_KEY)
        {
            if (!((SecretKeyObject*)a_pObject)->_sign)
            {
                throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
            }

            if (    (((SecretKeyObject*)a_pObject)->_keyType == CKK_AES)
                &&  (mech != CKM_AES_CMAC_GENERAL)
                &&  (mech != CKM_AES_CMAC)
            )
            {
                throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
            }
        }
        break;

    case CKF_SIGN_RECOVER:
        if(((c == CKO_PRIVATE_KEY)&&(!((PrivateKeyObject*)a_pObject)->_signRecover))){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        if (((PrivateKeyObject*)a_pObject)->_keyType == CKK_EC)
        {
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_DERIVE:
        if(!((KeyObject*)a_pObject)->_derive){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        if (((KeyObject*)a_pObject)->_keyType == CKK_RSA)
        {
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;
    }


}


/*
*/
bool Slot::isSessionOwner( const CK_SESSION_HANDLE& a_hSession ) {

    MAP_SESSIONS::iterator i = m_Sessions.find( a_hSession );

    if( m_Sessions.end( ) == i ) {

        return false;
    }

    return true;
}


/*
*/
Session* Slot::getSession( const CK_SESSION_HANDLE& a_hSession ) { 

    MAP_SESSIONS::iterator i = m_Sessions.find( a_hSession );

    if( i == m_Sessions.end( ) ) {

        throw PKCS11Exception( CKR_SESSION_HANDLE_INVALID ); 
    } 

    return i->second; 
}


/*
*/
void Slot::getCardProperty( CK_BYTE a_ucProperty, CK_BYTE a_ucFlags, CK_BYTE_PTR a_pValue, CK_ULONG_PTR a_pValueLen ) {

    if( !m_Token.get( ) || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {
	   Token::CAtomicLogin atomicLogin(m_Token.get(), false);
       std::unique_ptr<u1Array> pPropertyValue(m_Device->getCardProperty( a_ucProperty, a_ucFlags ));

       if( !pPropertyValue.get() ) {

            *a_pValueLen = 0;

            return;
        }

        if( !a_pValue ) {

            // If the incoming buffer pointer is null then only return the expected size
            *a_pValueLen = pPropertyValue->GetLength( );

            return;

        } else {

            // If the incoming buffer is too smal then throw an error
            if( *a_pValueLen < pPropertyValue->GetLength( ) ) {

                *a_pValueLen = pPropertyValue->GetLength( );

                throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
            }
        }

        memcpy( a_pValue, pPropertyValue->GetBuffer( ), pPropertyValue->GetLength( ) );

        *a_pValueLen = pPropertyValue->GetLength( );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::setCardProperty( CK_BYTE a_ucProperty, CK_BYTE a_ucFlags, CK_BYTE_PTR a_pValue, CK_ULONG a_ulValueLen ) {

    if( !m_Token.get(  ) || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {
		Token::CAtomicLogin atomicLogin(m_Token.get(), true);
        u1Array prop( a_ulValueLen );

        prop.SetBuffer( a_pValue );

        m_Device->setCardProperty( a_ucProperty, &prop, a_ucFlags );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}

/*
*/
StorageObject* Slot::getSessionObject( const CK_OBJECT_HANDLE& a_hObject ) {

	if( !a_hObject ) {

		throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	}

	// Find the targeted object
	SESSION_OBJECTS::iterator i = m_SessionObjects.find( a_hObject );

     if( i == m_SessionObjects.end( ) ) {
	
		 throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	 }

	return i->second;
}

/*
*/
void Slot::removeSessionObject( const CK_OBJECT_HANDLE& a_hObject ) {

	if( !a_hObject ) {

		throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	}

    m_SessionObjects.erase(a_hObject);
}
