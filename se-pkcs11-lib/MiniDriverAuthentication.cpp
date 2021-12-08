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

#include "MiniDriverAuthentication.hpp"
#include "Log.hpp"
#ifdef WIN32
#include "BioMan.h"
#else
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif
#include "Timer.hpp"
#include "util.h"
#include "cardmod.h"
#include "PCSCMissing.h"


// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
static BOOL IsRegularFallback(DWORD dwFlags)
{
    if ((dwFlags & 0x01000000) == 0x01000000)
    {
        return FALSE;
    }

    return TRUE;
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
static BOOL IsAutoPinpad(DWORD dwFlags)
{
    if ((dwFlags & 0x02000000) == 0x02000000)
    {
        return FALSE;
    }

    return TRUE;
}

bool MiniDriverAuthentication::isSSO( MiniDriverAuthentication::ROLES role ) {

    if (role == PIN_NONE)
        return false;
    bool hasSSO = m_CardModule? m_CardModule->HasSSO () : true;
    return ( hasSSO && (m_PinPolicyForRole[getRoleIndex(role)].getAllowSSO( ) != 0 ));

}


/*
*/
MiniDriverAuthentication::MiniDriverAuthentication( ) {

    //Log::begin( "MiniDriverAuthentication::MiniDriverAuthentication" );

    // Set the default role
    m_AuthenticatedRole = PIN_NONE;

    m_bIsAdministratorLogged = false;

    for (int i = 0; i < 6; i++)
    {
        m_wActiveModeForRole[i] = UVM_PIN_ONLY;
        m_ucTypePINForRole[i] = PIN_TYPE_REGULAR;
		m_ucCachePINForRole[i] = PIN_CACHE_NORMAL;
		m_unblockForRole[i] = PIN_ADMIN;
    }

    m_CardModule = NULL;
    //Log::end( "MiniDriverAuthentication::MiniDriverAuthentication" );
}


/*
*/
void MiniDriverAuthentication::read( void ) {

    Log::begin( "MiniDriverAuthentication::read" );
    Timer t;
    t.start( );


    // Read the PIN info ex property
    // Get the active mode (PIN only, Biometry only, PIN and Biometry, PIN or Biometry)
    // and get the PIN type (external for biometry or secured reader, regular or no pin)

	bool bIsPinPadSupported = isPinPadSupported();
    for (int i = 0; i < 6; i++)
    {
        ROLES role = getRoleFromIndex(i);
        if( m_PinPolicyForRole[i].empty( ) ) {

            try {
                    // Read the PIN policy
                    m_PinPolicyForRole[i].read( (unsigned char) role );

            } catch( ... ) {

            }
        }
		// Always read PIN info to avoid problems with SSO
        // if( m_PinInfoExForRole[i].IsNull( ) )
		{
            try {
                m_PinInfoExForRole[i].reset( m_CardModule->getCardProperty( CARD_PROPERTY_PIN_INFO_EX, (u1) role ) );

                if( !m_PinInfoExForRole[i].IsNull( ) ) {

                    m_wActiveModeForRole[i] = (unsigned short)( m_PinInfoExForRole[i].GetBuffer( )[ 12 ] + ( ( m_PinInfoExForRole[i].GetBuffer( )[ 13 ] ) << 8 ) );
                    m_ucTypePINForRole[i] = (unsigned char)m_PinInfoExForRole[i].GetBuffer( )[ 0 ];
					m_ucCachePINForRole[i] = (unsigned char)m_PinInfoExForRole[i].GetBuffer( )[ 3 ];
					DWORD unblockPinSet = (DWORD)(((m_PinInfoExForRole[i].GetBuffer()[2]) & ~((1 << getRolePinID(role)) >> 1)) << 1);
					if (unblockPinSet == (DWORD) (1 << getRolePinID(PIN_ADMIN)))
					{
						m_unblockForRole[i] = PIN_ADMIN;
					}
					else
					{
						// find first ROLE that can unblock us
						for (int j = 0; j < 6; j++)
						{
							ROLES unblockRole = getRoleFromIndex(j);
							if ((unblockRole != role) && (unblockPinSet & (DWORD) (1 << getRolePinID(unblockRole))))
							{
								m_unblockForRole[i] = unblockRole;
								break;
							}
						}
					}

					DWORD dwFlags = (DWORD)
						(m_PinInfoExForRole[i].GetBuffer()[8] +
						((m_PinInfoExForRole[i].GetBuffer()[9]) << 8) +
						((m_PinInfoExForRole[i].GetBuffer()[10]) << 16) +
						((m_PinInfoExForRole[i].GetBuffer()[11]) << 24)
						);
					DWORD dwFlagsEx = (DWORD)
						(m_PinInfoExForRole[i].GetBuffer()[12] +
						((m_PinInfoExForRole[i].GetBuffer()[13]) << 8) +
						((m_PinInfoExForRole[i].GetBuffer()[14]) << 16) +
						((m_PinInfoExForRole[i].GetBuffer()[15]) << 24)
						);

					// Fallback External -> Regular if necessary
					if (  (m_ucTypePINForRole[i] == PIN_TYPE_EXTERNAL)
						&&((dwFlagsEx & 0x0000FFFF) == 1)
						&&(!bIsPinPadSupported)
						&&(IsRegularFallback(dwFlags))
						)
					{
						m_ucTypePINForRole[i] = PIN_TYPE_REGULAR;
					}

					// Auto PIN Pad: Regular -> External if necessary
					if (  (m_ucTypePINForRole[i] == PIN_TYPE_REGULAR)
						&&((dwFlagsEx & 0x0000FFFF) == 1)

						&&(bIsPinPadSupported)

						&&(IsAutoPinpad(dwFlags))
//						&&(isSessionPinSupported(role))
						)
					{
						m_ucTypePINForRole[i] = PIN_TYPE_EXTERNAL;
					}
				}

            } catch( ... ) {

                m_PinInfoExForRole[i].reset( );
                m_wActiveModeForRole[i] = UVM_PIN_ONLY;
                m_ucTypePINForRole[i] = PIN_TYPE_REGULAR;
				m_ucCachePINForRole[i] = PIN_CACHE_NORMAL;
				m_unblockForRole[i] = PIN_ADMIN;
            }
        }
    }

    t.stop( "MiniDriverAuthentication::read" );
    Log::end( "MiniDriverAuthentication::read" );
}

/*
*/
void MiniDriverAuthentication::setStaticRoles(std::list<u1> roles)
{
	m_listStaticRoles.clear();

	for (std::list<u1>::iterator It = roles.begin(); It != roles.end(); It++)
	{
		m_listStaticRoles.push_back((MiniDriverAuthentication::ROLES) *It);
	}
}


/*
*/
void MiniDriverAuthentication::login( MiniDriverAuthentication::ROLES role, u1Array* a_pPin) {

    Log::begin( "MiniDriverAuthentication::login" );
    Timer t;
    t.start( );

    switch( howToAuthenticate( role, (unsigned char)a_pPin->GetLength( ) ) ) {

    case g_ucAuthenticateRegular:
        Log::log( "MiniDriverAuthentication::login - Normal login" );
        verifyPin( role, a_pPin);
        break;

    case g_ucAuthenticateSecure:
		Log::log( "MiniDriverAuthentication::AuthenticateUser - Secure Authentication not supported !!" );
		throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
        break;

    case g_AuthenticateBiometry:
        Log::log( "MiniDriverAuthentication::AuthenticateUser - BIO not supported !!" );
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
        break;

    default:
        Log::log( "MiniDriverAuthentication::login - Unknown !!" );
        throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
        break;
    }

    m_AuthenticatedRole = role;

    t.stop( "MiniDriverAuthentication::login" );
    Log::end( "MiniDriverAuthentication::login" );
}


/*
*/
unsigned char MiniDriverAuthentication::howToAuthenticate( MiniDriverAuthentication::ROLES role, unsigned char bPinLen ) {

    Log::begin( "MiniDriverAuthentication::howToAuthenticate" );
    Timer t;
    t.start( );

    unsigned char bRet = g_ucAuthenticateRegular;

    if (Log::s_bEnableLog)
    {
        Log::log( "MiniDriverAuthentication::howToAuthenticate - PIN type <%ld> (0 = regular ; 1 = external)", isExternalPin( role ) );
        Log::log( "MiniDriverAuthentication::howToAuthenticate - Card mode <%ld> (1 = pin only ; 2 = fp only ; 3 = fp or pin ; 4 = fp and pin)", getPinMode( role ) );
        Log::log( "MiniDriverAuthentication::howToAuthenticate - PIN len %s", bPinLen? "> 0" : "= 0" );
    }

    if( isExternalPin( role ) )
    {
        if( isModePinOnly( role ) )
        {
            // No PINPAD, so disallow login
            Log::log( "MiniDriverAuthentication::howToAuthenticate - External PIN && UVM1 && NO PINpad support -> ERROR !!!" );
            bRet = g_ucAuthenticateError;
        }
        else
        {

            Log::log( "MiniDriverAuthentication::howToAuthenticate - External PIN && (UVM2 || UVM3 || UVM4) -> Bio -> ERROR !!!" );
            bRet = g_AuthenticateBiometry;
        }
    }
    else
    {

        if( bPinLen && ( isModePinOnly( role ) || isModePinOrBiometry( role ) ) )
        {

            Log::log( "MiniDriverAuthentication::howToAuthenticate - Regular PIN && (UVM1 || UVM3)  && valid len -> PIN normal" );
            bRet = g_ucAuthenticateRegular;

        }
        else
        {

            Log::log( "MiniDriverAuthentication::howToAuthenticate - Regular PIN && (UVM2 || UVM4)  && NO valid len -> ERROR !!!" );
            bRet = g_ucAuthenticateError;
        }
    }

    t.stop( "MiniDriverAuthentication::howToAuthenticate" );
    Log::end( "MiniDriverAuthentication::howToAuthenticate" );

    return bRet;
}


/*
*/
unsigned char MiniDriverAuthentication::howToChangePin( MiniDriverAuthentication::ROLES role, unsigned char bOldPinLen, unsigned char bNewPinLen ) {

    Log::begin( "MiniDriverAuthentication::howToChangePin" );
    Timer t;
    t.start( );

    unsigned char bRet = g_ucAuthenticateRegular;

    if (Log::s_bEnableLog)
    {
        Log::log( "MiniDriverAuthentication::howToChangePin - PIN type <%ld> (0 = regular ; 1 = external)", isExternalPin( role ) );
        Log::log( "MiniDriverAuthentication::howToChangePin - Card mode <%ld> (1 = pin only ; 2 = fp only ; 3 = fp or pin ; 4 = fp and pin)", getPinMode( role ) );
        Log::log( "MiniDriverAuthentication::howToChangePin - Old PIN len %s", bOldPinLen? "> 0" : "= 0" );
		Log::log( "MiniDriverAuthentication::howToChangePin - New PIN len %s", bNewPinLen? "> 0" : "= 0" );
    }

    if( isExternalPin( role ) )
    {
		// No PINPAD, so disallow login
        Log::log( "MiniDriverAuthentication::howToChangePin - External PIN && UVM1 && NO PINpad support -> ERROR !!!" );
        bRet = g_ucAuthenticateError;
    }
    else
    {
        if( bOldPinLen && bNewPinLen )
        {

            Log::log( "MiniDriverAuthentication::howToChangePin - Regular PIN && (UVM1 || UVM3)  && valid len -> PIN normal" );
            bRet = g_ucAuthenticateRegular;

        }
        else
        {

            Log::log( "MiniDriverAuthentication::howToChangePin - Regular PIN && (UVM2 || UVM4)  && NO valid len -> ERROR !!!" );
            bRet = g_ucAuthenticateError;
        }
    }

    t.stop( "MiniDriverAuthentication::howToChangePin" );
    Log::end( "MiniDriverAuthentication::howToChangePin" );

    return bRet;
}

/*
*/
/*
void MiniDriverAuthentication::verifyPinWithBio( void ) {

    Log::begin( "MiniDriverAuthentication::verifyPinWithBio" );

    long rv = SCARD_F_INTERNAL_ERROR;

#ifdef WIN32
    // Get the current OS version
    OSVERSIONINFO osvi;
    memset( &osvi, 0, sizeof( OSVERSIONINFO ) );
    osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
    GetVersionEx(&osvi);
    // Check if the Os is W7 or W2K8R2
    if( ( 6 == osvi.dwMajorVersion ) && ( osvi.dwMinorVersion >= 1 ) )
    {
        Log::log( "MiniDriverAuthentication::verifyPinWithBio - Os is W7 or W2K8R2" );

        //		CardEndTransaction( );

        // The OS is W7 or W2K8R2
        HMODULE hDll = NULL;
        LRESULT lRes = GSC_OK;
        LRESULT (WINAPI *ptr_SetUITitles) (WCHAR*, WCHAR*);
        LRESULT (WINAPI *ptr_AuthenticateUserCard) ();

        // Load DLL
        hDll = LoadLibraryA("GemSelCert.dll");
        Log::log( "MiniDriverAuthentication::verifyPinWithBio - load lib" );

        if( 0 != hDll )
        {
            // Set UI Titles
            ptr_SetUITitles = (LRESULT (WINAPI *) (WCHAR*, WCHAR*))GetProcAddress(hDll,"SetUITitles");
            if( NULL != ptr_SetUITitles )
            {
                ptr_SetUITitles(L"Smartcard Security", L"User MiniDriverAuthentication");
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - ptr_SetUITitles" );

                // Authenticate Card User
                ptr_AuthenticateUserCard = (LRESULT (WINAPI *)())GetProcAddress(hDll,"AuthenticateUserCard");
                if( NULL != ptr_AuthenticateUserCard )
                {
                    lRes = ptr_AuthenticateUserCard();
                    Log::log( "MiniDriverAuthentication::verifyPinWithBio - ptr_AuthenticateUserCard" );

                    switch(lRes)
                    {
                    case GSC_OK:
                        rv = SCARD_S_SUCCESS;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_S_SUCCESS" );
                        break;

                    case GSC_CANCEL:
                        rv = SCARD_E_CANCELLED;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_CANCELLED" );
                        break;

                    case GSC_NO_CERT:
                        rv = SCARD_E_CERTIFICATE_UNAVAILABLE;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_CERTIFICATE_UNAVAILABLE" );
                        break;

                    case GSC_NO_CARD:
                        rv = SCARD_E_NO_SMARTCARD;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_NO_SMARTCARD" );
                        break;

                    case GSC_WRONG_PIN:
                        rv = SCARD_W_WRONG_CHV;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_W_WRONG_CHV" );
                        break;

                    case GSC_READ_CARD:
                        rv = SCARD_E_NO_ACCESS;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_NO_ACCESS" );
                        break;

                    case GSC_WRITE_CARD:
                        rv = SCARD_E_NO_ACCESS;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_NO_ACCESS" );
                        break;

                    default:
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_F_INTERNAL_ERROR" );
                        rv = SCARD_F_INTERNAL_ERROR;
                        break;
                    }
                }
            }

            // Release DLL
            FreeLibrary(hDll);
            Log::log( "MiniDriverAuthentication::verifyPinWithBio - FreeLibrary" );

            //		CardBeginTransaction( );
        }
        // The OS is Vista or XP
        else
        {
            Log::log( "MiniDriverAuthentication::verifyPinWithBio - Os is Vista or XP" );

            CBioMan* pBioMan = NULL;
            DWORD dwRes = BIO_ERR_NOT_SUPPORTED;

            // Init BioMan helper
            pBioMan = new CBioMan( m_CardModule );

            // Biometrics Verification
            dwRes = pBioMan->VerifyBio( );

            delete pBioMan;

            // Error ?
            switch( dwRes )
            {
            case BIO_ERR_SUCCESS:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - CKR_OK" );
                rv = SCARD_S_SUCCESS;
                break;

            case BIO_ERR_NO_CARD:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - CKR_TOKEN_NOT_PRESENT" );
                rv = SCARD_E_NO_SMARTCARD;
                break;

            case BIO_ERR_NOT_SUPPORTED:
            case BIO_ERR_NO_FINGER:
            case BIO_ERR_BIO_NOT_CHECKED:
            case BIO_ERR_PIN_NOT_CHECKED:
            case BIO_ERR_BIO_LAST:
            case BIO_ERR_PIN_LAST:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_W_WRONG_CHV" );
                rv = SCARD_W_WRONG_CHV;
                break;

            case BIO_ERR_BLOCKED:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_W_CHV_BLOCKED" );
                rv = SCARD_W_CHV_BLOCKED;
                break;

            case BIO_ERR_ABORT:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_CANCELLED" );
                rv = SCARD_E_CANCELLED;
                break;

            default:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_F_INTERNAL_ERROR" );
                rv = SCARD_F_INTERNAL_ERROR;
                break;
            }
        }
    }
#endif

    Log::log( "MiniDriverAuthentication::verifyPinWithBio - <END>" );

    if( SCARD_S_SUCCESS != rv ) {

        throw MiniDriverException( rv );
    }
}
*/

/*
*/
bool MiniDriverAuthentication::isLoggedIn( MiniDriverAuthentication::ROLES role ) {

    if( m_AuthenticatedRole == role ) {

        return true;
    }

    if(  isSSO( role ) && isAuthenticated( role ) ) {

        return true;
    }

    if( isNoPin( role ) ) {

        return true;
    }

    return false;
}

/*
*/
bool MiniDriverAuthentication::isPinPadSupported()
{
	return false;
}

/*
*/
bool MiniDriverAuthentication::isSessionPinSupported(MiniDriverAuthentication::ROLES role)
{
    bool bRes = FALSE;

	if (m_CardModule)
	{
		try
		{
		   u1Array* ba = NULL;

		   ba = m_CardModule->getCardProperty(C_CARD_PIN_STRENGTH_VERIFY, (u1) role);

		   // PIN Strength session is set
		   if (  (ba != NULL)
			   &&((ba->GetBuffer()[0] & CARD_PIN_STRENGTH_SESSION_PIN) == CARD_PIN_STRENGTH_SESSION_PIN)
			  )
		   {
			 bRes = true;
		   }

		   if (ba != NULL)
		   {
			  delete ba;
		   }
		}
		catch(...)
		{
			bRes = false;
		}
	}

    return bRes;
}

/*
*/
void MiniDriverAuthentication::changePin( MiniDriverAuthentication::ROLES role, u1Array* a_pOldPIN, u1Array* a_pNewPIN ) {
	if( m_CardModule )
	{
		if (m_CardModule->GetCardModel() == NET_STUB)
		{
			if (a_pOldPIN->GetLength() == 0 || a_pNewPIN->GetLength() == 0)
			{
				Log::log( "MiniDriverAuthentication::changePin - Error (PIN len = 0)!! for .NET card we only support changing a PIN by entring PIN values" );
				throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
			}

			s4 maxTries = -1;
			boost::shared_ptr< u1Array > baSrcPin;
			boost::shared_ptr< u1Array > baDestPin;
			u1ArraySecure sbSessionPin(0);
			SHA_CTX sha;
			BYTE       bKey[24] = {0};
			DWORD      dwPaddLen = 0;
			BYTE       bClearPin[264];
			BYTE       bCryptedPin[264];

         try
         {
			   if(generateSessionPinEx(role, a_pOldPIN, sbSessionPin, &maxTries))
			   {
				   baSrcPin.reset(new u1Array((s4)sbSessionPin.GetLength()));
				   baSrcPin->SetBuffer(sbSessionPin.GetBuffer());

				   // -------------------------
				   // Compute Encrypted New PIN
				   // -------------------------

				   // Compute Key = SHA1(Clear PIN)
				   SHA1_Init(&sha);
				   SHA1_Update(&sha, a_pOldPIN->GetBuffer(), a_pOldPIN->GetLength());
				   SHA1_Final(bKey, &sha);

				   // Padding length (PKCS#7)
				   dwPaddLen = 8 - (a_pNewPIN->GetLength() % 8);

				   // Fill Buffer to Encrypt (New PIN + PKCS#7 Padding)
				   memset(bClearPin, 0x00, sizeof(bClearPin));
				   memcpy(bClearPin, a_pNewPIN->GetBuffer(), a_pNewPIN->GetLength());
				   memset(&bClearPin[a_pNewPIN->GetLength()], (BYTE)dwPaddLen, dwPaddLen);

				   // Encrypt New PIN = 3DES_ECB(Encrypt, New PIN, SHA1(old PIN))
                   int cryptedPinLength = (int) a_pNewPIN->GetLength() + dwPaddLen;
                   EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
                   //EVP_CIPHER_CTX_init(&ctx);
                   EVP_EncryptInit(ctx, EVP_des_ede3(), bKey, NULL);
                   EVP_EncryptUpdate(ctx, bCryptedPin, &cryptedPinLength, bClearPin, a_pNewPIN->GetLength() + dwPaddLen);
                   EVP_CIPHER_CTX_free(ctx);

				   baDestPin.reset(new u1Array(a_pNewPIN->GetLength() + dwPaddLen));
				   baDestPin->SetBuffer(bCryptedPin);
			   }

			   else
			   {
				   baSrcPin.reset(new u1Array(a_pOldPIN->GetLength()));
				   baSrcPin->SetBuffer(a_pOldPIN->GetBuffer());
				   baDestPin.reset(new u1Array(a_pNewPIN->GetLength()));
				   baDestPin->SetBuffer(a_pNewPIN->GetBuffer());
			   }

			   // Unblock PIN Securely in the Card
			   m_CardModule->changeAuthenticatorEx(PIN_CHANGE_CHANGE, role, baSrcPin.get(), role, baDestPin.get(), maxTries);
         }
         catch(MiniDriverException& ex)
         {
            if (ex.getError() == SCARD_E_UNSUPPORTED_FEATURE)
            {
				   Log::log( "MiniDriverAuthentication::changePin - changeAuthenticatorEx not supported by the card. Using changeReferenceData." );
				   m_CardModule->changeReferenceData( MODE_CHANGE_PIN, (u1) role, a_pOldPIN, a_pNewPIN, -1 );
            }
            else
               throw;
         }
		}
		else
		{
			switch( howToChangePin( role, (unsigned char)a_pOldPIN->GetLength( ), (unsigned char)a_pNewPIN->GetLength( ) ) ) {

			case g_ucAuthenticateRegular:
				Log::log( "MiniDriverAuthentication::changePin - Normal login" );
				m_CardModule->changeReferenceData( MODE_CHANGE_PIN, (u1) role, a_pOldPIN, a_pNewPIN, -1 );
				break;

			case g_ucAuthenticateSecure:
				Log::log( "MiniDriverAuthentication::changePin - Can't use PinPad" );
				throw MiniDriverException( SCARD_E_CARD_UNSUPPORTED );
				break;

			default:
				Log::log( "MiniDriverAuthentication::changePin - Unknown !!" );
				throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
				break;
			}
		}
	}
	else
		throw MiniDriverException( SCARD_E_NO_SMARTCARD );
}

/*
*/
void MiniDriverAuthentication::synchronizePIN( void ) {
}


/*
*/
void MiniDriverAuthentication::unblockPin( MiniDriverAuthentication::ROLES role, u1Array* a_PinSo, u1Array* a_PinUser ) {

    if (Log::s_bEnableLog)
    {
        Log::begin( "MiniDriverAuthentication::unblockPin" );
        Log::log( "User PIN <Sensitive> - Administrator Key <Sensitive>");
    }

    Timer t;
    t.start( );

	MiniDriverAuthentication::ROLES unblockRole = getPinUnblockRole(role);
	if ( unblockRole == PIN_ADMIN)
	{
		if (a_PinSo->GetLength() != 24)
		{
			Log::error( "MiniDriverAuthentication::unblockPin", "No valid admin key given" );
			throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
		}

		// Unblock the user PIN. The retry counter value is not modified (-1)
		if (m_CardModule->GetCardModel() == NET_STUB)
		{
			if (a_PinUser->GetLength() == 0)
			{
				Log::log( "MiniDriverAuthentication::unblockPin - Error (PIN len = 0)!! for .NET card we only support unblock a PIN by entring PIN value" );
				throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
			}
			// Get a challenge from the smart card
			boost::shared_ptr< u1Array > pChallenge( m_CardModule->getChallenge( ) );

			// compute a 3DES cryptogramm from the challenge using the administrator key
			computeCryptogram( pChallenge.get( ), a_PinSo );

			// Unblock the user PIN. The retry counter value is not modified (-1)
			m_CardModule->changeReferenceData( MODE_UNBLOCK_PIN, (u1) role, m_Cryptogram.GetArray(), a_PinUser, -1 );
		}
		else
		{
			switch( howToUnblock( role, (unsigned char)a_PinUser->GetLength( ) ) ) {

			case g_ucAuthenticateRegular:
				{
					Log::log( "MiniDriverAuthentication::unblockPin - Normal unblock" );
					// Get a challenge from the smart card
					boost::shared_ptr< u1Array > pChallenge( m_CardModule->getChallenge( ) );

					// compute a 3DES cryptogramm from the challenge using the administrator key
					computeCryptogram( pChallenge.get( ), a_PinSo );

					m_CardModule->changeReferenceData( MODE_UNBLOCK_PIN, (u1) role, m_Cryptogram.GetArray(), a_PinUser, -1 );
				}
				break;

			case g_ucAuthenticateSecure:
				{
					Log::log( "MiniDriverAuthentication::unblockPin - PinPad" );
					Log::log( "MiniDriverAuthentication::unblockPin - Unblocking PIN is Admin key => Error : Can't use PinPad" );
					throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
				}
				break;

			default:
				Log::log( "MiniDriverAuthentication::unblockPin - Unknown !!" );
				throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
				break;
			}
		}
	}
	else
	{
		if (m_CardModule->GetCardModel() == NET_STUB)
		{
			if (a_PinSo->GetLength() == 0 || a_PinUser->GetLength() == 0)
			{
				Log::log( "MiniDriverAuthentication::unblockPin - Error (PIN len = 0)!! for .NET card we only support unblock a PIN by entring PIN values" );
				throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
			}

			s4 maxTries = -1;
			boost::shared_ptr< u1Array > baSrcPin;
			boost::shared_ptr< u1Array > baDestPin;
			u1ArraySecure sbSessionPin(0);

			if(generateSessionPinEx(unblockRole, a_PinSo, sbSessionPin, &maxTries))
			{
				baSrcPin.reset(new u1Array((s4)sbSessionPin.GetLength()));
				baSrcPin->SetBuffer(sbSessionPin.GetBuffer());
			}
			else
			{
				baSrcPin.reset(new u1Array(a_PinSo->GetLength()));
				baSrcPin->SetBuffer(a_PinSo->GetBuffer());
			}

			// Unblock PIN Securely in the Card
			m_CardModule->changeAuthenticatorEx(PIN_CHANGE_UNBLOCK, unblockRole, baSrcPin.get(), role, a_PinUser, -1);
		}
		else
		{
			switch( howToUnblock( role, (unsigned char)a_PinUser->GetLength( ) ) ) {

			case g_ucAuthenticateRegular:
				Log::log( "MiniDriverAuthentication::unblockPin - Normal unblock" );
				if (a_PinSo->GetLength() == 0)
				{
					Log::log( "MiniDriverAuthentication::unblockPin - Error (SO PIN len = 0)!! For regular PIN, we need the value of the unblocking PIN" );
					throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
				}
				m_CardModule->changeAuthenticatorEx(PIN_CHANGE_UNBLOCK, unblockRole, a_PinSo, role, a_PinUser, -1);
				break;

			case g_ucAuthenticateSecure:
				Log::log( "MiniDriverAuthentication::unblockPin - PinPad can't be used !");
				throw MiniDriverException( SCARD_E_CARD_UNSUPPORTED );
				break;

			default:
				Log::log( "MiniDriverAuthentication::unblockPin - Unknown !!" );
				throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
				break;
			}
		}

	}

    t.stop( "MiniDriverAuthentication::unblockPin" );
    Log::end( "MiniDriverAuthentication::unblockPin" );
}


/// ADMINISTRATOR


/*
*/
void MiniDriverAuthentication::administratorChangeKey( u1Array* a_OldKey, u1Array* a_NewKey ) {

    Log::begin( "MiniDriverAuthentication::administratorChangeKey" );
    Timer t;
    t.start( );

	if (a_OldKey->GetLength() != 24)
	{
		Log::error( "MiniDriverAuthentication::administratorChangeKey", "invalid old admin key given" );
		throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
	}

	if (a_NewKey->GetLength() != 24)
	{
		Log::error( "MiniDriverAuthentication::administratorChangeKey", "invalid new admin key given" );
		throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
	}

    // Get the challenge from the smart card
    boost::shared_ptr< u1Array > pChallenge( m_CardModule->getChallenge( ) );

    // Compute the 3DES cryptogram from the challeng using the current adminsitrator key
    computeCryptogram( pChallenge.get( ), a_OldKey );

    // The new administrator key has to be 24 bytes. if not we just pad rest of bytes as zeros
    u1Array a( 24 );

    memset( a.GetBuffer( ), 0, 24 );

    memcpy( a.GetBuffer( ), a_NewKey->GetBuffer( ), a_NewKey->GetLength( ) );

    // Change the administrator key
    m_CardModule->changeReferenceData( MODE_CHANGE_PIN, PIN_ADMIN, m_Cryptogram.GetArray(), &a, -1 );

    t.stop( "MiniDriverAuthentication::administratorChangeKey" );
    Log::end( "MiniDriverAuthentication::administratorChangeKey" );
}


/*
*/
void MiniDriverAuthentication::administratorLogin( u1Array* a_pAdministratorKey ) {

    Log::begin( "MiniDriverAuthentication::authenticateAdministrator" );
    Timer t;
    t.start( );

	if (a_pAdministratorKey->GetLength() != 24)
	{
		Log::error( "MiniDriverAuthentication::administratorLogin", "No admin key given" );
		throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
	}

    // Get a challenge
    boost::shared_ptr< u1Array > challenge( m_CardModule->getChallenge( ) );

    // Compute a cryptopgram from the challenge using the administror key
    computeCryptogram( challenge.get( ), a_pAdministratorKey );

    try {

        // Perform the administrator authentication
       m_CardModule->externalAuthenticate( m_Cryptogram.GetArray() );

    } catch( MiniDriverException& ) {

        Log::error( "MiniDriverAuthentication::administratorLogin", "externalAuthenticate failed" );

        // first check if pin is locked or not blocked
        if( !administratorGetTriesRemaining( ) ) {

            throw MiniDriverException( SCARD_W_CHV_BLOCKED );
        }

        throw;
    }

    t.stop( "MiniDriverAuthentication::authenticateAdministrator" );
    Log::end( "MiniDriverAuthentication::authenticateAdministrator" );
}


/* Only accept correct length, otherwise return a zero valued response that is sure to fail authentication.
*/
void MiniDriverAuthentication::computeCryptogram( u1Array* a_challenge, u1Array* a_pin ) {

    Log::begin( "MiniDriverAuthentication::computeCryptogram" );
    Timer t;
    t.start( );

    m_Cryptogram.reset( );

    if( 24 == a_pin->GetLength( ) ) {

         // compute the response
         m_Cryptogram.reset( new u1Array( 8 ) );
         ComputeCryptogram (a_pin->GetBuffer( ), a_challenge->GetBuffer( ), 8, m_Cryptogram.GetBuffer( ));

    }

    t.stop( "MiniDriverAuthentication::computeCryptogram" );
    Log::end( "MiniDriverAuthentication::computeCryptogram" );
}


/*
*/
void MiniDriverAuthentication::print( void ) {

    if (Log::s_bEnableLog)
    {
        Log::begin( "MiniDriverAuthentication::print\n" );
        for (int i = 0; i < 6; i++)
        {
            Log::log( "ROLE = <%ld>", (int) getRoleFromIndex(i) );
            Log::log( "m_wActiveMode <%ld>", m_wActiveModeForRole[i] );
            Log::log( "m_ucTypePIN <%ld>", m_ucTypePINForRole[i] );
			Log::log( "m_ucCachePIN <%ld>", m_ucCachePINForRole[i] );
            m_PinPolicyForRole[i].print( );
            Log::logCK_UTF8CHAR_PTR( "m_PinInfoEx", m_PinInfoExForRole[i].GetBuffer( ), m_PinInfoExForRole[i].GetLength( ) );
            Log::log( "\n" );
        }

        Log::end( "MiniDriverAuthentication::print" );
    }
}

const char* MiniDriverAuthentication::getRoleDescription(ROLES role)
{
    switch(role)
    {
        case PIN_NONE : return "No PIN";
		case PIN_USER : return g_sPinUserLabel.c_str();
		case PIN_ADMIN: return g_sPinAdminLabel.c_str();
		case PIN_3    : return g_sPin3Label.c_str();
		case PIN_4    : return g_sPin4Label.c_str();
		case PIN_5    : return g_sPin5Label.c_str();
		case PIN_6    : return g_sPin6Label.c_str();
		case PIN_7    : return g_sPin7Label.c_str();
        default       : return "Unknown";
    }
}

int MiniDriverAuthentication::getRoleIndex(ROLES role)
{
    switch(role)
    {
        case PIN_USER : return 0;
        case PIN_3    : return 1;
        case PIN_4    : return 2;
        case PIN_5    : return 3;
        case PIN_6    : return 4;
        case PIN_7    : return 5;
        default       : return -1;
    }
}

int MiniDriverAuthentication::getRolePinID(ROLES role)
{
    switch(role)
    {
        case PIN_USER : return 1;
		case PIN_ADMIN : return 2;
        case PIN_3    : return 3;
        case PIN_4    : return 4;
        case PIN_5    : return 5;
        case PIN_6    : return 6;
        case PIN_7    : return 7;
        default       : return -1;
    }
}

MiniDriverAuthentication::ROLES MiniDriverAuthentication::getRoleFromIndex( int index)
{
    switch(index)
    {
        case 0 : return PIN_USER;
        case 1 : return PIN_3;
        case 2 : return PIN_4;
        case 3 : return PIN_5;
        case 4 : return PIN_6;
        case 5 : return PIN_7;
        default: return PIN_NONE;
    }
}

MiniDriverAuthentication::ROLES MiniDriverAuthentication::getRoleFromDesc( const char* szDesc)
{
	if (0 == strcmp(szDesc, "No PIN"))
		return PIN_NONE;
	if (0 == strcmp(szDesc, g_sPinUserLabel.c_str()))
		return PIN_USER;
	if (0 == strcmp(szDesc, g_sPinAdminLabel.c_str()))
		return PIN_ADMIN;
	if (0 == strcmp(szDesc, g_sPin3Label.c_str()))
		return PIN_3;
	if (0 == strcmp(szDesc, g_sPin4Label.c_str()))
		return PIN_4;
	if (0 == strcmp(szDesc, g_sPin5Label.c_str()))
		return PIN_5;
	if (0 == strcmp(szDesc, g_sPin6Label.c_str()))
		return PIN_6;
	if (0 == strcmp(szDesc, g_sPin7Label.c_str()))
		return PIN_7;

	return PIN_NONE;
}

bool MiniDriverAuthentication::administratorIsAuthenticated( void ) {

    bool b = false;

    if( m_CardModule ) {

        b = (m_CardModule->isAuthenticated( PIN_ADMIN ) != 0);

        Log::log( "MiniDriverAuthentication - administratorIsAuthenticated <%d>", b );

    } else {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD );
    }

    return b;

}
