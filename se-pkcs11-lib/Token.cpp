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
// #include <boost/foreach.hpp>

#include <ctime>
#include <utility>
#include <list>
#include <map>
#include <memory>
#ifdef __APPLE__
#include <pwd.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "cryptoki.h"
#include "util.h"
#include "x509cert.h"
#include "attrcert.h"
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "Pkcs11ObjectKeyPublicECC.hpp"
#include "Pkcs11ObjectKeyPrivateECC.hpp"
#include "Pkcs11ObjectData.hpp"
#include "Pkcs11ObjectKeySecretAES.hpp"
#include "Pkcs11ObjectKeyGenericSecret.hpp"
#include "PKCS11Exception.hpp"
#include "digest.h"
#include "Log.hpp"
#include "Token.hpp"
#include "MiniDriverException.hpp"
#include "cardmod.h"
#include "Slot.hpp"
#include "PCSCMissing.h"
#include "zlib.h"
#include <errno.h>
#include "Application.hpp"

#ifdef _WIN32
#include "resource.h"
#else
#include <sys/wait.h>
#include <signal.h>
#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
#endif

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

const unsigned char g_ucPKCS_EMEV15_PADDING_TAG = 0x02;

bool Token::s_bForcePinUser = false;

unsigned char g_pbECC256k1_OID[7] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};

unsigned char g_pbECC256_OID[10] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

unsigned char g_pbECC384_OID[7] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};

unsigned char g_pbECC521_OID[7] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};

/*
*/
bool isFileExists( const std::string& a_stFileName, const MiniDriverFiles::FILES_NAME& a_stFilesList ) {

    // Look if the file name is present intot the list
    // BOOST_FOREACH( const std::string& fileName, a_stFilesList ) {
	for (MiniDriverFiles::FILES_NAME::iterator iter = a_stFilesList.begin () ; iter != a_stFilesList.end (); ++iter) {
		std::string& fileName = (std::string&)*iter;

        // The file name has been found
        if( std::string::npos != a_stFileName.find( fileName ) ) {
            return true;
        }
    }

    return false;
}

/*
*/
Token::CAtomicLogin::CAtomicLogin(Token* pToken, MiniDriverAuthentication::ROLES specificRole) : m_pToken(pToken)
{
	if (	m_pToken->m_Device
		&&	m_pToken->m_pSlot
        )
    {
        if (     (specificRole != MiniDriverAuthentication::PIN_USER)
                &&  !m_pToken->m_Device->isNoPin(MiniDriverAuthentication::PIN_USER)
                &&  (!m_pToken->m_Device->isSSO(MiniDriverAuthentication::PIN_USER) || !m_pToken->m_Device->isAuthenticated(MiniDriverAuthentication::PIN_USER))
                )
        {
			authenticateRole(MiniDriverAuthentication::PIN_USER);
        }
	}
}

Token::CAtomicLogin::CAtomicLogin(Token* pToken, bool bIsForWriteOperation, CK_BYTE specificRole) : m_pToken(pToken), m_bIsForWriteOperation(bIsForWriteOperation)
{
	if (	m_pToken->m_Device
		&&	m_pToken->m_pSlot
        )
    {
        MiniDriverAuthentication::ROLES tokenRole = m_pToken->getUserRole();
        if (    (specificRole == 0)
            &&  (!m_bIsForWriteOperation || (m_bIsForWriteOperation && ( tokenRole == MiniDriverAuthentication::PIN_USER)))
			&&  (!m_pToken->m_Device->isNoPin(tokenRole))
         &&  (!m_pToken->m_Device->isSSO(tokenRole) || !m_pToken->m_Device->isAuthenticated(tokenRole))
		    &&	m_pToken->m_pSlot->isAuthenticated()
            )
	    {
			CSecureString& tokenSecuredPin = m_pToken->m_Device->getSecuredPin(tokenRole);
		    try
		    {
				if (tokenSecuredPin.GetLength())
				{
					u1ArraySecure pin(tokenSecuredPin.GetLength());
					tokenSecuredPin.CopyTo(pin.GetBuffer());
					m_pToken->m_Device->verifyPin(tokenRole, &pin);
					m_vecAuthenticatedRoles.push_back(tokenRole);
					m_pToken->m_pSlot->setAuthenticationLost(false);
				}
				else if (m_pToken->getTokenInfo().flags & CKF_PROTECTED_AUTHENTICATION_PATH)
				{
					if ((m_pToken->m_pSlot->isAuthenticationLost() || !m_pToken->m_Device->isAuthenticated(tokenRole)))
					{
						u1Array pin(0);
						m_pToken->m_Device->verifyPin(tokenRole, &pin);
						if (m_pToken->IsPinCacheDisabled(tokenRole))
							m_pToken->m_pSlot->setAuthenticationLost(true);
						else
							m_pToken->m_pSlot->setAuthenticationLost(false);
					}
					else if (m_pToken->IsPinCacheDisabled(tokenRole))
					{
						m_pToken->m_pSlot->setAuthenticationLost(true);
					}
				}
				else if ( m_pToken->IsPinCacheDisabled(tokenRole) )
				{
					u1ArraySecure pin(tokenSecuredPin.GetLength());
					tokenSecuredPin.CopyTo(pin.GetBuffer());
					m_pToken->m_Device->verifyPin(tokenRole, &pin);
					m_vecAuthenticatedRoles.push_back(tokenRole);
					m_pToken->m_pSlot->setAuthenticationLost(false);
				}
		    }
		    catch(MiniDriverException& a_Exception)
		    {
				if ( (a_Exception.getError( ) == SCARD_W_CANCELLED_BY_USER) || (a_Exception.getError( ) == SCARD_E_TIMEOUT) )
				{
					throw PKCS11Exception(CKR_FUNCTION_CANCELED);
				}

				if( (a_Exception.getError( ) == SCARD_W_CARD_NOT_AUTHENTICATED) || (a_Exception.getError( )  == SCARD_W_WRONG_CHV))
			    {
				    // clear PIN
				    tokenSecuredPin.Reset();

					throw PKCS11Exception(CKR_PIN_INCORRECT);
			    }
				else
					throw PKCS11Exception(checkException(a_Exception));

		    }
			catch(PKCS11Exception& )
			{
				throw;
			}
		    catch(...)
			{
				throw PKCS11Exception(CKR_FUNCTION_FAILED);
			}
	    }
        else if (   bIsForWriteOperation
                &&  (tokenRole != MiniDriverAuthentication::PIN_USER)
                &&  !m_pToken->m_Device->isNoPin(MiniDriverAuthentication::PIN_USER)
                &&  (!m_pToken->m_Device->isSSO(MiniDriverAuthentication::PIN_USER) || !m_pToken->m_Device->isAuthenticated(MiniDriverAuthentication::PIN_USER))
                )
        {
			if (authenticateRole(MiniDriverAuthentication::PIN_USER))
			{
				if((specificRole != 0) && !m_pToken->m_Device->isNoPin((MiniDriverAuthentication::ROLES) specificRole))
					authenticateRole((MiniDriverAuthentication::ROLES) specificRole);
			}
        }
        else if (   (specificRole != 0)
                &&  (m_pToken->getUserRole() == MiniDriverAuthentication::PIN_USER)
                &&  (!m_pToken->m_Device->isSSO((MiniDriverAuthentication::ROLES) specificRole) || !m_pToken->m_Device->isAuthenticated((MiniDriverAuthentication::ROLES) specificRole))
                )
        {
			// special case for enrollement on PIN_USER slot using container associated to another role
			// used to signature/decryption
			bool bContinuePinLoop = false;
			bool bIsPinPad = m_pToken->isRoleUsingProtectedAuthenticationPath((MiniDriverAuthentication::ROLES) specificRole);
			do
			{
				CSecureString securedPin = m_pToken->m_Device->getSecuredPin((MiniDriverAuthentication::ROLES) specificRole);

				if (securedPin.IsEmpty())
				{
					if (!bIsPinPad)
					{
						throw PKCS11Exception(CKR_FUNCTION_CANCELED);
					}
				}

				try
				{
					u1ArraySecure pin(securedPin.GetLength());
					securedPin.CopyTo(pin.GetBuffer());
					m_pToken->m_Device->verifyPin((MiniDriverAuthentication::ROLES) specificRole, &pin);

					m_vecAuthenticatedRoles.push_back((MiniDriverAuthentication::ROLES) specificRole);
					bContinuePinLoop = false;
				}
				catch(MiniDriverException& a_Exception)
				{
					if( (a_Exception.getError( ) == SCARD_W_CARD_NOT_AUTHENTICATED) || (a_Exception.getError( )  == SCARD_W_WRONG_CHV))
					{
						m_pToken->m_Device->getSecuredPin((MiniDriverAuthentication::ROLES) specificRole).Reset();
						// if PIN was given from GUI, show error and retry
						throw PKCS11Exception(CKR_PIN_INCORRECT);
					}
					else
					{
						throw PKCS11Exception(checkException(a_Exception));
					}
				}
				catch(...)
				{
					throw PKCS11Exception(CKR_FUNCTION_FAILED);
				}
			}
			while (bContinuePinLoop);
        }
    }
}

bool Token::CAtomicLogin::authenticateRole(MiniDriverAuthentication::ROLES role )
{
	bool bSuccess = false;
	bool bContinuePinLoop = false;
	// bool bIsPinPad = m_pToken->isRoleUsingProtectedAuthenticationPath(role);

	{
		do
		{
			CSecureString securedUserPin = m_pToken->m_Device->getSecuredPin(role);
			if (securedUserPin.IsEmpty())
			{
				throw PKCS11Exception(CKR_FUNCTION_CANCELED);
			}

			try
			{
				if (!securedUserPin.IsEmpty())
				{
					u1ArraySecure pin(securedUserPin.GetLength());
					securedUserPin.CopyTo(pin.GetBuffer());
					m_pToken->m_Device->verifyPin(role, &pin);
					m_vecAuthenticatedRoles.push_back(role); // We don't loggout in case of PinPAD

					if (role == m_pToken->getUserRole())
						m_pToken->m_pSlot->setAuthenticationLost(false);
				}
				bSuccess = true;
				bContinuePinLoop = false;
			}
			catch(MiniDriverException& a_Exception)
			{
				if ( (a_Exception.getError( ) == SCARD_W_CANCELLED_BY_USER) || (a_Exception.getError( ) == SCARD_E_TIMEOUT) )
				{
					throw PKCS11Exception(CKR_FUNCTION_CANCELED);
				}

				if( (a_Exception.getError( ) == SCARD_W_CARD_NOT_AUTHENTICATED) || (a_Exception.getError( )  == SCARD_W_WRONG_CHV))
				{
					// clear PIN from device
					m_pToken->m_Device->getSecuredPin(role).Reset();
					throw PKCS11Exception(CKR_PIN_INCORRECT);
				}
			}
			catch(...)
			{
				throw PKCS11Exception(CKR_FUNCTION_FAILED);
			}
		}
		while (bContinuePinLoop);
	}

	return bSuccess;
}

/*
*/
Token::Token( Slot* a_pSlot, Device* a_pDevice ) {

    Log::begin( "Token::Token" );
    Timer t;
    t.start( );

    m_uiObjectIndex = 0;

    m_bCheckSmartCardContentDone = false;

    m_pSlot = a_pSlot;

    // Initialize a random engine with current time as seed for the generator
    m_RandomNumberGenerator.seed( static_cast< unsigned int >( std::time( 0 ) ) );

    m_bCreateDirectoryP11 = false;

    m_bCreateTokenInfoFile = false;

    m_bWriteTokenInfoFile = false;

    g_stPathPKCS11 = "p11";

    g_stPathTokenInfo = "tinfo";

    g_stPrefixData = "dat"; // Stands for "DATa".
    g_stPrefixKeyPublic = "puk"; // Stands for "PUblic Key".
    g_stPrefixKeyPrivate = "prk"; // Stands for "PRivate Key".
    g_stPrefixKeySecret = "sek"; // Stands for "SEcret Key".
    // Use the default key exchange certificate extension as root certificate extension
    g_stPrefixRootCertificate = szUSER_KEYEXCHANGE_CERT_PREFIX;

    g_stPrefixPublicObject = "pub";  // Stands for "PUBlic".
    g_stPrefixPrivateObject = "pri";  // Stands for "PRIvate".

    m_Device = a_pDevice;

    // Set the seed for the random generator
    u1Array challenge( 8 );
    generateRandom( challenge.GetBuffer( ), 8 );
    Util::SeedRandom( challenge );

    // Set the default role
    m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

    // Check if the PKCS11 directory and the token information file are present
    checkTokenInfo( );

    try {

        // Populate the token info structure
        setTokenInfo( );

        // Populate the pulic and private objects
        m_bSynchronizeObjectsPublic = true;
        synchronizePublicObjects( );

        m_bSynchronizeObjectsPrivate = true;
        synchronizePrivateObjects( );

        initializeObjectIndex( );

    } catch( ... ) {

    }

    t.stop( "Token::Token" );
    Log::end( "Token::Token" );
}


/*
*/
void Token::initializeObjectIndex( void ) {

    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    MiniDriverFiles::FILES_NAME fs( m_Device->enumFiles( g_stPathPKCS11 ) );

    m_uiObjectIndex = m_Device->containerCount( ) + 1;

    unsigned char idx = 0xFF;

    // BOOST_FOREACH( const std::string& s, fs ) {
	for (MiniDriverFiles::FILES_NAME::iterator iter = fs.begin () ; iter != fs.end (); ++iter) {
		std::string& s = (std::string&)*iter;

        if( s.find( g_stPrefixData ) != std::string::npos ) {

            idx = computeIndex( s );

            if( idx > m_uiObjectIndex ) {

                m_uiObjectIndex = idx;
            }
        }
    }

    Log::log( "Token::initializeObjectIndex - Index <%ld>", m_uiObjectIndex );
}


/*
*/
void Token::incrementObjectIndex( void ) {

    if( 0xFF == m_uiObjectIndex ) {

        m_uiObjectIndex = m_Device->containerCount( ) + 1;

    } else {

        ++m_uiObjectIndex;
    }
}


/*
*/
void Token::checkTokenInfo( void ) {

    Log::begin( "Token::checkTokenInfo" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    MiniDriverFiles::FILES_NAME fs;

    try {

        if( m_Device->isV2Plus( ) ) {

            // Check if the P11 directory is present by listing the root directory content
            std::string s( "root" );

            fs = m_Device->enumFiles( s );

            MiniDriverFiles::FILES_NAME::iterator i = fs.find( g_stPathPKCS11 );

            if( fs.end( ) == i ) {

                m_bCreateDirectoryP11 = true;
                m_bCreateTokenInfoFile = true;
                m_bWriteTokenInfoFile = true;
            }

        } else {

            // Check if the P11 directory is present by listing the directory content
            fs = m_Device->enumFiles( g_stPathPKCS11 );
        }

    } catch( MiniDriverException& x ) {

        // The token info file does not exist
        switch( x.getError( ) ) {

            // because the PKCS11 directory is not present
        case SCARD_E_DIR_NOT_FOUND:
            m_bCreateDirectoryP11 = true;
            m_bCreateTokenInfoFile = true;
            m_bWriteTokenInfoFile = true;
            break;

        case SCARD_E_NO_SMARTCARD:
            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );

        default:
            break;
        }
    }

    // Check if the token information file is present
    if( !m_bCreateDirectoryP11 ) {

        try {

            fs = m_Device->enumFiles( g_stPathPKCS11 );

            MiniDriverFiles::FILES_NAME::iterator i = fs.find( g_stPathTokenInfo );

            if( fs.end( ) != i ) {

                try {

                   std::unique_ptr<u1Array> p(m_Device->readFile( g_stPathPKCS11, g_stPathTokenInfo ));

                } catch( MiniDriverException& x ) {

                    // The token info file does not exist
                    switch( x.getError( ) ) {

                        // because the token information file is not present
                    case SCARD_E_FILE_NOT_FOUND:
                        m_bCreateDirectoryP11 = false;
                        m_bCreateTokenInfoFile = true;
                        m_bWriteTokenInfoFile = true;

                    default:
                        break;
                    }
                }

            } else {

                m_bCreateDirectoryP11 = false;
                m_bCreateTokenInfoFile = true;
                m_bWriteTokenInfoFile = true;
            }

        } catch( ... ) { }
    }

    t.stop( "Token::checkTokenInfo" );
    Log::end( "Token::checkTokenInfo" );
}


/* SerializeTokenInfo
*/
void Token::writeTokenInfo( void ) {

    if( !m_bWriteTokenInfoFile ) {

        return;
    }

    Log::begin( "Token::writeTokenInfo" );
    Timer t;
    t.start( );

    std::vector< unsigned char > v;

    // Version
    CK_BBOOL _version = 1;
    Util::PushBBoolInVector( &v, _version );

    // Label
    u1Array l( sizeof( m_TokenInfo.label ) );
    l.SetBuffer( m_TokenInfo.label );
    Util::PushByteArrayInVector( &v, &l );

    size_t z = v.size( );

    u1Array objData( z );

    for( unsigned int i = 0 ; i < z ; ++i ) {

        objData.SetU1At( i, v.at( i ) );
    }

    if( !m_Device ) {

        return;
    }

    try {

        m_Device->writeFile( g_stPathPKCS11, g_stPathTokenInfo, &objData );

    } catch( MiniDriverException& x ) {

        Log::log( "## Error ## Token::SerializeTokenInfo - writeFile failed" );
        throw PKCS11Exception( checkException( x ) );
    }

    m_bWriteTokenInfoFile = false;

    t.stop( "Token::writeTokenInfo" );
    Log::end( "Token::writeTokenInfo" );
}


/* Only read the label
*/
void Token::readTokenInfo( void ) {

    if( m_bCreateTokenInfoFile ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    Log::begin( "Token::readTokenInfo" );
    Timer t;
    t.start( );

    try {

        std::unique_ptr<u1Array> fileData ( m_Device->readFile( g_stPathPKCS11, g_stPathTokenInfo ) );

        std::vector< unsigned char > v;

        unsigned int l = fileData->GetLength( );

        if( !l ) {

            // The file exists but is empty
            m_bWriteTokenInfoFile = true;

            return;
        }

        for( unsigned int u = 0 ; u < l ; ++u ) {

            v.push_back( fileData->GetBuffer( )[ u ] );
        }

        CK_ULONG idx = 0;

        // Format version. Shall be 0 for this version
        /*CK_BBOOL _version =*/ Util::ReadBBoolFromVector( v, &idx );

        // label
        std::unique_ptr< u1Array > label( Util::ReadByteArrayFromVector( v, &idx ) );

        memset( m_TokenInfo.label, ' ', sizeof( m_TokenInfo.label ) );

        memcpy( m_TokenInfo.label, label->GetBuffer( ), label->GetLength( ) );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::readTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::readTokenInfo" );
    Log::end( "Token::readTokenInfo" );
}


/*
*/
void Token::createTokenInfo( void ) {

    Log::begin( "Token::createTokenInfo" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    if( m_bCreateDirectoryP11 ) {

        // Create the P11 directory into the smart card
        try {

            m_Device->createDirectory( std::string( "root" ), g_stPathPKCS11 );

            m_bCreateDirectoryP11 = false;

        } catch( MiniDriverException& x ) {

            Log::error( "Token::createTokenInfo", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }
    }

    if( m_bCreateTokenInfoFile ) {

        // Create the P11 token information file
        try {

            m_Device->createFile( g_stPathPKCS11, g_stPathTokenInfo, false );

            m_bCreateTokenInfoFile = false;

            m_bWriteTokenInfoFile = true;

        } catch( MiniDriverException& x ) {

            Log::error( "Token::createTokenInfo", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }
    }

    t.stop( "Token::createTokenInfo" );
    Log::end( "Token::createTokenInfo" );
}



/*
*/
/*
void Token::initializeTokenInfo( void ) {

    Log::begin( "Token::initializeTokenInfo" );
    Timer t;
    t.start( );

    // flush TokenInfo
    memset( &m_TokenInfo, 0, sizeof( CK_TOKEN_INFO ) );

    // Set serial number
    memset( m_TokenInfo.serialNumber, ' ', sizeof( m_TokenInfo.serialNumber ) );

    // Set the default label
    memset( m_TokenInfo.label, ' ', sizeof( m_TokenInfo.label ) );
    m_TokenInfo.label[0] = 'C';
    m_TokenInfo.label[1] = 'a';
    m_TokenInfo.label[2] = 'r';
    m_TokenInfo.label[3] = 'd';
    m_TokenInfo.label[4] = ' ';
    m_TokenInfo.label[5] = '#';
    memcpy( &m_TokenInfo.label[6], m_TokenInfo.serialNumber, sizeof( m_TokenInfo.serialNumber ) );

    // Set manufacturer id
    memset( m_TokenInfo.manufacturerID, ' ', sizeof( m_TokenInfo.manufacturerID ) );
    m_TokenInfo.manufacturerID[0] = 'G';
    m_TokenInfo.manufacturerID[1] = 'e';
    m_TokenInfo.manufacturerID[2] = 'm';
    m_TokenInfo.manufacturerID[3] = 'a';
    m_TokenInfo.manufacturerID[4] = 'l';
    m_TokenInfo.manufacturerID[5] = 't';
    m_TokenInfo.manufacturerID[6] = 'o';

    // Set model
    memset( m_TokenInfo.model, ' ', sizeof( m_TokenInfo.model ) );
    m_TokenInfo.model[0] = 'I';
    m_TokenInfo.model[1] = 'D';
    m_TokenInfo.model[2] = ' ';
    m_TokenInfo.model[3] = 'P';
    m_TokenInfo.model[4] = 'r';
    m_TokenInfo.model[5] = 'i';
    m_TokenInfo.model[6] = 'm';
    m_TokenInfo.model[7] = 'e';
    m_TokenInfo.model[8] = ' ';

    // Set flags
    m_TokenInfo.flags  =  CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED; // | CKF_RNG

    try {

            if( !m_Device->isPinInitialized( ) ) {

                Log::log( "Token::setTokenInfo - Disable CKF_USER_PIN_INITIALIZED" );
                m_TokenInfo.flags &= ~CKF_USER_PIN_INITIALIZED;
            }

            // Is login required ?
            if(  m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_pSlot->isAuthenticated( ) ) ) {

                m_TokenInfo.flags &= ~CKF_LOGIN_REQUIRED;
                Log::log( "Token::setTokenInfo - No login required" );
            }

            // Check if the CKF_PROTECTED_AUTHENTICATION_PATH flag must be raised
            if( m_Device->isExternalPin( ) || ( ( m_Device->isModePinOnly( ) && m_Device->isVerifyPinSecured( ) ) || m_Device->isModeNotPinOnly( ) ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_PROTECTED_AUTHENTICATION_PATH" );
                m_TokenInfo.flags  |= CKF_PROTECTED_AUTHENTICATION_PATH;
            }
        }

    // Set the sessions information
    m_TokenInfo.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxPinLen = 255;
    m_TokenInfo.ulMinPinLen = 4;

    // Set the memory information
    m_TokenInfo.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

    // Set the version of the Card Operating system
    m_TokenInfo.hardwareVersion.major  = 0;
    m_TokenInfo.hardwareVersion.minor  = 0;

    // Set the version of Card Module application
    m_TokenInfo.firmwareVersion.major  = 0;
    m_TokenInfo.firmwareVersion.minor  = 0;

    t.stop( "Token::setTokenInfo" );
    Log::end( "Token::setTokenInfo" );
}
*/

/*
*/
void Token::setTokenInfo( void )
{
    Log::begin( "Token::setTokenInfo" );
    Timer t;
    t.start( );

    // flush TokenInfo
    memset( &m_TokenInfo, 0, sizeof( CK_TOKEN_INFO ) );

    // Set serial number
    memset( m_TokenInfo.serialNumber, ' ', sizeof( m_TokenInfo.serialNumber ) );

    // If serial number length is too big to fit in 16 (hex) digit field, then use the 8 first bytes of MD5 hash of the original serial number.
    u1Array* sn = NULL;

    try {

        if( m_Device ) {

            sn = (u1Array *) m_Device->getSerialNumber( );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    if( sn ) {

        unsigned int l = sn->GetLength( );

        unsigned char* p = (unsigned char*) sn->GetBuffer( );

        if( l > 8 ) {

            CDigest* md5 = CDigest::getInstance(CDigest::MD5);
            CK_BYTE hash[ 16 ];
            md5->hashUpdate( p, 0, l );
            md5->hashFinal( hash );
            delete md5;
            Util::ConvAscii( hash, 8, m_TokenInfo.serialNumber );

        } else {

            Util::ConvAscii( p, l, m_TokenInfo.serialNumber );
        }
    } else {

        CK_CHAR emptySerialNumber[ ] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };

        memcpy( m_TokenInfo.serialNumber, emptySerialNumber, sizeof( emptySerialNumber ) );
    }

    // Set the default label
    memset( m_TokenInfo.label, ' ', sizeof( m_TokenInfo.label ) );
    m_TokenInfo.label[0] = 'C';
    m_TokenInfo.label[1] = 'a';
    m_TokenInfo.label[2] = 'r';
    m_TokenInfo.label[3] = 'd';
    m_TokenInfo.label[4] = ' ';
    m_TokenInfo.label[5] = '#';
    memcpy( &m_TokenInfo.label[6], m_TokenInfo.serialNumber, sizeof( m_TokenInfo.serialNumber ) );

    MiniDriverAuthentication::ROLES userRole = getUserRole();
    if (MiniDriverAuthentication::PIN_USER != userRole)
    {
        // Add PIN type to the label of the virtual slot
        std::string roleDesc = MiniDriverAuthentication::getRoleDescription(userRole);
        m_TokenInfo.label[23] = '(';
        memcpy(&m_TokenInfo.label[24], roleDesc.c_str(), min((int) roleDesc.length(), 6));
        m_TokenInfo.label[24 + min((int) roleDesc.length(), 6)] = ')';
    }

    // Try to read the token information from the smart card (only read the label)
    try {

        readTokenInfo( );

    } catch( MiniDriverException& ) {

        m_bCreateTokenInfoFile = true;
        m_bWriteTokenInfoFile = true;
    }

    // Set manufacturer id
    memset( m_TokenInfo.manufacturerID, ' ', sizeof( m_TokenInfo.manufacturerID ) );
    m_TokenInfo.manufacturerID[0] = 'G';
    m_TokenInfo.manufacturerID[1] = 'e';
    m_TokenInfo.manufacturerID[2] = 'm';
    m_TokenInfo.manufacturerID[3] = 'a';
    m_TokenInfo.manufacturerID[4] = 'l';
    m_TokenInfo.manufacturerID[5] = 't';
    m_TokenInfo.manufacturerID[6] = 'o';

    // Set model
    memset( m_TokenInfo.model, ' ', sizeof( m_TokenInfo.model ) );
    m_TokenInfo.model[0] = 'I';
    m_TokenInfo.model[1] = 'D';
    m_TokenInfo.model[2] = ' ';
    m_TokenInfo.model[3] = 'P';
    m_TokenInfo.model[4] = 'r';
    m_TokenInfo.model[5] = 'i';
    m_TokenInfo.model[6] = 'm';
    m_TokenInfo.model[7] = 'e';
    m_TokenInfo.model[8] = ' ';

    // Set flags
    m_TokenInfo.flags  = /*CKF_RNG |*/ CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED /*| CKF_USER_PIN_INITIALIZED*/;
    MiniDriverAuthentication::ROLES role = getUserRole();

    try {

        if( m_Device && m_pSlot ) {

            if (Log::s_bEnableLog)
            {
                Log::log( "Token::Token - No Pin <%d>", m_Device->isNoPin( role ) );
                Log::log( "Token::Token - SSO <%d>", m_Device->isSSO( role ) );
                Log::log( "Token::Token - External <%d>", m_Device->isExternalPin( role ) );
                Log::log( "Token::Token - isAuthenticated <%d>", m_pSlot->isAuthenticated( ) );
                Log::log( "Token::Token - isReadOnly <%d>", m_Device->isReadOnly( ) );
                Log::log( "Token::Token - isPinInitialized <%d>", m_Device->isPinInitialized( getUserRole()) );
                Log::log( "Token::Token - isVerifyPinSecured <%d>", m_Device->isVerifyPinSecured( ) );
				Log::log( "Token::Token - isDotNetCard <%d>", m_Device->isDotNetCard( ) );
            }

			// update the module of the card in token info
			if (m_Device->isDotNetCard())
			{
				m_TokenInfo.model[ 9] = '.';
				m_TokenInfo.model[10] = 'N';
				m_TokenInfo.model[11] = 'E';
				m_TokenInfo.model[12] = 'T';
			}
			else
			{
				m_TokenInfo.model[ 9] = 'M';
				m_TokenInfo.model[10] = 'D';
			}

			// Set RNG flag to MD cards
			if (!m_Device->isDotNetCard())
				m_TokenInfo.flags  |= CKF_RNG;

            if( m_Device->isReadOnly( ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_WRITE_PROTECTED" );
                m_TokenInfo.flags |= CKF_WRITE_PROTECTED;
            }

            if( m_Device->isPinInitialized( role ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_USER_PIN_INITIALIZED" );
                m_TokenInfo.flags |= CKF_USER_PIN_INITIALIZED;
            }

            // Is login required ?
            if(  m_Device->isNoPin( role ) || ( m_Device->isSSO( role ) && m_pSlot->isAuthenticated( ) ) ) {

                m_TokenInfo.flags &= ~CKF_LOGIN_REQUIRED;
                Log::log( "Token::setTokenInfo - No login required" );
            }

            // Check if the CKF_PROTECTED_AUTHENTICATION_PATH flag must be raised
            if ( isRoleUsingProtectedAuthenticationPath( role ) )
            {
                Log::log( "Token::setTokenInfo - Enable CKF_PROTECTED_AUTHENTICATION_PATH" );
                m_TokenInfo.flags  |= CKF_PROTECTED_AUTHENTICATION_PATH;
            }

            updatePinFlags();
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    // Set the sessions information
    m_TokenInfo.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxPinLen = 255;
    m_TokenInfo.ulMinPinLen = 4;
    try {
        if( m_Device ) {

            if ( !m_Device->isNoPin( role ))
            {
                m_TokenInfo.ulMaxPinLen = m_Device->getPinMaxPinLength( role );
                m_TokenInfo.ulMinPinLen = m_Device->getPinMinPinLength( role );
            }
            else
            {
                m_TokenInfo.ulMaxPinLen = CK_UNAVAILABLE_INFORMATION;
                m_TokenInfo.ulMinPinLen = CK_UNAVAILABLE_INFORMATION;
            }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    // Set the memory information
    m_TokenInfo.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

    // Set the version of the Card Operating system
    m_TokenInfo.hardwareVersion.major  = 0;
    m_TokenInfo.hardwareVersion.minor  = 0;

    // Set the version of Card Module application
    m_TokenInfo.firmwareVersion.major  = 0;
    m_TokenInfo.firmwareVersion.minor  = 0;

    t.stop( "Token::setTokenInfo" );
    Log::end( "Token::setTokenInfo" );
}


/*
*/
void Token::authenticateUser( u1Array* a_pPin ) {

    Log::begin( "Token::authenticateUser" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Device->verifyPin( getUserRole(), a_pPin );

        m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
        m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
        m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

        m_RoleLogged = CKU_USER;

    } catch( MiniDriverException& x ) {

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

        checkAuthenticationStatus( CKU_USER, x );
    }

    t.stop( "Token::authenticateUser" );
    Log::end( "Token::authenticateUser" );
}


/*
*/
void Token::updatePinFlags()
{
    if (m_Device)
    {
        int userTriesRemaining, soTriesRemaining;

        try {

            if (m_TokenInfo.flags & CKF_LOGIN_REQUIRED)
            {
                userTriesRemaining = m_Device->getTriesRemaining( getUserRole() );
                // Update the token information structure
                if( 0 == userTriesRemaining ) {

                    // PIN is blocked
                    m_TokenInfo.flags |= CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
                } else if( 1 == userTriesRemaining ) {

                    // Last retry
                    m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags |= CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
                }
            }

            MiniDriverAuthentication::ROLES unblockRole = m_Device->getPinUnblockRole(getUserRole());
            if ( unblockRole == MiniDriverAuthentication::PIN_ADMIN)
                soTriesRemaining = m_Device->administratorGetTriesRemaining( );
            else
                soTriesRemaining = m_Device->getTriesRemaining( unblockRole );
            if( 0 == soTriesRemaining ) {

                // Admin key/PUK is blocked
                m_TokenInfo.flags |= CKF_SO_PIN_LOCKED;
                m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
                m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
            } else if( 1 == soTriesRemaining ) {
                // Last retry
                m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
                m_TokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
                m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
            }
        } catch( MiniDriverException& ) {

            Log::error( "Token::updatePinFlags", "MiniDriverException" );
        }

    }
}

/*
*/
void Token::checkAuthenticationStatus( CK_ULONG a_ulRole, MiniDriverException& a_Exception ) {

    switch( a_Exception.getError( ) ) {

    case SCARD_W_CARD_NOT_AUTHENTICATED:
    case SCARD_W_WRONG_CHV:
        {
            // Authentication failed due to an incorrect PIN
            int triesRemaining = 0;

            try {

                triesRemaining = ( ( CKU_USER == a_ulRole ) ? m_Device->getTriesRemaining( getUserRole() ) : m_Device->administratorGetTriesRemaining( ) );

            } catch( MiniDriverException& x ) {

                Log::error( "Token::checkAuthenticationStatus", "MiniDriverException" );
                throw PKCS11Exception( checkException( x ) );
            }

            // Update the token information structure
            if( 0 == triesRemaining ) {

                // PIN / Admin key is blocked
                if( CKU_USER == a_ulRole ) {

                    m_TokenInfo.flags |= CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

                } else {

                    m_TokenInfo.flags |= CKF_SO_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
                }

                throw PKCS11Exception( CKR_PIN_LOCKED );

            } else if( 1 == triesRemaining ) {

                // Last retry
                if( CKU_USER == a_ulRole ) {

                    m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags |= CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

                } else {

                    m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
                    m_TokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
                }
            } else { //if(triesRemaining < MAX_USER_PIN_TRIES)

                if( CKU_USER == a_ulRole ) {

                    m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags |= CKF_USER_PIN_COUNT_LOW;

                } else {

                    m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
                    m_TokenInfo.flags |= CKF_SO_PIN_COUNT_LOW;
                }
            }

            throw PKCS11Exception ( CKR_PIN_INCORRECT );
        }
        break;

    case SCARD_W_CANCELLED_BY_USER:
    case SCARD_E_TIMEOUT:
        throw PKCS11Exception( CKR_FUNCTION_CANCELED );

    default:
        throw PKCS11Exception( checkException( a_Exception ) );
    }

}


/*
*/
void Token::authenticateAdmin( u1Array* a_pPin ) {

    Log::begin( "Token::authenticateAdmin" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Device->administratorLogin( a_pPin );

        m_RoleLogged = CKU_SO;

    } catch( MiniDriverException& x ) {

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

        checkAuthenticationStatus( CKU_SO, x );
    }

    t.stop( "Token::authenticateAdmin" );
    Log::end( "Token::authenticateAdmin" );
}


/*
*/
void Token::logout( void ) {

    Log::begin( "Token::logout" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        Log::log( "Token::logout - Token not present" );
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

    try {

        if( m_pSlot->isAuthenticated( ) ) {
            m_Device->logOut( getUserRole() , true);

        } else if( m_pSlot->administratorIsAuthenticated( ) ) {

            m_Device->administratorLogout( );

        } else {

            Log::log( "Token::logout - user not logged in" );
            throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::logout" );
    Log::end( "Token::logout" );
}


/*
*/
void Token::login( const CK_ULONG& a_ulUserType, u1Array* a_pPin ) {

    Log::begin( "Token::login" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        if( CKU_USER == a_ulUserType ) {

            if( ( m_TokenInfo.flags & CKF_USER_PIN_INITIALIZED ) != CKF_USER_PIN_INITIALIZED ) {

                throw PKCS11Exception( CKR_USER_PIN_NOT_INITIALIZED );
            }

            if( m_pSlot->administratorIsAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ANOTHER_ALREADY_LOGGED_IN );
            }

            if (m_Device->isPinExpired(getUserRole()))
            {
               m_TokenInfo.flags &= ~CKF_USER_PIN_INITIALIZED;
               throw PKCS11Exception( CKR_USER_PIN_NOT_INITIALIZED );
            }

            if( m_pSlot->isAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ALREADY_LOGGED_IN );
            }

            if( !m_pSlot->isAuthenticated( ) ) {

                authenticateUser( a_pPin );
                m_pSlot->setUserType( a_ulUserType );
            }

        } else if( CKU_SO == a_ulUserType ) {

            if( m_pSlot->administratorIsAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ALREADY_LOGGED_IN );
            }

            if( m_pSlot->isAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ANOTHER_ALREADY_LOGGED_IN );
            }

            if( !m_pSlot->administratorIsAuthenticated( ) ) {
				MiniDriverAuthentication::ROLES unblockRole = m_Device->getPinUnblockRole(getUserRole());
				if ( unblockRole == MiniDriverAuthentication::PIN_ADMIN)
                authenticateAdmin( a_pPin );
				else
					m_Device->verifyPin( unblockRole,a_pPin);

                m_pSlot->setUserType( a_ulUserType );
            }

        } else {

            throw PKCS11Exception( CKR_USER_TYPE_INVALID );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::login", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    try {

        // The smart card is checked to avoid to have empty containers with certificates
        if( checkSmartCardContent( ) ) {

            m_ObjectsToCreate.clear( );

            synchronizeObjects( );
        }

        // BOOST_FOREACH( StorageObject* p, m_ObjectsToCreate ) {
		for (std::vector<StorageObject*>::iterator iter = m_ObjectsToCreate.begin () ; iter != m_ObjectsToCreate.end (); ++iter) {
			StorageObject* p = (StorageObject*)*iter;

            Log::log( "Token::login - *** CREATE LATER *** <%s>", p->m_stFileName.c_str( ) );

            try {

                writeObject( p );

            } catch( ... ) {

            }
        }

        m_ObjectsToCreate.clear( );

        // After a successfull login, the cache has to be updated to get all private objects
        synchronizePrivateObjects( );
        //}

    } catch( ... ) {

    }

    if( Log::s_bEnableLog ) {

        Log::log(" Token::login - <<<<< P11 OBJ LIST >>>>>");
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) { printObject( o.second ); }
        Log::log(" Token::login - <<<<< P11 OBJ LIST >>>>>");
    }

    if (a_pPin && (a_pPin->GetLength() != 0))
	{
		if (CKU_USER == a_ulUserType)
			m_Device->logOut( getUserRole() , false);
		if (CKU_SO == a_ulUserType)
		{
			MiniDriverAuthentication::ROLES unblockRole = m_Device->getPinUnblockRole(getUserRole());
			if ( unblockRole != MiniDriverAuthentication::PIN_ADMIN)
				m_Device->logOut( unblockRole , false);
		}
	}

    t.stop( "Token::login" );
    Log::end( "Token::login" );
}


/*
*/
void Token::generateRandom( CK_BYTE_PTR a_pRandomData, const CK_ULONG& a_ulLen ) {

    Log::begin( "Token::generateRandom" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Initialize the PIN
        m_Device->GetRandom((unsigned char*) a_pRandomData, (unsigned int) a_ulLen);

    } catch( ... ) {

		 // fallback to software random

    // Initialize the range from the 0 to 255 for the generator
    boost::uniform_smallint< > range( 0, 255 );

    // initialize the generator
    boost::variate_generator< boost::mt19937&, boost::uniform_smallint< > > generator( m_RandomNumberGenerator, range );

    // Generate the random buffer
    for( CK_ULONG i = 0 ; i < a_ulLen ; ++i ) {

        a_pRandomData[ i ] = (CK_BYTE)generator( );
    }
    }

    t.stop( "Token::generateRandom" );
    Log::end( "Token::generateRandom" );
}


/*
*/
void Token::findObjects( Session* a_pSession, CK_OBJECT_HANDLE_PTR a_phObject, const CK_ULONG& a_ulMaxObjectCount, CK_ULONG_PTR a_pulObjectCount ) {

    //Log::begin( "Token::findObjects" );
    //Timer t;

    //t.start( );

    bool bUserAuthenticated = false;

    if( m_pSlot ) {

        bUserAuthenticated = m_pSlot->isAuthenticated( );

    }

    // For each P11 object
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

        // Check if the search has reached the allowed maximum of objects to search
        if( *a_pulObjectCount >= a_ulMaxObjectCount ) {

            break;
        }

        // Check if this object has been already compared to the search template
        if( a_pSession->m_TokenObjectsReturnedInSearch.end( ) != a_pSession->m_TokenObjectsReturnedInSearch.find( o->first ) ) {

            // This object has already been analysed by a previous call of findObjects for this template
            continue;
        }

        // If the object is private and the user is not logged in
        if( ( !bUserAuthenticated ) && o->second->isPrivate( ) )
        {
            // Then avoid this element.
            // Do not add it the list of already explored objects (may be a C_Login can occur)
            continue;
        }

        // Add the object to the list of the objects compared to the search template
        a_pSession->m_TokenObjectsReturnedInSearch.insert( o->first );

        // If the template is NULL then return all objects
        if( !a_pSession->_searchTempl ) {

            a_phObject[ *a_pulObjectCount ] = o->first;

            ++(*a_pulObjectCount);

        } else {
            // The template is not NULL.

            bool match = true;

            // In this case the template attributes have to be compared to the objects ones.
            BOOST_FOREACH( CK_ATTRIBUTE& t, a_pSession->_searchTempl->getAttributes( ) ) {

                if( ! o->second->compare( t ) ) {

                    match = false;

                    break;
                }
            }

            // The attributes match
            if( match ) {

                // Add the object handle to the outgoing list
                a_phObject[ *a_pulObjectCount ] = o->first;

                // Increment the number of found objects
                ++(*a_pulObjectCount);
            }
        }
    }

    //t.stop( "Token::findObjects" );
    //Log::end( "Token::findObjects" );
}


/*
*/
void Token::computeObjectFileName( StorageObject* a_pObject, std::string& a_stFileName ) {

    Log::begin( "Token::computeObjectFileName" );
    Timer t;
    t.start( );

    // Add the public or private prefix
    std::string stName /*a_stFileName*/ = "";//( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    switch( a_pObject->getClass ( ) ) {

    case CKO_DATA:
        computeObjectNameData( /*a_stFileName*/stName, a_pObject );
        break;

    case CKO_PUBLIC_KEY:
        computeObjectNamePublicKey( /*a_stFileName*/stName, a_pObject );
        break;

    case CKO_PRIVATE_KEY:
        computeObjectNamePrivateKey( /*a_stFileName*/stName, a_pObject );
        break;

    case CKO_CERTIFICATE:
        computeObjectNameCertificate( /*a_stFileName*/stName, a_pObject );
        break;

    default:
        throw PKCS11Exception( CKR_FUNCTION_FAILED );
    }

    a_stFileName = stName;

    Log::log( "Token::computeObjectFileName - Name <%s>", a_stFileName.c_str( ) );
    t.stop( "Token::computeObjectFileName" );
    Log::end( "Token::computeObjectFileName" );
}


/*
*/
void Token::computeObjectNameData( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

    // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    // Add the prefix
    a_stFileName.append( g_stPrefixData );

    MiniDriverFiles::FILES_NAME filesPKCS11;

    if( !m_bCreateDirectoryP11 ) {

        filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );
    }

    bool bGoodNameFound = false;

    std::string s;

    do {

        s = a_stFileName;

        incrementObjectIndex( );

        // Add the index of the data object
        Util::toStringHex( m_uiObjectIndex, s );

        if( isObjectNameValid( s, filesPKCS11 ) ) {

            bGoodNameFound = true;

            a_stFileName = s;
        }

    } while( !bGoodNameFound );
}


/*
*/
bool Token::isObjectNameValid( const std::string& a_stFileName, const MiniDriverFiles::FILES_NAME& a_filesList ) {

    bool bReturn = true;

    // BOOST_FOREACH( const std::string& s, a_filesList ) {
	for (MiniDriverFiles::FILES_NAME::iterator iter = a_filesList.begin () ; iter != a_filesList.end (); ++iter) {
		std::string& s = (std::string&)*iter;

        if( s.compare( a_stFileName ) == 0 ) {
            bReturn = false;
            break;
        }
    }

    return bReturn;
}


/*
*/
void Token::computeObjectNamePublicKey( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

    // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    // Add the prefix
    a_stFileName.append( g_stPrefixKeyPublic );

    unsigned char ucContainerIndex = ( (Pkcs11ObjectKeyPublicRSA*) a_pObject )->m_ucContainerIndex;

    MiniDriverFiles::FILES_NAME filesPKCS11;

    if( !m_bCreateDirectoryP11 ) {

        filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );
    }

    bool bGoodNameFound = false;

    std::string s;

    // The container index excists the file name must have the same name
    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID != ucContainerIndex ) {

        Util::toStringHex( ucContainerIndex, a_stFileName );

    } else {

        unsigned int uiStartIndex = m_Device->containerCount( );

        // In the case of the public is created before te private key, there is no container index available
        do {

            s = a_stFileName;

            incrementObjectIndex( );

            // Add the index of the data object
            Util::toStringHex( uiStartIndex + m_uiObjectIndex, s );

            if( isObjectNameValid( s, filesPKCS11 ) ) {

                bGoodNameFound = true;

                a_stFileName = s;
            }

        } while( !bGoodNameFound );
    }
}


/*
*/
void Token::computeObjectNamePrivateKey( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

        // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    // Add the key suffix
    a_stFileName.append( g_stPrefixKeyPrivate );

    unsigned char ucContainerIndex = ( (RSAPrivateKeyObject*) a_pObject )->m_ucContainerIndex;

    // Add the index of MiniDriver key container associated to this PKCS11 key object
    Util::toStringHex( ucContainerIndex, a_stFileName );
}


/*
*/
void Token::computeObjectNameCertificate( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

    // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    a_stFileName.append( ((CertificateObject*) a_pObject)->m_stCertificateName );
}


/* WriteObject
*/
void Token::writeObject( StorageObject* a_pObject ) {

    Log::begin( "Token::writeObject" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Compute this attribute for backward compatibility with odl version of P11 library
    a_pObject->_uniqueId = Util::MakeUniqueId( );

    // Build the content of the file
    std::vector< unsigned char > to;
    a_pObject->serialize( &to );

    u1Array o(to.size());
    o.SetBuffer(&to[0]);

    try {

        if( m_pSlot->isAuthenticated( ) ) {

            if( m_bCreateDirectoryP11 ) {

                m_Device->createDirectory( std::string( "root" ), g_stPathPKCS11 );
            }

            try {

                // If the user is authenticated then create the file on card
                m_Device->createFile( g_stPathPKCS11, a_pObject->m_stFileName, a_pObject->isPrivate( )  && (CKO_PRIVATE_KEY != a_pObject->getClass()) );

            } catch( MiniDriverException& e ) {

                // The file may be already created. In this case the file must only be written.
                // It could be the case for the public key which is created
                // but not deleted by the application (for example Firefox)
                if( SCARD_E_WRITE_TOO_MANY != e.getError( ) ) {

                    // Otherwise the error must be thrown
                    throw;
                }
            }

            if ( ( CKO_DATA == a_pObject->getClass( ) ) && a_pObject->isPrivate( ) ) {

                m_Device->cacheDisable( a_pObject->m_stFileName );
            }

			try
			{
				m_Device->writeFile( g_stPathPKCS11, a_pObject->m_stFileName, &o );
			}
			catch(MiniDriverException& x)
			{
				Log::log( "Token::writeObject - exception occured while writing <%s>. Deleting it.", a_pObject->m_stFileName.c_str( ) );
				m_Device->deleteFile(g_stPathPKCS11, a_pObject->m_stFileName);
				throw x;
			}

            Log::log( "Token::writeObject - Create & write <%s>", a_pObject->m_stFileName.c_str( ) );

        } else {

            Log::log( "Token::writeObject - *** CREATE LATER *** <%s>", a_pObject->m_stFileName.c_str( ) );

            // If the user is not authenticated then store the object to create it later
            m_ObjectsToCreate.push_back( a_pObject );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::writeObject", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::writeObject" );
    Log::end( "Token::writeObject" );
}


/* Create an object required by the PKCS11 API (C_CreateObject
*/
void Token::addObject( StorageObject* a_pObject, CK_OBJECT_HANDLE_PTR a_pHandle, const bool& a_bRegisterObject ) {

    Log::begin( "Token::addObject" );
    Timer t;
    t.start( );

    *a_pHandle = CK_UNAVAILABLE_INFORMATION;

    try {

        // Build the name of the file
        computeObjectFileName( a_pObject, a_pObject->m_stFileName );

        // Write the file into the smart card
        writeObject( a_pObject );

        // Add the object into the list of managed objects
        if( a_bRegisterObject ) {

            *a_pHandle = registerStorageObject( a_pObject , false); // don't check existence since we have just created a new filename for it and thus it is unique
        }

    } catch( MiniDriverException &x ) {

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::addObject" );
    Log::end( "Token::addObject" );
}


/* AddPrivateKeyObject
*/
void Token::addObjectPrivateKey( PrivateKeyObject* a_pObject, CK_OBJECT_HANDLE_PTR a_phObject ) {

    Log::begin( "Token::addObjectPrivateKey" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
    else if (m_Device->isReadOnly())
    {
        throw PKCS11Exception( CKR_TOKEN_WRITE_PROTECTED );
    }

    // No private key for public object
    if( !a_pObject->isPrivate( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    u1Array* pPublicKeyValue = NULL;
    if (a_pObject->_keyType == CKK_RSA)
	{
		RSAPrivateKeyObject* pRsaPrvKey = (RSAPrivateKeyObject*) a_pObject;
        pPublicKeyValue = pRsaPrvKey->m_pModulus.get();
		if (	pRsaPrvKey->m_pPublicExponent.get()
			&&  !Util::compareArraysAsBigIntegers(pRsaPrvKey->m_pPublicExponent.get(), (const unsigned char*) "\x01\x00\x01", 3)
		   )
		{
			throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
		}
	}
    else
    {
        ((ECCPrivateKeyObject*) a_pObject)->computePublicPoint();
        pPublicKeyValue = ((ECCPrivateKeyObject*) a_pObject)->m_pPublicPoint.get();
    }

    // Public key modulus is mandatory
    if( !pPublicKeyValue) {

        throw PKCS11Exception( CKR_TEMPLATE_INCOMPLETE );
    }

    if (a_pObject->_keyType == CKK_RSA)
    {
        RSAPrivateKeyObject* rsaKey = (RSAPrivateKeyObject*) a_pObject;
        // Check the modulus length
        unsigned int uiModulusLength = rsaKey->m_pModulus->GetLength( );
		int minRsa = 1024, maxRsa = 2048, minRsaGen = 0, maxRsaGen = 0;
		m_Device->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, getUserRole());

        if( ( ( uiModulusLength * 8 ) < (unsigned int) minRsa ) || ( (uiModulusLength * 8 ) > (unsigned int) maxRsa ) ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        // Get the middle size
        unsigned int uiKeyHalfSize = uiModulusLength / 2;

        // Check the Prime P (PKCS11 prime 1 attribute) size
        unsigned int uiPrimePLength = rsaKey->m_pPrime1->GetLength( );

        if( uiPrimePLength > uiKeyHalfSize ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( uiPrimePLength < uiKeyHalfSize ) {

            // Pad with zeros in the front since big endian
            u1Array* val = new u1Array( uiKeyHalfSize );

            memset( val->GetBuffer( ), 0, uiKeyHalfSize );

            size_t i = uiKeyHalfSize - uiPrimePLength;

            memcpy( val->GetBuffer( ) + i, rsaKey->m_pPrime1->GetBuffer( ), uiPrimePLength );

            rsaKey->m_pPrime1.reset( val );

            uiPrimePLength = uiKeyHalfSize;
        }

        // Check the Prime Q (PKCS11 prime 2 attribute) size
        unsigned int uiPrimeQLength = rsaKey->m_pPrime2->GetLength( );

        if( uiPrimeQLength > uiKeyHalfSize ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( uiPrimeQLength < uiKeyHalfSize ) {

            // Pad with zeros in the front since big endian
            u1Array* val = new u1Array( uiKeyHalfSize );

            memset( val->GetBuffer( ), 0, uiKeyHalfSize );

            size_t i = uiKeyHalfSize - uiPrimeQLength;

            memcpy( val->GetBuffer( ) + i, rsaKey->m_pPrime2->GetBuffer( ), uiPrimeQLength );

            rsaKey->m_pPrime2.reset( val );

            uiPrimeQLength = uiKeyHalfSize;
        }

        // Check the Inverse Q (PKCS11 coefficient attribute) size
        unsigned int uiInverseQLength = rsaKey->m_pCoefficient->GetLength( );

        if( uiInverseQLength > uiKeyHalfSize ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( uiInverseQLength < uiKeyHalfSize ) {

            // Pad with zeros in the front since big endian
            u1Array* val = new u1Array( uiKeyHalfSize );

            memset( val->GetBuffer( ), 0, uiKeyHalfSize );

            size_t i = uiKeyHalfSize - uiInverseQLength;

            memcpy( val->GetBuffer( ) + i, rsaKey->m_pCoefficient->GetBuffer( ), uiInverseQLength );

            rsaKey->m_pCoefficient.reset( val );

            uiInverseQLength = uiKeyHalfSize;
        }

        // Check the DP Length (PKCS11 CKA_EXPONENT_1 attribute) size
        unsigned int uiDPLength = rsaKey->m_pExponent1->GetLength( );

        if( uiDPLength > uiKeyHalfSize ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( uiDPLength < uiKeyHalfSize ) {

            // Pad with zeros in the front since big endian
            u1Array* val = new u1Array( uiKeyHalfSize );

            memset( val->GetBuffer( ), 0, uiKeyHalfSize );

            size_t i = uiKeyHalfSize - uiDPLength;

            memcpy( val->GetBuffer( ) + i, rsaKey->m_pExponent1->GetBuffer( ), uiDPLength );

            rsaKey->m_pExponent1.reset( val );

            uiDPLength = uiKeyHalfSize;
        }

        // Check the DQ Length (PKCS11 CKA_EXPONENT_2 attribute) size
        unsigned int uiDQLength = rsaKey->m_pExponent2->GetLength( );

        if( uiDQLength > uiKeyHalfSize ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( uiDQLength < uiKeyHalfSize ) {

            // Pad with zeros in the front since big endian
            u1Array* val = new u1Array( uiKeyHalfSize );

            memset( val->GetBuffer( ), 0, uiKeyHalfSize );

            size_t i = uiKeyHalfSize - uiDQLength;

            memcpy( val->GetBuffer( ) + i, rsaKey->m_pExponent2->GetBuffer( ), uiDQLength );

            rsaKey->m_pExponent2.reset( val );

            uiDQLength = uiKeyHalfSize;
        }

        // Check the Private Exponent Length (PKCS11 CKA_PRIVATE_EXPONENT attribute) size
        unsigned int uiPrivateExponentLength = rsaKey->m_pPrivateExponent->GetLength( );

        if( uiPrivateExponentLength > uiModulusLength ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        if( uiPrivateExponentLength < uiModulusLength ) {

            // Pad with zeros in the front since big endian
            u1Array* val = new u1Array( uiModulusLength );

            memset( val->GetBuffer( ), 0, uiPrivateExponentLength );

            size_t i = uiModulusLength - uiPrivateExponentLength;

            memcpy( val->GetBuffer( ) + i, rsaKey->m_pPrivateExponent->GetBuffer( ), uiPrivateExponentLength );

            rsaKey->m_pPrivateExponent.reset( val );

            uiPrivateExponentLength = uiModulusLength;
        }

        // Check the public exponent size
        unsigned int uiPublicExponentLength = rsaKey->m_pPublicExponent->GetLength( );

        if( ( uiPublicExponentLength < 1 ) || ( uiPublicExponentLength > 4 ) ) {

            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        // Check the public key exponent size
        u1Array* pPublicExponent = rsaKey->m_pPublicExponent.get( );

        if( uiPublicExponentLength < 4 ) {

            // Pad with zeros in the front since big endian
            pPublicExponent = new u1Array( 4 );

            memset( pPublicExponent->GetBuffer( ), 0, 4 );

            size_t i = 4 - uiPublicExponentLength;

            memcpy( pPublicExponent->GetBuffer( ) + i, rsaKey->m_pPublicExponent->GetBuffer( ), uiPublicExponentLength );

            uiPublicExponentLength = 4;
        }

        //if( uiPublicExponentLength < 4 ) {

        //    // Pad with zeros in the front since big endian
        //    u1Array* exp = new u1Array( 4 );

        //    memset( exp->GetBuffer( ), 0, 4 );

        //    size_t i = 4 - uiPublicExponentLength;

        //    memcpy( exp->GetBuffer( ) + i, rsaKey->m_pPublicExponent->GetBuffer( ), uiPublicExponentLength );

        //    rsaKey->m_pPublicExponent.reset( exp );

        //    uiPublicExponentLength = 4;
        //}

        // compute the total length;
        unsigned int uiKeyLength = uiPrimePLength + uiPrimeQLength + uiInverseQLength + uiDPLength + uiDQLength + uiPrivateExponentLength + uiModulusLength + 4;

        // Prepare the keyValue
        u1Array keyValue( uiKeyLength );

        unsigned char* p = keyValue.GetBuffer( );

        memset( p, 0, uiKeyLength );

        // Add the Prime P
        memcpy( p, rsaKey->m_pPrime1->GetBuffer( ), uiPrimePLength );

        int offset = uiPrimePLength;

        // Add the the Prime Q
        memcpy( p + offset, rsaKey->m_pPrime2->GetBuffer( ), uiPrimeQLength );

        offset += uiPrimeQLength;

        // Add the inverse Q
        memcpy( p + offset, rsaKey->m_pCoefficient->GetBuffer( ), uiInverseQLength );

        offset += uiInverseQLength;

        // Add the DP
        memcpy( p + offset, rsaKey->m_pExponent1->GetBuffer( ), uiDPLength );

        offset += uiDPLength;

        // Add the DQ
        memcpy( p + offset, rsaKey->m_pExponent2->GetBuffer( ), uiDQLength );

        offset += uiDQLength;

        // Addt he private exponent D
        memcpy( p + offset, rsaKey->m_pPrivateExponent->GetBuffer( ), uiPrivateExponentLength );

        offset += uiPrivateExponentLength;

        // Add the modulus
        memcpy( p + offset, rsaKey->m_pModulus->GetBuffer( ), uiModulusLength );

        offset += uiModulusLength;

        // Add the public exponent
        //memcpy( p + offset, rsaKey->m_pPublicExponent->GetBuffer( ), uiPublicExponentLength );
        memcpy( p + offset, pPublicExponent->GetBuffer( ), uiPublicExponentLength );

        // Specify what is able to do the key (sign only or sign & decrypt)
        rsaKey->m_ucKeySpec = (unsigned char)( rsaKey->_decrypt ? MiniDriverContainer::KEYSPEC_EXCHANGE : MiniDriverContainer::KEYSPEC_SIGNATURE );

        // Create the on card key container
        // This method checks if a certificate with the same public key exists.
        // In this case this new key must be imported into the key container already associated with this certificate and the key spec is also updated
        rsaKey->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

        try {

            m_Device->containerCreate( getUserRole(), rsaKey->m_ucContainerIndex, true, rsaKey->m_ucKeySpec, pPublicKeyValue, ( uiModulusLength * 8 ), &keyValue );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::addObjectPrivateKey", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }
    }
    else
    {
        ECCPrivateKeyObject* eccKey = (ECCPrivateKeyObject*) a_pObject;
        boost::shared_ptr< u1Array > params = eccKey->m_pParams;
        int keyBitSize = 0;
        unsigned char ucKeySpec;
        CK_BBOOL bIsExchangeKey = (eccKey->_decrypt || eccKey->_derive)? TRUE : FALSE;

        if (Util::compareU1Arrays(params.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
        {
            keyBitSize = 256;
            ucKeySpec = (bIsExchangeKey)? MiniDriverContainer::KEYSPEC_ECDHE_256 : MiniDriverContainer::KEYSPEC_ECDSA_256;
        }
        else if (Util::compareU1Arrays(params.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
        {
            keyBitSize = 384;
            ucKeySpec = bIsExchangeKey? MiniDriverContainer::KEYSPEC_ECDHE_384 : MiniDriverContainer::KEYSPEC_ECDSA_384;
        }
        else if (Util::compareU1Arrays(params.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
        {
            keyBitSize = 521;
            ucKeySpec = bIsExchangeKey? MiniDriverContainer::KEYSPEC_ECDHE_521 : MiniDriverContainer::KEYSPEC_ECDSA_521;
        }
        else
        {
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        int keyByteLen = (keyBitSize + 7) / 8;
		int minEcc = 256, maxEcc = 521, minEccGen, maxEccGen;

		m_Device->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, getUserRole());

		if ((keyBitSize < minEcc) || (keyBitSize > maxEcc))
        {
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        // compute the total length;
        unsigned int uiKeyLength = 8 + 3*keyByteLen;

        // Prepare the keyValue
        u1Array keyValue( uiKeyLength );

        unsigned char* p = keyValue.GetBuffer( );
        memset( p, 0, uiKeyLength );

        // get the uncompressed point representation
        const unsigned char* pPoint = eccKey->m_pPublicPoint->GetBuffer();
        long len = eccKey->m_pPublicPoint->GetLength();
        ASN1_OCTET_STRING* oct = d2i_ASN1_OCTET_STRING(NULL, &pPoint, len);
        if (oct && (pPoint == eccKey->m_pPublicPoint->GetBuffer() + len))
        {
            pPoint = oct->data;
            len = oct->length;
        }
        else
        {
            pPoint = eccKey->m_pPublicPoint->GetBuffer();
            len = eccKey->m_pPublicPoint->GetLength();
        }

        if (pPoint[0] != 0x04)
        {
            if (oct) ASN1_OCTET_STRING_free(oct);
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        pPoint++;
        len--;

        if ((len % 2) || (len > 2*keyByteLen) || ((int) eccKey->m_pPrivateValue->GetLength() > keyByteLen))
        {
            if (oct) ASN1_OCTET_STRING_free(oct);
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        // copy the coordinates X and Y
        memcpy(p + 8 + keyByteLen - (len/2), pPoint, len/2);
        memcpy(p + 8 + 2*keyByteLen - (len/2), pPoint + len/2, len/2);

        if (oct) ASN1_OCTET_STRING_free(oct);

        // copy the private key value
        memcpy(p + 8 + 3*keyByteLen - eccKey->m_pPrivateValue->GetLength(), eccKey->m_pPrivateValue->GetBuffer(), eccKey->m_pPrivateValue->GetLength());

        // Specify what is able to do the key (sign only or sign & decrypt)
        eccKey->m_ucKeySpec = ucKeySpec;

        // Create the on card key container
        // This method checks if a certificate with the same public key exists.
        // In this case this new key must be imported into the key container already associated with this certificate and the key spec is also updated
        eccKey->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

        try {

            m_Device->containerCreate( getUserRole(), eccKey->m_ucContainerIndex, true, eccKey->m_ucKeySpec, pPublicKeyValue, keyBitSize, &keyValue );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::addObjectPrivateKey", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }
    }


    if( a_pObject->m_ucContainerIndex == MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID ) {

        // No free container available
        Log::error( "Token::AddPrivateKeyObject", "no index available - Return CKR_DEVICE_MEMORY" );

        throw PKCS11Exception( CKR_DEVICE_MEMORY );
    }

    setDefaultAttributesKeyPrivate( a_pObject );

    a_pObject->_local = CK_FALSE;

    // Create the associated PKCS#11 key object
    addObject( a_pObject, a_phObject );

    t.stop( "Token::addObjectPrivateKey" );
    Log::end( "Token::addObjectPrivateKey" );
}


/*
*/
void Token::addObjectCertificate( X509PubKeyCertObject* a_pObject, CK_OBJECT_HANDLE_PTR a_phObject ) {

    Log::begin( "Token::addObjectCertificate" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
    else if (m_Device->isReadOnly())
    {
        throw PKCS11Exception( CKR_TOKEN_WRITE_PROTECTED );
    }

    // Private certificate object is not allowed
    if( !a_pObject || a_pObject->isPrivate( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    // Set the certificate with sign & decrypt purposes by default
    a_pObject->m_ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

    // Set the certificate container as invalid
    a_pObject->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

    // Actually the certificates attributes have been provided by the creation template.
    // But some of then can be not set.
    // Get all empty attributes from the certificate
    // Set the same CKA_LABEL, CKA_ID and CKA_SUBJECT for this certificate
    // than an existing private key using the same public key modulus attribute
    setDefaultAttributesCertificate( a_pObject );

    Log::log( "Token::addObjectCertificate - Smart card logon <%d>", a_pObject->m_bIsSmartCardLogon );
    Log::log( "Token::addObjectCertificate - root <%d>", a_pObject->m_bIsRoot );
    Log::log( "Token::addObjectCertificate - index <%d>", a_pObject->m_ucContainerIndex );

    bool bIsRSA = a_pObject->m_bIsRSA;
    MiniDriverAuthentication::ROLES roleToUse = getUserRole();
    if (roleToUse == MiniDriverAuthentication::PIN_USER)
    {
        // See if there is a private key that has been generated with a specific role and that should
        // be associated with our certificate
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {
            if( CKO_PRIVATE_KEY == obj->second->getClass( ) ) {

                PrivateKeyObject* objPrivateKey = (PrivateKeyObject*) obj->second;
                if (bIsRSA == (objPrivateKey->_keyType == CKK_RSA))
                {
                    if (objPrivateKey->m_role != 0)
                    {
                        u1Array* pPublicKeyValue = NULL;
                        if (objPrivateKey->_keyType == CKK_RSA)
                            pPublicKeyValue = ((RSAPrivateKeyObject*) objPrivateKey)->m_pModulus.get();
                        else
                            pPublicKeyValue = ((ECCPrivateKeyObject*) objPrivateKey)->m_pPublicPoint.get();
                        // customized role
                        // check if it has the same modulus as our certificate
                        if(     pPublicKeyValue
                            &&  a_pObject->m_pPublicKeyValue.get()
                            &&  (pPublicKeyValue->GetLength() == a_pObject->m_pPublicKeyValue->GetLength())
                            &&  (0 == memcmp(pPublicKeyValue->GetBuffer(), a_pObject->m_pPublicKeyValue->GetBuffer(), a_pObject->m_pPublicKeyValue->GetLength()))
                          )
                        {
                            roleToUse = (MiniDriverAuthentication::ROLES) objPrivateKey->m_role;
                            break;
                        }
                    }
                }
            }
        }
    }

    //unsigned char ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
    //unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
    std::string stFileName = "";
    m_Device->containerGetMatching( roleToUse, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec, stFileName, a_pObject->m_pPublicKeyValue.get( ) );
    Log::log( "Token::addObjectCertificate - m_ucContainerIndex <%d>", a_pObject->m_ucContainerIndex );
    Log::log( "Token::addObjectCertificate - m_ucKeySpec <%d>", a_pObject->m_ucKeySpec );
    Log::log( "Token::addObjectCertificate - stFileName <%s>", stFileName.c_str( ) );

    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID != a_pObject->m_ucContainerIndex ) {

        Log::log( "Token::addObjectCertificate - Create a certificate associated to a key pair container" );

        // Create the certificate into the smart card
        try {

            // If a container already exists using the same public key modulus then the container index will be updated with the index of this container.
            // The keyspec will also be updated
            // The file name will anyway built automaticaly
            m_Device->createCertificate( roleToUse, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec, a_pObject->m_stCertificateName, a_pObject->m_pValue.get( ), a_pObject->m_pPublicKeyValue.get( ), a_pObject->m_bIsSmartCardLogon );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::addObjectCertificate", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }

    } else {

        Log::log( "Token::addObjectCertificate - Create a ROOT certificate" );

         // check that it doesn't already exists
         bool bFound = false;
         BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {
            if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

                X509PubKeyCertObject* objCert = (X509PubKeyCertObject*) obj->second;
                if (objCert->m_pValue->IsEqual(a_pObject->m_pValue.get( )))
                {
                   bFound = true;
                   break;
                }
            }
         }

         if (bFound)
         {
            Log::error( "Token::addObjectCertificate", "Root certificate already exists" );
            throw PKCS11Exception( CKR_FUNCTION_FAILED );
         }

        // Create the ROOT certificate into the smart card
        try {

            m_Device->createCertificateRoot( a_pObject->m_stCertificateName, a_pObject->m_pValue.get( ) );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::addObjectCertificate", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }
    }

    // Write the PKCS#11 certificate object into the smart card
    addObject( a_pObject, a_phObject );

    t.stop( "Token::addObjectCertificate" );
    Log::end( "Token::addObjectCertificate" );
}


/*
*/
void Token::addObjectPublicKey( Pkcs11ObjectKeyPublic* a_pObject, CK_OBJECT_HANDLE_PTR a_phObject ) {

    Log::begin( "Token::addObjectPublicKey" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
    else if (m_Device->isReadOnly())
    {
        throw PKCS11Exception( CKR_TOKEN_WRITE_PROTECTED );
    }

    // Private public key object is not allowed
    if( a_pObject->isPrivate( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    u1Array* pPublicKeyValue = NULL;
    if (a_pObject->_keyType == CKK_RSA)
	{
		Pkcs11ObjectKeyPublicRSA* pRsaPubKey = (Pkcs11ObjectKeyPublicRSA*) a_pObject;
        pPublicKeyValue = pRsaPubKey->m_pModulus.get();
		if (	pRsaPubKey->m_pPublicExponent.get()
			&&  !Util::compareArraysAsBigIntegers(pRsaPubKey->m_pPublicExponent.get(), (const unsigned char*) "\x01\x00\x01", 3)
		   )
		{
			throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
		}
	}
    else
        pPublicKeyValue = ((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pPublicPoint.get();

    // Create the certificate into the smart card
    try {

        // If a container already exists using the same public key modulus then the container index will be updated with the index of this container.
        // The keyspec will also be updated
        // The file name will anyway be build automaticaly
        m_Device->containerGetMatching( getUserRole(), a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec, a_pObject->m_stFileName, pPublicKeyValue );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::addObjectPublicKey", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    setDefaultAttributesKeyPublic( a_pObject );

    a_pObject->_local = CK_FALSE;

    // Write the PKCS#11 certificate object into the smart card
    addObject( a_pObject, a_phObject );

    t.stop( "Token::addObjectPublicKey" );
    Log::end( "Token::addObjectPublicKey" );
}


/*
*/
void Token::deleteObject( const CK_OBJECT_HANDLE& a_hObject ) {

    Log::begin( "Token::deleteObject" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Are we allowed to delete objects ? We must be logged in
    if( m_pSlot && !m_pSlot->isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

	CAtomicLogin atomicLogin(this, true);

    StorageObject* o = getObject( a_hObject );

    printObject( o );

    // Delete the PKCS#11 object & MiniDriver file/container from card
    deleteObjectFromCard( o );

    // Delete the PKCS#11 object from inner list of managed objects
    unregisterStorageObject( a_hObject );

    t.stop( "Token::deleteObject" );
    Log::end( "Token::deleteObject" );
}


/*
*/
void Token::deleteObjectFromCard( StorageObject* a_pObject ) {

    Log::begin( "Token::deleteObjectFromCard" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Delete the file from the MiniDriver file system
        switch( a_pObject->getClass( ) ) {

        case CKO_CERTIFICATE:
            {
                CertificateObject* t = static_cast< CertificateObject* >( a_pObject );

                // Delete the certificate file
                //try {

                if (t->m_stCertificateName == szROOT_STORE_FILE)
                {
                   X509PubKeyCertObject* pCert = static_cast< X509PubKeyCertObject* >( a_pObject );
                   // delete certificate from msroots
                   if (pCert->m_pValue)
                     m_Device->deleteCertificateRoot (pCert->m_pValue.get());
                }
                else
                {
                   try {

                       // Check if the container is still valid. Throw an exception if not.
                       MiniDriverContainer c = m_Device->containerGet( t->m_ucContainerIndex );
                       if (m_Device->containerReadOnly (t->m_ucContainerIndex))
                           throw PKCS11Exception( CKR_FUNCTION_FAILED );

                       // Delete the associated certificate
					   m_Device->certificateDelete( t->m_ucContainerIndex, t->m_ucKeySpec );

                   } catch( MiniDriverException ) {

                       // The container is not associated to this certitifcate object
                       // Delete the MiniDriver file from the PKCS11 object file name
                       m_Device->deleteFile( std::string( szBASE_CSP_DIR ), t->m_stCertificateName );

                       // delete it from msroots if present there
                        X509PubKeyCertObject* pCert = reinterpret_cast< X509PubKeyCertObject* >( a_pObject );
                        // delete certificate from msroots
                        if (pCert && pCert->m_pValue && pCert->m_bIsRoot)
                           m_Device->deleteCertificateRoot (pCert->m_pValue.get());

                   }
                }

                //if( 0xFF == t->m_ucContainerIndex ) {

                //    // The container is not associated to this certitifcate object
                //    // Delete the MiniDriver file from the PKCS11 object file name
                //    m_Device->deleteFile( std::string( szBASE_CSP_DIR ), t->m_stCertificateName );

                //} else {

                //    m_Device->certificateDelete( t->m_ucContainerIndex );
                //}

                ////} catch( MiniDriverException& ex ) {

                ////    // The container is not associated to this certitifcate object
                ////    // Delete the MiniDriver file from the PKCS11 object file name
                ////    m_Device->deleteFile( std::string( szBASE_CSP_DIR ), t->m_stCertificateName );

                ////    throw ex;
                ////}
            }
            break;

        case CKO_PRIVATE_KEY:
            {
                RSAPrivateKeyObject * v = static_cast< RSAPrivateKeyObject* >( a_pObject );
                if (m_Device->containerReadOnly (v->m_ucContainerIndex))
                    throw PKCS11Exception( CKR_FUNCTION_FAILED );
                // Delete the key container
				m_Device->containerDelete( v->m_ucContainerIndex, v->m_ucKeySpec );
            }
            break;

        default:
            break;
        }

        // Delete the PKCS#11 file from card
        if( !a_pObject->m_stFileName.empty( ) && !a_pObject->m_bOffCardObject ) {

            m_Device->deleteFile( g_stPathPKCS11, a_pObject->m_stFileName );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::deleteObjectFromCard", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::deleteObjectFromCard" );
    Log::end( "Token::deleteObjectFromCard" );
}


/*
*/
void Token::getAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    //Log::begin( "Token::getAttributeValue" );
    //Timer t;
    //t.start( );

    if( !m_pSlot) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    StorageObject* o = getObject( a_hObject );


    // Check if we are allowed to retreive the queried attributes
    if( o->isPrivate( ) && !m_pSlot->isAuthenticated( ) ) {

        for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

            a_pTemplate[ i ].ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }

        throw PKCS11Exception(CKR_USER_NOT_LOGGED_IN);
    }


    // Get the attributes from the object
    for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

        o->getAttribute( &a_pTemplate[ i ] );
    }

    //t.stop( "Token::getAttributeValue" );
    //Log::end( "Token::getAttributeValue" );
}


/*
*/
void Token::setAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    // ??? TODO : verify the new attribute is different from the existing attribute. If both are the same do nothing

    Log::begin( "Token::setAttributeValue" );
    Timer t;
    t.start( );

    if( !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    StorageObject* o = getObject( a_hObject );

    // Check if we are allowed to write
    if( /*o->isPrivate( ) && 	*/ !m_pSlot->isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

	CAtomicLogin atomicLogin(this, true);

    // Check if the object is not read-only
    if( ! o->isModifiable( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
    }

    for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

        o->setAttribute( a_pTemplate[ i ], false );
    }

    // Compute this attribute for backward compatibilit with old version of the P11 library
    o->_uniqueId = Util::MakeUniqueId();

    // Get the object buffer
    std::vector< unsigned char > v;
    o->serialize( &v );
    size_t l =  v.size( );
    u1Array d( l );
    for( unsigned int i = 0 ; i <l ; ++i ) {

        d.SetU1At( i, v.at( i ) );
    }

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

	bool bFileCreated = false;

    try {

        if( o->m_bOffCardObject ) {

			// Build the name of the file
			computeObjectFileName( o, o->m_stFileName );

			if( m_bCreateDirectoryP11 ) {

				// Create the P11 directory into the smart card
				try {
					m_Device->createDirectory( std::string( "root" ), g_stPathPKCS11 );
					m_bCreateDirectoryP11 = false;
				} catch( MiniDriverException& x ) {
					Log::error( "Token::setAttributeValue", "MiniDriverException while creating PKCS11 directory" );
					throw PKCS11Exception( checkException( x ) );
				}
			}
			else if (o->getClass( ) == CKO_CERTIFICATE)
			{
				MiniDriverFiles::FILES_NAME filesPKCS11;
				try {
					filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );
				}
				catch(...)
				{}

				if (isFileExists( o->m_stFileName, filesPKCS11 ))
				{
					// if the P11 certificate object already exists, it means it was rejected because it is inconsistent with the real certificate
					// we delete it here
					try
					{
						Log::log("Token::setAttributeValue - old P11 certificate object with the same name exists (\"%s\"). Deleting it", o->m_stFileName.c_str());
						m_Device->deleteFile(g_stPathPKCS11, o->m_stFileName);
					}
					catch(...)
					{}
				}
			}

         m_Device->createFile( g_stPathPKCS11, o->m_stFileName, ( o->m_Private == CK_TRUE ) && (CKO_PRIVATE_KEY != o->getClass()));

			bFileCreated = true;

            o->m_bOffCardObject = false;
        }

        m_Device->writeFile( g_stPathPKCS11, o->m_stFileName, &d );

    } catch( MiniDriverException& x ) {
		if (bFileCreated)
			m_Device->deleteFile(g_stPathPKCS11, o->m_stFileName);
        Log::error( "Token::setAttributeValue", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    printObject( o );

    t.stop( "Token::setAttributeValue" );
    Log::end( "Token::setAttributeValue" );
}


/*
*/
void Token::generateKeyPair( Pkcs11ObjectKeyPublic* a_pObjectPublicKey, PrivateKeyObject* a_pObjectPrivateKey, CK_OBJECT_HANDLE_PTR a_pHandlePublicKeyRSA, CK_OBJECT_HANDLE_PTR a_pHandlePrivateKeyRSA ) {

    Log::begin( "Token::generateKeyPair" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
    else if (m_Device->isReadOnly())
    {
        throw PKCS11Exception( CKR_TOKEN_WRITE_PROTECTED );
    }

    bool bIsRSA = (a_pObjectPublicKey->_keyType == CKK_RSA);
    int keyBitSize = 0;
    unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
	 bool bIsForSignOnly = (TRUE == a_pObjectPrivateKey->_sign) && (FALSE == a_pObjectPrivateKey->_decrypt) && (FALSE == a_pObjectPrivateKey->_derive);

    if (bIsRSA)
    {
		Pkcs11ObjectKeyPublicRSA* pRsaPubKey = (Pkcs11ObjectKeyPublicRSA*) a_pObjectPublicKey;
        CK_ULONG modulusBits = pRsaPubKey->m_ulModulusBits;
		int minRsa = 1024, maxRsa = 2048, minRsaGen = 0, maxRsaGen = 0;
		m_Device->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, getUserRole());

        if( ( modulusBits < (CK_ULONG) minRsaGen ) || ( modulusBits > (CK_ULONG) maxRsaGen ) ) {

            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

        keyBitSize = modulusBits;
		ucKeySpec = (bIsForSignOnly)? MiniDriverContainer::KEYSPEC_SIGNATURE : MiniDriverContainer::KEYSPEC_EXCHANGE;

		// check that the public exponent has the only supported value 0x010001
		if (	pRsaPubKey->m_pPublicExponent.get()
			&&	!Util::compareArraysAsBigIntegers(pRsaPubKey->m_pPublicExponent.get(), (const unsigned char*) "\x01\x00\x01", 3)
		   )
		{
			throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
		}

    }
    else
    {
        boost::shared_ptr< u1Array > params = ((Pkcs11ObjectKeyPublicECC*) a_pObjectPublicKey)->m_pParams;

        if (Util::compareU1Arrays(params.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
        {
            keyBitSize = 256;
			ucKeySpec = (bIsForSignOnly)? MiniDriverContainer::KEYSPEC_ECDSA_256: MiniDriverContainer::KEYSPEC_ECDHE_256;
        }
        else if (Util::compareU1Arrays(params.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
        {
            keyBitSize = 384;
            ucKeySpec = (bIsForSignOnly)? MiniDriverContainer::KEYSPEC_ECDSA_384: MiniDriverContainer::KEYSPEC_ECDHE_384;
        }
        else if (Util::compareU1Arrays(params.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
        {
            keyBitSize = 521;
            ucKeySpec = (bIsForSignOnly)? MiniDriverContainer::KEYSPEC_ECDSA_521: MiniDriverContainer::KEYSPEC_ECDHE_521;
        }
        else
        {
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

		int minEcc = 256, maxEcc = 521, minEccGen, maxEccGen;
		m_Device->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, getUserRole());

		if ((keyBitSize < minEccGen) || (keyBitSize > maxEccGen))
        {
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }

    // Create a smart card container to generate and store the new key pair
    unsigned char ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
    if (a_pObjectPublicKey->m_pID.get()->GetLength() == 1) // 1 byte ID , use it container index for IoT Safe
    {
        ucContainerIndex = (unsigned char) a_pObjectPublicKey->m_pID.get()->GetBuffer()[0];
    }

    MiniDriverAuthentication::ROLES roleToUse = getUserRole();
    if (roleToUse == MiniDriverAuthentication::PIN_USER)
    {
		if (!Token::s_bForcePinUser && !m_pSlot->isStaticProfile() && m_Device->IsMultiPinSupported())
			throw PKCS11Exception(CKR_FUNCTION_CANCELED);
    }

	CAtomicLogin atomicLogin(this, true, (getUserRole() == MiniDriverAuthentication::PIN_USER)? 0 : getUserRole());


    try {

        m_Device->containerCreate( roleToUse, ucContainerIndex, false, ucKeySpec, NULL, keyBitSize, 0 );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::generateKeyPair", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    if( ucContainerIndex == MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID ) {

        throw PKCS11Exception( CKR_DEVICE_MEMORY );
    }

    a_pObjectPrivateKey->m_ucContainerIndex = ucContainerIndex;

    a_pObjectPrivateKey->m_ucKeySpec = ucKeySpec;

    a_pObjectPublicKey->m_ucContainerIndex = ucContainerIndex;

    a_pObjectPublicKey->m_ucKeySpec = ucKeySpec;

    if (roleToUse != getUserRole())
    {
        a_pObjectPrivateKey->m_role = (CK_BYTE) roleToUse;
        a_pObjectPublicKey->m_role = (CK_BYTE) roleToUse;
    }

    try {

        // Populate these objects with the new key material
        MiniDriverContainer c = m_Device->containerGet( ucContainerIndex );

        // Fill the PKCS#11 object with the information about the new key pair
        a_pObjectPublicKey->_local = CK_TRUE;

        ///// ???
        //a_pObjectPublicKeyRSA->m_pPublicExponent = c.getExchangePublicKeyExponent( );
        if (bIsRSA)
        {
            ((Pkcs11ObjectKeyPublicRSA*) a_pObjectPublicKey)->m_pModulus = (bIsForSignOnly)? c.getSignaturePublicKeyModulus() : c.getExchangePublicKeyModulus( );
        }
        else
        {
            ((Pkcs11ObjectKeyPublicECC*) a_pObjectPublicKey)->m_pPublicPoint = (bIsForSignOnly)? c.getEcdsaPointDER() : c.getEcdhePointDER();
        }

        // Copy these modulus and exponent in the private key component also
        a_pObjectPrivateKey->_local = CK_TRUE;

        if (bIsRSA)
        {
            ((RSAPrivateKeyObject*) a_pObjectPrivateKey)->m_pPublicExponent = (bIsForSignOnly)? c.getSignaturePublicKeyExponent() : c.getExchangePublicKeyExponent( );
            ((RSAPrivateKeyObject*) a_pObjectPrivateKey)->m_pModulus = (bIsForSignOnly)? c.getSignaturePublicKeyModulus() : c.getExchangePublicKeyModulus( );
        }
        else
        {
            ((ECCPrivateKeyObject*) a_pObjectPrivateKey)->m_pParams = ((Pkcs11ObjectKeyPublicECC*) a_pObjectPublicKey)->m_pParams;
            ((ECCPrivateKeyObject*) a_pObjectPrivateKey)->m_pPublicPoint = ((Pkcs11ObjectKeyPublicECC*) a_pObjectPublicKey)->m_pPublicPoint;
        }

        setDefaultAttributesKeyPrivate( a_pObjectPrivateKey );

        setDefaultAttributesKeyPublic( a_pObjectPublicKey );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::generateKeyPair", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    // The public key may be a session object, in that case, don't save it.
    if( a_pObjectPublicKey->isToken( ) ) {

        addObject( a_pObjectPublicKey, a_pHandlePublicKeyRSA );
    }

    try {

        addObject( a_pObjectPrivateKey, a_pHandlePrivateKeyRSA );

    } catch( MiniDriverException& x ) {

        if( a_pObjectPublicKey->isToken( ) ) {

            deleteObject( *a_pHandlePublicKeyRSA );

            try {

                m_Device->containerDelete( ucContainerIndex, ucKeySpec );

            } catch( MiniDriverException& ) {

                Log::error( "Token::generateKeyPair", "MiniDriverException" );
            }

            throw PKCS11Exception( checkException( x ) );
        }
    }

    t.stop( "Token::generateKeyPair" );
    Log::end( "Token::generateKeyPair" );
}

/*
*/
void Token::deriveKey( PrivateKeyObject* a_pObjectPrivateKey, CK_ECDH1_DERIVE_PARAMS_PTR a_pEcdhParams, SecretKeyObject* a_pDerivedKey, CK_OBJECT_HANDLE_PTR a_pHandleDerivedKey)
{
    UNREFERENCED_PARAMETER(a_pHandleDerivedKey);

    Log::begin( "Token::deriveKey" );
    Timer t;
    t.start( );

    if (a_pObjectPrivateKey->_keyType != CKK_EC || a_pDerivedKey->_keyType != CKK_GENERIC_SECRET)
    {
        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    ECCPrivateKeyObject* eccPrvKey = (ECCPrivateKeyObject*) a_pObjectPrivateKey;
    GenericSecretKeyObject* derivedKey = (GenericSecretKeyObject*) a_pDerivedKey;

    u4 nLen = (eccPrvKey->getOrderBitLength() + 7) / 8;

    // Set the other party public point
    const unsigned char* ptr = a_pEcdhParams->pPublicData;
    long len = a_pEcdhParams->ulPublicDataLen;
    ASN1_OCTET_STRING* oct = d2i_ASN1_OCTET_STRING(NULL, &ptr, len);
    if (oct && (ptr == a_pEcdhParams->pPublicData + len))
    {
        ptr = oct->data;
        len = oct->length;
    }
    else
    {
        ptr = a_pEcdhParams->pPublicData;
        len = a_pEcdhParams->ulPublicDataLen;
    }

    CK_ULONG xLen = (len - 1)/2;
    CK_ULONG yLen = xLen;

    if (ptr[0] != 0x04 || ((len%2) != 1) || (xLen > nLen))
    {
        // we only suppport uncompressed format
        if (oct) ASN1_OCTET_STRING_free(oct);
        throw PKCS11Exception(CKR_MECHANISM_PARAM_INVALID);
    }

    // copy the x and y coordinates
    u1Array Qx(nLen), Qy(nLen);

    memcpy(Qx.GetBuffer() + (nLen - xLen), ptr + 1, xLen);
    memcpy(Qy.GetBuffer() + (nLen - yLen), ptr + 1 + xLen, yLen);

    // free the ASN.1 memory
    if (oct) ASN1_OCTET_STRING_free(oct);

    // compute ECDH value
    boost::shared_ptr< u1Array > DHAgreement;
    CAtomicLogin atomicLogin(this, false, eccPrvKey->m_role);

    try {

        DHAgreement = m_Device->constructDHAgreement( eccPrvKey->m_ucContainerIndex, &Qx, &Qy );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::deriveKey", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    u1Array SharedInfo(a_pEcdhParams->ulSharedDataLen);

    SharedInfo.SetBuffer(a_pEcdhParams->pSharedData);

    if (a_pEcdhParams->kdf == CKD_NULL)
    {
        derivedKey->NULL_drive(DHAgreement.get());
    }
    else
    {
        derivedKey->ANSI_X9_63_drive(DHAgreement.get(), &SharedInfo);
    }

    derivedKey->_local = TRUE;

    t.stop( "Token::deriveKey" );
    Log::end( "Token::deriveKey" );
}


/*
*/
void Token::encrypt( const StorageObject* pubObj, u1Array* dataToEncrypt, const CK_ULONG& mechanism, CK_VOID_PTR pParameters, CK_BYTE_PTR pEncryptedData ) {

    Pkcs11ObjectKeyPublicRSA* object = ( Pkcs11ObjectKeyPublicRSA* )pubObj;

    if(mechanism == CKM_RSA_PKCS){
        // first do the length checks
        if(dataToEncrypt->GetLength() > (object->m_pModulus->GetLength() - 11)){
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }

        u4 modulusLen = object->m_pModulus->GetLength();

        // do the padding ourselves
        u1Array messageToEncrypt(modulusLen);
        u1* ptrMsg = messageToEncrypt.GetBuffer();
        u4 i, inputLen = dataToEncrypt->GetLength();
        R_RANDOM_STRUCT & randomStruct = Util::RandomStruct();
        unsigned char byte;

        ptrMsg[0] = 0;
        ptrMsg[1] = 2;

        for (i = 2; i < modulusLen - inputLen - 1; i++)
        {
            /**
            * Find nonzero random byte.
            */
            do {
               R_GenerateBytes (&byte, 1, &randomStruct);
            } while (byte == 0);

            ptrMsg[i] = byte;
        }
        ptrMsg[i++] = 0;
        memcpy (ptrMsg + i, dataToEncrypt->GetBuffer(), inputLen);

        RSA* rsa = RSA_new();
        BIGNUM* rsa_n = BN_bin2bn(object->m_pModulus->GetBuffer(), object->m_pModulus->GetLength(), NULL);
        BIGNUM* rsa_e = BN_bin2bn(object->m_pPublicExponent->GetBuffer(), object->m_pPublicExponent->GetLength(), NULL);
	 RSA_set0_key(rsa,rsa_n,rsa_e,NULL);
        int l = RSA_public_encrypt(modulusLen, ptrMsg, pEncryptedData, rsa, RSA_NO_PADDING);
        RSA_free(rsa);

        if (l < 0)
        {
            // should never happen
            throw PKCS11Exception(CKR_FUNCTION_FAILED);
        }
    }
    else if (mechanism == CKM_RSA_PKCS_OAEP){
        const EVP_MD* dgst = NULL;
        unsigned int modulusLen = object->m_pModulus->GetLength();
        CK_RSA_PKCS_OAEP_PARAMS_PTR pParams = (CK_RSA_PKCS_OAEP_PARAMS_PTR) pParameters;

        switch(pParams->hashAlg)
        {
            case CKM_SHA_1: dgst = EVP_sha1(); break;
            case CKM_SHA256: dgst = EVP_sha256(); break;
            case CKM_SHA384: dgst = EVP_sha384(); break;
            case CKM_SHA512: dgst = EVP_sha512(); break;
        }

        if(dataToEncrypt->GetLength() > (modulusLen - 2 - (2*EVP_MD_size(dgst)))){
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }

        u1Array encodedMessage(modulusLen);
        memset(encodedMessage.GetBuffer(),0,modulusLen);

        if (!EncodeOAEP(encodedMessage.GetBuffer(), modulusLen, dataToEncrypt->GetBuffer(), dataToEncrypt->GetLength(), dgst, NULL, 0))
        {
            // should never happen
            throw PKCS11Exception(CKR_FUNCTION_FAILED);
        }

        // now perform raw RSA exponentiation
        RSA* rsa = RSA_new();
        BIGNUM* rsa_n = BN_bin2bn(object->m_pModulus->GetBuffer(), object->m_pModulus->GetLength(), NULL);
        BIGNUM* rsa_e = BN_bin2bn(object->m_pPublicExponent->GetBuffer(), object->m_pPublicExponent->GetLength(), NULL);
	RSA_set0_key(rsa,rsa_n,rsa_e,NULL);
        int l = RSA_public_encrypt(encodedMessage.GetLength(), encodedMessage.GetBuffer(), pEncryptedData, rsa, RSA_NO_PADDING);
        RSA_free(rsa);

        if (l < 0)
        {
            // should never happen
            throw PKCS11Exception(CKR_FUNCTION_FAILED);
        }

    }else{

        unsigned int modulusLen = object->m_pModulus->GetLength();

        if(dataToEncrypt->GetLength() > (modulusLen)){
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }

        // pre-pad with zeros
        u1Array messageToEncrypt(modulusLen);
        memset(messageToEncrypt.GetBuffer(),0,modulusLen);

        s4 offsetMsgToEncrypt = modulusLen - dataToEncrypt->GetLength();

        unsigned int l = dataToEncrypt->GetLength( );
        for( unsigned int i = 0, j = offsetMsgToEncrypt ; i < l ; ++i, ++j ) {

            messageToEncrypt.GetBuffer()[j] = dataToEncrypt->GetBuffer()[i];
        }

        // now perform raw RSA exponentiation
        RSA* rsa = RSA_new();
        BIGNUM* rsa_n = BN_bin2bn(object->m_pModulus->GetBuffer(), object->m_pModulus->GetLength(), NULL);
        BIGNUM* rsa_e = BN_bin2bn(object->m_pPublicExponent->GetBuffer(), object->m_pPublicExponent->GetLength(), NULL);
	RSA_set0_key(rsa,rsa_n,rsa_e,NULL);
        int status = RSA_public_encrypt(messageToEncrypt.GetLength(), messageToEncrypt.GetBuffer(), pEncryptedData, rsa, RSA_NO_PADDING);
        RSA_free(rsa);

        if (status < 0)
        {
            // should never happen
            throw PKCS11Exception(CKR_FUNCTION_FAILED);
        }
    }
}


/*
*/
void Token::decrypt( const StorageObject* privObj, u1Array* dataToDecrypt, const CK_ULONG& mechanism, unsigned char algo, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen ) {

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    RSAPrivateKeyObject* rsaKey = (RSAPrivateKeyObject*)privObj;

    boost::shared_ptr< u1Array > data;
    CAtomicLogin atomicLogin(this, false, rsaKey->m_role);

    try {
        if (CKM_RSA_PKCS_OAEP != mechanism)
            data = m_Device->privateKeyDecrypt( rsaKey->m_ucContainerIndex, rsaKey->m_ucKeySpec, dataToDecrypt );
        else
            data = m_Device->privateKeyDecryptEx( rsaKey->m_ucContainerIndex, rsaKey->m_ucKeySpec, PADDING_OAEP, algo, dataToDecrypt );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::decrypt", "MiniDriverException" );
        if (x.getError() == SCARD_E_INVALID_PARAMETER)
            throw PKCS11Exception( CKR_ENCRYPTED_DATA_INVALID );
        else
            throw PKCS11Exception( checkException( x ) );
    }

    unsigned int l = data->GetLength( );

    unsigned char* p = (unsigned char*)data->GetBuffer( );

    if( CKM_RSA_PKCS == mechanism ) {

        unsigned char* decryptedMessage = p;

        if( decryptedMessage[ 0 ] || ( g_ucPKCS_EMEV15_PADDING_TAG != decryptedMessage[ 1 ] ) ) {

            // invalid message padding
            throw PKCS11Exception( CKR_ENCRYPTED_DATA_INVALID );

        } else {

            // seach message padding separator
            unsigned int mPos = 2 + 8;

            while( decryptedMessage[ mPos ] && (mPos < l ) ) {

                ++mPos;
            }

            // point on message itself.
            ++mPos;

            l = l - mPos;

            data.reset( new u1Array( l ) );

            p = data->GetBuffer( );

            memcpy( p, (unsigned char*)&decryptedMessage[ mPos ],  l );
        }
    }
    // else... CKM_RSA_X_509: Ignore padding

    if( data ) {

        if ( *pulDataLen >= l ) {

            memset( pData, 0, *pulDataLen );

            memcpy( pData, p, l );

            *pulDataLen = l;
        } else {

            *pulDataLen = l;

            throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
        }
    }
}


/*
*/
void Token::verify( const StorageObject* pubObj, u1Array* dataToVerify, const CK_ULONG& mechanism, u1Array* signature) {

    Pkcs11ObjectKeyPublic* o = (Pkcs11ObjectKeyPublic*)pubObj;
    bool bIsRSA = o->_keyType == CKK_RSA;

    if (bIsRSA)
    {
        Pkcs11ObjectKeyPublicRSA* rsaKey = (Pkcs11ObjectKeyPublicRSA*) o;
        if(((mechanism == CKM_RSA_PKCS) && (dataToVerify->GetLength() > (rsaKey->m_pModulus->GetLength() - 11))) ||
            ((mechanism == CKM_RSA_X_509) && (dataToVerify->GetLength() > rsaKey->m_pModulus->GetLength())))
        {
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }

        if( signature->GetLength( ) != rsaKey->m_pModulus->GetLength( ) ){

            throw PKCS11Exception(CKR_SIGNATURE_LEN_RANGE);
        }

        int size = rsaKey->m_pModulus->GetLength();
        int bits = size * 8;
        unsigned int messageToVerifyLen = size;
        u1Array messageToVerify( messageToVerifyLen );

        RSA* rsa = RSA_new();
        BIGNUM* rsa_n = BN_bin2bn(rsaKey->m_pModulus->GetBuffer(), rsaKey->m_pModulus->GetLength(), NULL);
        BIGNUM* rsa_e = BN_bin2bn(rsaKey->m_pPublicExponent->GetBuffer(), rsaKey->m_pPublicExponent->GetLength(), NULL);
	RSA_set0_key(rsa,rsa_n,rsa_e,NULL);
        int l = RSA_public_encrypt(size, signature->GetBuffer(), messageToVerify.GetBuffer(), rsa, RSA_NO_PADDING);
        RSA_free(rsa);

        if (l < 0)
        {
            // should never happen
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }

        switch(mechanism){

        case CKM_RSA_PKCS:
            Pkcs11ObjectKeyPublicRSA::verifyRSAPKCS1v15( &messageToVerify,dataToVerify,size);
            break;

        case CKM_RSA_X_509:
            Pkcs11ObjectKeyPublicRSA::verifyRSAX509( &messageToVerify,dataToVerify,size);
            break;

        case CKM_SHA1_RSA_PKCS:
            Pkcs11ObjectKeyPublicRSA::verifyHash( &messageToVerify,dataToVerify,size,CKM_SHA_1);
            break;

        case CKM_SHA256_RSA_PKCS:
            Pkcs11ObjectKeyPublicRSA::verifyHash( &messageToVerify,dataToVerify,size,CKM_SHA256);
            break;

        case CKM_SHA384_RSA_PKCS:
            Pkcs11ObjectKeyPublicRSA::verifyHash( &messageToVerify,dataToVerify,size,CKM_SHA384);
            break;

        case CKM_SHA512_RSA_PKCS:
            Pkcs11ObjectKeyPublicRSA::verifyHash( &messageToVerify,dataToVerify,size,CKM_SHA512);
            break;

        case CKM_MD5_RSA_PKCS:
            Pkcs11ObjectKeyPublicRSA::verifyHash( &messageToVerify,dataToVerify,size,CKM_MD5);
            break;

        case CKM_RSA_PKCS_PSS:
            {
                const EVP_MD* Hash = NULL;
                if (dataToVerify->GetLength() == 20)
                    Hash = EVP_sha1();
                else if (dataToVerify->GetLength() == 32)
                    Hash = EVP_sha256();
                else if (dataToVerify->GetLength() == 48)
                    Hash = EVP_sha384();
                else if (dataToVerify->GetLength() == 64)
                    Hash = EVP_sha512();

                const EVP_MD* Mgf1 = Hash; // We only support MGF1 based on the same hash

                if (0 == VerifyPSS(bits, dataToVerify->GetBuffer(), Hash, Mgf1, messageToVerify.GetBuffer(), EVP_MD_size(Hash)))
                    throw PKCS11Exception( CKR_SIGNATURE_INVALID );
            }
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
            if (0 == VerifyPSS(bits, dataToVerify->GetBuffer(), EVP_sha1(), EVP_sha1(), messageToVerify.GetBuffer(), 20))
                throw PKCS11Exception( CKR_SIGNATURE_INVALID );
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            if (0 == VerifyPSS(bits, dataToVerify->GetBuffer(), EVP_sha256(), EVP_sha256(), messageToVerify.GetBuffer(), 32))
                throw PKCS11Exception( CKR_SIGNATURE_INVALID );
            break;
        case CKM_SHA384_RSA_PKCS_PSS:
            if (0 == VerifyPSS(bits, dataToVerify->GetBuffer(), EVP_sha384(), EVP_sha384(), messageToVerify.GetBuffer(), 48))
                throw PKCS11Exception( CKR_SIGNATURE_INVALID );
            break;
        case CKM_SHA512_RSA_PKCS_PSS:
            if (0 == VerifyPSS(bits, dataToVerify->GetBuffer(), EVP_sha512(), EVP_sha512(), messageToVerify.GetBuffer(), 64))
                throw PKCS11Exception( CKR_SIGNATURE_INVALID );
            break;

        default:
            throw PKCS11Exception( CKR_GENERAL_ERROR );
        }
    }
    else
    {
        Pkcs11ObjectKeyPublicECC* eccKey = (Pkcs11ObjectKeyPublicECC*) o;
        u4 nLen = (eccKey->getOrderBitLength() + 7) / 8;
        u4 ulExpectedSigLen = 2 * nLen;

        if (mechanism == CKM_ECDSA)
        {
            if (dataToVerify->GetLength() != 20 && dataToVerify->GetLength() != 32 && dataToVerify->GetLength() != 48 && dataToVerify->GetLength() != 64)
            {
                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
            }
        }

        if( (signature->GetLength() == 0) || (signature->GetLength( ) > ulExpectedSigLen) || (signature->GetLength() % 2 != 0)){

            throw PKCS11Exception(CKR_SIGNATURE_LEN_RANGE);
        }

        if (!eccKey->verify(dataToVerify, signature))
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }
}

/*
*/
void Token::sign( const KeyObject* keyObj, u1Array* dataToSign, u1Array* intermediateHash, u1Array* hashCounter, const CK_ULONG& mechanism, CK_BYTE_PTR pSignature ) {

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if (keyObj->_keyType == CKK_AES){

        SecretKeyObjectAES* aesKey = ( SecretKeyObjectAES* ) keyObj;

        boost::shared_ptr< u1Array > signatureData;
        CAtomicLogin atomicLogin(this, false, aesKey->m_role);
        try {

            // CMAC does not need hashing and any padding is done in the CMAC itself
            signatureData = m_Device->privateKeySign( aesKey->m_ucContainerIndex, aesKey->m_ucKeySpec, 0, 0, dataToSign, intermediateHash, hashCounter );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::sign", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }

        if( !signatureData ) {

            throw PKCS11Exception( CKR_FUNCTION_FAILED );
        }

        memcpy( pSignature, signatureData->GetBuffer( ), signatureData->GetLength( ) );
    }
    else if (keyObj->_keyType == CKK_RSA)
    {
        boost::shared_ptr< u1Array > messageToSign;

        RSAPrivateKeyObject* rsaKey = ( RSAPrivateKeyObject* ) keyObj;

        if( !(rsaKey->m_pModulus) ) {

            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        CK_ULONG modulusLen = rsaKey->m_pModulus->GetLength( );

        if( ( ( mechanism == CKM_RSA_PKCS ) && ( dataToSign->GetLength( ) > ( modulusLen - 11 ) ) ) || ( ( mechanism == CKM_RSA_X_509 ) && ( dataToSign->GetLength( ) > modulusLen ) ) ) {

            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        unsigned char ucAlgo = 0, ucPaddingType = 0;
        bool bIsExplicitSign = (intermediateHash != NULL);

        switch( mechanism ) {

        case CKM_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::PadRSAPKCS1v15( dataToSign, modulusLen ) );
            break;

        case CKM_RSA_X_509:
            messageToSign.reset( RSAPrivateKeyObject::PadRSAX509( dataToSign, modulusLen ) );
            break;

        case CKM_SHA1_RSA_PKCS:
            if (bIsExplicitSign)
            {
                ucPaddingType = PADDING_PKCS1;
                ucAlgo = ALGO_SHA_1;
            }
            else
                messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA_1 ) );
            break;

        case CKM_SHA256_RSA_PKCS:
            if (bIsExplicitSign)
            {
                ucPaddingType = PADDING_PKCS1;
                ucAlgo = ALGO_SHA_256;
            }
            else
                messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA256 ) );
            break;

        case CKM_SHA384_RSA_PKCS:
            if (bIsExplicitSign)
            {
                ucPaddingType = PADDING_PKCS1;
                ucAlgo = ALGO_SHA_384;
            }
            else
                messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA384 ) );
            break;

        case CKM_SHA512_RSA_PKCS:
            if (bIsExplicitSign)
            {
                ucPaddingType = PADDING_PKCS1;
                ucAlgo = ALGO_SHA_512;
            }
            else
                messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA512 ) );
            break;

        case CKM_MD5_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_MD5 ) );
            break;

        case CKM_RSA_PKCS_PSS:
            bIsExplicitSign = true;
            ucPaddingType = PADDING_PSS;
            if (dataToSign->GetLength() == 20)
                ucAlgo = ALGO_SHA_1;
            else if (dataToSign->GetLength() == 32)
                ucAlgo = ALGO_SHA_256;
            else if (dataToSign->GetLength() == 48)
                ucAlgo = ALGO_SHA_384;
            else if (dataToSign->GetLength() == 64)
                ucAlgo = ALGO_SHA_512;
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
            bIsExplicitSign = true;
            ucPaddingType = PADDING_PSS;
            ucAlgo = ALGO_SHA_1;
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            bIsExplicitSign = true;
            ucPaddingType = PADDING_PSS;
            ucAlgo = ALGO_SHA_256;
            break;
        case CKM_SHA384_RSA_PKCS_PSS:
            bIsExplicitSign = true;
            ucPaddingType = PADDING_PSS;
            ucAlgo = ALGO_SHA_384;
            break;
        case CKM_SHA512_RSA_PKCS_PSS:
            bIsExplicitSign = true;
            ucPaddingType = PADDING_PSS;
            ucAlgo = ALGO_SHA_512;
            break;
        }

        boost::shared_ptr< u1Array > signatureData;
        CAtomicLogin atomicLogin(this, false, rsaKey->m_role);
        try {

            if (bIsExplicitSign)
                signatureData = m_Device->privateKeySign( rsaKey->m_ucContainerIndex, rsaKey->m_ucKeySpec, ucPaddingType, ucAlgo, dataToSign, intermediateHash, hashCounter );
            else
                signatureData = m_Device->privateKeyDecrypt( rsaKey->m_ucContainerIndex, rsaKey->m_ucKeySpec, messageToSign.get( ) );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::sign", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }

        if( !signatureData ) {

            throw PKCS11Exception( CKR_FUNCTION_FAILED );
        }

        memcpy( pSignature, signatureData->GetBuffer( ), signatureData->GetLength( ) );
    }
    else
    {
        ECCPrivateKeyObject* eccKey = ( ECCPrivateKeyObject* ) keyObj;
        unsigned char ucAlgo;

        if( !(eccKey->m_pParams) ) {

            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        if (!intermediateHash)
        {
            // full hash given in input
            switch( dataToSign->GetLength() ) {

            case 20:
                ucAlgo = ALGO_SHA_1;
                break;

            case 32:
                ucAlgo = ALGO_SHA_256;
                break;

            case 48:
                ucAlgo = ALGO_SHA_384;
                break;

            case 64:
                ucAlgo = ALGO_SHA_512;
                break;

            default:
                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
                break;
            }
        }
        else
        {
            switch(mechanism)
            {
            case CKM_ECDSA_SHA1:
                ucAlgo = ALGO_SHA_1;
                break;
            case CKM_ECDSA_SHA256:
                ucAlgo = ALGO_SHA_256;
                break;
            case CKM_ECDSA_SHA384:
                ucAlgo = ALGO_SHA_384;
                break;
            case CKM_ECDSA_SHA512:
                ucAlgo = ALGO_SHA_512;
                break;
            default:
                throw PKCS11Exception( CKR_GENERAL_ERROR );
                break;
            }
        }

        boost::shared_ptr< u1Array > signatureData;
        CAtomicLogin atomicLogin(this, false, eccKey->m_role);
        try {

            signatureData = m_Device->privateKeySign( eccKey->m_ucContainerIndex, eccKey->m_ucKeySpec, 0, ucAlgo, dataToSign, intermediateHash, hashCounter );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::sign", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }

        if( !signatureData ) {

            throw PKCS11Exception( CKR_FUNCTION_FAILED );
        }

        memcpy( pSignature, signatureData->GetBuffer( ), signatureData->GetLength( ) );
    }
}

bool Token::CheckStorageObjectExisting( StorageObject* a_pObject)
{
	Log::begin( "Token::CheckStorageObjectExisting" );

	bool bRet = false;

	// look for the object in our list
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

		if (a_pObject->m_stFileName != "")
		{
			// we use the filename on the card
			if (o->second->m_stFileName == a_pObject->m_stFileName)
			{
				Log::log( "CheckStorageObjectExisting - object found on internal list (filename check <%s>)", a_pObject->m_stFileName.c_str());
				bRet = true;
				break;
			}
		}
		else
		{
			// we use the object attributes
			if (o->second->isEqual(a_pObject))
			{
				Log::log( "CheckStorageObjectExisting - object found on internal list (attributes check)");
				bRet = true;
				break;
			}
		}
	}

	if (!bRet)
	{
		Log::log( "CheckStorageObjectExisting - object doesn't exist");
	}

	Log::end( "Token::CheckStorageObjectExisting" );
	return bRet;
}

/* Add a PKCS11 object to the token object list
*/
CK_OBJECT_HANDLE Token::registerStorageObject( StorageObject* a_pObject , bool bCheckExistence) {

    Log::begin( "Token::registerStorageObject" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        Log::error( "Token::registerStorageObject", "Invalid object" );
		Log::end( "Token::registerStorageObject" );
        return CK_UNAVAILABLE_INFORMATION;
    }

	CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;

	// check if the object already exists
	if ( bCheckExistence && CheckStorageObjectExisting(a_pObject) )
	{
        Log::log( "Token::registerStorageObject - object already exists. Skipping." );
		// we delete the object to free its memory
		delete a_pObject;
	}
	else
	{
		// increment the object index
		h = computeObjectHandle( a_pObject->getClass( ), a_pObject->isPrivate( ) );

		// Expand the object list
		m_Objects.insert( h, a_pObject );

		Log::log( "registerStorageObject - Handle <%#02x> - Type <%ld> - File <%s>", h, a_pObject->getClass( ), a_pObject->m_stFileName.c_str( ) );
		printObject( a_pObject );
	}

    t.stop( "Token::registerStorageObject" );
    Log::end( "Token::registerStorageObject" );

    // Return the object index
    return h;
}


/*
*/
void Token::printObject( StorageObject* a_pObject ) {

    if( !Log::s_bEnableLog ) {

        return;
    }

    Log::log( "    ====" );

    switch( a_pObject->getClass( ) ) {
        case CKO_DATA:
            Log::log( "Object CKO_DATA" );
            ( (DataObject*) a_pObject )->print( );
            break;

        case CKO_CERTIFICATE:
            Log::log( "Object CKO_CERTIFICATE" );
            ( (X509PubKeyCertObject*) a_pObject )->print( );
            break;

        case CKO_PRIVATE_KEY:
            Log::log( "Object CKO_PRIVATE_KEY" );
            ( (PrivateKeyObject*) a_pObject )->print( );
            //( (RSAPrivateKeyObject*) a_pObject )->print( );
            break;

        case CKO_PUBLIC_KEY:
            Log::log( "Object CKO_PUBLIC_KEY" );
            ( (Pkcs11ObjectKeyPublic*) a_pObject )->print( );
            //( (Pkcs11ObjectKeyPublicRSA*) a_pObject )->print( );
            break;

        case CKO_SECRET_KEY:
            Log::log( "Object CKO_SECRET_KEY" );
            ( (SecretKeyObject*) a_pObject )->print( );
            break;
    };

    Log::log( "    ====" );

}


/*
*/
void Token::unregisterStorageObject( const CK_OBJECT_HANDLE& a_pObject ) {

    Log::begin( "Token::unregisterStorageObject" );
    Timer t;
    t.start( );

    TOKEN_OBJECTS::iterator i = m_Objects.find( a_pObject );

    if( i != m_Objects.end( ) ) {

        m_Objects.erase( i );

        Log::log( "unregisterStorageObject - Handle <%#02x> erased", a_pObject );
    }

    t.stop( "Token::unregisterStorageObject" );
    Log::end( "Token::unregisterStorageObject" );
}


/*
*/
void Token::initPIN( u1Array* a_PinSo, u1Array* a_PinUser ) {

    Log::begin( "Token::initPIN" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    MiniDriverAuthentication::ROLES unblockRole;
    bool bPukAuthenticated = false;
    try {

        // if SO is a PUK, authenticate it first
        unblockRole = m_Device->getPinUnblockRole(getUserRole());
        if ( (unblockRole != MiniDriverAuthentication::PIN_ADMIN) && (a_PinSo->GetLength() > 0) && m_Device->isDotNetCard( ))
        {
            m_Device->verifyPin( unblockRole, a_PinSo);
            bPukAuthenticated = true;
        }
        // Initialize the PIN
        m_Device->unblockPin( getUserRole(), a_PinSo, a_PinUser );

        if ( bPukAuthenticated )
        {
            try { m_Device->logOut( unblockRole , false); } catch (...) {}
            bPukAuthenticated = false;
        }

        // ??? TO DO ??? Utiliser la proprieté card pin initalize
        m_TokenInfo.flags |= CKF_USER_PIN_INITIALIZED;

        // Reset some User PIN flags
        m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
        m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
        m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

    } catch( MiniDriverException& a_pEx) {
		if ( bPukAuthenticated )
		{
			try { m_Device->logOut( unblockRole , false); } catch (...) {}
		}
		checkAuthenticationStatus(CKU_SO, a_pEx);
    }

    t.stop( "Token::initPIN" );
    Log::end( "Token::initPIN" );
}


/*
*/
void Token::setPIN( u1Array* a_pOldPIN, u1Array* a_pNewPIN ) {

    Log::begin( "Token::setPIN" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    CK_ULONG usedRole = CKU_USER;
    // According the logical state of the slot the PIN is set for the user or the administrator
    // The logical state is based on the PKCS11 state of the slot's sessions
    try {

        if( m_pSlot->isAuthenticated( ) ) {
            m_Device->changePin( getUserRole(), a_pOldPIN, a_pNewPIN );

        } else if( m_pSlot->administratorIsAuthenticated( ) ) {
            usedRole = CKU_SO;
			MiniDriverAuthentication::ROLES unblockRole = m_Device->getPinUnblockRole(getUserRole());
			if (unblockRole == MiniDriverAuthentication::PIN_ADMIN)
				m_Device->administratorChangeKey( a_pOldPIN, a_pNewPIN );
			else
			{
				m_Device->changePin( unblockRole, a_pOldPIN, a_pNewPIN );
			}

        } else {
            m_Device->changePin( getUserRole(), a_pOldPIN, a_pNewPIN );
        }

    } catch( MiniDriverException& x ) {
        checkAuthenticationStatus( usedRole, x );
    }

    t.stop( "Token::setPIN" );
    Log::end( "Token::setPIN" );
}


/*
*/
void Token::initToken( u1Array* a_pinSO, u1Array* a_label ) {

    Log::begin( "Token::initToken" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check that label does not contain null-characters
    unsigned int l = a_label->GetLength( );

    for( unsigned int i = 0 ; i < l; ++i ) {

        if( !a_label->ReadU1At( i ) ) {

            throw PKCS11Exception( CKR_ARGUMENTS_BAD );
        }
    }

    // actual authentication
    authenticateAdmin( a_pinSO );

    try
    {
        // Synchronize all private objects to delete them
        synchronizePrivateDataObjects( );

        synchronizePrivateKeyObjects( );

        // Destroy all the token objects present into the PKCS11 directory
        // Note that when the private key is destroyed the associated container is also deleted
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

            // Delete the PKCS#11 object file from card
            deleteObjectFromCard( o->second );
        }

        // Destroy all PKCS11 objects from the inner list of objects to manage
        m_Objects.clear( );

        // Destroy all the token objects present into the MSCP directory
        try {

            m_Device->deleteFileStructure( );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::initToken", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }

        // Update the token's label and flags attribute.
        m_TokenInfo.flags |= CKF_TOKEN_INITIALIZED;

        m_TokenInfo.flags &= ~CKF_USER_PIN_INITIALIZED;

        memcpy( m_TokenInfo.label, a_label->GetBuffer( ), sizeof( m_TokenInfo.label ) );

        createTokenInfo( );

        // Write the new token information file into the smart card
        m_bWriteTokenInfoFile = true;

        writeTokenInfo( );

        // Log out
        m_Device->administratorLogout( );

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

    } catch( MiniDriverException& x) {

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

        try { m_Device->administratorLogout( ); } catch(...) {}

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::initToken" );
    Log::end( "Token::initToken" );
}


/*
*/
CK_OBJECT_HANDLE Token::computeObjectHandle( const CK_OBJECT_CLASS& a_ulClass, const bool& a_bIsPrivate ) {

    // Increment the object counter
    incrementObjectIndex( );

    // Register the token object id (value from 0 to 255)
    unsigned char ucByte1 = m_uiObjectIndex;

    // Register the object class and if the object is private:
    // Private Data	        1000 [08] = set class to CKO_DATA (0x00) and Private to TRUE (0x08)
    // Public Data	        0000 [00] = set class to CKO_DATA (0x00) and Private to FALSE (0x00)
    // Private Certificate	1001 [09] = set class to CKO_CERTIFICATE (0x01) and Private to TRUE (0x08)
    // Public Certificate	0001 [01] = set class to CKO_CERTIFICATE (0x01) and Private to FALSE (0x00)
    // Private Public Key	1010 [0A] = set class to CKO_PUBLIC_KEY (0x02) and Private to TRUE (0x08)
    // Public Public Key	0010 [02] = set class to CKO_PUBLIC_KEY (0x02) and Private to FALSE (0x00)
    // Private Private Key	1011 [0B] = set class to CKO_PRIVATE_KEY (0x03) and Private to TRUE (0x08)
    // Public Private Key	0011 [03] = set class to CKO_PRIVATE_KEY (0x03) and Private to FALSE (0x00)
    unsigned char ucByte2 = (unsigned char)a_ulClass | ( a_bIsPrivate ? 0x10 : 0x00 );

    // Register if the object is owned by the token (value 0) or the session (value corresponding to the session id from 1 to 255)
    unsigned char ucByte3 = 0;

    // Register the slot id
    unsigned char ucByte4 = 0xFF;

    if( m_Device ) {

       ucByte4 = (unsigned char) ( 0x000000FF & m_pSlot->getSlotId() );
    }



    // Compute the object handle: byte4 as Slot Id, byte3 as Token/Session, byte2 as attributes and byte1 as object Id
    CK_OBJECT_HANDLE h = ( ucByte4 << 24 ) + ( ucByte3 << 16 ) + ( ucByte2 << 8 )+ ucByte1;

    return h;
}


/*
*/
StorageObject* Token::getObject( const CK_OBJECT_HANDLE& a_hObject ) {

    TOKEN_OBJECTS::iterator i = m_Objects.find( a_hObject );

    if( i == m_Objects.end( ) ) {

        throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
    }

    return i->second;
}


/*
*/
void Token::synchronizeObjects( void ) {

    Log::begin( "Token::synchronizeObjects" );
    Timer t;
    t.start( );

    try {

        initializeObjectIndex( );

        // PIN changed, so re-synchronize
        synchronizePIN( );

        // Remove all PKCS11 objects
        m_Objects.clear( );

        // Files changed, so re-synchronize
        m_bSynchronizeObjectsPublic = true;
        synchronizePublicObjects( );

        m_bSynchronizeObjectsPrivate = true;
        synchronizePrivateObjects( );

    } catch( ... ) {

    }

    t.stop( "Token::synchronizeObjects" );
    Log::end( "Token::synchronizeObjects" );
}


/*
*/
bool Token::synchronizeIfSmartCardContentHasChanged( void ) {

    Log::begin( "Token::synchronizeIfSmartCardContentHasChanged" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    bool bSynchronizationPerformed = false;

    try {

        // Check if the smart card content has changed
        MiniDriverCardCacheFile::ChangeType pins = MiniDriverCardCacheFile::NONE;
        MiniDriverCardCacheFile::ChangeType containers = MiniDriverCardCacheFile::NONE;
        MiniDriverCardCacheFile::ChangeType files = MiniDriverCardCacheFile::NONE;
        m_Device->hasChanged( pins, containers, files );

        if( MiniDriverCardCacheFile::PINS == pins ) {

            // PIN changed, so re-synchronize
            synchronizePIN( );
        }

        if( ( MiniDriverCardCacheFile::CONTAINERS == containers ) || ( MiniDriverCardCacheFile::FILES == files ) ) {

            synchronizeObjects( );

            bSynchronizationPerformed = true;
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizeIfSmartCardContentHasChanged", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );

    }

    t.stop( "Token::synchronizeIfSmartCardContentHasChanged" );
    Log::end( "Token::synchronizeIfSmartCardContentHasChanged" );

    return bSynchronizationPerformed;
}

MiniDriverAuthentication::ROLES Token::getUserRole() const
{
    return m_pSlot->getUserRole();
}


/* Synchronise the cache with the smart card content
*/
void Token::synchronizePublicObjects( void ) {

    try {

        if( !m_bSynchronizeObjectsPublic ) {

            return;
        }
        m_bSynchronizeObjectsPublic = false;

        Log::begin( "Token::synchronizeObjectsPublic" );
        Timer t;
        t.start( );

        if (getUserRole() == MiniDriverAuthentication::PIN_USER)
        {
            synchronizeRootCertificateObjects( );

            synchronizePublicDataObjects( );
        }

        synchronizePublicCertificateAndKeyObjects( );

        t.stop( "Token::synchronizePublicObjects" );
        Log::end( "Token::synchronizePublicObjects" );

    } catch( ... ) {

    }
}


/*
*/
void Token::synchronizePrivateObjects( void ) {

    if( !m_bSynchronizeObjectsPrivate ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    try {

        // Synchronization of the private objects is only possible is the user is logged in

        //========= TEST
        if( m_pSlot && !m_pSlot->isAuthenticated()
            && (!m_Device->isSmartCardRecognized( ) || !m_Device->isNoPin( getUserRole()))

           ) {
        //if( !m_Device->isAuthenticated( ) ) {

            return;
        }

        Log::begin( "Token::synchronizeObjectsPrivate" );
        Timer t;
        t.start( );

        if (getUserRole() == MiniDriverAuthentication::PIN_USER)
        {
            synchronizePrivateDataObjects( );
        }

        synchronizePrivateKeyObjects( );

        synchronizeSecretKeyObjects( );

        m_bSynchronizeObjectsPrivate = false;

        t.stop( "Token::synchronizeObjectsPrivate" );
        Log::end( "Token::synchronizeObjectsPrivate" );

    } catch( ... ) {

        m_bSynchronizeObjectsPrivate = true;
    }

    //m_bSynchronizeObjectsPrivate = false;
}


/*
*/
void Token::synchronizePIN( void ) {

    try {

        Log::begin( "Token::synchronizePIN" );
        Timer t;
        t.start( );

        // ??? TO DO ???

        t.stop( "Token::synchronizePIN" );
        Log::end( "Token::synchronizePIN" );

    } catch( ... ) {

    }
}


/*
*/
void Token::synchronizeRootCertificateObjects( void ) {

    Log::begin( "Token::synchronizeRootCertificateObjects" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    unsigned char ucIndex = 0;
    unsigned char ucIndexMax = m_Device->containerCount( );

    try {

        // read roots from P11 only if p11 directory exists
        if( !m_bCreateDirectoryP11 ) {

           // Get all PKCS11 object files from the PKCS11 directory into the smart card
           MiniDriverFiles::FILES_NAME filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

           // Get all certificate files from the smart card
           MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

           std::string stPrefixMiniDriver = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );

           std::string stPrefixPKCS11 = g_stPrefixPublicObject + g_stPrefixRootCertificate;

           std::string stFilePKCS11 = "";

           // BOOST_FOREACH( const std::string& stFileMiniDriver, filesMiniDriver ) {
		   for (MiniDriverFiles::FILES_NAME::iterator iter = filesMiniDriver.begin () ; iter != filesMiniDriver.end (); ++iter) {
			   std::string& stFileMiniDriver = (std::string&)*iter;

               // All files must begin with a fixed prefix for public objects
               if( stFileMiniDriver.find( stPrefixMiniDriver ) != 0 ) {

                   // Only deal with objects corresponding to the incoming prefix
                   continue;
               }

               // The index of a root certificate is out of the range of the valid MiniDriver containers
               ucIndex = computeIndex( stFileMiniDriver );
               if ( ucIndex <= ucIndexMax ) {

                   continue;
               }

               stFilePKCS11 = stPrefixPKCS11;
               Util::toStringHex( ucIndex, stFilePKCS11 );

               MiniDriverFiles::FILES_NAME::iterator it = filesPKCS11.find( stFilePKCS11 );

 	       boost::shared_ptr<u1Array> pOID;

               if( it != filesPKCS11.end( ) ) {
                   // The PKCS11 object exists. Load it.
                   if (!createCertificateFromPKCS11ObjectFile( stFilePKCS11, stFileMiniDriver ))
                   {
                     // The PKCS11 object is not consistent with the one in the minidriver file. Create a memory object from the MiniDriver file.
                     createCertificateFromMiniDriverFile( stFileMiniDriver, MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID,  MiniDriverContainer::KEYSPEC_SIGNATURE,pOID );
                   }

               } else {

                   // The PKCS11 object does not exists. Create a memory object from the MiniDriver file.
                   createCertificateFromMiniDriverFile( stFileMiniDriver, MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID,  MiniDriverContainer::KEYSPEC_SIGNATURE , pOID);
               }
           }
        }

         std::string stPathCertificateRoot( szROOT_STORE_FILE );
         std::unique_ptr< u1Array > pCompressedRoots;

         try {

            pCompressedRoots.reset( m_Device->readFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot ) );
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

               if (Util::ParsePkcs7(pRoots->GetBuffer(), pRoots->GetLength(), certList))
               {
	               for (std::list<X509*>::iterator It = certList.begin(); It != certList.end(); It++)
	               {
	                  // check if it exists
	                  bool bFound = false;
                     BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects )
                     {
                        if( CKO_CERTIFICATE == o->second->getClass( ) )
                        {
                           X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) o->second;
                           if (objCertificate->m_pValue)
                           {
                              unsigned char* ptr = objCertificate->m_pValue->GetBuffer();
                              X509* pCert = d2i_X509(NULL, (const unsigned char**) &ptr, objCertificate->m_pValue->GetLength());
                              if (pCert)
                              {
                                 if (X509_cmp(pCert, *It) == 0)
                                    bFound = true;
                                 X509_free(pCert);
                                 if (bFound)
                                    break;
                              }
                           }
		                  }
	                  }

                     if (!bFound)
                     {
                        // The Root certificate object does not exists. Create a memory object from the certificate value.
                        unsigned char* pbCert = NULL;
                        int certLen = i2d_X509(*It, &pbCert);
                        try
                        {
                           createRootCertificateFromValue( pbCert, certLen, MiniDriverContainer::KEYSPEC_SIGNATURE );
                        }
                        catch(...) {}
                        if (pbCert)
                           OPENSSL_free(pbCert);
                     }
	               }

                  Util::FreeCertList(certList);
               }
            }

         } catch( ... ) {}

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizeRootCertificateObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizeRootCertificateObjects" );
    Log::end( "Token::synchronizeRootCertificateObjects" );
}


/* Read all public data
*/
void Token::synchronizePublicDataObjects( void ) {

    Log::begin( "Token::synchronizePublicDataObjects" );
    Timer t;
    t.start( );

    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME files = m_Device->enumFiles( g_stPathPKCS11 );

        std::string a_stPrefix = g_stPrefixPublicObject + g_stPrefixData;

        // BOOST_FOREACH( const std::string& s, files ) {
		for (MiniDriverFiles::FILES_NAME::iterator iter = files.begin () ; iter != files.end (); ++iter) {
			std::string& s = (std::string&)*iter;

            // All files must begin with a fixed prefix for public objects
            if( s.find( a_stPrefix ) != 0 ) {

                // Only deal with objects corresponding to the incoming prefix
                continue;
            }

            // Read the file
            std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, s ) );

            // Construct the PKCS11 object attributes from the file
            std::vector< unsigned char > attributes;

            unsigned int l = f->GetLength( );

            for( unsigned int u = 0 ; u < l ; ++u ) {

                attributes.push_back( f->GetBuffer( )[ u ] );
            }

            // Create the PKCS11 object
            DataObject* o = new DataObject( );

            // Put the file content into the object
            CK_ULONG idx = 0;
            o->deserialize( attributes, &idx );

            // Save the fileName in the object
            o->m_stFileName = s;

            Log::log( "Found %s - Public data object created", s.c_str( ) );

            registerStorageObject( o );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizePublicDataObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizePublicDataObjects" );
    Log::end( "Token::synchronizePublicDataObjects" );
}


/* Read all private data
*/
void Token::synchronizePrivateDataObjects( void ) {

    Log::begin( "Token::synchronizePrivateDataObjects" );
    Timer t;
    t.start( );

    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME files = m_Device->enumFiles( g_stPathPKCS11 );

        std::string a_stPrefix = g_stPrefixPrivateObject + g_stPrefixData;

        // BOOST_FOREACH( const std::string& s, files ) {
		for (MiniDriverFiles::FILES_NAME::iterator iter = files.begin () ; iter != files.end (); ++iter) {
			std::string& s = (std::string&)*iter;

            // All files must begin with a fixed prefix for public objects
            if( s.find( a_stPrefix ) != 0 ) {

                // Only deal with objects corresponding to the incoming prefix
                continue;
            }

            // Read the file
            std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, s ) );

            // Construct the PKCS11 object attributes from the file
            std::vector< unsigned char > attributes;

            unsigned int l = f->GetLength( );

            for( unsigned int u = 0 ; u < l ; ++u ) {

                attributes.push_back( f->GetBuffer( )[ u ] );
            }

            // Create the PKCS11 object
            DataObject* o = new DataObject( );

            // Put the file content into the object
            CK_ULONG idx = 0;
            o->deserialize( attributes, &idx );

            // Save the fileName in the object
            o->m_stFileName = s;

            Log::log( "Found %s - Private data created", s.c_str( ) );

            registerStorageObject( o );

            m_Device->cacheDisable( s );
        }

    } catch( MiniDriverException& ) {

        Log::error( "Token::synchronizePrivateDataObjects", "MiniDriverException" );
    }

    t.stop( "Token::synchronizePrivateDataObjects" );
    Log::end( "Token::synchronizePrivateDataObjects" );
}


/*
*/
bool Token::checkSmartCardContent( void ) {

    Log::begin( "Token::checkSmartCardContent" );
    Timer t;
    t.start( );

    if( m_bCheckSmartCardContentDone ) {

        return false;
    }

    if (Log::s_bEnableLog)
    {
        Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj BEFORE P11 clean");
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

            printObject( o.second );
        }
        Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj BEFORE P11 clean");
    }


    bool bReturn = false;

    if( !m_Device ) {

        return bReturn;
    }

    // Get all PKCS11 object files from the PKCS11 directory into the smart card
    MiniDriverFiles::FILES_NAME filesPKCS11;

    if( !m_bCreateDirectoryP11 ) {

        try {

            filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

        } catch( ... ) { }
    }

    // We don't perform this check in virtual slots because it is already done on the main slot
    // and it involves only moving certificates associated to empty containers to the PKCS11 tree
    if (!m_pSlot->isVirtual())
    {
        // Get all certificate files from the smart card
        MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

        std::string stContainerIndex = "";
        unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
        std::string stPrefix = "";
        std::string stCertificateFileName = "";
        std::string stObjectPKCS11 = "";
        std::string stPublicCertificateExchange = g_stPrefixPublicObject + std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );
        std::string stPublicCertificateSignature = g_stPrefixPublicObject + std::string( szUSER_SIGNATURE_CERT_PREFIX );
        std::string stPublicKey = g_stPrefixPublicObject + g_stPrefixKeyPublic;
        std::string stPrivateKey = g_stPrefixPrivateObject + g_stPrefixKeyPrivate;
        unsigned char ucKeyContainerIndexReal = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
        std::string stFileName = "";

        try {

            // Explore each smart card key container to fix any CMapFile anomaly or wrong associated certificate
            unsigned char ucContainerCount = m_Device->containerCount( );

            for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

                stContainerIndex = "";
                Util::toStringHex( ucContainerIndex, stContainerIndex );

                // Get the current container
                MiniDriverContainer cont = m_Device->containerGet( ucContainerIndex );

                Log::log( "=========" );
                Log::log( "Token::checkSmartCardContent - Container <%d>", ucContainerIndex );

                unsigned char flags = cont.getFlags( );
                if ( flags == MiniDriverContainer::CMAPFILE_FLAG_EMPTY ) {

                    // The current container is empty

                    // Check that none P11 object is associated to this container
                    // If a P11 object using this index then it must be associated to the good container or be deleted

                    // Check that none MiniDriver certificate is associated to this container
                    // If a MiniDriver certificate exists then it must be associated to the good contained or be deleted
                    // It could also be a root certificate enrolled by an old P11 version

                    // Check the container properties is compliant with the CMapFile state
                    // If the CMapFile state shows a type (signature/exchange), a size (1024/2048) or a state (empty/valid/valid & default) different
                    // from the information given by the container property then the CMapFile must be changed

                    Log::log( "Token::checkSmartCardContent - This container is empty" );

                    stCertificateFileName = szUSER_KEYEXCHANGE_CERT_PREFIX;
                    stCertificateFileName += stContainerIndex;
                    Log::log( "Token::checkSmartCardContent - Check if the certificate <%s> is present", stCertificateFileName.c_str( ) );

                    MiniDriverFiles::FILES_NAME::iterator it = filesMiniDriver.find( stCertificateFileName );

                    if( it != filesMiniDriver.end( ) ) {

                        // The container is empty but a certificate is associated into the MiniDriver file structure.
                        // That certificate must be moved from the MiniDriver file structure to the PKCS11 one.

                        // Create a new root certificate
                        X509PubKeyCertObject* pNewCertificate = new X509PubKeyCertObject( );

                        pNewCertificate->m_stCertificateName = "";

                        pNewCertificate->m_stFileName = "";

                        pNewCertificate->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

                        try {

                            // Read the file
                            m_Device->readCertificate( stCertificateFileName, pNewCertificate->m_pValue );

                        } catch( MiniDriverException& ) {

                            // Unable to read the on card certificate.
                            // The P11 object creation is skipped.
                            Log::error( "Token::createCertificateFromMiniDriverFile", "Unable to read the certificate" );
                            continue;
                        }

                        if( pNewCertificate->m_pValue.get( ) ) {

                            generatePublicKeyValue( pNewCertificate->m_pValue, pNewCertificate->m_pPublicKeyValue, pNewCertificate->m_bIsRSA, pNewCertificate->m_ucKeySpec, pNewCertificate->_checkValue , pNewCertificate->m_pOID);

                            generateRootAndSmartCardLogonFlags( pNewCertificate->m_pValue, pNewCertificate->m_bIsRoot, pNewCertificate->_certCategory, pNewCertificate->m_bIsSmartCardLogon );
                        }

                        // Delete the old certificate from the MiniDriver file structure
                        m_Device->deleteFile( std::string( szBASE_CSP_DIR ), stCertificateFileName );
                        Log::log( "Token::checkSmartCardContent - delete <%s> in MSCP dir", stCertificateFileName.c_str( ) );
                        bReturn = true;

                        // Remove the previous PKCS11 certificate associated to the MiniDriver certificate
                        std::string stIndex = stCertificateFileName.substr( stCertificateFileName.length( ) - 2, 2 );
                        std::string stPKCS11CertificateName = stPublicCertificateExchange + stIndex;
                        m_Device->deleteFile( g_stPathPKCS11, stPKCS11CertificateName );
                        Log::log( "Token::checkSmartCardContent - delete <%s> in P11 dir", stPKCS11CertificateName.c_str( ) );

                        //// Delete the PKCS#11 object from inner list of managed objects
                        //unregisterStorageObject( p );
                        //Log::log( "Token::checkSmartCardContent - delete <%s> in MSCP dir", stCertificateFileName.c_str( ) );

                        // Create the new root certificate intot the MniDriver & PKCS11 file structures
                        CK_OBJECT_HANDLE h = CK_UNAVAILABLE_INFORMATION;
                        addObjectCertificate( pNewCertificate, &h );
                        Log::log( "Token::checkSmartCardContent - add new P11 root certificate <%s>", pNewCertificate->m_stFileName.c_str( ) );

                        pNewCertificate->m_stCertificateName = pNewCertificate->m_stFileName.substr( 3, 5 );

                        // Delete the container from the MiniDriver file structure
                        m_Device->containerDelete( ucContainerIndex, 0 );
                        Log::log( "Token::checkSmartCardContent - delete container <%d>", ucContainerIndex );

                        // Check if a private or a public key was associated to this container
                        std::string stPrefix = stPrivateKey;

                        do {

                            stObjectPKCS11 = stPrefix + stIndex;

                            MiniDriverFiles::FILES_NAME::iterator it = filesPKCS11.find( stObjectPKCS11 );

                            if( it != filesPKCS11.end( ) ) {

                                // The PKCS11 private/public key exists.
                                // Check the public key modulus to find a new container to associate with

                                // Read the file
                                std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, stObjectPKCS11 ) );

                                // Construct the PKCS11 object attributes from the file
                                std::vector< unsigned char > attributes;

                                unsigned int l = f->GetLength( );

                                for( unsigned int u = 0 ; u < l ; ++u ) {

                                    attributes.push_back( f->GetBuffer( )[ u ] );
                                }

                                // Create the PKCS11 object from the file content
                                boost::shared_ptr< StorageObject > oldObjectOnCard;
                                KeyObject helperObj;
                                bool bIsRSA = false;

                                CK_ULONG idx = 0;

                                helperObj.deserialize( attributes, &idx );

                                bIsRSA = (helperObj._keyType == CKK_RSA);

                                idx = 0;

                                if( stPrefix.compare( stPublicKey ) == 0 ) {

                                    if (bIsRSA)
                                    {
                                        oldObjectOnCard.reset( new Pkcs11ObjectKeyPublicRSA );
                                        ( ( Pkcs11ObjectKeyPublicRSA* ) oldObjectOnCard.get( ) )->deserialize( attributes, &idx );
                                    }
                                    else
                                    {
                                        oldObjectOnCard.reset( new Pkcs11ObjectKeyPublicECC );
                                        ( ( Pkcs11ObjectKeyPublicECC* ) oldObjectOnCard.get( ) )->deserialize( attributes, &idx );
                                    }

                                } else {

                                    if (bIsRSA)
                                    {
                                        oldObjectOnCard.reset( new RSAPrivateKeyObject );
                                        ( ( RSAPrivateKeyObject* ) oldObjectOnCard.get( ) )->deserialize( attributes, &idx );
                                    }
                                    else
                                    {
                                        oldObjectOnCard.reset( new ECCPrivateKeyObject );
                                        ( ( ECCPrivateKeyObject* ) oldObjectOnCard.get( ) )->deserialize( attributes, &idx );
                                    }
                                }

                                // Set the old file name
                                oldObjectOnCard->m_stFileName = stObjectPKCS11;

                                // Get the container index written into the object
                                unsigned char ucKeyContainerIndexInObject = ( ( KeyObject* ) oldObjectOnCard.get( ) )->m_ucContainerIndex;
                                Log::log( "Token::checkSmartCardContent - Container index found into the P11 object <%d>", ucKeyContainerIndexInObject );

                                // Get the container index set into the file name
                                unsigned char ucKeyContainerIndexInFileName = computeIndex( stIndex );
                                Log::log( "Token::checkSmartCardContent - Container index found into the P11 file name <%d>", ucKeyContainerIndexInFileName );

                                // Get the public key modulus
                                u1Array* pPublicKeyValue = NULL;

                                if( 0 == stPrefix.compare( stPublicKey ) ) {

                                    if (bIsRSA)
                                        pPublicKeyValue = ( ( Pkcs11ObjectKeyPublicRSA* ) oldObjectOnCard.get( ) )->m_pModulus.get( );
                                    else
                                        pPublicKeyValue = ( ( Pkcs11ObjectKeyPublicECC* ) oldObjectOnCard.get( ) )->m_pPublicPoint.get( );

                                } else {

                                    if (bIsRSA)
                                        pPublicKeyValue = ( ( RSAPrivateKeyObject* ) oldObjectOnCard.get( ) )->m_pModulus.get( );
                                    else
                                        pPublicKeyValue = ( ( ECCPrivateKeyObject* ) oldObjectOnCard.get( ) )->m_pPublicPoint.get( );
                                }

                                if( pPublicKeyValue ) {

                                    if (bIsRSA)
                                        Log::logCK_UTF8CHAR_PTR( "Token::checkSmartCardContent - File RSA Public key modulus", pPublicKeyValue->GetBuffer( ), pPublicKeyValue->GetLength( ) );
                                    else
                                        Log::logCK_UTF8CHAR_PTR( "Token::checkSmartCardContent - File ECC Public key point Q", pPublicKeyValue->GetBuffer( ), pPublicKeyValue->GetLength( ) );

                                    // Search for a container using the same public key container
                                    ucKeyContainerIndexReal = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
                                    ucKeySpec = 0xFF;
                                    stFileName = "";
                                    m_Device->containerGetMatching( getUserRole(), ucKeyContainerIndexReal, ucKeySpec, stFileName, pPublicKeyValue );
                                    Log::log( "Token::checkSmartCardContent - Real container index found comparing the public key modulus of each container with the P11 object one <%d>", ucKeyContainerIndexReal );

                                    // Compare the container index defined in the PKCS11 object with the container index using that public key modulus
                                    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == ucKeyContainerIndexReal ) {

                                        // No container exists into the smart card matching with the public key set into the P11 object
                                        // This object should be deleted
                                        Log::log( "Token::checkSmartCardContent - No inner container index for <%s>", stObjectPKCS11.c_str( ) );

                                    } else if( ucKeyContainerIndexInFileName != ucKeyContainerIndexReal ) {

                                        // The both index are different !

                                        CK_OBJECT_HANDLE h = CK_UNAVAILABLE_INFORMATION;
                                        if( stPrefix.compare( stPublicKey ) == 0 ) {

                                            Pkcs11ObjectKeyPublic* pNewKey;

                                            if (bIsRSA)
                                                pNewKey = new Pkcs11ObjectKeyPublicRSA( ( const Pkcs11ObjectKeyPublicRSA* ) oldObjectOnCard.get( ) );
                                            else
                                                pNewKey = new Pkcs11ObjectKeyPublicECC( ( const Pkcs11ObjectKeyPublicECC* ) oldObjectOnCard.get( ) );

                                            // Set the good container index into the PKCS11 object
                                            pNewKey->m_ucContainerIndex = ucKeyContainerIndexReal;

                                            // Set the good file name in to the PKCS11 object
                                            pNewKey->m_stFileName = stPrefix;
                                            Util::toStringHex( ucKeyContainerIndexReal, pNewKey->m_stFileName );

                                            // Create the new root certificate
                                            addObject( pNewKey, &h );

                                            //m_bSynchronizeObjectsPublic = true;

                                            Log::log( "Token::checkSmartCardContent - add new P11 public key <%s>", pNewKey->m_stFileName.c_str( ) );

                                        } else {

                                            PrivateKeyObject* pNewKey;

                                            if (bIsRSA)
                                                pNewKey = new RSAPrivateKeyObject( ( const RSAPrivateKeyObject* ) oldObjectOnCard.get( ) );
                                            else
                                                pNewKey = new ECCPrivateKeyObject( ( const ECCPrivateKeyObject* ) oldObjectOnCard.get( ) );

                                            // Set the good container index into the PKCS11 object
                                            pNewKey->m_ucContainerIndex = ucKeyContainerIndexReal;

                                            // Set the good file name in to the PKCS11 object
                                            pNewKey->m_stFileName = stPrefix;
                                            Util::toStringHex( ucKeyContainerIndexReal, pNewKey->m_stFileName );

                                            // Create the new root certificate
                                            addObject( pNewKey, &h );

                                            //m_bSynchronizeObjectsPrivate = true;

                                            Log::log( "Token::checkSmartCardContent - add new P11 private key <%s>", pNewKey->m_stFileName.c_str( ) );
                                        }

                                        // Delete the old PKCS#11 object & MiniDriver file/container from card
                                        m_Device->deleteFile( g_stPathPKCS11, oldObjectOnCard->m_stFileName );
                                        Log::log( "Token::checkSmartCardContent - delete old P11 key <%s>", oldObjectOnCard->m_stFileName.c_str( ) );

                                        // Delete the old PKCS#11 object from inner list of managed objects
                                        TOKEN_OBJECTS::iterator i = m_Objects.begin( );
                                        while( i != m_Objects.end( ) ) {

                                            if( 0 == i->second->m_stFileName.compare( oldObjectOnCard->m_stFileName ) ) {

                                                m_Objects.erase( i );

                                                break;
                                            }

                                            ++i;
                                        }
                                    }

                                } else {

                                    // The public key modulus is missing. The public/private key is not well formated
                                    if (bIsRSA)
                                        Log::log( "Token::checkSmartCardContent - No RSA modulus for <%s>", stObjectPKCS11.c_str( ) );
                                    else
                                        Log::log( "Token::checkSmartCardContent - No ECC public point for <%s>", stObjectPKCS11.c_str( ) );
                                }
                            }

                            if( stPrefix.compare( stPrivateKey ) == 0 ) {

                                stPrefix = stPublicKey;

                            } else if( stPrefix.compare( stPublicKey ) == 0 ) {

                                stPrefix ="";
                                break;
                            }

                        } while( 0 != stPrefix.compare( "" ) );
                    }
                }
            }
        } catch( MiniDriverException& ) {

            Log::error( "Token::checkSmartCardContent", "MiniDriverException" );
        }
    }

    if (Log::s_bEnableLog)
    {
        Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj after P11 clean");
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

            printObject( o.second );
        }
        Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj after P11 clean");
    }

    t.stop( "Token::checkSmartCardContent" );
    Log::end( "Token::checkSmartCardContent" );

    m_bCheckSmartCardContentDone = true;

    return bReturn;
}


/*
*/
void Token::synchronizePublicCertificateAndKeyObjects( void ) {

    Log::begin( "Token::synchronizePublicCertificateAndKeyObjects" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME filesPKCS11;

        if( !m_bCreateDirectoryP11 ) {

            try {

                filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

            } catch( ... ) {

            }
        }

        // Get all certificate files from the smart card
        MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

        std::string stContainerIndex = "";
        unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
        unsigned int uiKeySize = 0;
        std::string stPrefix = "";
        std::string stCertificateFileName = "";
        std::string stObjectPKCS11 = "";

        // Explore each smart card key container
        unsigned char ucContainerCount = m_Device->containerCount( );
        MiniDriverAuthentication::ROLES userRole = getUserRole();

        for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

            stContainerIndex = "";
            Util::toStringHex( ucContainerIndex, stContainerIndex );

            // Get the current container
            MiniDriverContainer& c = m_Device->containerGet( ucContainerIndex );

            // Only deal with valid containers that are associated with our role
            if(     (MiniDriverContainer::CMAPFILE_FLAG_EMPTY != c.getFlags( ) )
                &&  (   (c.getPinIdentifier() == userRole)
                    ||  (m_Device->isNoPin(c.getPinIdentifier()) && m_Device->isNoPin(userRole))
                    )
                )
            {
				Log::log( "Token::synchronizePublicCertificateAndKeyObjects - <%d> valid container", ucContainerIndex );
				// check both exchange and signature keys
				for (int i = 0; i < 2; i++)
				{
					int retryCounter = 0;
					boost::shared_ptr< u1Array > pPublicKeyExponent, pPublicKeyModulus, pEccPublicKey;
                                        boost::shared_ptr< u1Array > pOID;
retryContainer:
					// Get the key information
					if (i == 0)
					{
						ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

						uiKeySize = c.getKeyExchangeSizeBits( );

						pPublicKeyExponent = c.getExchangePublicKeyExponent( );

						pPublicKeyModulus = c.getExchangePublicKeyModulus( );

						pEccPublicKey = c.getEcdhePointDER();

						if (pEccPublicKey.get())
							ucKeySpec = c.getEcdheKeySpec();

						stPrefix = szUSER_KEYEXCHANGE_CERT_PREFIX;
					}
					else
					{
						ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

						uiKeySize = c.getKeySignatureSizeBits( );

						pPublicKeyExponent = c.getSignaturePublicKeyExponent( );

						pPublicKeyModulus = c.getSignaturePublicKeyModulus( );

						pEccPublicKey = c.getEcdsaPointDER();

						if (pEccPublicKey.get())
							ucKeySpec = c.getEcdsaKeySpec();

						stPrefix = szUSER_SIGNATURE_CERT_PREFIX;
					}

	                if( !uiKeySize )
					{
						Log::log( "Token::synchronizePublicCertificateAndKeyObjects - no %s key", (i == 0)? "Exchange" : "Signature" );
						continue;
					}

					Log::log( "Token::synchronizePublicCertificateAndKeyObjects - KeySpec=<%d> KeySize=<%d> PubExp=<%p> PubMod=<%p> EccPub=<%p>", ucKeySpec, uiKeySize, pPublicKeyExponent.get(), pPublicKeyModulus.get(), pEccPublicKey.get());

					if (!pEccPublicKey.get() && (!pPublicKeyExponent.get() || !pPublicKeyModulus.get()))
					{
						if (retryCounter == 0)
						{
							Log::log( "Token::synchronizePublicCertificateAndKeyObjects - inconsistency discovered. Reading container.");
							try
							{
								// Populate the container info (throws if the container is empty)
								boost::shared_ptr< u1Array > ci( m_Device->getContainer( ucContainerIndex ) );

								c.setContainerInformation( ci );
							}
							catch(MiniDriverException&)
							{
								Log::log( "Token::synchronizePublicCertificateAndKeyObjects - error while reading container. Skipping.");
								//Continue reading the cert  objects do not break;
							}

							retryCounter++;
							goto retryContainer;
						}
						else
						{
							Log::log( "Token::synchronizePublicCertificateAndKeyObjects - Container still inconsistent after retry. Skipping.");
							//Continue reading the cert objects do not break;
						}
					}

					// Build the certificate file name associated to this container
					stCertificateFileName = stPrefix + stContainerIndex;

					// Locate the associated certificate into the MiniDriver file structure
					bool bExistsMSCPFile = isFileExists( stCertificateFileName, filesMiniDriver );

					//??? TO ??? si le fichier n'existe pas il faut supprimer le container

					Log::log( "Token::synchronizePublicCertificateAndKeyObjects - check for <%s> - Exists in MSCP <%d>", stCertificateFileName.c_str( ), bExistsMSCPFile );

					// A public PKCS11 certificate object must exist on cache and on card to represent this MiniDriver certificate
					stObjectPKCS11 = g_stPrefixPublicObject + stCertificateFileName;

					// Does this certificate also exist as a PKCS11 object ?
					bool bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );

					Log::log( "Token::synchronizePublicCertificateAndKeyObjects - check for <%s> - Exists in P11 <%d>", stObjectPKCS11.c_str( ), bExistsPKCS11Object );

					if( bExistsMSCPFile ) {

						// The associated certificate exists into the mscp directory

						if( bExistsPKCS11Object ) {

							// The PCKS11 certificate object exists

							// Load the PKCS11 object from the already existing PKCS11 file
							try {

								if (!createCertificateFromPKCS11ObjectFile( stObjectPKCS11, stCertificateFileName ))
								{
									Log::log( "**************************************************** [P11 cert exists but not consistent with the one in mscp. Using the minidriver certificate instead] - <%s> <%s>", stObjectPKCS11.c_str( ), stCertificateFileName.c_str( ) );
									// The PKCS11 object is not consistent with the one in the minidriver file. Create a memory object from the MiniDriver file.
									createCertificateFromMiniDriverFile( stCertificateFileName, ucContainerIndex, ucKeySpec , pOID);
								}

							} catch( ... ) {

								Log::log( "**************************************************** CASE #1 [P11 cert exists but not possible read] - <%s> <%s>", stObjectPKCS11.c_str( ), stCertificateFileName.c_str( ) );

								// Create the PKCS11 object from the MSCP file
								createCertificateFromMiniDriverFile( stCertificateFileName, ucContainerIndex, ucKeySpec , pOID);

								//m_ObjectsToDelete.push_back( stObjectPKCS11 );
							}

						} else {

							// The PKCS11 file does not exist

							// Create the PKCS11 object from the MSCP file
							createCertificateFromMiniDriverFile( stCertificateFileName, ucContainerIndex, ucKeySpec, pOID );
						}

					} else {

						// The associated certificate does not exist into the mscp directory

						// If a old corresponding PKCS11 object exists then delete it
						if( bExistsPKCS11Object ) {

							Log::log( "**************************************************** CASE #2 [P11 cert exists but no associated KXC] - <%s> <%s>", stObjectPKCS11.c_str( ), stCertificateFileName.c_str( ) );

							// NO DELETE
							//m_ObjectsToDelete.push_back( stObjectPKCS11 );
						}
					}

					// Locate the associated PUBLIC key
					// Build the public key file name associated to this container
					stObjectPKCS11 = g_stPrefixPublicObject + g_stPrefixKeyPublic + stContainerIndex;

					// Does this public key also exist as a PKCS11 object ?
					bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );

					if( bExistsPKCS11Object ) {

						// The PCKS11 public key object exists
						// Create the PKCS11 object from the already existing PKCS11 file
						try {

							createPublicKeyFromPKCS11ObjectFile( stObjectPKCS11 );

						} catch( ... ) {

							Log::log( "**************************************************** CASE #3 [P11 pub key exists but no read possible] - <%s>", stObjectPKCS11.c_str( ) );

							if (pEccPublicKey.get())
								createPublicKeyFromMiniDriverFile( stObjectPKCS11, ucContainerIndex, ucKeySpec, NULL, pEccPublicKey.get( ), pOID );
							else
								createPublicKeyFromMiniDriverFile( stObjectPKCS11, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ), pOID );

							//stObjectPKCS11 = g_stPrefixPublicObject + std::string( szUSER_SIGNATURE_CERT_PREFIX ) + stContainerIndex;
							//m_ObjectsToDelete.push_back( stObjectPKCS11 );
						}

					} else {

						// The PKCS11 public key object does not exist
						// Create the PKCS11 object from the MSCP key container
						if (pEccPublicKey.get())
							createPublicKeyFromMiniDriverFile( stObjectPKCS11, ucContainerIndex, ucKeySpec, NULL, pEccPublicKey.get( ), pOID );
						else
							createPublicKeyFromMiniDriverFile( stObjectPKCS11, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) , pOID);
					}

					if (!m_Device->supportsDualKeyContainers ())
						break;
				}

            } else {

                // The container is empty
                Log::log( "Token::synchronizePublicCertificateAndKeyObjects - <%d> empty container", ucContainerIndex );
            }
        }

        // update the label of memory-only certificates to match the one from the associated public key
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {
        if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

				  X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;
				  if (objCertificate->m_bOffCardObject)
				  {
					  BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj2, m_Objects ) {
						  if( CKO_PUBLIC_KEY == obj2->second->getClass( ) ) {

								Pkcs11ObjectKeyPublic* objPublicKey = (Pkcs11ObjectKeyPublic*) obj2->second;
								if (objPublicKey->m_ucContainerIndex == objCertificate->m_ucContainerIndex)
								{
									// we use only stored P11 public key
									if (!objPublicKey->m_bOffCardObject)
									{
										// Set the same CKA_ID
										if( objPublicKey->m_pID.get( ) ) {

											 objCertificate->m_pID.reset( new u1Array( *( objPublicKey->m_pID.get( ) ) ) );
										}

										// Set the same CKA_LABEL
										if( objPublicKey->m_pLabel.get( ) ) {

											 objCertificate->m_pLabel.reset( new u1Array( *( objPublicKey->m_pLabel.get( ) ) ) );
										}
									}
									break;
								}
						  }
					  }
				  }
			  }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizePublicCertificateAndKeyObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizePublicCertificateAndKeyObjects" );
    Log::end( "Token::synchronizePublicCertificateAndKeyObjects" );
}


/*
*/
void Token::synchronizePrivateKeyObjects( void ) {

    Log::begin( "Token::synchronizePrivateKeyObjects" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME filesPKCS11;

        if( !m_bCreateDirectoryP11 ) {

            try {

                filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

            } catch( ... ) {

            }
        }

        // Get all certificate files from the smart card
        MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

        std::string stContainerIndex = "";
        unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
        unsigned int uiKeySize = 0;
        std::string stPrefix = "";
        std::string stCertificateFileName = "";
        std::string stKeyFileName = "";
        bool bExistsPKCS11Object = false;

        // Explore each smart card key container
        unsigned char ucContainerCount = m_Device->containerCount( );
        MiniDriverAuthentication::ROLES userRole = getUserRole();

        for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

            // Get the current container
            MiniDriverContainer& c = m_Device->containerGet( ucContainerIndex );

            // Build the certificate file name associated to this container
            stContainerIndex = "";
            Util::toStringHex( ucContainerIndex, stContainerIndex );

            // Locate the associated PRIVATE key
            // Build the private key file name associated to this container
            stKeyFileName = g_stPrefixPrivateObject + g_stPrefixKeyPrivate + stContainerIndex;

            // Does this private key also exist as a PKCS11 object ?
            bExistsPKCS11Object = isFileExists( stKeyFileName, filesPKCS11 );

            // Only deal with valid containers that are associated with our role
            if(     (MiniDriverContainer::CMAPFILE_FLAG_EMPTY != c.getFlags( ) )
                &&  (   (c.getPinIdentifier() == userRole)
                    ||  (m_Device->isNoPin(c.getPinIdentifier()) && m_Device->isNoPin(userRole))
                    )
                )
            {
				Log::log( "Token::synchronizePrivateKeyObjects - <%d> valid container", ucContainerIndex );
				// check both exchange and signature keys
				for (int i = 0; i < 2; i++)
				{
					int retryCounter = 0;
					boost::shared_ptr< u1Array > pPublicKeyExponent, pPublicKeyModulus, pEccPublicKey;
					try
					{
retryPrivateKeyContainer:
						if (i == 0)
						{
							// Get the key information
							ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

							uiKeySize = c.getKeyExchangeSizeBits( );

							pPublicKeyExponent = c.getExchangePublicKeyExponent( );

							pPublicKeyModulus = c.getExchangePublicKeyModulus( );

							pEccPublicKey = c.getEcdhePointDER();

							if (pEccPublicKey.get())
								ucKeySpec = c.getEcdheKeySpec();

							stPrefix = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );
						}
						else
						{
							ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

							uiKeySize = c.getKeySignatureSizeBits( );

							pPublicKeyExponent = c.getSignaturePublicKeyExponent( );

							pPublicKeyModulus = c.getSignaturePublicKeyModulus( );

							pEccPublicKey = c.getEcdsaPointDER();

							if (pEccPublicKey.get())
								ucKeySpec = c.getEcdsaKeySpec();

							stPrefix = std::string( szUSER_SIGNATURE_CERT_PREFIX );
						}


						if( !uiKeySize )
						{
							Log::log( "Token::synchronizePrivateKeyObjects - no %s key", (i == 0)? "Exchange" : "Signature" );
							continue;
						}


						Log::log( "Token::synchronizePrivateKeyObjects - KeySpec=<%d> KeySize=<%d> PubExp=<%p> PubMod=<%p> EccPub=<%p>", ucKeySpec, uiKeySize, pPublicKeyExponent.get(), pPublicKeyModulus.get(), pEccPublicKey.get());

						if (!pEccPublicKey.get() && (!pPublicKeyExponent.get() || !pPublicKeyModulus.get()))
						{
							if (retryCounter == 0)
							{
								Log::log( "Token::synchronizePrivateKeyObjects - inconsistency discovered. Reading container.");
								try
								{
									// Populate the container info (throws exception if the container is empty)
									boost::shared_ptr< u1Array > ci( m_Device->getContainer( ucContainerIndex ) );

									c.setContainerInformation( ci );
								}
								catch(MiniDriverException&)
								{
									Log::log( "Token::synchronizePrivateKeyObjects - error while reading container. Skipping.");
									break;
								}

								retryCounter++;
								goto retryPrivateKeyContainer;
							}
							else
							{
								Log::log( "Token::synchronizePrivateKeyObjects - Container still inconsistent after retry. Skipping.");
								break;
							}
						}

						if( bExistsPKCS11Object ) {
							Log::log( "Token::synchronizePrivateKeyObjects - The PKCS11 private key object exists");
							// The PCKS11 key object exists
							// Create the PKCS11 object from the already existing PKCS11 file
							try {
								Log::log( "Token::synchronizePrivateKeyObjects - Create the PKCS11 object from the already existing PKCS11 file");
								createPrivateKeyFromPKCS11ObjectFile( stKeyFileName );

							} catch( ... ) {
								Log::log( "Token::synchronizePrivateKeyObjects - exception occured");
								// Create the PKCS11 object from the MSCP key container
								if (pEccPublicKey.get())
								{
									Log::log( "Token::synchronizePrivateKeyObjects - creating ECC private key object from the MSCP key container");
									createPrivateKeyFromMiniDriverFile( stKeyFileName, ucContainerIndex, ucKeySpec, NULL, pEccPublicKey.get( ) );
								}
								else
								{
									Log::log( "Token::synchronizePrivateKeyObjects - creating RSA private key object from the MSCP key container");
									createPrivateKeyFromMiniDriverFile( stKeyFileName, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) );
								}
							}

						} else {
							Log::log( "Token::synchronizePrivateKeyObjects - The PKCS11 private key object does not exist");
							// The PKCS11 private key object does not exist
							// Create the PKCS11 object from the MSCP key container
							if (pEccPublicKey.get())
							{
								Log::log( "Token::synchronizePrivateKeyObjects - creating ECC private key object from the MSCP key container");
								createPrivateKeyFromMiniDriverFile( stKeyFileName, ucContainerIndex, ucKeySpec, NULL, pEccPublicKey.get( ) );
							}
							else
							{
								Log::log( "Token::synchronizePrivateKeyObjects - creating RSA private key object from the MSCP key container");
								createPrivateKeyFromMiniDriverFile( stKeyFileName, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) );
							}
						}

						if (!m_Device->supportsDualKeyContainers ())
							break;
					}
					catch (...)
					{
						Log::log( "Token::synchronizePrivateKeyObjects - exception occured while parsing %s part of container %d. Skipping.", (i == 0)? "Exchange" : "Signature" , (int) ucContainerIndex);
					}
				}
			}
			else {

					// The container is empty
			}
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizePrivateKeyObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizePrivateKeyObjects" );
    Log::end( "Token::synchronizePrivateKeyObjects" );
}

void Token::synchronizeSecretKeyObjects( void ) {

    Log::begin( "Token::synchronizeSecretKeyObjects" );
    Timer t;
    t.start( );

    if( !m_Device ) {
        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME filesPKCS11;

        if( !m_bCreateDirectoryP11 ) {

            try {

                filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

            } catch( ... ) {

            }
        }

        std::string stContainerIndex = "";
        std::string stKeyFileName = "";
        bool bExistsPKCS11Object = false;

        // Explore each smart card key container
        unsigned char ucContainerCount = m_Device->containerCount( );
        MiniDriverAuthentication::ROLES userRole = getUserRole();

        for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

            // Get the current container
            MiniDriverContainer& c = m_Device->containerGet( ucContainerIndex );

            // Locate the associated SECRET key
            // Build the secret key file name associated to this container
            stContainerIndex = "";
            Util::toStringHex( ucContainerIndex, stContainerIndex );
            stKeyFileName = g_stPrefixPrivateObject + g_stPrefixKeySecret + stContainerIndex;

            // Does this secret key exist as a PKCS11 object ?
            bExistsPKCS11Object = isFileExists( stKeyFileName, filesPKCS11 );

            // Only deal with valid containers that are associated with our role
            if(     bExistsPKCS11Object
                /*&&  (MiniDriverContainer::CMAPFILE_FLAG_EMPTY != c.getFlags( ) )
                &&  (   (c.getPinIdentifier() == userRole)
                    ||  (m_Device->isNoPin(c.getPinIdentifier()) && m_Device->isNoPin(userRole))
                    )*/
                )
            {
                Log::log( "Token::synchronizeSecretKeyObjects - <%d> valid container", ucContainerIndex );
/*
                try
                {
                    // Populate the container info (throws exception if the container is empty)
                    boost::shared_ptr< u1Array > ci( m_Device->getContainer( ucContainerIndex ) );

                    c.setContainerInformation( ci );
                }
                catch(MiniDriverException&)
                {
                    Log::log( "Token::synchronizeSecretKeyObjects - error while reading container. Skipping.");
                    continue;
                }
*/
                Log::log( "Token::synchronizeSecretKeyObjects - The PKCS11 secret key object exists");
                // The PCKS11 key object exists
                // Create the PKCS11 object from the already existing PKCS11 file
                try {
                    Log::log( "Token::synchronizeSecretKeyObjects - Create the PKCS11 object from the already existing PKCS11 file");
                    createSecretKeyFromPKCS11ObjectFile( stKeyFileName, ucContainerIndex );
                }
                catch (...)
                {
                    Log::log( "Token::synchronizeSecretKeyObjects - exception occured while parsing container %d. Skipping.", (int) ucContainerIndex);
                    continue;
                }
            }
            else {

                    // The container is empty
            }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizeSecretKeyObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizeSecretKeyObjects" );
    Log::end( "Token::synchronizeSecretKeyObjects" );
}

/* Create the PKCS11 certifcate object associated to the MiniDriver certificate file
*/
bool Token::createCertificateFromPKCS11ObjectFile( const std::string& a_CertificateFileP11, const std::string& a_CertificateFileMiniDriver ) {

    Log::begin( "Token::createCertificateFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, a_CertificateFileP11 ) );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        // Create the PKCS11 object
        X509PubKeyCertObject* o = new X509PubKeyCertObject( );

        // Put the file content into the object
        CK_ULONG idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object
        o->m_stFileName = a_CertificateFileP11;

        o->m_stCertificateName = a_CertificateFileMiniDriver;

        // Read the file
        m_Device->readCertificate( a_CertificateFileMiniDriver, o->m_pValue );

        if( o->m_pValue ) {

           // check if the attributes of the P11 object are compatible with the value of the certificate
           if ( !Application::g_DisableCertificateValidation && !o->validate() )
           {
               // attributes mismatch: abort creating the object from the P11 file because it seems corrupted.
               delete o;
               return false;
           }

            generateRootAndSmartCardLogonFlags( o->m_pValue, o->m_bIsRoot, o->_certCategory, o->m_bIsSmartCardLogon );

            generatePublicKeyValue( o->m_pValue, o->m_pPublicKeyValue, o->m_bIsRSA, o->m_ucKeySpec, o->_checkValue , o->m_pOID);
        }

        if( o->m_pPublicKeyValue && ( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == o->m_ucContainerIndex ) ) {

            searchContainerIndex( o->m_pPublicKeyValue, o->m_ucContainerIndex, o->m_ucKeySpec );
        }

        // As the PKCS11 file exists on card, the PKCS11 object has just to be added to the list of the PKCS11 managed object list.
        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createCertificateFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createCertificateFromPKCS11ObjectFile" );
    Log::end( "Token::createCertificateFromPKCS11ObjectFile" );

	 return true;
}


/* Create the PKCS11 certifcate object associated to the MiniDriver certificate file
*/
void Token::createCertificateFromMiniDriverFile( const std::string& a_CertificateFile, const unsigned char& a_ucIndex, const unsigned char& a_ucKeySpec , boost::shared_ptr<u1Array>& a_pOID) {

    Log::begin( "Token::createCertificateFromMiniDriverFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Create the PKCS11 object
    X509PubKeyCertObject* o = new X509PubKeyCertObject( );

    o->m_ucKeySpec = a_ucKeySpec;

    o->m_ucContainerIndex = a_ucIndex;

    o->m_bOffCardObject = true;

    o->m_Token = CK_TRUE;

    o->m_Private = CK_FALSE;

    o->m_Modifiable = ((a_ucIndex != 0xFF) && m_Device && m_Device->containerReadOnly(a_ucIndex)) ? CK_FALSE: CK_TRUE;

    // No PKCS#11 certificate name for an offcard object. There is only a MiniDriver certificate into the smart card
    o->m_stFileName = "";

    o->m_stCertificateName = a_CertificateFile;

    try {

        // Read the file
        m_Device->readCertificate( a_CertificateFile, o->m_pValue );

    } catch( MiniDriverException& x ) {

        // Unable to read the on card certificate.
        // The P11 object creation is skipped.
        Log::error( "Token::createCertificateFromMiniDriverFile", "Unable to read the certificate" );

        delete o;

        throw PKCS11Exception( checkException( x ) );
    }

    // Get object attributes from the parsed certificate
    generateDefaultAttributesCertificate( o );
    if (o->m_pOID->GetLength() > 0)
    {
    	a_pOID.reset( new u1Array( o->m_pOID->GetLength( ) ) );
    	a_pOID->SetBuffer( (u1*) o->m_pOID->GetBuffer( ) );
    }
    // Register this PKCS11 object into the list of the PKCS11 managed objects
    registerStorageObject( o );

    t.stop( "Token::createCertificateFromMiniDriverFile" );
    Log::end( "Token::createCertificateFromMiniDriverFile" );
}

/* Create the PKCS11 root certifcate object from the msroots content
*/
void Token::createRootCertificateFromValue( unsigned char* pbCert, unsigned int iCertLen, const unsigned char& a_ucKeySpec ) {

    Log::begin( "Token::createRootCertificateFromValue" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Create the PKCS11 object
    X509PubKeyCertObject* o = new X509PubKeyCertObject( );

    o->m_ucKeySpec = a_ucKeySpec;

    o->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

    o->m_bOffCardObject = true;

    o->m_Token = CK_TRUE;

    o->m_Private = CK_FALSE;

    o->m_Modifiable = CK_FALSE;

    // No PKCS#11 certificate name for an offcard object. There is only a MiniDriver certificate into the smart card
    o->m_stFileName = "";

    o->m_stCertificateName = szROOT_STORE_FILE;

    o->m_pValue.reset(new u1Array(pbCert, iCertLen));

    // Get object attributes from the parsed certificate
    generateDefaultAttributesCertificate( o );

    // Register this PKCS11 object into the list of the PKCS11 managed objects
    registerStorageObject( o );

    t.stop( "Token::createRootCertificateFromValue" );
    Log::end( "Token::createRootCertificateFromValue" );
}


/* Create the PKCS11 public key object associated to the PKCS11 public key file stored into the smart card
*/
void Token::createPublicKeyFromPKCS11ObjectFile( const std::string& a_PKCS11PublicKeyFile ) {

    Log::begin( "Token::createPublicKeyFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, a_PKCS11PublicKeyFile ) );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        KeyObject helperObj;
        bool bIsRSA = false;
        CK_ULONG idx = 0;

        helperObj.deserialize( attributes, &idx );
        bIsRSA = (helperObj._keyType == CKK_RSA);

        // Create the PKCS11 object
        Pkcs11ObjectKeyPublic* o;
        if (bIsRSA)
            o = new Pkcs11ObjectKeyPublicRSA( );
        else
            o = new Pkcs11ObjectKeyPublicECC( );

        // Put the file content into the object
        idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object
        o->m_stFileName = a_PKCS11PublicKeyFile;

        boost::shared_ptr< u1Array> a_pPubKeyValue = (bIsRSA)? ((Pkcs11ObjectKeyPublicRSA*) o)->m_pModulus : ((Pkcs11ObjectKeyPublicECC*)o)->m_pPublicPoint;

        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == o->m_ucContainerIndex ) {

            searchContainerIndex( a_pPubKeyValue, o->m_ucContainerIndex, o->m_ucKeySpec );
        }

        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createPublicKeyFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createPublicKeyFromPKCS11ObjectFile" );
    Log::end( "Token::createPublicKeyFromPKCS11ObjectFile" );
}


/* Create the PKCS11 public key object associated to the MiniDriver container
*/
void Token::createPublicKeyFromMiniDriverFile( const std::string& /*a_stKeyFileName*/, const unsigned char& a_ucIndex, const unsigned int& a_ucKeySpec, u1Array* a_pPublicKeyExponent, u1Array* a_pPublicKeyModulus, boost::shared_ptr<u1Array> a_pOID ) {

	Log::begin( "Token::createPublicKeyFromMiniDriverFile");
	Log::log ("Token::createPublicKeyFromMiniDriverFile (index=<%d>, KeySpec=<%d>, PubExp=<%p>, PubMod=<%d>)", a_ucIndex, a_ucKeySpec, a_pPublicKeyExponent, a_pPublicKeyModulus );
    Timer t;
    t.start( );

    // Create the PKCS11 object
    Pkcs11ObjectKeyPublic* o = NULL;
    bool bIsRSA = false;

	if (a_pPublicKeyExponent && a_pPublicKeyModulus)
    {
        o = new Pkcs11ObjectKeyPublicRSA( );
        bIsRSA = true;
    }
    else if (a_pPublicKeyModulus)
    {
        o = new Pkcs11ObjectKeyPublicECC( );
        bIsRSA = false;
    }
	else
	{
		Log::error( "Token::createPublicKeyFromMiniDriverFile", "No exponent or modulus passed. Can't create public key. Skipping." );
		t.stop( "Token::createPublicKeyFromMiniDriverFile" );
		Log::end( "Token::createPublicKeyFromMiniDriverFile" );
		return;
	}

    o->m_stFileName = ""; // No PKCS#11 key file into the smart card. This object is build for a off card usage using the information given by the container //a_stKeyFileName;

    o->m_Token = CK_TRUE;

    o->m_Private = CK_FALSE;

    o->m_Modifiable = ((a_ucIndex != 0xFF) && m_Device && m_Device->containerReadOnly(a_ucIndex)) ? CK_FALSE: CK_TRUE;

    o->m_ucContainerIndex = a_ucIndex;

    o->m_ucKeySpec = (unsigned char)a_ucKeySpec;

    o->m_bOffCardObject = true;

    o->_wrap = CK_FALSE;

    o->_trusted = CK_TRUE;

    o->_derive = CK_FALSE;

    o->_local = CK_FALSE;

    o->_verifyRecover = CK_FALSE;

    if(     MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec
        ||  MiniDriverContainer::KEYSPEC_ECDHE_256 == a_ucKeySpec
        ||  MiniDriverContainer::KEYSPEC_ECDHE_384 == a_ucKeySpec
        ||  MiniDriverContainer::KEYSPEC_ECDHE_521 == a_ucKeySpec
      ) {

        o->_verify = CK_TRUE;

        if (MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec)
            o->_encrypt = CK_TRUE;
        else
            o->_encrypt = CK_FALSE;

        if( m_Device ) {

            if( !m_Device->containerIsImportedExchangeKey( a_ucIndex ) ) {

                o->_local = CK_TRUE;
            }
        }

    } else {

        o->_verify = CK_TRUE;

        o->_encrypt = CK_FALSE;

        if( m_Device ) {

            if( !m_Device->containerIsImportedSignatureKey( a_ucIndex ) ) {

                o->_local = CK_TRUE;
            }
        }
    }

    if (bIsRSA)
    {
        Pkcs11ObjectKeyPublicRSA* oRSA = (Pkcs11ObjectKeyPublicRSA*) o;

        oRSA->m_pPublicExponent.reset( new u1Array( a_pPublicKeyExponent->GetLength( ) ) );

        oRSA->m_pPublicExponent->SetBuffer( a_pPublicKeyExponent->GetBuffer( ) );

        oRSA->m_pModulus.reset( new u1Array( a_pPublicKeyModulus->GetLength( ) ) );

        oRSA->m_pModulus->SetBuffer( a_pPublicKeyModulus->GetBuffer( ) );

        oRSA->m_ulModulusBits = a_pPublicKeyModulus->GetLength( ) * 8;
    }
    else
    {
        Pkcs11ObjectKeyPublicECC* oECC = (Pkcs11ObjectKeyPublicECC*) o;

        oECC->m_pPublicPoint.reset( new u1Array( a_pPublicKeyModulus->GetLength( ) ) );

        oECC->m_pPublicPoint->SetBuffer( a_pPublicKeyModulus->GetBuffer( ) );

        u4 ulOidLen = 0;
        unsigned char* pOid = NULL;

	if ((a_pOID) && (a_pOID->GetLength() > 0))
	{
		ulOidLen = a_pOID->GetLength();
		pOid = a_pOID->GetBuffer();
	}
	else if (    MiniDriverContainer::KEYSPEC_ECDHE_256 == a_ucKeySpec
            ||  MiniDriverContainer::KEYSPEC_ECDSA_256 == a_ucKeySpec
           )
        {
            pOid = g_pbECC256_OID;
            ulOidLen = sizeof(g_pbECC256_OID);
        } else if (    MiniDriverContainer::KEYSPEC_ECDHE_384 == a_ucKeySpec
            ||  MiniDriverContainer::KEYSPEC_ECDSA_384 == a_ucKeySpec
           )
        {
            pOid = g_pbECC384_OID;
            ulOidLen = sizeof(g_pbECC384_OID);
        } else if (    MiniDriverContainer::KEYSPEC_ECDHE_521 == a_ucKeySpec
            ||  MiniDriverContainer::KEYSPEC_ECDSA_521 == a_ucKeySpec
           )
        {
            pOid = g_pbECC521_OID;
            ulOidLen = sizeof(g_pbECC521_OID);
        }

        oECC->m_pParams.reset( new u1Array( ulOidLen ) );

        oECC->m_pParams->SetBuffer( pOid );
    }

    generateDefaultAttributesKeyPublic( o );

    registerStorageObject( o );

    t.stop( "Token::createPublicKeyFromMiniDriverFile" );
    Log::end( "Token::createPublicKeyFromMiniDriverFile" );
}


/* Create the PKCS11 public key object associated to the PKCS11 public key file stored into the smart card
*/
void Token::createPrivateKeyFromPKCS11ObjectFile( const std::string& a_PKCS11PrivateKeyFile ) {

    Log::begin( "Token::createPrivateKeyFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, a_PKCS11PrivateKeyFile ) );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        KeyObject helperObj;
        bool bIsRSA = false;
        CK_ULONG idx = 0;

        helperObj.deserialize( attributes, &idx );
        bIsRSA = (helperObj._keyType == CKK_RSA);

        // Create the PKCS11 object
        PrivateKeyObject* o;
        if (bIsRSA)
            o = new RSAPrivateKeyObject( );
        else
            o = new ECCPrivateKeyObject( );

        // Put the file content into the object
        idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object
        o->m_stFileName = a_PKCS11PrivateKeyFile;

        boost::shared_ptr< u1Array> a_pPubKeyValue = (bIsRSA)? ((RSAPrivateKeyObject*) o)->m_pModulus : ((ECCPrivateKeyObject*)o)->m_pPublicPoint;

        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == o->m_ucContainerIndex ) {

            searchContainerIndex( a_pPubKeyValue, o->m_ucContainerIndex, o->m_ucKeySpec );
        }

        // Compatibility with old P11
        o->_checkValue = Util::MakeCheckValue( a_pPubKeyValue->GetBuffer( ), a_pPubKeyValue->GetLength( ) );

        setContainerIndexToCertificate( a_pPubKeyValue, o->m_ucContainerIndex, o->m_ucKeySpec );

        setContainerIndexToKeyPublic( a_pPubKeyValue, o->m_ucContainerIndex, o->m_ucKeySpec );

        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createPrivateKeyFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createPrivateKeyFromPKCS11ObjectFile" );
    Log::end( "Token::createPrivateKeyFromPKCS11ObjectFile" );
}

void Token::createSecretKeyFromPKCS11ObjectFile( const std::string& a_PKCS11SecretKeyFile, u1 ctrIndex ) {

    Log::begin( "Token::createPrivateKeyFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        std::unique_ptr<u1Array> f ( m_Device->readFile( g_stPathPKCS11, a_PKCS11SecretKeyFile ) );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        KeyObject helperObj;
        bool bIsAES = false;
        CK_ULONG idx = 0;

        helperObj.deserialize( attributes, &idx );
        bIsAES = (helperObj._keyType == CKK_AES);

        // Create the PKCS11 object
        SecretKeyObject* o;
        if (bIsAES)
            o = new SecretKeyObjectAES( );
        else
            throw MiniDriverException( std::string("the library only supports secret key AES") );

        // Put the file content into the object
        idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object
        o->m_stFileName = a_PKCS11SecretKeyFile;

        // Save the container index in the object
        o->m_ucContainerIndex = ctrIndex;

        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createPrivateKeyFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createPrivateKeyFromPKCS11ObjectFile" );
    Log::end( "Token::createPrivateKeyFromPKCS11ObjectFile" );
}

/* Create the PKCS11 public key object associated to the MiniDriver container
*/
void Token::createPrivateKeyFromMiniDriverFile( const std::string& /*a_stKeyFileName*/, const unsigned char& a_ucIndex, const unsigned int& a_ucKeySpec, u1Array* a_pPublicKeyExponent, u1Array* a_pPublicKeyValue ) {

    Log::begin( "Token::createPrivateKeyFromMiniDriverFile" );
    Timer t;
    t.start( );

    // Create the PKCS11 object
    bool bIsRSA = (a_ucKeySpec == MiniDriverContainer::KEYSPEC_SIGNATURE || a_ucKeySpec == MiniDriverContainer::KEYSPEC_EXCHANGE);
    PrivateKeyObject* o = NULL;

	 if (bIsRSA && a_pPublicKeyExponent && a_pPublicKeyValue)
    {
        o = new RSAPrivateKeyObject( );
    }
    else if (!bIsRSA && a_pPublicKeyValue)
    {
        o = new ECCPrivateKeyObject( );
    }
	else
	{
		Log::error( "Token::createPrivateKeyFromMiniDriverFile", "Inconsistency in parameters. Skipping." );
		t.stop( "Token::createPrivateKeyFromMiniDriverFile" );
		Log::end( "Token::createPrivateKeyFromMiniDriverFile" );
		return;
	}

    o->m_stFileName = ""; // No PKCS#11 key file into the smart card. This object is build for a off card usage using the information given by the container

    o->m_Token = CK_TRUE;

    o->m_Private = CK_TRUE;

    o->m_Modifiable = ((a_ucIndex != 0xFF) && m_Device && m_Device->containerReadOnly(a_ucIndex)) ? CK_FALSE: CK_TRUE;

    o->m_bOffCardObject = true;

    o->m_ucKeySpec = (unsigned char)a_ucKeySpec;

    o->_sensitive = CK_TRUE;

    o->_signRecover = CK_FALSE;

    o->_unwrap = CK_FALSE;

    o->_extractable = CK_FALSE;

    o->_alwaysSensitive = CK_TRUE;

    o->_neverExtractable = CK_TRUE;

    o->_wrapWithTrusted = CK_FALSE;

    o->_alwaysAuthenticate = CK_FALSE;

    o->_derive = CK_FALSE;

    o->_local = CK_FALSE;

    if(     MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec
        ||  MiniDriverContainer::KEYSPEC_ECDHE_256 == a_ucKeySpec
        ||  MiniDriverContainer::KEYSPEC_ECDHE_384 == a_ucKeySpec
        ||  MiniDriverContainer::KEYSPEC_ECDHE_521 == a_ucKeySpec
      ) {

        o->_sign = CK_TRUE;

        if (MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec)
            o->_decrypt = CK_TRUE;
        else
        {
            o->_decrypt = CK_FALSE;
            o->_derive = CK_TRUE;
        }

    } else {

        o->_sign = CK_TRUE;

        o->_decrypt = CK_FALSE;

    }

    o->m_ucContainerIndex = a_ucIndex;

    if (bIsRSA)
    {
		 Log::log( "Token::createPrivateKeyFromMiniDriverFile - Building RSAPrivateKeyObject from modulus and exponent");
        RSAPrivateKeyObject* rsa = (RSAPrivateKeyObject*) o;
        rsa->m_pPublicExponent.reset( new u1Array( a_pPublicKeyExponent->GetLength( ) ) );
        rsa->m_pPublicExponent->SetBuffer( a_pPublicKeyExponent->GetBuffer( ) );

        rsa->m_pModulus.reset( new u1Array( a_pPublicKeyValue->GetLength( ) ) );
        rsa->m_pModulus->SetBuffer( a_pPublicKeyValue->GetBuffer( ) );
    }
    else
    {
		 Log::log( "Token::createPrivateKeyFromMiniDriverFile - Building ECCPrivateKeyObject from public point and curve parameters");
        ECCPrivateKeyObject* ecc = (ECCPrivateKeyObject*) o;
        ecc->m_pPublicPoint.reset(new u1Array( a_pPublicKeyValue->GetLength( ) ) );
        ecc->m_pPublicPoint->SetBuffer( a_pPublicKeyValue->GetBuffer( ) );

        if (a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDHE_256 || a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDSA_256)
        {
            ecc->m_pParams.reset(new u1Array( sizeof(g_pbECC256_OID) ));
            ecc->m_pParams->SetBuffer( g_pbECC256_OID );
        }
        if (a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDHE_384 || a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDSA_384)
        {
            ecc->m_pParams.reset(new u1Array( sizeof(g_pbECC384_OID) ));
            ecc->m_pParams->SetBuffer( g_pbECC384_OID );
        }
        if (a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDHE_521 || a_ucKeySpec == MiniDriverContainer::KEYSPEC_ECDSA_521)
        {
            ecc->m_pParams.reset(new u1Array( sizeof(g_pbECC521_OID) ));
            ecc->m_pParams->SetBuffer( g_pbECC521_OID );
        }
    }

    //setDefaultAttributes( o, true );
    generateDefaultAttributesKeyPrivate( o );

    // Add the object into the cache
    registerStorageObject( o );

    t.stop( "Token::createPrivateKeyFromMiniDriverFile" );
    Log::end( "Token::createPrivateKeyFromMiniDriverFile" );
}


/*
*/
CK_RV Token::checkException( MiniDriverException& x ) {

    CK_RV rv = CKR_GENERAL_ERROR;

    switch( x.getError( ) ) {

    case SCARD_E_INVALID_PARAMETER:
        rv = CKR_ARGUMENTS_BAD;
        break;

    case SCARD_E_UNEXPECTED:
    case SCARD_F_INTERNAL_ERROR:
        rv = CKR_FUNCTION_FAILED;
        break;
#ifdef WIN32
    case SCARD_E_UNSUPPORTED_FEATURE:
        rv = CKR_FUNCTION_NOT_SUPPORTED;
        break;
#endif
    case SCARD_W_CARD_NOT_AUTHENTICATED:
        rv = CKR_USER_NOT_LOGGED_IN;
        break;

    case SCARD_W_CHV_BLOCKED:
        rv = CKR_PIN_LOCKED;
        break;

    case SCARD_W_WRONG_CHV:
        rv = CKR_PIN_INCORRECT;
        break;

    case SCARD_E_INVALID_CHV:
        rv = CKR_PIN_INVALID;
        break;

    case SCARD_E_NO_SMARTCARD:
    case SCARD_W_REMOVED_CARD:
        rv = CKR_DEVICE_REMOVED;
        break;

    case SCARD_E_TIMEOUT:
    case SCARD_W_CANCELLED_BY_USER:
    case SCARD_E_CANCELLED:
        rv = CKR_FUNCTION_CANCELED;
        break;

    case SCARD_E_NO_MEMORY:
    case SCARD_E_DIR_NOT_FOUND:
    case SCARD_E_FILE_NOT_FOUND:
    case SCARD_E_CERTIFICATE_UNAVAILABLE:
    case SCARD_E_NO_ACCESS:
        rv = CKR_DEVICE_MEMORY;
        break;

    default:
        rv = CKR_GENERAL_ERROR;
        break;
    }

    return rv;
}


/*
*/
unsigned char Token::computeIndex( const std::string& a_stFileName ) {

    if( a_stFileName.length( ) < 2 ) {

        return 0xFF;
    }

    // Get the container index set into the file name
    unsigned char h1 = a_stFileName[ a_stFileName.length( ) - 2 ];
    unsigned char h2 = a_stFileName[ a_stFileName.length( ) - 1 ];

    unsigned char a = ( ( h1 >= 0x41 ) ? ( h1 - 0x41 + 10 ) : ( h1 - 0x30 ) ) * 16;
    unsigned char b = ( h2 >= 0x41 ) ? ( h2 - 0x41 + 10 ) : ( h2 - 0x30 );

    unsigned char ucKeyContainerIndexInFileName = a + b;

    return ucKeyContainerIndexInFileName;
}


/*
*/
void Token::generateDefaultAttributesCertificate( X509PubKeyCertObject* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesCertificate" );
    Timer t;
    t.start( );

    if( !a_pObject && !a_pObject->m_pValue ) {

        return;
    }

    // Parse the certifcate value to extract the PKCS11 attribute values not already set
    try {

        // Generate the root and smart card logon flags
        generateRootAndSmartCardLogonFlags( a_pObject->m_pValue, a_pObject->m_bIsRoot, a_pObject->_certCategory, a_pObject->m_bIsSmartCardLogon );

        // Generate the serial number
        generateSerialNumber( a_pObject->m_pValue, a_pObject->m_pSerialNumber );

        // Generate the issuer
        generateIssuer( a_pObject->m_pValue, a_pObject->m_pIssuer );

        // Get the certificate public key modulus
        generatePublicKeyValue( a_pObject->m_pValue, a_pObject->m_pPublicKeyValue, a_pObject->m_bIsRSA, a_pObject->m_ucKeySpec, a_pObject->_checkValue , a_pObject->m_pOID);

        // Generate the certicate label
        generateLabel( a_pObject->m_pPublicKeyValue, a_pObject->m_pLabel );

        // Generate the ID
        generateID( a_pObject->m_pPublicKeyValue, a_pObject->m_pID );

        // Generate the subject
        generateSubject( a_pObject->m_pValue, a_pObject->m_pSubject );

    } catch( ... ) {

        // If a parsing error occurs then these attributes can't be set.
    }
}


/*
*/
void Token::generateDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublic* a_pObject ) {

    Log::begin( "Token::generateDefaultAttributesKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pObject) {

        return;
    }

    bool bisRSA = (a_pObject->_keyType == CKK_RSA);
    unsigned int l = 0;
    unsigned char* p = NULL;
    boost::shared_ptr< u1Array> pPublicKeyValue;

    if (bisRSA)
    {
        if (!((Pkcs11ObjectKeyPublicRSA*)a_pObject)->m_pModulus)
        {
            return;
        }
        l = ((Pkcs11ObjectKeyPublicRSA*)a_pObject)->m_pModulus->GetLength( );
        p = ((Pkcs11ObjectKeyPublicRSA*)a_pObject)->m_pModulus->GetBuffer( );
        pPublicKeyValue = ((Pkcs11ObjectKeyPublicRSA*)a_pObject)->m_pModulus;
    }
    else
    {
        if( !((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pPublicPoint ) {

            return;
        }
        l = ((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pPublicPoint->GetLength( );
        p = ((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pPublicPoint->GetBuffer( );
        pPublicKeyValue = ((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pPublicPoint;
    }


    // Search for a private key using the same public key exponent to set the same container index
    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pObject->m_ucContainerIndex ) {

        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

            if( CKO_PRIVATE_KEY == obj->second->getClass( ) ) {

                PrivateKeyObject* objPrivateKey = (PrivateKeyObject*) obj->second;

                if (bisRSA == (objPrivateKey->_keyType == CKK_RSA))
                {
                    boost::shared_ptr< u1Array> keyPubVal;
                    if (bisRSA)
                        keyPubVal = ((RSAPrivateKeyObject*) objPrivateKey)->m_pModulus;
                    else
                        keyPubVal = ((ECCPrivateKeyObject*) objPrivateKey)->m_pPublicPoint;

                    if(     keyPubVal.get()
                        &&  (keyPubVal->GetLength() == l)
                        &&  (0 == memcmp( keyPubVal->GetBuffer( ), p, l ) )
                      )
                    {
                        if (!bisRSA)
                        {
                            if (!Util::compareU1Arrays(((ECCPrivateKeyObject*) objPrivateKey)->m_pParams.get(),
                                ((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pParams->GetBuffer(),
                                ((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pParams->GetLength()))
                            {
                                continue;
                            }
                        }

                        // Set the same CKA_ID
                        if( objPrivateKey->m_pID.get( ) ) {

                            a_pObject->m_pID.reset( new u1Array( *( objPrivateKey->m_pID.get( ) ) ) );
                        }

                        // Set the same CKA_LABEL
                        if( objPrivateKey->m_pLabel.get( ) ) {

                            a_pObject->m_pLabel.reset( new u1Array( *( objPrivateKey->m_pLabel.get( ) ) ) );
                        }

                        // Set the same CKA_SUBJECT
                        if( objPrivateKey->m_pSubject.get( ) ) {

                            a_pObject->m_pSubject.reset( new u1Array( *( objPrivateKey->m_pSubject.get( ) ) ) );
                        }

                        a_pObject->m_ucContainerIndex = objPrivateKey->m_ucContainerIndex;

                        a_pObject->m_ucKeySpec = objPrivateKey->m_ucKeySpec;

                        break;
                    }
                }
            }
        }
    }

    // If no private key has been found then generate the attributes

    // Get the certificate subject if it is still empty
    if( !a_pObject->m_pSubject.get( ) ) {

        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

            if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

                X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;

                if( !objCertificate && !objCertificate->m_pValue ) {

                    continue;
                }

                try
                {
                    X509Cert x509cert( objCertificate->m_pValue->GetBuffer( ), objCertificate->m_pValue->GetLength( ) );

                    if (bisRSA == x509cert.IsRsaPublicKey())
                    {
                        // Get the certificate public key modulus
                        BEROctet::Blob pubValue;
                        if (bisRSA)
                            pubValue = x509cert.Modulus( );
                        else
                            pubValue = x509cert.EcPublicPoint();

                        // Check if the both certificate and public key share the same modulus
                        if( (pubValue.size() == l) && (0 == memcmp( pubValue.data(), p, l ))) {

                            if (!bisRSA)
                            {
                                // check the curve
                                BEROctet::Blob oid = x509cert.EcCurveOid();
                                if (!Util::compareU1Arrays(((Pkcs11ObjectKeyPublicECC*) a_pObject)->m_pParams.get(), oid.data(), oid.size()))
                                    continue;
                            }

                            if( objCertificate->m_pSubject.get( ) ) {

                                // Copyt the certificate subject
                                a_pObject->m_pSubject.reset( new u1Array( *( objCertificate->m_pSubject.get( ) ) ) );

                            } else {

                                // Generate the subject
                                BEROctet::Blob sb( x509cert.Subject( ) );

                                a_pObject->m_pSubject.reset( new u1Array( static_cast< s4 >( sb.size( ) ) ) );

                                a_pObject->m_pSubject->SetBuffer( const_cast< unsigned char* >( sb.data( ) ) );
                            }

                            // By the way copy the certificate ID
                            if( objCertificate->m_pID.get( ) && !a_pObject->m_pID.get( ) ) {

                                a_pObject->m_pID.reset( new u1Array( *( objCertificate->m_pID.get( ) ) ) );
                            }

                            if( objCertificate->m_pLabel.get( ) && !a_pObject->m_pLabel.get( ) ) {

                                a_pObject->m_pLabel.reset( new u1Array( *( objCertificate->m_pLabel.get( ) ) ) );
                            }

                            break;
                        }
                    }
                }
                catch (...) {}
            }
        }
    }

    // Generate the id
    if( !a_pObject->m_pID.get( ) ) {

        generateID( pPublicKeyValue, a_pObject->m_pID );
    }

    // Generate the label from the public key modulus
    if( !a_pObject->m_pLabel.get( ) ) {

        generateLabel( pPublicKeyValue, a_pObject->m_pLabel );
    }

    t.stop( "Token::generateDefaultAttributesKeyPublic" );
    Log::end( "Token::generateDefaultAttributesKeyPublic" );
}


/*
*/
void Token::generateDefaultAttributesKeyPrivate( PrivateKeyObject* a_pObject ) {

    Log::begin( "Token::generateDefaultAttributesKeyPrivate" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    bool bisRSA = (a_pObject->_keyType == CKK_RSA);
    unsigned int l = 0;
    unsigned char* p = NULL;
    boost::shared_ptr< u1Array> pPublicKeyValue;

    if (bisRSA)
    {
        if( !((RSAPrivateKeyObject*) a_pObject)->m_pModulus ) {

            return;
        }
        l = ((RSAPrivateKeyObject*) a_pObject)->m_pModulus->GetLength( );
        p = ((RSAPrivateKeyObject*) a_pObject)->m_pModulus->GetBuffer( );
        pPublicKeyValue = ((RSAPrivateKeyObject*) a_pObject)->m_pModulus;
    }
    else
    {
        if( !((ECCPrivateKeyObject*) a_pObject)->m_pPublicPoint ) {

            return;
        }
        l = ((ECCPrivateKeyObject*) a_pObject)->m_pPublicPoint->GetLength( );
        p = ((ECCPrivateKeyObject*) a_pObject)->m_pPublicPoint->GetBuffer( );
        pPublicKeyValue = ((ECCPrivateKeyObject*) a_pObject)->m_pPublicPoint;
    }

    // Compatibility with old P11
    a_pObject->_checkValue = Util::MakeCheckValue( p, l );

    // Give the same container index of the private key to the associated certificate
	bool bCertFound = false;

    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

            X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;

			if( objCertificate->m_pValue.get( ) && (objCertificate->m_pValue->GetLength() > 0)) {

				try
				{
					X509Cert x509cert( objCertificate->m_pValue->GetBuffer( ), objCertificate->m_pValue->GetLength( ) );

					if (bisRSA == x509cert.IsRsaPublicKey())
					{
						// Get the certificate public key modulus
						BEROctet::Blob pubValue;
						if (bisRSA)
							pubValue = x509cert.Modulus( );
						else
							pubValue = x509cert.EcPublicPoint();

						if((pubValue.size() == l) && (0 == memcmp( pubValue.data(), p, l )))
						{
							if (!bisRSA)
							{
								// check the curve
								BEROctet::Blob oid = x509cert.EcCurveOid();
								if (!Util::compareU1Arrays(((ECCPrivateKeyObject*) a_pObject)->m_pParams.get(), oid.data(), oid.size()))
									continue;
							}
							// Give the same container index of the private key to the certificate
							objCertificate->m_ucContainerIndex = a_pObject->m_ucContainerIndex;

							objCertificate->m_ucKeySpec = a_pObject->m_ucKeySpec;

							if( objCertificate->m_pSubject.get( ) ) {

								a_pObject->m_pSubject.reset( new u1Array( objCertificate->m_pSubject->GetLength( ) ) );

								a_pObject->m_pSubject->SetBuffer( objCertificate->m_pSubject->GetBuffer( ) );

							} else {

								// Get the certificate subject
								BEROctet::Blob sb( x509cert.Subject( ) );

								a_pObject->m_pSubject.reset( new u1Array( static_cast< s4 >( sb.size( ) ) ) );

								a_pObject->m_pSubject->SetBuffer( const_cast< unsigned char* >( sb.data( ) ) );
							}

							if (objCertificate->m_pID.get() ) {

								a_pObject->m_pID.reset( new u1Array( objCertificate->m_pID->GetLength( ) ) );

								a_pObject->m_pID->SetBuffer( objCertificate->m_pID->GetBuffer( ) );
							}

							if (objCertificate->m_pLabel.get() ) {

								a_pObject->m_pLabel.reset( new u1Array( objCertificate->m_pLabel->GetLength( ) ) );

								a_pObject->m_pLabel->SetBuffer( objCertificate->m_pLabel->GetBuffer( ) );
							}

							bCertFound = true;

							break;
						}
					}
				}
				catch(...)
				{
					Log::log( "Token::generateDefaultAttributesKeyPrivate - exception while parsing certificate at index %d. Skipping.", (int) objCertificate->m_ucContainerIndex );
				}
            }
        }
    }

	if (!bCertFound)
	{
		// Look for an associated public key
		BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

			if( CKO_PUBLIC_KEY == obj->second->getClass( ) ) {

				Pkcs11ObjectKeyPublic* objPublicKey = (Pkcs11ObjectKeyPublic*) obj->second;

				if( a_pObject->_keyType == objPublicKey->_keyType) {

					unsigned int pubKeyLen;
					unsigned char* pubKeyBuffer;
					if (bisRSA)
					{
						if( !((Pkcs11ObjectKeyPublicRSA*) objPublicKey)->m_pModulus ) {

							continue;
						}
						pubKeyLen = ((Pkcs11ObjectKeyPublicRSA*) objPublicKey)->m_pModulus->GetLength( );
						pubKeyBuffer = ((Pkcs11ObjectKeyPublicRSA*) objPublicKey)->m_pModulus->GetBuffer( );
					}
					else
					{
						if( !((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pPublicPoint ) {

							continue;
						}
						pubKeyLen = ((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pPublicPoint->GetLength( );
						pubKeyBuffer = ((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pPublicPoint->GetBuffer( );
					}

					if((pubKeyLen == l) && (0 == memcmp( pubKeyBuffer, p, l )))
					{
						if (!bisRSA)
						{
							// check the curve
							if (	(((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pParams->GetLength() != ((ECCPrivateKeyObject*) a_pObject)->m_pParams->GetLength())
								||
									!Util::compareU1Arrays(((ECCPrivateKeyObject*) a_pObject)->m_pParams.get(), ((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pParams->GetBuffer(), ((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pParams->GetLength())
								)
								continue;
						}

						if (objPublicKey->m_pID.get() ) {

							a_pObject->m_pID.reset( new u1Array( objPublicKey->m_pID->GetLength( ) ) );

							a_pObject->m_pID->SetBuffer( objPublicKey->m_pID->GetBuffer( ) );
						}

						if (objPublicKey->m_pLabel.get() ) {

							a_pObject->m_pLabel.reset( new u1Array( objPublicKey->m_pLabel->GetLength( ) ) );

							a_pObject->m_pLabel->SetBuffer( objPublicKey->m_pLabel->GetBuffer( ) );
						}

						break;
					}
				}
			}
		}
	}

    // Generate a default id from the public key modulus if not found in previous certificate or public key search
	if (!a_pObject->m_pID)
		generateID( pPublicKeyValue, a_pObject->m_pID );

    // Generate a default label from the public key modulus if not found in previous certificate or public key search
	if (!a_pObject->m_pLabel)
		generateLabel( pPublicKeyValue, a_pObject->m_pLabel );

    //// Give the same container index of the private key to the associated public key
    //BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

    //    if( CKO_PUBLIC_KEY == obj->second->getClass( ) ) {

    //        Pkcs11ObjectKeyPublicRSA* objPublicKey = (Pkcs11ObjectKeyPublicRSA*) obj->second;

    //        if( 0 == memcmp( objPublicKey->m_pModulus->GetBuffer( ), p, l ) ) {

    //            // Give the same container index of the private key to the certificate
    //            objPublicKey->m_ucContainerIndex = o->m_ucContainerIndex;

    //            objPublicKey->m_ucKeySpec = o->m_ucKeySpec;

    //            // By the way, if the previous search for a certificate failed
    //            // try to get the same CKA_ID, CKA_LABEL and CKA_SUBJECT as the associated public key
    //            //if( /*o->m_bOffCardObject &&*/ objPublicKey->m_pSubject.get( ) && !o->m_pSubject.get( ) ) {

    //            //    o->m_pSubject.reset( new u1Array( objPublicKey->m_pSubject->GetLength( ) ) );

    //            //    o->m_pSubject->SetBuffer( objPublicKey->m_pSubject->GetBuffer( ) );
    //            //}

    //            if( /*o->m_bOffCardObject &&*/ objPublicKey->m_pID.get( ) && !o->m_pID.get( ) ) {

    //                o->m_pID.reset( new u1Array( objPublicKey->m_pID->GetLength( ) ) );

    //                o->m_pID->SetBuffer( objPublicKey->m_pID->GetBuffer( ) );
    //            }

    //            if( /*o->m_bOffCardObject &&*/ objPublicKey->m_pLabel.get( ) && !o->m_pLabel.get( ) ) {

    //                o->m_pLabel.reset( new u1Array( objPublicKey->m_pLabel->GetLength( ) ) );

    //                o->m_pLabel->SetBuffer( objPublicKey->m_pLabel->GetBuffer( ) );
    //            }

    //            break;
    //        }
    //    }
    //}

    t.stop( "Token::generateDefaultAttributesKeyPrivate" );
    Log::end( "Token::generateDefaultAttributesKeyPrivate" );
}


/* Generate a default label from the public key modulus
*/
void Token::generateLabel( boost::shared_ptr< u1Array>& a_pModulus, boost::shared_ptr< u1Array>& a_pLabel ) {

    if( !a_pModulus ) {

        return;
    }

    std::string stLabel = CAttributedCertificate::DerivedUniqueName( a_pModulus->GetBuffer( ), a_pModulus->GetLength( ) );

    a_pLabel.reset( new u1Array( stLabel.size( ) ) );

    a_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

    // Generate the certificate label from the certificate value
    //std::string stLabel;
    //std::vector<std::string> vs = x509cert.UTF8SubjectCommonName( );
    //BOOST_FOREACH( const std::string& s, vs ) {
    //    if( !stLabel.empty( ) ) {
    //        stLabel += " ";
    //    }
    //    stLabel += s;
    //}
    //a_pObject->m_pLabel.reset( new u1Array( stLabel.size( ) ) );
    //a_pObject->m_pLabel->SetBuffer( reinterpret_cast< const unsigned char* >( stLabel.c_str( ) ) );
}


/* Generate a default id from the public key modulus
*/
void Token::generateID( boost::shared_ptr< u1Array>& a_pModulus, boost::shared_ptr< u1Array>& a_pID ) {

    if( !a_pModulus ) {

        return;
    }

    a_pID.reset( Session::computeSHA1( a_pModulus->GetBuffer( ), a_pModulus->GetLength( ) ) );
}


/* Get the certificate serial number
*/
void Token::generateSerialNumber( boost::shared_ptr< u1Array>& a_pCertificateValue, boost::shared_ptr< u1Array>& a_pSerialNumber ) {

    try
    {
        X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

        BEROctet::Blob b( x509cert.SerialNumber( ) );

        a_pSerialNumber.reset( new u1Array( static_cast< s4 >( b.size( ) ) ) );

        a_pSerialNumber->SetBuffer( const_cast< unsigned char* >( b.data( ) ) );
    }
    catch (...)
    {
        a_pSerialNumber.reset( new u1Array( 0 ) );
    }
}


/* Get the certificate issuer from the certifcate value
*/
void Token::generateIssuer( boost::shared_ptr< u1Array>& a_pCertificateValue, boost::shared_ptr< u1Array>& a_pIssuer ) {

    try
    {
        X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

        BEROctet::Blob b( x509cert.Issuer( ) );

        a_pIssuer.reset( new u1Array( static_cast< s4 >( b.size( ) ) ) );

        a_pIssuer->SetBuffer( const_cast< unsigned char* >( b.data( ) ) );
    }
    catch (...)
    {
        a_pIssuer.reset( new u1Array(0 ) );
    }
}


/* Get the certificate subject from the certifcate value
*/
void Token::generateSubject( boost::shared_ptr< u1Array>& a_pCertificateValue, boost::shared_ptr< u1Array>& a_pSubject ) {

    try
    {
        X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

        BEROctet::Blob b( x509cert.Subject( ) );

        a_pSubject.reset( new u1Array( static_cast< s4 >( b.size( ) ) ) );

        a_pSubject->SetBuffer( const_cast< unsigned char* >( b.data( ) ) );
    }
    catch (...)
    {
        a_pSubject.reset( new u1Array(0) );
    }
}


/* Get the public key modulus
*/
void Token::generatePublicKeyValue( boost::shared_ptr< u1Array>& a_pCertificateValue, boost::shared_ptr< u1Array>& a_pPublicKeyValue, bool& bIsRSA, unsigned char &ucKeySpec, u8& a_u8CheckValue , boost::shared_ptr< u1Array>& a_pOID) {

    Log::begin( "Token::generatePublicKeyValue" );
    BEROctet::Blob pubKeyVal;
    try
    {
        X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );
        bIsRSA = x509cert.IsRsaPublicKey();
        if (bIsRSA)
        {
            pubKeyVal = x509cert.Modulus( );
        }
        else
        {
            BEROctet::Blob oid = x509cert.EcCurveOid();
    	    a_pOID.reset( new u1Array( oid.size( ) ) );
            a_pOID->SetBuffer( (u1*) oid.data( ) );

            if (MiniDriverContainer::KEYSPEC_EXCHANGE == ucKeySpec)
            {
                if (    (oid.size() == sizeof(g_pbECC256_OID))
                    &&  (0 == memcmp(oid.data(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
                   )
                {
                    ucKeySpec = MiniDriverContainer::KEYSPEC_ECDHE_256;
                }
                if (    (oid.size() == sizeof(g_pbECC384_OID))
                    &&  (0 == memcmp(oid.data(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
                   )
                {
                    ucKeySpec = MiniDriverContainer::KEYSPEC_ECDHE_384;
                }
                if (    (oid.size() == sizeof(g_pbECC521_OID))
                    &&  (0 == memcmp(oid.data(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
                   )
                {
                    ucKeySpec = MiniDriverContainer::KEYSPEC_ECDHE_521;
                }
            }
            else if (MiniDriverContainer::KEYSPEC_SIGNATURE == ucKeySpec)
            {
                if (    (oid.size() == sizeof(g_pbECC256_OID))
                    &&  (0 == memcmp(oid.data(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
                   )
                {
                    ucKeySpec = MiniDriverContainer::KEYSPEC_ECDSA_256;
                }
                if (    (oid.size() == sizeof(g_pbECC384_OID))
                    &&  (0 == memcmp(oid.data(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
                   )
                {
                    ucKeySpec = MiniDriverContainer::KEYSPEC_ECDSA_384;
                }
                if (    (oid.size() == sizeof(g_pbECC521_OID))
                    &&  (0 == memcmp(oid.data(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
                   )
                {
                    ucKeySpec = MiniDriverContainer::KEYSPEC_ECDSA_521;
                }
            }
            pubKeyVal = x509cert.EcPublicPoint();
        }
    }
    catch (...)
    {
        bIsRSA = false;
    }

    a_pPublicKeyValue.reset( new u1Array( pubKeyVal.size( ) ) );

    a_pPublicKeyValue->SetBuffer( (u1*) pubKeyVal.data( ) );

    // Compatibility with old P11
    a_u8CheckValue = Util::MakeCheckValue( pubKeyVal.data( ), static_cast< unsigned int >( pubKeyVal.size( ) ) );
    Log::end( "Token::generatePublicKeyValue" );
}


/* Get the public key modulus
*/
void Token::generateRootAndSmartCardLogonFlags( boost::shared_ptr< u1Array>& a_pCertificateValue, bool& a_bIsRoot, unsigned long& a_ulCertificateCategory, bool& a_bIsSmartCardLogon ) {

    try
    {
        X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

        a_bIsRoot = ( x509cert.IsCACert( ) || x509cert.IsRootCert( ) );

        // CKA_CERTIFICATE_CATEGORY attribute set to "authority" (2) is the certificate is a root or CA one
        a_ulCertificateCategory = a_bIsRoot ? 2 : 1;

        // Look for the Windows Smart Card Logon OID
        a_bIsSmartCardLogon = x509cert.isSmartCardLogon( );
        //Log::log( "SmartCardLogon <%d>", a_pObject->m_bIsSmartCardLogon );
    }
    catch (...)
    {
        a_bIsRoot = false;
        a_ulCertificateCategory = 1;
        a_bIsSmartCardLogon = false;
    }
}


/* Search for a private key using the same public key exponent to set the same container index
*/
void Token::searchContainerIndex( boost::shared_ptr< u1Array>& a_pPubKeyValue, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec ) {

    if( !a_pPubKeyValue ) {

        return;
    }

    int l = a_pPubKeyValue->GetLength( );

    unsigned char* p = a_pPubKeyValue->GetBuffer( );

    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        if( CKO_PRIVATE_KEY == obj->second->getClass( ) ) {

            PrivateKeyObject* prvKey =  (PrivateKeyObject*) obj->second;
            if (prvKey->_keyType == CKK_RSA)
            {
                RSAPrivateKeyObject* objPrivateKey = (RSAPrivateKeyObject*) prvKey;

                if( 0 == memcmp( objPrivateKey->m_pModulus->GetBuffer( ), p, l ) ) {

                    a_ucContainerIndex = objPrivateKey->m_ucContainerIndex;

                    a_ucKeySpec = objPrivateKey->m_ucKeySpec;

                    break;
                }
            }

            if (prvKey->_keyType == CKK_EC)
            {
                ECCPrivateKeyObject* objPrivateKey = (ECCPrivateKeyObject*) prvKey;

                if( (objPrivateKey->m_pPublicPoint->GetLength() == (u4)l) && (0 == memcmp( objPrivateKey->m_pPublicPoint->GetBuffer( ), p, l ) )) {

                    a_ucContainerIndex = objPrivateKey->m_ucContainerIndex;

                    a_ucKeySpec = objPrivateKey->m_ucKeySpec;

                    break;
                }
            }
        }
    }
}


/*
*/
void Token::setDefaultAttributesCertificate( X509PubKeyCertObject* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesCertificate" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    if( !a_pObject->m_pValue ) {

        return;
    }

    // Parse the certifcate value to extract the PKCS11 attribute values not already set
    try {

        generateRootAndSmartCardLogonFlags( a_pObject->m_pValue, a_pObject->m_bIsRoot, a_pObject->_certCategory, a_pObject->m_bIsSmartCardLogon );

        generatePublicKeyValue( a_pObject->m_pValue, a_pObject->m_pPublicKeyValue,  a_pObject->m_bIsRSA, a_pObject->m_ucKeySpec, a_pObject->_checkValue, a_pObject->m_pOID );

        if( a_pObject->m_pPublicKeyValue ) {

            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pObject->m_ucContainerIndex ) {

                searchContainerIndex( a_pObject->m_pPublicKeyValue, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec );
            }

            if( !a_pObject->m_pLabel ) {

                generateLabel( a_pObject->m_pPublicKeyValue, a_pObject->m_pLabel );
            }

            if( !a_pObject->m_pID ) {

                generateID( a_pObject->m_pPublicKeyValue, a_pObject->m_pID );
            }

            if( !a_pObject->m_pSubject ) {

                generateSubject( a_pObject->m_pValue, a_pObject->m_pSubject );
            }

            if( !a_pObject->m_pIssuer ) {

                generateIssuer( a_pObject->m_pValue, a_pObject->m_pIssuer );
            }

            if( !a_pObject->m_pSerialNumber ) {

                generateSerialNumber( a_pObject->m_pValue, a_pObject->m_pSerialNumber );
            }
        }

    } catch( ... ) {

    }

    t.stop( "Token::setDefaultAttributesCertificate" );
    Log::end( "Token::setDefaultAttributesCertificate" );
}


/*
*/
void Token::setDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublic* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    if (a_pObject->_keyType == CKK_RSA)
    {
        Pkcs11ObjectKeyPublicRSA* a_pRsaKey = (Pkcs11ObjectKeyPublicRSA*) a_pObject;

        if( !a_pRsaKey->m_pModulus ) {

            return;
        }

        try {

            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pRsaKey->m_ucContainerIndex ) {

                searchContainerIndex( a_pRsaKey->m_pModulus, a_pRsaKey->m_ucContainerIndex, a_pRsaKey->m_ucKeySpec );
            }

            if( !a_pRsaKey->m_pLabel ) {

                generateLabel( a_pRsaKey->m_pModulus, a_pRsaKey->m_pLabel );
            }

            if( !a_pRsaKey->m_pID ) {

                generateID( a_pRsaKey->m_pModulus, a_pRsaKey->m_pID );
            }

        } catch( ... ) {

        }
    }
    else
    {
        Pkcs11ObjectKeyPublicECC* a_pEccKey = (Pkcs11ObjectKeyPublicECC*) a_pObject;

        if( !a_pEccKey->m_pPublicPoint ) {

            return;
        }

        try {

            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pEccKey->m_ucContainerIndex ) {

                searchContainerIndex( a_pEccKey->m_pPublicPoint, a_pEccKey->m_ucContainerIndex, a_pEccKey->m_ucKeySpec );
            }

            if( !a_pEccKey->m_pLabel ) {

                generateLabel( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pLabel );
            }

            if( !a_pEccKey->m_pID ) {

                generateID( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pID );
            }

        } catch( ... ) {

        }
    }

    t.stop( "Token::setDefaultAttributesKeyPublic" );
    Log::end( "Token::setDefaultAttributesKeyPublic" );
}


/*
*/
void Token::setDefaultAttributesKeyPrivate( PrivateKeyObject* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesKeyPrivate" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    if (a_pObject->_keyType == CKK_RSA)
    {
        RSAPrivateKeyObject* a_pRsaKey = (RSAPrivateKeyObject*) a_pObject;

        if( !a_pRsaKey->m_pModulus ) {

            return;
        }

        try {

            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pRsaKey->m_ucContainerIndex ) {

                searchContainerIndex( a_pRsaKey->m_pModulus, a_pRsaKey->m_ucContainerIndex, a_pRsaKey->m_ucKeySpec );
            }

            // Compatibility with old P11
            unsigned char* p = a_pRsaKey->m_pModulus->GetBuffer( );
            unsigned int l = a_pRsaKey->m_pModulus->GetLength( );

            a_pObject->_checkValue = Util::MakeCheckValue( p, l );

            setContainerIndexToCertificate( a_pRsaKey->m_pModulus, a_pRsaKey->m_ucContainerIndex, a_pRsaKey->m_ucKeySpec );

            setContainerIndexToKeyPublic( a_pRsaKey->m_pModulus, a_pRsaKey->m_ucContainerIndex, a_pRsaKey->m_ucKeySpec );

            if( !a_pRsaKey->m_pLabel ) {

                generateLabel( a_pRsaKey->m_pModulus, a_pRsaKey->m_pLabel );
            }

            if( !a_pRsaKey->m_pID ) {

                generateID( a_pRsaKey->m_pModulus, a_pRsaKey->m_pID );
            }

        } catch( ... ) {

        }
    }
    else
    {
        ECCPrivateKeyObject* a_pEccKey = (ECCPrivateKeyObject*) a_pObject;

        if( !a_pEccKey->m_pPublicPoint ) {

            return;
        }

        try {

            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pEccKey->m_ucContainerIndex ) {

                searchContainerIndex( a_pEccKey->m_pPublicPoint, a_pEccKey->m_ucContainerIndex, a_pEccKey->m_ucKeySpec );
            }

            // Compatibility with old P11
            unsigned char* p = a_pEccKey->m_pPublicPoint->GetBuffer( );
            unsigned int l = a_pEccKey->m_pPublicPoint->GetLength( );

            a_pObject->_checkValue = Util::MakeCheckValue( p, l );

            setContainerIndexToCertificate( a_pEccKey->m_pPublicPoint, a_pEccKey->m_ucContainerIndex, a_pEccKey->m_ucKeySpec );

            setContainerIndexToKeyPublic( a_pEccKey->m_pPublicPoint, a_pEccKey->m_ucContainerIndex, a_pEccKey->m_ucKeySpec );

            if( !a_pEccKey->m_pLabel ) {

                generateLabel( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pLabel );
            }

            if( !a_pEccKey->m_pID ) {

                generateID( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pID );
            }

        } catch( ... ) {

        }
    }

    t.stop( "Token::setDefaultAttributesKeyPrivate" );
    Log::end( "Token::setDefaultAttributesKeyPrivate" );
}


/*
*/
void Token::setContainerIndexToCertificate( boost::shared_ptr< u1Array>& a_pPublicKeyValue, const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec ) {

    Log::begin( "Token::setContainerIndexToCertificate" );
    Timer t;
    t.start( );

    if( !a_pPublicKeyValue ) {

        return;
    }

    unsigned char* p = a_pPublicKeyValue->GetBuffer( );

    unsigned int l = a_pPublicKeyValue->GetLength( );

    // Give the same container index of the private key to the associated certificate
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

            X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;

            if( objCertificate->m_pValue.get( ) ) {

                try
                {
                    X509Cert x509cert( objCertificate->m_pValue->GetBuffer( ), objCertificate->m_pValue->GetLength( ) );

                    // Get the certificate public key modulus
                    BEROctet::Blob pubVal;
                    if (x509cert.IsRsaPublicKey())
                        pubVal = x509cert.Modulus( );
                    else
                        pubVal = x509cert.EcPublicPoint( );

                    if( (l == pubVal.size()) && (0 == memcmp( pubVal.data(), p, l )) ) {

                        // Give the same container index of the private key to the certificate
                        objCertificate->m_ucContainerIndex = a_ucContainerIndex;

                        objCertificate->m_ucKeySpec = a_ucKeySpec;

                        break;
                    }
                }
                catch (...) {}
            }
        }
    }

    t.stop( "Token::setContainerIndexToCertificate" );
    Log::begin( "Token::setContainerIndexToCertificate" );
}


/* Search for an associated public key created before the private key to rename it properly using the index of the created container
*/
void Token::setContainerIndexToKeyPublic( boost::shared_ptr< u1Array>& a_pPublicKeyValue, const unsigned char& a_ucContainerIndex, const unsigned char& /*a_ucKeySpec*/ ) {

    Log::begin( "Token::setContainerIndexToKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pPublicKeyValue ) {

        return;
    }

    unsigned char* p = a_pPublicKeyValue->GetBuffer( );

    unsigned int l = a_pPublicKeyValue->GetLength( );

    // Give the same container index of the private key to the associated public key
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        // Search for a PKCS11 public key object
        if( CKO_PUBLIC_KEY == obj->second->getClass( ) ) {

            Pkcs11ObjectKeyPublic* objPublicKey = (Pkcs11ObjectKeyPublic*) obj->second;
            bool bIsRSA = (objPublicKey->_keyType == CKK_RSA);

           // When the public key is created first the index is not set
            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == objPublicKey->m_ucContainerIndex ) {

                boost::shared_ptr< u1Array> pubVal = (bIsRSA)? ((Pkcs11ObjectKeyPublicRSA*) objPublicKey)->m_pModulus : ((Pkcs11ObjectKeyPublicECC*) objPublicKey)->m_pPublicPoint;
                // Search for the same modulus as the private key
                if( (pubVal->GetLength() == l) && (0 == memcmp( pubVal->GetBuffer( ), p, l )) ) {

                    // Delete the old object
                    deleteObjectFromCard( objPublicKey );

                    // Compute a new name regardiong the new index for the public key
                    std::string stNewName = objPublicKey->m_stFileName.substr( 0, objPublicKey->m_stFileName.length( ) - 2 );
                    Util::toStringHex( a_ucContainerIndex, stNewName );

                    // Update the inner object's properties
                    objPublicKey->m_stFileName = stNewName;

                    objPublicKey->m_ucContainerIndex = a_ucContainerIndex;

                    // Save the new object
                    writeObject( objPublicKey );

                    break;
                }
            }
        }
    }

    t.stop( "Token::setContainerIndexToKeyPublic" );
    Log::end( "Token::setContainerIndexToKeyPublic" );
}

bool Token::isRoleUsingProtectedAuthenticationPath(MiniDriverAuthentication::ROLES role)
{
	if ( !m_Device->isNoPin( role ) )
	{
		if(  (  (m_Device->isExternalPin(role))
				&&(m_Device->isVerifyPinSecured())
				)
			||(m_Device->isModeNotPinOnly(role))
			)
		{
			return true;
		}
	}

	return false;
}
