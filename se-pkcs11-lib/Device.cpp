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

#include <memory>
#include "Device.hpp"
#include "Application.hpp"

extern Application g_Application;

bool Device::s_bEnableDiskCache = true;

std::vector<CardDesc> Device::s_vAdditionalAtrs;

#define TIMEOUT_CHANGE 2.0

#define TIMEOUT_AUTH 0.2

/*
*/
Device::Device (const DEVICEINFO& a_DeviceInfo, const unsigned char& a_ID ) {

    m_ucDeviceID = a_ID;

    clear ();

    try {
        set (a_DeviceInfo);
    
    } catch (...) {
    
    }
   
    m_TimerLastChange.start( );    
}


/*
*/
Device::~Device( ) {

    clear( );
}


/*
*/
void Device::clear( void ) {

    memset (&m_stDeviceInfo, 0, sizeof (DEVICEINFO));

    m_MiniDriver.reset ();

    clearPinCache ();
}


/*
*/
void Device::set (const DEVICEINFO& p_stDevInfo) {

    Log::begin ("Device::set");

	// Get a copy of the device information
	m_stDeviceInfo = p_stDevInfo;

    // clear PIN cache
    clearPinCache ();

	addMiniDriver ();

	Log::end ("Device::set");
}


/*
*/
void Device::addMiniDriver( void ) {

    Log::begin ("Device::addMiniDriver");

    bool bTransactionTaken = false;
    try {
    
        // Create a card module service
        m_MiniDriver.reset( new MiniDriver( ) );

        m_MiniDriver->setSmartCardReader( m_stDeviceInfo.szDeviceName, m_stDeviceInfo.rgbAtr, m_stDeviceInfo.cbAtr );
        bTransactionTaken = beginTransaction( );

        m_MiniDriver->CheckSmartCardType();

        m_MiniDriver->read( s_bEnableDiskCache );

		m_AuthRoles.clear();

        for (int i = 0; i < 6; i++)
        {
            MiniDriverAuthentication::ROLES role = MiniDriverAuthentication::getRoleFromIndex(i);
            if ( m_MiniDriver->isAuthenticated( role ) )
            {
                m_AuthRoles[role] = true;
                break;
            }
        }
    
    } catch( ... ) {
    
    }

    if (bTransactionTaken)
        endTransaction( );

	Log::end ("Device::addMiniDriver");
}


/*
*/
void Device::removeMiniDriver( void ) {

    // Remove the card module service
    m_MiniDriver.reset( );
    clearPinCache();
}


/*
*/
/*
void Device::update( const SCARD_READERSTATE& scr ) {

    memcpy( m_DeviceInfo.rgbAtr, scr.rgbAtr, scr.cbAtr );
    m_DeviceInfo.cbAtr = scr.cbAtr;
    m_DeviceInfo.dwCurrentState = scr.dwCurrentState;
    m_DeviceInfo.dwEventState = scr.dwEventState;

    if( !isSmartCardPresent( ) || isSmartCardMute( ) )
        clearPinCache();
}
*/

/*
*/
/*
void Device::put( SCARD_READERSTATE& scr ) {

    memset( &scr, 0, sizeof( SCARD_READERSTATE ) );
    scr.szReader = m_sSMCReader.c_str( );
    scr.dwCurrentState = m_DeviceInfo.dwCurrentState;
    scr.dwEventState = m_DeviceInfo.dwEventState;
    memcpy( scr.rgbAtr, m_DeviceInfo.rgbAtr, m_DeviceInfo.cbAtr );
    scr.cbAtr = m_DeviceInfo.cbAtr;

    if( !isSmartCardPresent( ) || isSmartCardMute( ) )
        clearPinCache();
}
*/

/*
*/
void Device::hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files ) {

    if( m_TimerLastChange.getCurrentDuration( ) < (double)TIMEOUT_CHANGE ) {
     
        return;
    }
    
    if( !m_MiniDriver ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }
    
    m_MiniDriver->hasChanged( a_Pins, a_Containers, a_Files );
    
    m_TimerLastChange.start( );
}


/*
*/
bool Device::isAuthenticated( MiniDriverAuthentication::ROLES role ) {

	if(		(m_TimerLastAuth.find(role) != m_TimerLastAuth.end())
		&&	(m_TimerLastAuth[role].getCurrentDuration( ) < (double)TIMEOUT_AUTH) ) {
     
        return (m_AuthRoles[role]);
    }

    if( !m_MiniDriver ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    if (m_MiniDriver->isAuthenticated( role ))
        m_AuthRoles[role] = true;
    else
        m_AuthRoles[role] = false;
    
    m_TimerLastAuth[role].start( );

    return (m_AuthRoles[role]);
}

void Device::changePin( MiniDriverAuthentication::ROLES role, u1Array* a_pOldPIN, u1Array* a_pNewPIN )
{ 
    if( m_MiniDriver.get( ) ) 
    { 
        m_MiniDriver->changePin( role, a_pOldPIN, a_pNewPIN );
        m_securedPin[MiniDriverAuthentication::getRoleIndex(role)].CopyFrom(a_pNewPIN->GetBuffer(), a_pNewPIN->GetLength());
    } 
    else 
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
}


/*
*/
void Device::verifyPin( MiniDriverAuthentication::ROLES role, u1Array* a_Pin ) {

    if( !m_MiniDriver ) {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_MiniDriver->verifyPin( role,  a_Pin); 

    m_AuthRoles[role] = true;

    m_TimerLastAuth[role].start( );

    m_securedPin[MiniDriverAuthentication::getRoleIndex(role)].CopyFrom(a_Pin->GetBuffer(), a_Pin->GetLength());
}


/*
*/
void Device::logOut( MiniDriverAuthentication::ROLES role, bool bClearCache ) {

    if( !m_MiniDriver ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_MiniDriver->logOut( role ); 

    if (bClearCache)
    {
        clearPinCache(role);
    }

    m_TimerLastAuth[role].start( );

    m_AuthRoles[role] = false;
}


/*
*/
u1Array* Device::getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags ) {

    if( !m_MiniDriver ) {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    return m_MiniDriver->getCardProperty( a_ucProperty, a_ucFlags );
}


/*
*/
void Device::setCardProperty( const unsigned char& a_ucProperty, u1Array* a_Data, const unsigned char& a_ucFlags ) {

    if( !m_MiniDriver ) {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_MiniDriver->setCardProperty( a_ucProperty, a_Data, a_ucFlags );
}


bool Device::beginTransaction() 
{ 
	bool bCardReset = false, bCardRemoved = false, bTaken = false;
	if( m_MiniDriver.get( ) ) 
	{ 
		bTaken = m_MiniDriver->beginTransaction( bCardReset, bCardRemoved );
		if (bCardReset)
        {
			g_Application.handleResetOnDevice(this);
            if (bCardRemoved)
            {
                g_Application.handleRemovalOnDevice(this);
            }
        }
	} 

	return bTaken;
}
