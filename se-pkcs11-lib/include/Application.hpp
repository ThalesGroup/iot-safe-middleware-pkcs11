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
#ifndef __GEMALTO_APPLICATION__
#define __GEMALTO_APPLICATION__

#include <sys/stat.h>
#include <string>

#include "cryptoki.h"

#include "Slot.hpp"

// const int g_iMaxSlotsPerReader = 6;
// const int g_iMaxSlot = g_iMaxReader * g_iMaxSlotsPerReader;
const int g_iMaxSlot = 2;

// class DeviceMonitor;
class Device;
class Slot;


/*
*/
class Application  {

public:
	Application( );
	virtual ~Application( );

	inline boost::shared_ptr< Slot >* getSlotList( void ) { return m_Slots; }
	void getSlotList( const CK_BBOOL& tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount );
	const boost::shared_ptr< Slot >& getSlot( const CK_SLOT_ID& );
	const boost::shared_ptr< Slot >& getSlotFromSession( const CK_SESSION_HANDLE& );

    void initialize( void );
    void initializeOpenSSL( void );

    void finalize( void );

	void handleResetOnDevice(Device* d);
    void handleRemovalOnDevice(Device* d);

    static bool g_bOpensslInitialized;
	static bool g_bHideStaticSlots;
    static bool g_DisableCertificateValidation;

private:

	void getDevices( void );
	void addSlot( const boost::shared_ptr< Device >& , bool bSetEvent);
	void addVirtualSlots( const boost::shared_ptr< Device >& , CK_SLOT_ID slotID, bool bSetEvent);

	boost::shared_ptr< Slot > m_Slots [g_iMaxSlot];
};

#endif // __GEMALTO_APPLICATION__
