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

#ifndef __GEMALTO_CARDMANAGER__
#define __GEMALTO_CARDMANAGER__

#include <string>
#include <atomic>         // std::atomic, std::atomic_flag, ATOMIC_FLAG_INIT
#include <mutex>
#include <string>
#include <vector>

#ifdef WIN32
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include "wintypes.h"
#endif

#include "Array.h"
#include "cryptoki.h"
#include "Timer.hpp"


typedef struct DeviceInfo {
	char szDeviceName[128];		// Device name - PCSC : reader name, SPI : device node name
	DWORD       cbAtr;          // Number of bytes in the returned ATR.
	BYTE        rgbAtr[36];     // Atr of inserted card, (extra alignment bytes)
	// DeviceInfo () {printf ("----- DeviceInfo Constructor -----\n");}
	// ~DeviceInfo () {printf ("----- DeviceInfo Destructor -----");}
} DEVICEINFO, *PDEVICEINFO;


class CardManager
{
private:
	static std::atomic<CardManager*> 	m_pCMInstance;
	static std::mutex 					m_mutex;
	bool            					m_fTransacted = false;
	void*								m_gtoCtxt = NULL;
	u1* 								m_pAPDUCmdData = NULL;
	u1*									m_pAPDURspData = NULL;
	u4									m_dwActiveProtocol = 0;

protected:
	CardManager ();
    ~CardManager ();

public:
	// Non sensitive APDUs logging flag : Default = no logging 
	static bool s_bAPDULogging;

	static CardManager* getInstance ();   // throw (int)
    static CK_RV listAvailableDevices (std::vector<DEVICEINFO>& vDevices);

	bool beginTransaction (void);
    void endTransaction (void);

	void exchangeData (u1Array &dataIn, u1Array &dataout, BOOL isSensitive); // throw
	void exchangeData (u1Array &dataIn, u1Array &dataout, u2* SW1SW2, BOOL isSensitive); // throw

	void resetCard (void); //throw

	std::string getDeviceName (void);
};

class DeviceTransaction
{
protected:
    std::string       m_sDeviceName; 
    bool              m_fTransacted;

public:
    DeviceTransaction (const std::string& p_sDeviceName) : m_sDeviceName(p_sDeviceName), m_fTransacted (false)
    {
		try
		{
			m_fTransacted = CardManager::getInstance ()->beginTransaction ();
		}
		catch (...) {}
    }

    ~DeviceTransaction ()
    {
		try
		{
			if (m_fTransacted)
				CardManager::getInstance ()->endTransaction ();
			m_fTransacted = false;
		}
		catch (...){}
    }
};

#endif
