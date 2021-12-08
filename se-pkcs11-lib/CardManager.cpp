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
#include <windows.h>
#else
#include <string.h>
#endif

#include "CardManager.hpp"
#include "libse-gto.h"

#ifdef WIN32
// Extra function to determine the smart card protocol (T=0, T=1)
extern "C"
{
	DWORD se_gto_get_selected_protocol (struct se_gto_ctx *ctx);
}
#endif

#include "PKCS11Exception.hpp"
#include "Log.hpp"
#include "Except.h"

// Secure Element Access Library logging
// #define SEACCESSLIB_LOGGING

// APDU data buffer max size
#define APDUCMD_DATA_MAX_SIZE  		260
#define APDURSP_DATA_MAX_SIZE 		600

#define ATR_DATA_MAX_SIZE			36

#define STR_PCSCTESTREADER_NAME 	"Broadcom Corp Contacted SmartCard 0"
// #define STR_PCSCTESTREADER_NAME 	"Gemalto Prox-DU Contact interface 0"
// #define STR_PCSCTESTREADER_NAME     "Gemalto Prox-DU Contactless interface 0"
// #define STR_PCSCTESTREADER_NAME 	"Gemalto Virtual Card Simulator Reader 0"
// #define STR_PCSCTESTREADER_NAME 	"Gemalto MULTIFF SE Reader ISO 0"
// #define STR_PCSCTESTREADER_NAME 	"Gemalto MULTIFF SE Reader SPI0 0"
#define STR_CINTERION_MODEM_NAME "/dev/ttyUSB0"
#define CARD_ATR_TEST_T0			("\x3B\x7F\x96\x00\x00\x80\x31\x80\x65\xB0\x84\x41\x3D\xF6\x12\x0F\xFE\x82\x90\x00")
#define CARD_ATR_TEST_LEN			20

#define CARD_PROTOCOL_T0			1
#define CARD_PROTOCOL_T1			2
#define SPEED					1000000

std::atomic<CardManager*> CardManager::m_pCMInstance;
std::mutex CardManager::m_mutex;

// Non sensitive APDUs logging flag : Default = no logging
bool CardManager::s_bAPDULogging = true;


#ifndef WIN32
#ifdef SEACCESSLIB_LOGGING
// Secure Element Access Library logging level
#define  SEACCESSB_LOGLEVEL_ERROR 	0
#define  SEACCESSB_LOGLEVEL_WARNING 1
#define  SEACCESSB_LOGLEVEL_NOTICE  2
#define  SEACCESSB_LOGLEVEL_INFO    3
#define  SEACCESSB_LOGLEVEL_DEBUG   4

// Secure Element Access Library : logging call back function
void seaccess_logging (struct se_gto_ctx* p_gtoCtx, const char * p_szLogMsg)
{
	Log::log ("se-access-lib - %s", p_szLogMsg);
}
*/
#endif
#endif


CardManager::CardManager () // throw PKCS11Exception
{
	Log::begin ("CardManager::CardManager");

	// Allocate needed resources
	m_pAPDUCmdData = new u1[APDUCMD_DATA_MAX_SIZE];
	m_pAPDURspData = new u1[APDURSP_DATA_MAX_SIZE];

	// ----- Initialize the card access library -----
	// Create a new device context
	if (se_gto_new ((struct se_gto_ctx**)&m_gtoCtxt) < 0)
    {
		Log::error ("CardManager::CardManager", "Error while initializing the Card  Access library ! Context creation.");
		throw PKCS11Exception (CKR_GENERAL_ERROR);
    }

#ifdef WIN32
	// Select the device to use (the laptop embedded reader)
	se_gto_set_gtodev ((struct se_gto_ctx*) m_gtoCtxt, STR_PCSCTESTREADER_NAME);
#else
	// Select the device to use (the first SPI device slave)
	//se_gto_set_gtodev ((struct se_gto_ctx*) m_gtoCtxt, "/dev/spidev0.0");
	se_gto_set_gtodev ((struct se_gto_ctx*) m_gtoCtxt, STR_CINTERION_MODEM_NAME);

	// se_gto_speed (struct se_gto_ctx*) m_gtoCtxt, 5);
#ifdef SEACCESSLIB_LOGGING
	//se_gto_set_log_fn ((struct se_gto_ctx*) m_gtoCtxt, seaccess_logging);
	//se_gto_set_log_level ((struct se_gto_ctx*) m_gtoCtxt, SEACCESSB_LOGLEVEL_DEBUG);
#endif
#endif

	// Open the device context
    if (se_gto_open ((struct se_gto_ctx*) m_gtoCtxt) < 0)
	{
		Log::error ("CardManager::CardManager", "Error while initializing the Card  Access library ! Context opening.");
		throw PKCS11Exception (CKR_DEVICE_REMOVED);
	}
    if(se_gto_speed((struct se_gto_ctx*) m_gtoCtxt,SPEED)<0)
	{
		Log::error ("CardManager::CardManager", "Error while setting speed.");	
		throw PKCS11Exception (CKR_DEVICE_REMOVED);
	}

	// Reset the device
	resetCard ();

	// Register the current selected smart card protocol
#ifdef WIN32
	m_dwActiveProtocol = se_gto_get_selected_protocol ((struct se_gto_ctx*) m_gtoCtxt);
#else
	// SPI --> protocol T=1
	m_dwActiveProtocol = CARD_PROTOCOL_T1;
#endif

	Log::end ("CardManager::CardManager");
}


CardManager::~CardManager ()
{
	Log::begin ("CardManager::CardManager");

	// Free the allocated resources
	delete[] m_pAPDUCmdData;
	delete[] m_pAPDURspData;

	// Finalize the card access library
    if (se_gto_close ((struct se_gto_ctx*) m_gtoCtxt) < 0)
		Log::error ("CardManager::~CardManager", "Error while finalizing the Card  Access library ! Context closing.");
	m_gtoCtxt = NULL;

	Log::end ("CardManager::CardManager");
}


CardManager* CardManager::getInstance () // throw PKCS11Exception
{
    CardManager* l_pCM = m_pCMInstance.load (std::memory_order_relaxed);

	if (l_pCM == NULL)
	{
        std::lock_guard<std::mutex> lock (m_mutex);
        l_pCM = m_pCMInstance.load (std::memory_order_relaxed);

		if (l_pCM == NULL)
		{
			l_pCM = new CardManager ();
            m_pCMInstance.store (l_pCM, std::memory_order_relaxed);
        }
    }

	return l_pCM;
}


CK_RV CardManager::listAvailableDevices (std::vector<DEVICEINFO>& vDevices) // PKCS11Exception
{
	CK_RV 	l_ulErc = CKR_OK;

	vDevices.clear ();

	// Initialize the devices list
	try
	{
		CardManager* l_pCardMgr = CardManager::getInstance ();

		DEVICEINFO stDevInfo;
		memset (&stDevInfo, 0, sizeof(DEVICEINFO));

		strcpy (stDevInfo.szDeviceName, l_pCardMgr->getDeviceName ().c_str ());

		BYTE* l_pbAtrTest = (BYTE*)CARD_ATR_TEST_T0;
		for (int l_nI = 0; l_nI < CARD_ATR_TEST_LEN; l_nI++)
			stDevInfo.rgbAtr [l_nI] = * (l_pbAtrTest + l_nI);
		stDevInfo.cbAtr = CARD_ATR_TEST_LEN;

		std::vector<DEVICEINFO>::iterator iter = vDevices.begin ();
		vDevices.insert (iter, stDevInfo);
	}
	catch (...)
	{
		// No device : The device list remains empty
	}

	return (l_ulErc);
}


std::string CardManager::getDeviceName (void)
{
	return (std::string (se_gto_get_gtodev ((struct se_gto_ctx*) m_gtoCtxt)));
}


void CardManager::exchangeData (u1Array &dataIn, u1Array &dataout, BOOL isSensitive)
{
    Log::begin ("CardManager::exchangeData");
	try
	{
		// The library takes care of the transaction management
		// beginTransaction ();
		Timer t;
		int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

		DWORD dwLen = dataIn.GetLength ();

		memset (m_pAPDUCmdData, 0x00, APDUCMD_DATA_MAX_SIZE);
		memcpy (m_pAPDUCmdData, dataIn.GetBuffer(), dataIn.GetLength());

		Log::log ("CardManager::exchangeData - Smart card active protocol : %s", (m_dwActiveProtocol == CARD_PROTOCOL_T1) ? "T=1" : "T=0");
		if (m_dwActiveProtocol == CARD_PROTOCOL_T1)
		{
			// T = 1 -> Add LE to ISO Case 3
			if ((dataIn.GetLength () == (5 + (u4)dataIn.GetBuffer ()[4])) && (dataIn.GetBuffer ()[4] != 0))
			{
				//dwLen++;
			}
			// T = 1 -> Add LE to ISO Case 1
			if (dataIn.GetLength () == 4)
			{
				//dwLen++;
			}
		}

		if (s_bAPDULogging)
		{
			std::string szApdu;
			Log::toString (m_pAPDUCmdData, (isSensitive) ? 4 : dwLen, szApdu);

			if (isSensitive)
			{
				Log::log ("APDU Cmd Data Buffer => %s <Sensitive>", szApdu.c_str());
			}
			else
			{
				Log::log ("APDU Cmd Data Buffer => %s", szApdu.c_str());
			}
			t.start( );

		}



		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit ((struct se_gto_ctx *)m_gtoCtxt, m_pAPDUCmdData, (int)dwLen, m_pAPDURspData, l_nAPDURspLen);


		if (l_nAPDURspLen < 0 )
		{
			if (s_bAPDULogging)
			{
				Log::log ("Card Transmit error : 0x%08X\n", l_nAPDURspLen);
				t.stop( "CardManager::exchangeData Execution time");
			}

			throw RemotingException ("Card Transmit error", l_nAPDURspLen);
		}

		if (s_bAPDULogging)
		{
			std::string szApdu;
			Log::toString (m_pAPDURspData, l_nAPDURspLen, szApdu);
			Log::log ("APDU Rsp Data Buffer <= %s", szApdu.c_str ());
		}

		if (l_nAPDURspLen < 2)
		{
			throw RemotingException ("Card Transmit error - Incorrect length returned", -1);
		}

		if (l_nAPDURspLen > 2)
		{
			u1Array temp (l_nAPDURspLen - 2);
			temp.SetBuffer (m_pAPDURspData);
			dataout += temp;
		}

		u1 sw1 = m_pAPDURspData[l_nAPDURspLen - 2];
		u1 sw2 = m_pAPDURspData[l_nAPDURspLen - 1];

		if (s_bAPDULogging)
		{
			Log::log ("SW1SW2: %02x%02x\n", sw1, sw2);
			t.stop( "CardManager::exchangeData Execution time");
		}

		while ((sw1 == 0x61) || (sw1 == 0x9F))
		{
			u1 sw22 = sw2;
			u1 l_pAPDUCmdGetResponse[5];

			if (sw1 == 0x9F)
			{
				l_pAPDUCmdGetResponse[0] = 0xA0;
			}
			else
			{
				l_pAPDUCmdGetResponse[0] = dataIn.GetBuffer()[0] & 0x07;	// 0x00;
			}

			l_pAPDUCmdGetResponse[1] = 0xC0;
			l_pAPDUCmdGetResponse[2] = 0x00;
			l_pAPDUCmdGetResponse[3] = 0x00;
			l_pAPDUCmdGetResponse[4] = sw2;
			l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

			if (s_bAPDULogging)
			{
				Log::log ("APDU Cmd Data Buffer => %02X %02X %02X %02X %02X", l_pAPDUCmdGetResponse[0], l_pAPDUCmdGetResponse[1], l_pAPDUCmdGetResponse[2], l_pAPDUCmdGetResponse[3], l_pAPDUCmdGetResponse[4]);
				t.start( );

			}


			// Transmit the APDU to the card
			l_nAPDURspLen = se_gto_apdu_transmit ((struct se_gto_ctx *)m_gtoCtxt, l_pAPDUCmdGetResponse, 5, m_pAPDURspData, l_nAPDURspLen);



			if (l_nAPDURspLen < 0 )
			{
				if (s_bAPDULogging)
				{
					Log::log ("Card Transmit error : 0x%08X\n", l_nAPDURspLen);
					t.stop( "CardManager::exchangeData Execution time");
				}

				throw RemotingException ("Card Transmit error", l_nAPDURspLen);
			}


			if (s_bAPDULogging)
			{
				std::string szApdu;
				Log::toString (m_pAPDURspData, l_nAPDURspLen, szApdu);
				Log::log ("APDU Rsp Data Buffer <= %s", szApdu.c_str());
			}

			if (l_nAPDURspLen < 2)
			{
				throw RemotingException ("Card Transmit error - Incorrect length returned", CKR_DEVICE_ERROR);
			}

			if (l_nAPDURspLen > 2)
			{
				u1Array temp (l_nAPDURspLen - 2);
				temp.SetBuffer (m_pAPDURspData);
				dataout += temp;
			}
			sw1 = m_pAPDURspData[l_nAPDURspLen - 2];
			sw2 = m_pAPDURspData[l_nAPDURspLen - 1];

			if(s_bAPDULogging)
			{
				Log::log("SW1SW2: %02x%02x\n",sw1,sw2);
				t.stop( "CardManager::exchangeData Execution time");
			}

			// TODO: SW1SW2 = 60xx -> retry ?!
			if (sw1 == 0x60)
			{
				sw1 = 0x61;
				sw2 = sw22;
			}
		}
	}
	catch (...)
	{
		// The library takes care of the transaction management
		// endTransaction ();
		throw;
	}

	// The library takes care of the transaction management
	// endTransaction ();
    Log::end ("CardManager::exchangeData");
}


void CardManager::exchangeData (u1Array &dataIn, u1Array &dataout, u2* SW1SW2, BOOL isSensitive)
{
    Log::begin ("CardManager::exchangeData");
    try
    {
		// The library takes care of the transaction management
        // beginTransaction ();
		Timer t;

        int l_nAPDURspLen = 0;

REPLAY:
        l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

		DWORD dwLen = dataIn.GetLength ();

        memset (m_pAPDUCmdData, 0x00, APDUCMD_DATA_MAX_SIZE);
        memcpy (m_pAPDUCmdData, dataIn.GetBuffer(), dataIn.GetLength());

		Log::log ("CardManager::exchangeData -  Smart card active protocol : %s", (m_dwActiveProtocol == CARD_PROTOCOL_T1) ? "T=1" : "T=0");
		if (m_dwActiveProtocol == CARD_PROTOCOL_T1)
        {
			// T = 1 -> Add LE to ISO Case 3
            if ((dataIn.GetLength () == (5 + (u4)dataIn.GetBuffer ()[4])) && (dataIn.GetBuffer ()[4] != 0))
            {
                //dwLen++;
            }
			// T = 1 -> Add LE to ISO Case 1
			if (dataIn.GetLength () == 4)
			{
				//dwLen++;
			}
		}

        if (s_bAPDULogging)
		{
			std::string szApdu;
			Log::toString (m_pAPDUCmdData, (isSensitive) ? 4 : dwLen, szApdu);

            if (isSensitive)
            {
			    Log::log ("APDU Cmd Data Buffer => %s <Sensitive>", szApdu.c_str ());
            }
            else
            {
			    Log::log ("APDU Cmd Data Buffer => %s", szApdu.c_str ());
            }
			t.start ();
		}

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit ((struct se_gto_ctx *)m_gtoCtxt, m_pAPDUCmdData, (int)dwLen, m_pAPDURspData, l_nAPDURspLen);

		if (l_nAPDURspLen < 0 )
		{
			if (s_bAPDULogging)
			{
				Log::log ("Card Transmit error : 0x%08X\n", l_nAPDURspLen);
				t.stop ("CardManager::exchangeData Execution time");
			}

			throw RemotingException ("Card Transmit error", l_nAPDURspLen);
		}

		if (s_bAPDULogging)
		{
			std::string szApdu;
			Log::toString (m_pAPDURspData, l_nAPDURspLen, szApdu);
			Log::log ("APDU Rsp Data Buffer <= %s", szApdu.c_str ());
		}

        if (l_nAPDURspLen < 2)
        {
			throw RemotingException ("Card Transmit error - Incorrect length returned", CKR_DEVICE_ERROR);
        }

        if (l_nAPDURspLen > 2)
        {
            u1Array temp (l_nAPDURspLen - 2);
            temp.SetBuffer (m_pAPDURspData);
            dataout += temp;
        }

        u1 sw1 = m_pAPDURspData[l_nAPDURspLen - 2];
        u1 sw2 = m_pAPDURspData[l_nAPDURspLen - 1];

        *SW1SW2 = (sw1 << 8) + sw2;

        if (s_bAPDULogging)
		{
			Log::log ("SW1SW2: %02x%02x\n", sw1, sw2);
			t.stop ("CardManager::exchangeData Execution time");

			if (*SW1SW2 == 0x6D00)
            {
                Log::log ("Lost context !\n");
            }
        }

        if (sw1 == 0x6C)
        {
            dataIn.GetBuffer()[4] = sw2;
            goto REPLAY;
        }


        while ((sw1 == 0x61) || (sw1 == 0x9F))
        {
            u1 sw22 = sw2;
            u1 l_pAPDUCmdGetResponse[5];

            if (sw1 == 0x9F)
            {
                l_pAPDUCmdGetResponse[0] = 0xA0;
            }
            else
            {
                l_pAPDUCmdGetResponse[0] = dataIn.GetBuffer()[0] & 0x07;//0x00;
            }

            l_pAPDUCmdGetResponse[1] = 0xC0;
            l_pAPDUCmdGetResponse[2] = 0x00;
            l_pAPDUCmdGetResponse[3] = 0x00;
            l_pAPDUCmdGetResponse[4] = sw2;
            l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

			if (s_bAPDULogging)
			{
				Log::log("APDU Cmd Data Buffer => %02X %02X %02X %02X %02X", l_pAPDUCmdGetResponse[0], l_pAPDUCmdGetResponse[1], l_pAPDUCmdGetResponse[2], l_pAPDUCmdGetResponse[3], l_pAPDUCmdGetResponse[4]);
				t.start ();
			}

			// Transmit the APDU to the card
			l_nAPDURspLen = se_gto_apdu_transmit ((struct se_gto_ctx *)m_gtoCtxt, l_pAPDUCmdGetResponse, 5, m_pAPDURspData, l_nAPDURspLen);

			if (l_nAPDURspLen < 0 )
			{
				if (s_bAPDULogging)
				{
					Log::log ("Card Transmit error : 0x%08X\n", l_nAPDURspLen);
					t.stop ("CardManager::exchangeData Execution time");
				}

				throw RemotingException ("Card Transmit error", l_nAPDURspLen);
			}

			if (s_bAPDULogging)
			{
				std::string szApdu;
				Log::toString (m_pAPDURspData, l_nAPDURspLen, szApdu);
				Log::log ("APDU Rsp Data Buffer <= %s", szApdu.c_str());
			}

            if (l_nAPDURspLen < 2)
            {
                throw RemotingException ("Card Transmit error - Incorrect length returned", CKR_DEVICE_ERROR);
            }

            if (l_nAPDURspLen > 2)
            {
                u1Array temp (l_nAPDURspLen - 2);
                temp.SetBuffer (m_pAPDURspData);
                dataout += temp;
            }
            sw1 = m_pAPDURspData[l_nAPDURspLen - 2];
            sw2 = m_pAPDURspData[l_nAPDURspLen - 1];

            *SW1SW2 = (sw1 << 8) + sw2;

			if (s_bAPDULogging)
			{
				Log::log ("SW1SW2: %02x%02x\n", sw1, sw2);
				t.stop ("CardManager::exchangeData Execution time");
			}

			// TODO: SW1SW2 = 60xx -> retry ?!
            if (sw1 == 0x60)
            {
                sw1 = 0x61;
                sw2 = sw22;
            }
        }
    }
    catch (...)
    {
		// The library takes care of the transaction management
        // endTransaction ();
        throw;
    }

	// The library takes care of the transaction management
    // endTransaction ();
    Log::end ("CardManager::exchangeData");
}


void CardManager::resetCard (void)
{
	u1 l_pbAtr[ATR_DATA_MAX_SIZE];

	memset (l_pbAtr, 0x00, ATR_DATA_MAX_SIZE);
	int l_nAtrLen = se_gto_reset ((struct se_gto_ctx *)m_gtoCtxt, &l_pbAtr, ATR_DATA_MAX_SIZE);

	if (l_nAtrLen < 0)
	{
		throw RemotingException ("Card Reset error", CKR_DEVICE_ERROR);
	}
}


bool CardManager::beginTransaction (void)
{
	/***** CC TODO : Manage the transaction based on the original one in the Minidriver.hpp file *****/
	return true;
}


void CardManager::endTransaction (void)
{
	/***** CC TODO : Manage the transaction based on the original one in the Minidriver.hpp file *****/
}

