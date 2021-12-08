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
#include <stdio.h>
#include <string.h>

#include "CardManager.hpp"
#include "PKCS11Exception.hpp"
using namespace std;

#ifndef WIN32
#define memcpy_s(dest,numberOfElements,src,count)    memcpy(dest,src,count)
#endif

#define CARD_APPLET_AID                ("\xA0\x00\x00\x00\x30\x53\xF1\x24\x01\x77\x01\x01\x49\x53\x41")
#define CARD_APPLET_AID_LEN             (15)

#ifndef WIN32
#include <sys/sysinfo.h>

u4 GetTickCount ()
{
	struct sysinfo info;
	sysinfo(&info);
	return info.uptime * 1000;
}
#endif

void selectApplet (void)
{
	u2 l_SW1SW2 = 0x9000;

	u1Array* l_parAPDUCmd = NULL;
	u1Array* l_parAPDURsp = NULL;

	try
    {
        // Applet Select 
        l_parAPDUCmd = new u1Array (5 + CARD_APPLET_AID_LEN);
        l_parAPDURsp = new u1Array(0);
        
        l_parAPDUCmd->GetBuffer()[0] = 0x00;
        l_parAPDUCmd->GetBuffer()[1] = 0xA4;
        l_parAPDUCmd->GetBuffer()[2] = 0x04;
        l_parAPDUCmd->GetBuffer()[3] = 0x00;
        l_parAPDUCmd->GetBuffer()[4] = (BYTE)CARD_APPLET_AID_LEN;
        
        memcpy_s (&(l_parAPDUCmd->GetBuffer()[5]), CARD_APPLET_AID_LEN, (BYTE*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);
        
		printf ("\tAPDU Comand   : ");
		for (int l_nI = 0; l_nI < (int)l_parAPDUCmd->GetLength (); l_nI++)
		{
			printf ("%02X ", l_parAPDUCmd->GetBuffer()[l_nI]);
		}
		printf ("\n");
	        
        CardManager::getInstance ()->exchangeData (*l_parAPDUCmd, *l_parAPDURsp, &l_SW1SW2, FALSE);

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < (int)l_parAPDURsp->GetLength (); l_nI++)
		{
			printf ("%02X ", l_parAPDURsp->GetBuffer()[l_nI]);
		}
		printf ("%02X %02X", l_SW1SW2 >> 8, l_SW1SW2 & 0x00FF);
		printf ("\n");
	}
    catch (...)
    {
		throw new PKCS11Exception (CKR_DEVICE_ERROR);
    }
    
    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:   
			throw new PKCS11Exception (CKR_DEVICE_ERROR);
    }
}

/**
 * Secure Element PKCS#11 Library - Card Manager interface test
 * Send a set of APDU to the SE/CArd to validate the Card Manager access.
 * 
 * @param argc
 * @param argv
 * 
 * @return 
 */
int main (int argc, char *argv[])
{
	vector<DEVICEINFO>	l_vDevices;

	printf ("\n***** Secure Element Access Test *****\n\n");

	try
	{
		printf ("Obtaining the card manager instance ... ");
		CardManager* l_pobjCardManager = CardManager::getInstance ();
		printf ("done.\n");

		printf ("Retrieving the list of available devices ... "); 
		l_pobjCardManager->listAvailableDevices (l_vDevices);
		printf ("done.\n");

		if (l_vDevices.empty ())
		{
			printf ("\n\tNo device available !!!\n");
			throw new PKCS11Exception (CKR_DEVICE_REMOVED);
		}

		printf ("Resetting the device ... "); 
		l_pobjCardManager->resetCard ();
		printf ("done.\n");

		printf ("Selecting applet ...\n");
		selectApplet ();

		printf ("\nTest successful.\n");
	}
	catch (PKCS11Exception exc)
	{
		printf ("\n\tTest failed  ! Exception : 0x%08X\n", exc.getError ());
	}

	printf ("\n");
}

