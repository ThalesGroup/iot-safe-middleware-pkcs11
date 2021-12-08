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
#include <cstdlib>

using namespace std;

#define STR_DEVICE_NAME "/dev/ttyACM0"

extern "C" {
 #include "../libse-gto.h"
}

 struct se_gto_ctx * l_gtoCtxt = NULL;


#define CARD_APPLET_AID                 ("\xA0\x00\x00\x00\x30\x53\xF1\x24\x01\x77\x01\x01\x49\x53\x41")
#define CARD_APPLET_AID_LEN             (15)

#define READ_CERT_DATA_IN_LEN           (3)
#define READ_CERT_DATA_IN               ("\x83\x01\x02")

#define GEN_KEY_PAIR_DATA_LEN			(3)
#define GEN_KEY_PAIR_DATA_IN			("\x84\x01\x04")

#define SIGN_INIT_DATA_IN               ("\x84\x01\x01\xA1\x01\x03\x91\x02\x00\x01\x92\x01\x04")
#define SIGN_INIT_DATA_LEN              (13)

#define SIGN_DATA 						("\x9E\x20\x2C\xF2\x4D\xBA\x5F\xB0\xA3\x0E\x26\xE8\x3B\x2A\xC5\xB9\xE2\x9E\x1B\x16\x1E\x5C\x1F\xA7\x42\x5E\x73\x04\x33\x62\x93\x8B\x98\x24")
#define SIGN_DATA_LEN 					(34)

#define ATR_DATA_MAX_SIZE				36

// APDU data buffer max size
#define APDUCMD_DATA_MAX_SIZE  		128
#define APDURSP_DATA_MAX_SIZE 		260

#define SPEED					1000000

typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;


//function declaration

void selectApplet (struct se_gto_ctx * p_pGtoCtxt)
{
	u2 l_SW1SW2 = 0x9000;

	u1 l_parAPDUCmd[APDUCMD_DATA_MAX_SIZE] = {0};
	u1 l_parAPDURsp[APDURSP_DATA_MAX_SIZE] = {0};

	memset (l_parAPDUCmd, 0, APDUCMD_DATA_MAX_SIZE);
	memset (l_parAPDURsp, 0, APDURSP_DATA_MAX_SIZE);

	try
         {
		int l_nAPDUCmdLen = 5 + CARD_APPLET_AID_LEN;
		int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

		// Applet Select
                l_parAPDUCmd[0] = 0x00;
                l_parAPDUCmd[1] = 0xA4;
                l_parAPDUCmd[2] = 0x04;
                l_parAPDUCmd[3] = 0x00;
                l_parAPDUCmd[4] = (u1)CARD_APPLET_AID_LEN;

                memcpy (&(l_parAPDUCmd[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

		printf ("\tAPDU Comand length %d : ", l_nAPDUCmdLen);
		for (int l_nI = 0; l_nI < l_nAPDUCmdLen; l_nI++)
		{
			printf ("%02X ", l_parAPDUCmd[l_nI]);
		}
		printf ("\n");

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit (p_pGtoCtxt, l_parAPDUCmd, l_nAPDUCmdLen, l_parAPDURsp, l_nAPDURspLen);
		if (l_nAPDURspLen < 0 )
                	printf ("\nERROR \n");

		u1 l_sw1 = l_parAPDURsp[l_nAPDURspLen - 2];
		u1 l_sw2 = l_parAPDURsp[l_nAPDURspLen - 1];
		l_SW1SW2 = (l_sw1 << 8) + l_sw2;

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < l_nAPDURspLen; l_nI++)
		{
			printf ("%02X ", l_parAPDURsp[l_nI]);
		}
		printf ("\n");
	}
    catch (...)
    {
	printf ("\nERROR \n");
    }

    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:
	printf ("\nERROR \n");
    }
}

void signInit (struct se_gto_ctx * p_pGtoCtxt)
{
	u2 l_SW1SW2 = 0x9000;

	u1 l_parAPDUCmd[APDUCMD_DATA_MAX_SIZE] = {0};
	u1 l_parAPDURsp[APDURSP_DATA_MAX_SIZE] = {0};

	memset (l_parAPDUCmd, 0, APDUCMD_DATA_MAX_SIZE);
	memset (l_parAPDURsp, 0, APDURSP_DATA_MAX_SIZE);

	try
         {
		int l_nAPDUCmdLen = 5 + SIGN_INIT_DATA_LEN;
		int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

		// Applet Select
                l_parAPDUCmd[0] = 0x00;
                l_parAPDUCmd[1] = 0x2A;
                l_parAPDUCmd[2] = 0x00;
                l_parAPDUCmd[3] = 0x01;
                l_parAPDUCmd[4] = (u1)SIGN_INIT_DATA_LEN;


                memcpy (&(l_parAPDUCmd[5]), (u1*)SIGN_INIT_DATA_IN, SIGN_INIT_DATA_LEN);

		printf ("\tAPDU Comand length %d : ", l_nAPDUCmdLen);
		for (int l_nI = 0; l_nI < l_nAPDUCmdLen; l_nI++)
		{
			printf ("%02X ", l_parAPDUCmd[l_nI]);
		}
		printf ("\n");

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit (p_pGtoCtxt, l_parAPDUCmd, l_nAPDUCmdLen, l_parAPDURsp, l_nAPDURspLen);
		if (l_nAPDURspLen < 0 )
                	printf ("\nERROR \n");

		u1 l_sw1 = l_parAPDURsp[l_nAPDURspLen - 2];
		u1 l_sw2 = l_parAPDURsp[l_nAPDURspLen - 1];
		l_SW1SW2 = (l_sw1 << 8) + l_sw2;

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < l_nAPDURspLen; l_nI++)
		{
			printf ("%02X ", l_parAPDURsp[l_nI]);
		}
		printf ("\n");
	}
    catch (...)
    {
	printf ("\nERROR \n");
    }

    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:
	printf ("\nERROR \n");
    }
}
void signUpdate (struct se_gto_ctx * p_pGtoCtxt)
{
	u2 l_SW1SW2 = 0x9000;

	u1 l_parAPDUCmd[APDUCMD_DATA_MAX_SIZE] = {0};
	u1 l_parAPDURsp[APDURSP_DATA_MAX_SIZE] = {0};

	memset (l_parAPDUCmd, 0, APDUCMD_DATA_MAX_SIZE);
	memset (l_parAPDURsp, 0, APDURSP_DATA_MAX_SIZE);

	try
         {
		int l_nAPDUCmdLen = 5 + SIGN_DATA_LEN;
		int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;
		// Applet Select
                l_parAPDUCmd[0] = 0x00;
                l_parAPDUCmd[1] = 0x2B;
                l_parAPDUCmd[2] = 0x80;
                l_parAPDUCmd[3] = 0x01;
				l_parAPDUCmd[4] = 0x22;

                memcpy (&(l_parAPDUCmd[5]), (u1*)SIGN_DATA, SIGN_DATA_LEN);

		printf ("\tAPDU Comand length %d : ", l_nAPDUCmdLen);
		for (int l_nI = 0; l_nI < l_nAPDUCmdLen; l_nI++)
		{
			printf ("%02X ", l_parAPDUCmd[l_nI]);
		}
		printf ("\n");

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit (p_pGtoCtxt, l_parAPDUCmd, l_nAPDUCmdLen, l_parAPDURsp, l_nAPDURspLen);
		if (l_nAPDURspLen < 0 )
                	printf ("\nERROR \n");

		u1 l_sw1 = l_parAPDURsp[l_nAPDURspLen - 2];
		u1 l_sw2 = l_parAPDURsp[l_nAPDURspLen - 1];
		l_SW1SW2 = (l_sw1 << 8) + l_sw2;

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < l_nAPDURspLen; l_nI++)
		{
			printf ("%02X ", l_parAPDURsp[l_nI]);
		}
		printf ("\n");
	}
    catch (...)
    {
	printf ("\nERROR \n");
    }

    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:
	printf ("\nERROR \n");
    }
}
void readCertificate(struct se_gto_ctx * p_pGtoCtxt){

        u2 l_SW1SW2 = 0x9000;

	u1 l_parAPDUCmd[APDUCMD_DATA_MAX_SIZE] = {0};
	u1 l_parAPDURsp[APDURSP_DATA_MAX_SIZE] = {0};

	memset (l_parAPDUCmd, 0, APDUCMD_DATA_MAX_SIZE);
	memset (l_parAPDURsp, 0, APDURSP_DATA_MAX_SIZE);
	try
         {
            int l_nAPDUCmdLen = 5 + READ_CERT_DATA_IN_LEN + 1;
            int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

                // Read file
                l_parAPDUCmd[0] = 0x00;
                l_parAPDUCmd[1] = 0xB0;
                l_parAPDUCmd[2] = 0x00;
                l_parAPDUCmd[3] = 0x00;
                l_parAPDUCmd[4] = (u1)READ_CERT_DATA_IN_LEN;

                memcpy (&(l_parAPDUCmd[5]), (u1*)READ_CERT_DATA_IN, READ_CERT_DATA_IN_LEN);

                l_parAPDUCmd[l_nAPDUCmdLen] = 0x00;

		printf ("\tAPDU Comand length %d : ", l_nAPDUCmdLen);
		for (int l_nI = 0; l_nI < l_nAPDUCmdLen; l_nI++)
		{
			printf ("%02X ", l_parAPDUCmd[l_nI]);
		}
		printf ("\n");

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit (p_pGtoCtxt, l_parAPDUCmd, l_nAPDUCmdLen, l_parAPDURsp, l_nAPDURspLen);
		if (l_nAPDURspLen < 0 )
                	printf ("\nERROR \n");

		u1 l_sw1 = l_parAPDURsp[l_nAPDURspLen - 2];
		u1 l_sw2 = l_parAPDURsp[l_nAPDURspLen - 1];
		l_SW1SW2 = (l_sw1 << 8) + l_sw2;

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < l_nAPDURspLen; l_nI++)
		{
			printf ("%02X ", l_parAPDURsp[l_nI]);
		}
		printf ("\n");
	}
    catch (...)
    {
	printf ("\nERROR \n");
    }

    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:
	printf ("\nERROR \n");
    }

}

void generateKeyPair(struct se_gto_ctx * p_pGtoCtxt) {
	 u2 l_SW1SW2 = 0x9000;

	u1 l_parAPDUCmd[APDUCMD_DATA_MAX_SIZE] = {0};
	u1 l_parAPDURsp[APDURSP_DATA_MAX_SIZE] = {0};

	memset (l_parAPDUCmd, 0, APDUCMD_DATA_MAX_SIZE);
	memset (l_parAPDURsp, 0, APDURSP_DATA_MAX_SIZE);
	try
         {
            int l_nAPDUCmdLen = 5 + GEN_KEY_PAIR_DATA_LEN + 1;
            int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;
	    


                // Generate keypair
                l_parAPDUCmd[0] = 0x00;
                l_parAPDUCmd[1] = 0xB9;
                l_parAPDUCmd[2] = 0x00;
                l_parAPDUCmd[3] = 0x00;
                l_parAPDUCmd[4] = (u1)GEN_KEY_PAIR_DATA_LEN;
		
		memcpy (&(l_parAPDUCmd[5]), (u1*)GEN_KEY_PAIR_DATA_IN, GEN_KEY_PAIR_DATA_LEN);
		l_parAPDUCmd[l_nAPDUCmdLen] = 0x00;

		printf ("\tAPDU Comand length %d : ", l_nAPDUCmdLen);
		for (int l_nI = 0; l_nI < l_nAPDUCmdLen; l_nI++){
			printf ("%02X ", l_parAPDUCmd[l_nI]);
		}
		printf ("\n");

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit (p_pGtoCtxt, l_parAPDUCmd, l_nAPDUCmdLen, l_parAPDURsp, l_nAPDURspLen);
		if (l_nAPDURspLen < 0 )
                	printf ("\nERROR \n");

		u1 l_sw1 = l_parAPDURsp[l_nAPDURspLen - 2];
		u1 l_sw2 = l_parAPDURsp[l_nAPDURspLen - 1];
		l_SW1SW2 = (l_sw1 << 8) + l_sw2;

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < l_nAPDURspLen; l_nI++)
		{
			printf ("%02X ", l_parAPDURsp[l_nI]);
		}
		printf ("\n");
	}
    catch (...)
    {
	printf ("\nERROR \n");
    }

    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:
	printf ("\nERROR \n");
    }
	
}
void generateRandom(struct se_gto_ctx * p_pGtoCtxt) {

        u2 l_SW1SW2 = 0x9000;

	u1 l_parAPDUCmd[APDUCMD_DATA_MAX_SIZE] = {0};
	u1 l_parAPDURsp[APDURSP_DATA_MAX_SIZE] = {0};

	memset (l_parAPDUCmd, 0, APDUCMD_DATA_MAX_SIZE);
	memset (l_parAPDURsp, 0, APDURSP_DATA_MAX_SIZE);
	try
         {
            int l_nAPDUCmdLen = 5;
            int l_nAPDURspLen = APDURSP_DATA_MAX_SIZE;

                // Generate Random
                l_parAPDUCmd[0] = 0x00;
                l_parAPDUCmd[1] = 0x84;
                l_parAPDUCmd[2] = 0x00;
                l_parAPDUCmd[3] = 0x00;
                l_parAPDUCmd[4] = 0x1C;

		printf ("\tAPDU Comand length %d : ", l_nAPDUCmdLen);
		for (int l_nI = 0; l_nI < l_nAPDUCmdLen; l_nI++){
			printf ("%02X ", l_parAPDUCmd[l_nI]);
		}
		printf ("\n");

		// Transmit the APDU to the card
		l_nAPDURspLen = se_gto_apdu_transmit (p_pGtoCtxt, l_parAPDUCmd, l_nAPDUCmdLen, l_parAPDURsp, l_nAPDURspLen);
		if (l_nAPDURspLen < 0 )
                	printf ("\nERROR \n");

		u1 l_sw1 = l_parAPDURsp[l_nAPDURspLen - 2];
		u1 l_sw2 = l_parAPDURsp[l_nAPDURspLen - 1];
		l_SW1SW2 = (l_sw1 << 8) + l_sw2;

		printf ("\tAPDU Response : ");
		for (int l_nI = 0; l_nI < l_nAPDURspLen; l_nI++)
		{
			printf ("%02X ", l_parAPDURsp[l_nI]);
		}
		printf ("\n");
	}
    catch (...)
    {
	printf ("\nERROR \n");
    }

    // Result
    switch (l_SW1SW2)
    {
        case 0x9000:
            break;

        default:
	printf ("\nERROR \n");
    }

}

int main (int argc, char *argv[]) {

 printf("\n **** Cinterion Modem access test **** \n\n ");

 try {
      printf("\nCreating a new device context ...\n");

       if(se_gto_new(&l_gtoCtxt) < 0) {
          printf("\n Error while initializing the card \n");
       }

       printf("done \n");

       //Select the device to use
       se_gto_set_gtodev(l_gtoCtxt, STR_DEVICE_NAME);

       //Display the device description
        printf("\t Device name: %s \n", se_gto_get_gtodev(l_gtoCtxt));

       //Open the device context
       printf("\n \t Opening the device context...\n");
       if(se_gto_open(l_gtoCtxt) < 0) {
        printf("\n\t Error while opening the context\n");
       }

        selectApplet(l_gtoCtxt);
        readCertificate(l_gtoCtxt);
        generateRandom(l_gtoCtxt);
		    generateKeyPair(l_gtoCtxt);
		    signInit(l_gtoCtxt);
		    signUpdate(l_gtoCtxt);

       //Close the context
       printf("\n \t Closing the device context...\n");
       if(se_gto_close(l_gtoCtxt) < 0) {
        printf("\n Error while closing device context \n");
       }
        printf("done\n");
    }
    catch(...) {}

 return 0;
}



