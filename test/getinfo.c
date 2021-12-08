/**
* Copyright (c) 2015 GEMALTO. All Rights Reserved.
* Copyright (c) 2021 Thales. All Rights Reserved.
*
* This software is the confidential and proprietary information of GEMALTO.
*
* -------------------------------------------------------------------------
* GEMALTO MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
* THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
* THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
* PURPOSE OR NON-INFRINGEMENT. GEMALTO SHALL NOT BE LIABLE FOR ANY
* DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
* DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
*
* THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
* CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
* PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
* NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
* SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
* SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
* PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"). GEMALTO
* SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR
* HIGH RISK ACTIVITIES.
*/

/*****************************************************************************
* This sample code shows how to retrieve the token information, the slot
* information and the session information.
* It prints out a listing of all the objects and their attributes in the token.
* It illustrates how to find objects using the C_FindObject
* functions and then how to determine their attributes using C_GetAttribute.
* The user is assumed to have logged in (C_Login), before using this function.
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef WIN32
#include <windows.h>
#include <conio.h>
#ifndef _WINDOWS
#define _WINDOWS
#endif
#else
#include <stdlib.h>
#include <unistd.h>
#endif
#ifndef WIN32
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#include "utils.h"
#include "getinfo.h"

CK_BYTE myKey[60] = {0};

CK_RV geLibraryInfo (CK_FUNCTION_LIST_PTR p_pFunctions)
{
    CK_RV       l_ulErc = CKR_OK;
    CK_INFO     l_stInfo;
    CK_CHAR     l_szId[33], l_szDescription[33];

    if ((l_ulErc = (*p_pFunctions->C_GetInfo)(&l_stInfo)) != CKR_OK)
    {
        CKRLOG ("C_GetInfo", l_ulErc);
        return l_ulErc;
    }

    memcpy (l_szId, l_stInfo.manufacturerID, sizeof (l_stInfo.manufacturerID));
    l_szId[sizeof (l_szId) - 1] = '\0';
    memcpy (l_szDescription, l_stInfo.libraryDescription, sizeof (l_stInfo.libraryDescription));
    l_szDescription[sizeof (l_szDescription) - 1] = '\0';

    printf ("Library Information :\n\
            \t> Cryptoki Version : %d.%02d\n\
            \t> Manufacturer Id : %s\n\
            \t> Flags : %04lX\n\
            \t> Library Description : %s\n\
            \t> Library Version : %d.%d\n\n",
           l_stInfo.cryptokiVersion.major, l_stInfo.cryptokiVersion.minor,
           l_szId,
           l_stInfo.flags,
           l_szDescription,
           l_stInfo.libraryVersion.major, l_stInfo.libraryVersion.minor);

    return l_ulErc;
}


CK_RV getSlotInfo (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SLOT_ID p_ulSlotID)
{
    CK_RV           l_ulErc = CKR_OK;
    CK_SLOT_INFO    l_stSlotInfo;
    CK_CHAR         l_szId[33], l_szSlotDescription[65];

    if ((l_ulErc = (*p_pFunctions->C_GetSlotInfo)(p_ulSlotID, &l_stSlotInfo)) != CKR_OK)
    {
        CKRLOG ("C_GetSlotInfo", l_ulErc);
        return l_ulErc;
    }

    memcpy (l_szId, l_stSlotInfo.manufacturerID, sizeof (l_stSlotInfo.manufacturerID));
    l_szId[sizeof (l_szId) - 1] = '\0';
    memcpy (l_szSlotDescription, l_stSlotInfo.slotDescription, sizeof (l_stSlotInfo.slotDescription));
    l_szSlotDescription[sizeof (l_szSlotDescription) - 1] = '\0';

    printf ("Slot Information for slot %ld :\n\
            \t> Slot Description : %s\n\
            \t> Manufacturer Id : %s\n\
            \t> Flags: %s %s %s\n\
            \t> Hardware Version : %d.%d\n\
            \t> Firmware Version : %d.%d\n\n",
           p_ulSlotID,
           l_szSlotDescription,
           l_szId,
           ((l_stSlotInfo.flags & 1) ? "CKF_TOKEN_PRESENT" : ""),
           ((l_stSlotInfo.flags & 2) ? "CKF_REMOVABLE_DEVICE" : ""),
           ((l_stSlotInfo.flags & 4) ? "CKF_HW_SLOT" : ""),
           l_stSlotInfo.hardwareVersion.major, l_stSlotInfo.hardwareVersion.minor,
           l_stSlotInfo.firmwareVersion.major, l_stSlotInfo.firmwareVersion.minor
          );

    return l_ulErc;
}


CK_RV getTokenInfo (CK_FUNCTION_LIST_PTR p, CK_SLOT_ID slotID)
{
    CK_RV           rv = CKR_OK;
    CK_TOKEN_INFO   tinfo;
    CK_CHAR         szId[33], szLabel[33], szModel[17], szSerialNumber[17];

    if ((rv = (*p->C_GetTokenInfo)(slotID, &tinfo)) != CKR_OK)
    {
        CKRLOG ("C_GetTokenInfo", rv);
        return rv;
    }

    memcpy (szLabel, tinfo.label, 32);
    szLabel[sizeof(szLabel) - 1] = '\0';
    memcpy (szId, tinfo.manufacturerID, 32);
    szId[sizeof(szId) - 1] = '\0';
    memcpy (szModel, tinfo.model, 16);
    szModel[sizeof (szModel) - 1] = '\0';
    memcpy (szSerialNumber, tinfo.serialNumber, 16);
    szSerialNumber [sizeof(szSerialNumber) - 1] = '\0';
    printf ("Token Information for slot %ld:\n\
            \t> Label: %s\n\
            \t> Manufacturer Id: %s\n\
            \t> Model: %s\n\
            \t> Serial Number: %s\n\
            \t> Flags: %s%s%s%s%s%s%s%s%s%s\n\
            \t> Max sessions: %ld\n\
            \t> Current sessions: %ld\n\
            \t> Max R/W sessions %ld\n\
            \t> Current R/W sessions: %ld\n\
            \t> Max Pin Len: %ld\n\
            \t> Min Pin Len: %ld\n\
            \t> Total public memory: %ld\n\
            \t> Free public memory: %ld\n\
            \t> Total private memory: %ld\n\
            \t> Free private memory: %ld\n",
           slotID,
           szLabel,
           szId,
           szModel,
           szSerialNumber,
           ((tinfo.flags & 1) ? "CKF_RNG " : ""),
           ((tinfo.flags & 2) ? "CKF_WRITE_PROTECTED " : ""),
           ((tinfo.flags & 4) ? "CKF_LOGIN_REQUIRED " : ""),
           ((tinfo.flags & 8) ? "CKF_USER_PIN_INITIALIZED " : ""),
           ((tinfo.flags & 16) ? "CKF_EXCLUSIVE_EXISTS " : ""),
           ((tinfo.flags & 32) ? "CKF_RESTORE_KEY_NOT_NEEDED " : ""),
           ((tinfo.flags & 64) ? "CKF_CLOCK_ON_TOKEN " : ""),
           ((tinfo.flags & 128) ? "CKF_SUPPORTS_PARALLEL " : ""),
           ((tinfo.flags & 256) ? "CKF_PROTECTED_AUTHENTICATION_PATH " : ""),
           ((tinfo.flags & 512) ? "CKF_DUAL_CRYPTO_OPERATIONS " : ""),
           tinfo.ulMaxSessionCount,
           tinfo.ulSessionCount,
           tinfo.ulMaxRwSessionCount,
           tinfo.ulRwSessionCount,
           tinfo.ulMaxPinLen,
           tinfo.ulMinPinLen,
           tinfo.ulTotalPublicMemory,
           tinfo.ulFreePublicMemory,
           tinfo.ulTotalPrivateMemory,
           tinfo.ulFreePrivateMemory
          );

    return rv;
}


CK_RV getSessionInfo (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession)
{
    CK_RV           rv = CKR_OK;
    CK_SESSION_INFO si;

    if ((rv = (*p->C_GetSessionInfo)(hSession, &si)) != CKR_OK)
    {
        CKRLOG ("C_GetSessionInfo", rv);
        return rv;
    }
    printf ("Session Information\n\
            \t> slotID: %ld\n\
            \t> state: %ld\n\
            \t> flags: %ld\n\
            \t> ulDeviceError: %ld\n\n",
            si.slotID,
            si.state,
            si.flags,
            si.ulDeviceError
           );

    return rv;
}


char* objectClassToString (CK_ULONG value)
{
    switch (value)
    {
        case CKO_DATA               : return "CKO_DATA : Application defined data";
        case CKO_CERTIFICATE        : return "CKO_CERTIFICATE : Certificate";
        case CKO_PUBLIC_KEY         : return "CKO_PUBLIC_KEY : Public key";
        case CKO_PRIVATE_KEY        : return "CKO_PRIVATE_KEY : Private key";
        case CKO_SECRET_KEY         : return "CKO_SECRET_KEY : Secret key";
        case CKO_HW_FEATURE         : return "CKO_HW_FEATURE : Device feature";
        case CKO_DOMAIN_PARAMETERS  : return "CKO_DOMAIN_PARAMETERS : Algorithm's extended parameters";
        case CKO_MECHANISM          : return "CKO_MECHANISM : Device machanism information";
        case CKO_VENDOR_DEFINED     : return "CKO_VENDOR_DEFINED : Device machanism information";
        default                     : return "Unknown";
    }
}


/*****************************************************************************
* CK_RV dumpAll(void)
*****************************************************************************/
CK_RV dumpAll (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession)
{
    /* List of possible format types for attributes */
    #define FT_ULONG (1)
    #define FT_BYTES (2)
    #define FT_BOOL (3)

    /*---- Full list of all possible Cryptoki attributes ----*/
    static const struct
    {
        const char *pszName;
        CK_ULONG ulType;
        int nFormat;
    } ATypes[] =
    {
        /* Name Attrbute ID Format type */
        { "CKA_CLASS", CKA_CLASS, FT_ULONG },
        { "CKA_TOKEN", CKA_TOKEN, FT_BOOL },
        { "CKA_PRIVATE", CKA_PRIVATE, FT_BOOL },
        { "CKA_LABEL", CKA_LABEL, FT_BYTES },
        { "CKA_APPLICATION", CKA_APPLICATION, FT_BYTES },
        { "CKA_VALUE", CKA_VALUE, FT_BYTES },
        { "CKA_CERTIFICATE_TYPE", CKA_CERTIFICATE_TYPE, FT_ULONG },
        { "CKA_ISSUER", CKA_ISSUER, FT_BYTES },
        { "CKA_SERIAL_NUMBER", CKA_SERIAL_NUMBER, FT_BYTES },
        { "CKA_KEY_TYPE", CKA_KEY_TYPE, FT_ULONG },
        { "CKA_SUBJECT", CKA_SUBJECT, FT_BYTES },
        { "CKA_ID", CKA_ID, FT_BYTES },
        { "CKA_SENSITIVE", CKA_SENSITIVE, FT_BOOL },
        { "CKA_ENCRYPT", CKA_ENCRYPT, FT_BOOL },
        { "CKA_DECRYPT", CKA_DECRYPT, FT_BOOL },
        { "CKA_WRAP", CKA_WRAP, FT_BOOL },
        { "CKA_UNWRAP", CKA_UNWRAP, FT_BOOL },
        { "CKA_SIGN", CKA_SIGN, FT_BOOL },
        { "CKA_SIGN_RECOVER", CKA_SIGN_RECOVER, FT_BOOL },
        { "CKA_VERIFY", CKA_VERIFY, FT_BOOL },
        { "CKA_VERIFY_RECOVER", CKA_VERIFY_RECOVER, FT_BOOL },
        { "CKA_DERIVE", CKA_DERIVE, FT_BOOL },
        { "CKA_START_DATE", CKA_START_DATE, FT_BYTES },
        { "CKA_END_DATE", CKA_END_DATE, FT_BYTES },
        { "CKA_MODULUS", CKA_MODULUS, FT_BYTES },
        { "CKA_MODULUS_BITS", CKA_MODULUS_BITS, FT_ULONG },
        { "CKA_PUBLIC_EXPONENT", CKA_PUBLIC_EXPONENT, FT_BYTES },
        { "CKA_PRIVATE_EXPONENT", CKA_PRIVATE_EXPONENT, FT_BYTES },
        { "CKA_PRIME_1", CKA_PRIME_1, FT_BYTES },
        { "CKA_PRIME_2", CKA_PRIME_2, FT_BYTES },
        { "CKA_EXPONENT_1", CKA_EXPONENT_1, FT_BYTES },
        { "CKA_EXPONENT_2", CKA_EXPONENT_2, FT_BYTES },
        { "CKA_COEFFICIENT", CKA_COEFFICIENT, FT_BYTES },
        { "CKA_PRIME", CKA_PRIME, FT_BYTES },
        { "CKA_SUBPRIME", CKA_SUBPRIME, FT_BYTES },
        { "CKA_BASE", CKA_BASE, FT_BYTES },
        { "CKA_VALUE_BITS", CKA_VALUE_BITS, FT_BYTES },
        { "CKA_VALUE_LEN", CKA_VALUE_LEN, FT_ULONG },
        { "CKA_EXTRACTABLE", CKA_EXTRACTABLE, FT_BOOL },
        { "CKA_LOCAL", CKA_LOCAL, FT_BOOL },
        { "CKA_NEVER_EXTRACTABLE", CKA_NEVER_EXTRACTABLE, FT_BOOL },
        { "CKA_ALWAYS_SENSITIVE", CKA_ALWAYS_SENSITIVE, FT_BOOL },
        { "CKA_MODIFIABLE", CKA_MODIFIABLE, FT_BOOL },
        { "CKA_VENDOR_DEFINED", CKA_VENDOR_DEFINED, FT_BYTES },
        { "", 0, 0 }
    };

    CK_RV               l_ulErc = CKR_OK;
    CK_OBJECT_HANDLE    l_hObject;
    CK_ULONG            l_ulObjectsFound = 0;
    int                 l_nTotalObjects = 0;
    int		        	l_keyIndex = 0;

    // Allocate a buffer large enough to contain all the attributes for an object
    CK_ULONG            l_ulBufferSize = 8192;
    char*               l_pszBuffer = (char*)malloc (l_ulBufferSize);
    if (l_pszBuffer == NULL)
        return CKR_HOST_MEMORY;

    CK_ATTRIBUTE l_stAttribute = { 0, l_pszBuffer, 0 };

    logInfo (("\nDumping all objects...\n"));

    /* Find *all* objects (NULL_PTR means all objects) */
    if ((l_ulErc = (*p->C_FindObjectsInit)(hSession, NULL_PTR, 0)) != CKR_OK)
    {
        CKRLOG("C_FindObjectsInit", l_ulErc);
        free (l_pszBuffer);
        return l_ulErc;
    }

    do
    {
        // Locate the next object
        if ((l_ulErc = (*p->C_FindObjects)(hSession, &l_hObject, 1, &l_ulObjectsFound)) != CKR_OK)
        {
            CKRLOG ("C_FindObjects", l_ulErc);
            free (l_pszBuffer);
            return l_ulErc;
        }

        if (l_ulObjectsFound == 1)
        {
            l_nTotalObjects++;

            // Write out a header
            logInfo (("\n\n\n================== Begin Object %d ===============================\n", l_nTotalObjects));

            int l_nI;

            // Loop for all possible attributes
            for (l_nI = 0; (ATypes[l_nI].nFormat != 0); l_nI++)
            {
                // Get the next attrivute
                l_stAttribute.type = ATypes[l_nI].ulType;
                l_stAttribute.ulValueLen = l_ulBufferSize;
                l_ulErc = (*p->C_GetAttributeValue)(hSession, l_hObject, &l_stAttribute, 1);

                // Print out the attribute
                switch (l_ulErc)
                {
                    case CKR_OK:
                        logInfo (("%-22s", ATypes[l_nI].pszName));
                        switch (ATypes[l_nI].nFormat)
                        {
                            case FT_ULONG:
                                if (CKA_CLASS == ATypes[l_nI].ulType)
                                {
                                    logInfo (("%s\n", objectClassToString (((CK_ULONG_PTR)l_stAttribute.pValue)[0])));
                                }
                                else
                                {
                                    logInfo (("%lu\n", ((CK_ULONG_PTR)l_stAttribute.pValue)[0]));
                                }
                                break;
                            case FT_BYTES:
				  				if(strcmp(ATypes[l_nI].pszName, "CKA_ID") == 0)
								{	
									memcpy(&myKey[l_keyIndex], l_stAttribute.pValue, l_stAttribute.ulValueLen);						
									l_keyIndex += 20; 
								}
                                // Print out a byte buffer in 16 byte blocks
                                if ( l_stAttribute.ulValueLen != CK_UNAVAILABLE_INFORMATION)
                                {
                                    logInfo (("(%lu bytes)\n", l_stAttribute.ulValueLen));
                                    logDump (_INFO_, l_stAttribute.pValue, l_stAttribute.ulValueLen);
                                }
                                else
                                {
                                    logInfo (("(N.A)\n" ));
                                }
                                break;
                            case FT_BOOL:
                                logInfo (((((CK_BBOOL *)l_stAttribute.pValue)[0]) ? "TRUE\n" : "FALSE\n"));
                                break;
                            default:
                                break;
                        }
                        break;

                    case CKR_ATTRIBUTE_SENSITIVE:
                        // Opps! we're not allowed to see it
                        logInfo (("%-22s<sensitive>\n", ATypes[l_nI].pszName));
                        break;

                    case CKR_ATTRIBUTE_TYPE_INVALID:
                        // This attrbute doesn't exist for this object
                        break;

                    default:
                        CKRLOG ("C_GetAttributeValue", l_ulErc);
                        // A real error has occured.
                        free (l_pszBuffer);
                        return l_ulErc;
                }
            }

            // Write out a footer
            logInfo (("================== End Object %d =================================\n", l_nTotalObjects));

        }
    } while (l_ulObjectsFound == 1);

    logInfo (("\nTotal number of object(s) found = %d\n", l_nTotalObjects));

    if ((l_ulErc = (*p->C_FindObjectsFinal)(hSession)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsFinal", l_ulErc);
    }

    free (l_pszBuffer);
    return l_ulErc;
}

