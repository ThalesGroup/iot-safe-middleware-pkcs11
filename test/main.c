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

#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#include <conio.h>
#ifndef _WINDOWS
#define _WINDOWS
#endif
#ifdef _WIN64
#define LIBRARY_NAME "C:\\Program Files (x86)\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS1164"
#else
#define LIBRARY_NAME "C:\\Program Files (x86)\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS11"
#endif
#define LIBRARY_EXT ".dll"
#define DLOPEN(lib) LoadLibrary(lib)
#define DLSYM(h, function) GetProcAddress(h, function)
#define DLCLOSE(h) FreeLibrary(h)
#else
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>

#define LIBRARY_NAME "/usr/local/lib/libgtosepkcs11"
#ifdef __APPLE__
#define LIBRARY_EXT ".dylib"
#else
#define LIBRARY_EXT ".so"
#endif
#define DLOPEN(lib) dlopen(lib ,RTLD_NOW)
#define DLSYM(h, function) dlsym(h, function)
#define DLCLOSE(h) dlclose(h)
#endif

#include "utils.h"
#include "delete.h"
#include "getinfo.h"
#include "rsa.h"
#include "aes.h"
#include "random.h"
#include "ecc.h"

extern CK_BYTE myKey[60];
typedef struct
{
    CK_CHAR_PTR     pszAlgo;
    CK_CHAR_PTR     pszID;
} OBJECT_ID , *OBJECT_ID_PTR;

typedef struct
{
    CK_ULONG        size;
    OBJECT_ID       stID;
} OBJECT_KEY , *OBJECT_KEY_PTR;

typedef struct
{
    CK_BYTE_PTR     data;
    OBJECT_ID       stID;
} OBJECT_DATA , *OBJECT_DATA_PTR;


/*---------------------------------------------------------------------------
 Static Global Variables
----------------------------------------------------------------------------*/
static char         g_szDLLName[128] = LIBRARY_NAME LIBRARY_EXT;
static CK_CHAR      g_szPinCode[49] = "";
static CK_SLOT_ID   g_ulSlotID = 0;
static int          g_nMaxObjects = 10;
static CK_BYTE      g_pbData[] = {  0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x05, 0x00, 0x04, 0x10, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x06,
                                    0x31, 0x21, 0x31, 0x0d
                                };



/*****************************************************************************
* void usage(void)
*
* Description : Prints out program information and then terminates the
* application.
*****************************************************************************/
void usage (void)
{
    printf ("(c)2021 Thales Development\n\
            usage:  program  [Options]\n\n"
            " Options \n\n"
            "      -p:<pincode>                     pin value\n"
            "      -i:<slotid>                      slot id value\n"
            "      -l:<cryptoki/library/path>       cryptoki library path\n"
            "      -f                               Prints all the objects and their\n"
            "                                       attributes in the token.\n"
            "      -R                               Remove all objects from the token.\n"
            "      -r:<id>                          Remove object identified by id from\n"
            "                                       the token.\n"
            "      -k:<algo:length:id>              Generate a new key pair public\n"
            "                                       private pair and aes key.\n"
            "                                       for example -k:rsa:1024 -k:aes:128.\n"
            "      -s:<algo:id:data>                Signature with verification\n"
            "                                       Sign data using a private key identified by id.\n"
            "                                       Verify the sgnature using the related public key\n"
            "                                       Example : -s:rsa:keyid:data -s:ec:keyid:data\n"
            "      -e:<algo:id:data>                Encryption / decryption\n"
            "                                       Encrypt plain text data using a public key identified by id\n"
            "                                       Decrypt the encrypted data using the private key to get the plain text data\n"
            "                                       Example : -e:rsa:keyid of pubk -e:aes:keyid\n"
            "      -c                               Perform AES CMAC 128-bit signature."
            "      -g                               Random generation 8 bytes.\n"
            "      -a:<nb tests>                    Perform nb iteration of all tests.\n\n"
            "      -h                               Perform a Diffie-Hellman.\n"
            "All arguments are optional. Defaults are: \n\
            <pincode> %s\n\
            <slotid> %lu\n\
            <cryptokidll> %s\n", g_szPinCode, g_ulSlotID, g_szDLLName);
    exit (0);
}

CK_RV performAESCMACTest (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration) {
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[3] = {0x30, 0x36};
    CK_ULONG  l_ulBufferLen = 16;
    CK_BYTE   l_pbBuffer[16] = {0};

    printf ("\nAES CMAC 128-bit signature ...\n");
    printf ("\tInput value : %lu bytes\n", 256UL);
    HexDump (g_pbData, 256);

    l_ulErc = signAESCMAC(p, hSession,
                          (CK_CHAR_PTR) l_pszKeyID, (CK_ULONG) strlen(l_pszKeyID),
                          (CK_BYTE_PTR) &g_pbData, (CK_ULONG) 256,
                          (CK_BYTE_PTR) &l_pbBuffer, (CK_ULONG_PTR) &l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\nAES CMAC 128-bit signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    return l_ulErc;
}

CK_RV performAESCMACTest_InputLength0 (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration) {
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[3] = {0x30, 0x36};
    CK_ULONG  l_ulBufferLen = 16;
    CK_BYTE   l_pbBuffer[16] = {0};
    CK_BYTE   l_pbMessage[] = {
        'D', 'U', 'M', 'M', 'Y'
    };

    printf ("\nAES CMAC 128-bit signature ...\n");
    printf ("\tInput value : %lu bytes\n", 0UL);

    l_ulErc = signAESCMAC(p, hSession,
                          (CK_CHAR_PTR) l_pszKeyID, (CK_ULONG) strlen(l_pszKeyID),
                          (CK_BYTE_PTR) &l_pbMessage, (CK_ULONG) 0,
                          (CK_BYTE_PTR) &l_pbBuffer, (CK_ULONG_PTR) &l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\nAES CMAC 128-bit signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    return l_ulErc;
}

CK_RV performAESCMACTest_InputLength16 (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration) {
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[3] = {0x30, 0x36};
    CK_ULONG  l_ulBufferLen = 16;
    CK_BYTE   l_pbBuffer[16] = {0};
    CK_BYTE   l_pbMessage[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 
        0x2e, 0x40, 0x9f, 0x96, 
        0xe9, 0x3d, 0x7e, 0x11, 
        0x73, 0x93, 0x17, 0x2a
    };

    printf ("\nAES CMAC 128-bit signature ...\n");
    printf ("\tInput value : %lu bytes\n", 16UL);
    HexDump (l_pbMessage, 16);

    l_ulErc = signAESCMAC(p, hSession,
                          (CK_CHAR_PTR) l_pszKeyID, (CK_ULONG) strlen(l_pszKeyID),
                          (CK_BYTE_PTR) &l_pbMessage, (CK_ULONG) 16,
                          (CK_BYTE_PTR) &l_pbBuffer, (CK_ULONG_PTR) &l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\nAES CMAC 128-bit signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    return l_ulErc;
}

CK_RV performAESCMACTest_InputLength40 (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration) {
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[3] = {0x30, 0x36};
    CK_ULONG  l_ulBufferLen = 16;
    CK_BYTE   l_pbBuffer[16] = {0};
    CK_BYTE   l_pbMessage[40] = {
        0x6b, 0xc1, 0xbe, 0xe2, 
        0x2e, 0x40, 0x9f, 0x96, 
        0xe9, 0x3d, 0x7e, 0x11, 
        0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11
    };

    printf ("\nAES CMAC 128-bit signature ...\n");
    printf ("\tInput value : %lu bytes\n", 40UL);
    HexDump (l_pbMessage, 40);

    l_ulErc = signAESCMAC(p, hSession,
                          (CK_CHAR_PTR) l_pszKeyID, (CK_ULONG) strlen(l_pszKeyID),
                          (CK_BYTE_PTR) &l_pbMessage, (CK_ULONG) 40,
                          (CK_BYTE_PTR) &l_pbBuffer, (CK_ULONG_PTR) &l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\nAES CMAC 128-bit signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    return l_ulErc;
}

CK_RV performAESCMACTest_InputLength64 (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration) {
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[3] = {0x30, 0x36};
    CK_ULONG  l_ulBufferLen = 16;
    CK_BYTE   l_pbBuffer[16] = {0};
    CK_BYTE   l_pbMessage[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 
        0x2e, 0x40, 0x9f, 0x96, 
        0xe9, 0x3d, 0x7e, 0x11, 
        0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10
    };

    printf ("\nAES CMAC 128-bit signature ...\n");
    printf ("\tInput value : %lu bytes\n", 64UL);
    HexDump (l_pbMessage, 64);

    l_ulErc = signAESCMAC(p, hSession,
                          (CK_CHAR_PTR) l_pszKeyID, (CK_ULONG) strlen(l_pszKeyID),
                          (CK_BYTE_PTR) &l_pbMessage, (CK_ULONG) 64,
                          (CK_BYTE_PTR) &l_pbBuffer, (CK_ULONG_PTR) &l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\nAES CMAC 128-bit signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    return l_ulErc;
}

CK_RV performECCTest (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration)
{
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[20] = "ECCkey";
    CK_ULONG  l_ulBufferLen = 256;
    CK_BYTE   l_pbBuffer[256];

    // ECC 256 Tests
    //--------------
    printf ("\nGenerating ECDSA 256 Key Pair ...\n");
    l_ulErc = genECDSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID), 256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tgenECDSAKeyPair ", l_ulErc);
        return l_ulErc;
    }
    printf ("\tECDSA 256 Key Pair generation successful.\n");
    

    printf ("\nECDSA 256 signature ...\n");
    l_ulErc = signECDSA (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID),
                         (CK_BYTE_PTR)g_pbData, (CK_ULONG)256, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR) & l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tECDSA 256 signature failed !", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }
    
    /*
    printf ("\nECDSA 256 signature verification...\n");

    l_ulErc = verifyECDSASignature (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID),
                                    (CK_BYTE_PTR)l_pbBuffer, l_ulBufferLen, (CK_BYTE_PTR)g_pbData, (CK_ULONG)256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tECDSA 256 signature verification failed !\n", l_ulErc);
    } else
    {
        printf ("\tECDSA 256 signature verification successful.\n");
    }

    printf ("\nDeleting ECDSA 256 Key Pair ...\n");
    l_ulErc = deleteECCKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID));
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tdeleteECCKeyPair ", l_ulErc);
        return l_ulErc;
    }
    printf ("\tECDSA 256 Key Pair deletion successful.\n");

    // ECC 384 Tests
    //--------------
    printf ("\nGenerating ECDSA 384 Key Pair ...\n");
    l_ulErc = genECDSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID), 384);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("genECDSAKeyPair ", l_ulErc);
        return l_ulErc;
    }
    printf ("\tECDSA 384 Key Pair generation successful.\n");

    printf ("\nECDSA 384 signature ...\n");
    l_ulBufferLen = 256;
    l_ulErc = signECDSA (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID),
                         (CK_BYTE_PTR)g_pbData, (CK_ULONG)256, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR) & l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tECDSA 384 signature failed !", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }
    printf ("\nECDSA 384 signature verification...\n");

    l_ulErc = verifyECDSASignature (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID),
                                    (CK_BYTE_PTR)l_pbBuffer, l_ulBufferLen, (CK_BYTE_PTR)g_pbData, (CK_ULONG)256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tECDSA 384 signature verification failed !\n", l_ulErc);
    } else
    {
        printf ("\tECDSA 384 signature verification successful.\n");
    }

    printf ("\nDeleting ECDSA 384 Key Pair ...\n");
    l_ulErc = deleteECCKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID));
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tdeleteECCKeyPair ", l_ulErc);
        return l_ulErc;
    }
    printf ("\tECDSA Key 384 Pair deletion successful.\n");

    // ECC 521 Tests
    //--------------
    printf ("\nGenerating ECDSA 521 Key Pair ...\n");
    l_ulErc = genECDSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID), 521);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tgenECDSAKeyPair ", l_ulErc);
        return l_ulErc;
    }
    printf ("\tECDSA 521 Key Pair generation successful.\n");

    printf ("\nECDSA 521 signature ...\n");
    l_ulBufferLen = 256;
    l_ulErc = signECDSA (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID),
                         (CK_BYTE_PTR)g_pbData, (CK_ULONG)256, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR) & l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tECDSA 521 signature failed !", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }
    printf ("\nECDSA 521 signature verification...\n");

    l_ulErc = verifyECDSASignature (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID),
                                    (CK_BYTE_PTR)l_pbBuffer, l_ulBufferLen, (CK_BYTE_PTR)g_pbData, (CK_ULONG)256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tECDSA 521 signature verification failed !\n", l_ulErc);
    } else
    {
        printf ("\tECDSA 521 signature verification successful.\n");
    }

    printf ("\nDeleting ECDSA 521 Key Pair ...\n");
    l_ulErc = deleteECCKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID));
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tdeleteECCKeyPair ", l_ulErc);
        return l_ulErc;
    }

    printf ("\tECDSA 251 Key Pair deletion successful.\n");
*/
    return l_ulErc;
}


CK_RV performRSATest (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration)
{
    CK_RV     l_ulErc = CKR_OK;
    CK_ULONG  l_ulBufferLen = 256;
    CK_BYTE   l_pbBuffer[256];
    CK_ULONG  l_ulBufferEncLen = 256;
    CK_BYTE   l_pbBufferEnc[256];
    char      l_pszKey[20] = "RSAkey";

    // RSA 1024 Tests
    //---------------
    printf ("\nGenerating RSA 1024 Key Pair ...\n");
    l_ulErc = genRSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey), 1024);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tgenRSAKeyPair 1024", l_ulErc);
        return l_ulErc;
    }
    printf ("\tRSA 1024 Key Pair generation successful.\n");

    printf ("\nRSA 1024 signature ...\n");
    l_ulErc = signRSAData (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                           (CK_BYTE_PTR)g_pbData, (CK_ULONG)256, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 1024 signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    printf ("\nRSA 1024 signature verification ...\n");
    l_ulErc = verifyRSASignature (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                                  (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)g_pbData, (CK_ULONG)256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 1024 signature verification failed !\n", l_ulErc);
    } else
        printf ("\tRSA 1024 signature verification successful.\n");

    printf ("\nRSA 1024 encryption ...\n");
    // PKCS #1 v1.5 RSA mechanism
    // This mechanism :
    //      - supports single-part signatures and verification
    //      - The maximum length of data is key lenght - 11
    l_ulErc = encryptRSA (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                          (CK_BYTE_PTR)g_pbData, (CK_ULONG)117, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 1024 encryption failed !\n", l_ulErc);
    } else
        printf ("\tRSA 1024 encryption successful.\n");

    printf ("\nRSA 1024 decryption ...\n");
    l_ulErc = decryptRSA (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                          (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)l_pbBufferEnc, (CK_ULONG_PTR)&l_ulBufferEncLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 1024 decryption failed !\n", l_ulErc);
    }
    if (memcmp (g_pbData, l_pbBufferEnc, l_ulBufferEncLen) != 0)
        printf ("RSA 1024 decryption failed, bad data !\n");
    else
        printf ("\tRSA 1024 decryption successful.\n");

    printf ("\nDeleting RSA 1024 Key Pair ...\n");
    l_ulErc = deleteRSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey));
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 1024 Key Pair deletion failed !\n", l_ulErc);
    } else
        printf ("\tRSA 1024 Key Pair deletion successful.\n");

    // RSA 2048 Tests
    //---------------
    printf ("\nGenerating RSA 2048 Key Pair ...\n");
    l_ulErc = genRSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey), 2048);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tgenRSAKeyPair 2048", l_ulErc);
        return l_ulErc;
    }

    printf ("\tRSA 2048 Key Pair generation successful.\n");

    printf ("\nRSA 2048 signature ...\n");
    l_ulBufferLen = 256;
    l_ulErc = signRSAData (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                           (CK_BYTE_PTR)g_pbData, (CK_ULONG)256, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 2048 signature failed !\n", l_ulErc);
    } else
    {
        printf ("\tSignature value : %lu bytes\n", l_ulBufferLen);
        HexDump (l_pbBuffer, l_ulBufferLen);
    }

    printf ("\nRSA 2048 signature verification ...\n");
    l_ulErc = verifyRSASignature (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                                  (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)g_pbData, (CK_ULONG)256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 2048 signature verification failed !\n", l_ulErc);
    } else
        printf ("\tRSA 2048 signature verification successful.\n");

    printf ("\nRSA 2048 encryption ...\n");
    l_ulBufferLen = 256;

    // PKCS #1 v1.5 RSA mechanism
    // This mechanism :
    //      - supports single-part signatures and verification
    //      - The maximum length of data is key lenght - 11
    l_ulErc = encryptRSA (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                          (CK_BYTE_PTR)g_pbData, (CK_ULONG)245, (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 2048 encryption failed !\n", l_ulErc);
    } else
        printf ("\tRSA 2048 encryption successful.\n");

    printf ("\nRSA 2048 decryption ...\n");
    l_ulBufferEncLen = 256;
    l_ulErc = decryptRSA (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey),
                          (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)l_pbBufferEnc, (CK_ULONG_PTR)&l_ulBufferEncLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 2048 decryption failed !\n", l_ulErc);
    }
    if (memcmp (g_pbData, l_pbBufferEnc, l_ulBufferEncLen) != 0)
        printf ("RSA 2048 decryption failed, bad data !\n");
    else
        printf ("\tRSA 2048 decryption successful.\n");

    printf ("\nDeleting RSA 2048 Key Pair ...\n");
    l_ulErc = deleteRSAKeyPair (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey));
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tRSA 2048 Key Pair deletion failed !\n", l_ulErc);
    } else
        printf ("\tRSA 2048 Key Pair deletion successful.\n");

    return l_ulErc;
}


CK_RV performAESTest (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession)
{
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKey[] = "AESKey128";

    printf ("\nGenerating AES 128 Key ...\n");
    l_ulErc = genAESKey (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey), 128);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tAES 128 Key generation failed !\n", l_ulErc);
        return l_ulErc;
    } else
        printf ("\tAES 128 Key generation successful.\n");

    printf ("Deleting AES 128 Key ...\n");
    l_ulErc = deleteAESKey (p, hSession, (CK_CHAR_PTR)l_pszKey, (CK_ULONG)strlen (l_pszKey));
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\tAES 128 Key deletion failed !\n", l_ulErc);
    } else
        printf ("\tAES 128 Key deletion successful.\n");

    return l_ulErc;
}


CK_RV performRandomTest (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession)
{
    CK_RV     l_ulErc = CKR_OK;
    CK_ULONG  l_ulBufferLen = 8;
    CK_BYTE   l_pbBuffer[8];

    printf ("\nGenerating a random ...\n");
    l_ulErc = generateRandom (p, hSession, (CK_BYTE_PTR) & l_pbBuffer, l_ulBufferLen);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("Random generation failed !", l_ulErc);
        return l_ulErc;
    }
    printf ("\tRandom : \n");
    HexDump ((unsigned char *)&l_pbBuffer, (unsigned long)l_ulBufferLen);

    return l_ulErc;

}


CK_RV performAllTests (CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, int iteration)
{
    CK_RV     l_ulErc = CKR_OK;
    /*

    // Remove all cryptographic objects from the token
    // deleteAll (p, hSession);

    printf ("\n==============================================\n");
    printf ("Performing random generation test ... \n");
    printf ("=============================================\n");
    if ((l_ulErc = performRandomTest (p, hSession)) != CKR_OK)
        printf ("\nRandom generation test failed !\n");
    else
        printf ("\nRandom generation test successful.\n");

    printf ("\n==============================================\n");
    printf ("Performing AES tests ... \n");
    printf ("==============================================\n");
    if ((l_ulErc = performAESTest (p, hSession)) != CKR_OK)
        printf ("\nAES tests failed !\n");
    else
        printf ("\nAES tests successful.\n");

    printf ("\n==============================================\n");
    printf ("Performing RSA tests ... \n");
    printf ("==============================================\n");
    if ((l_ulErc = performRSATest (p, hSession, iteration)) != CKR_OK)
        printf ("\nRSA tests failed !\n");
    else
        printf ("\nRSA tests successful.\n");*/

    printf ("\n==============================================\n");
    printf ("Performing ECC tests ... \n");
    printf ("==============================================\n");
    if ((l_ulErc = performECCTest (p, hSession, iteration)) != CKR_OK)
        printf ("\nECC tests failed !\n");
    else
        printf ("\nECC tests successful.\n");

    return l_ulErc;
}


/*****************************************************************************
* void main (int argc, char* argv[])
*
* Description : Standard initialization and termination code for all
* samples.
*
*****************************************************************************/
int main (int argc, char *argv[])
{
    CK_RV               l_ulErc = CKR_OK;
    int                 l_nArg = 0;
    int                 i = 0;

    int                 nbObjectID = 0;
    int                 nbgenerateKey = 0;
    int                 nbgenerateSig = 0;
    int                 nbgenerateEnc = 0;
    int                 nbgenerateDec = 0;
    int                 nbiteration = 1;

    CK_RV (*pC_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR);
    CK_FUNCTION_LIST_PTR l_pFunctions = NULL;

    void *l_hModule = NULL;
    CK_BBOOL            l_fIsSlotEnter = FALSE;
    CK_BBOOL            l_removeObject = FALSE;
    CK_BBOOL            l_random = FALSE;
    CK_BBOOL            l_printAll = FALSE;
    CK_BBOOL            l_ecdh = FALSE;
    CK_BBOOL            l_aes_cmac = FALSE;
    CK_BBOOL            l_signAll = FALSE;
    CK_BBOOL            l_all = FALSE;
    CK_SLOT_ID_PTR      l_pSlotList = NULL;
    CK_SESSION_HANDLE   l_hSession = 0;
    CK_ULONG            l_ulCount = 0;
    CK_CHAR_PTR         l_pObject[10];
    OBJECT_KEY          l_pKey[10];
    OBJECT_DATA         l_pSign[10];
    OBJECT_DATA         l_pEncrypt[10];
    OBJECT_DATA         l_pDecrypt[10];


    // Set the log level to Info : Required for more verbose logs, dump ....
    setLoggingLevel (_INFO_);

    /*---- Analyze the command line for parameters (see usage) ----*/
    for (l_nArg = 1; l_nArg < argc; l_nArg++)
    {
        /* Expect arguments of the form -x:<param> */
        if ((strlen (argv[l_nArg]) < 2) || (argv[l_nArg][0] != '-')) usage ();

        switch (argv[l_nArg][1])
        {
        case 'h':
            l_ecdh = TRUE;
            break;

        case 'l':
            strncpy ((char *)g_szDLLName, &(argv[l_nArg][3]), sizeof(g_szDLLName));
            g_szDLLName[sizeof(g_szDLLName) - 1] = '\0';
            printf ("Using library : %s\n", g_szDLLName);
            break;

        case 'i':
            if (sscanf (&(argv[l_nArg][3]), "%lu", &g_ulSlotID) != 1) usage ();
            printf ("Using slot ID : %lu\n", g_ulSlotID);
            l_fIsSlotEnter = TRUE;
            break;

        case 'p':
            strncpy ((char *)g_szPinCode, &(argv[l_nArg][3]), sizeof(g_szPinCode));
            g_szPinCode[sizeof(g_szPinCode) - 1] = '\0';
            printf ("Using PIN : %s\n", g_szPinCode);
            break;

        case 'f':
            l_printAll = TRUE;
            break;

        case 'R':
            l_removeObject = TRUE;
            break;

		case 'S':
		   l_signAll = TRUE;
	    	break;

        case 'r':
            l_removeObject = TRUE;
            if (argv[l_nArg][2] == ':')
            {
                if (nbObjectID < g_nMaxObjects - 1)
                {
                    int size = strlen (&argv[l_nArg][3]);
                    l_pObject[nbObjectID] = (CK_CHAR_PTR)malloc (size);
                    strncpy ((char *)l_pObject[nbObjectID], &(argv[l_nArg][3]), size);
                    l_pObject[nbObjectID][size] = '\0';
                    printf ("Removal of object ID : %s\n", l_pObject[nbObjectID]);
                    nbObjectID++;
                }
            }
            break;

        case 'k':
            if (argv[l_nArg][2] == ':')
            {
                if (nbgenerateKey < g_nMaxObjects - 1)
                {
                    printf ("Key generation : %s\n", &(argv[l_nArg][3]));
                    int size = strlen (&argv[l_nArg][3]);
                    int pos = size - strlen (strchr (&(argv[l_nArg][3]), ':'));

                    l_pKey[nbgenerateKey].stID.pszAlgo = (CK_CHAR_PTR)malloc (pos * sizeof(CK_CHAR));
                    strncpy ((char *)l_pKey[nbgenerateKey].stID.pszAlgo, &argv[l_nArg][3], pos);
                    l_pKey[nbgenerateKey].stID.pszAlgo[pos] = '\0';

                    char *temp = strchr (&(argv[l_nArg][3]) + pos + 1, ':');
                    pos = size - strlen (temp) - 1;
                    temp += 1;

                    l_pKey[nbgenerateKey].stID.pszID = malloc (strlen (temp));
                    strncpy ((char *)l_pKey[nbgenerateKey].stID.pszID, temp, strlen (temp));
                    l_pKey[nbgenerateKey].stID.pszID[strlen (temp)] = '\0';

                    pos = strlen ((char *)l_pKey[nbgenerateKey].stID.pszAlgo) + 1;
                    size = size - pos - strlen ((char *)l_pKey[nbgenerateKey].stID.pszID) - 1;
                    temp = &(argv[l_nArg][3]) + pos;
                    temp[size] = '\0';

                    l_pKey[nbgenerateKey].size = (CK_ULONG)atol (temp);

                    printf ("\tKey algo  : %s\n", (char *)l_pKey[nbgenerateKey].stID.pszAlgo);
                    printf ("\tKey size  : %d\n", (int)l_pKey[nbgenerateKey].size);
                    printf ("\tKey ID    : %s\n", (char *)l_pKey[nbgenerateKey].stID.pszID);

                    nbgenerateKey++;
                }
            }
            break;

        case 's':       // Signature algo:id:data
            if (argv[l_nArg][2] == ':')
            {
                if (nbgenerateSig < g_nMaxObjects - 1)
                {
                    printf ("Signature : %s\n", &(argv[l_nArg][3]));
                    int size = strlen (&argv[l_nArg][3]);
                    int pos = size - strlen (strchr (&(argv[l_nArg][3]), ':'));
                    l_pSign[nbgenerateSig].stID.pszAlgo = (CK_CHAR_PTR)malloc (pos);
                    strncpy ((char *)l_pSign[nbgenerateSig].stID.pszAlgo, &argv[l_nArg][3], pos);
                    l_pSign[nbgenerateSig].stID.pszAlgo[pos] = '\0';


                    char *temp = strchr (&(argv[l_nArg][3]) + pos + 1, ':');
                    pos = size - strlen (temp) - 1;
                    temp += 1;

                    l_pSign[nbgenerateSig].data = (CK_BYTE_PTR)malloc (strlen (temp));
                    strncpy ((char *)l_pSign[nbgenerateSig].data, temp, strlen (temp));
                    l_pSign[nbgenerateSig].data[strlen (temp)] = '\0';

                    pos = strlen ((char *)l_pSign[nbgenerateSig].stID.pszAlgo) + 1;
                    size = size - pos - strlen ((char *)l_pSign[nbgenerateSig].data) - 1;
                    temp = &(argv[l_nArg][3]) + pos;
                    temp[size] = '\0';

                    l_pSign[nbgenerateSig].stID.pszID = (CK_CHAR_PTR)malloc (strlen (temp));
                    strncpy ((char *)l_pSign[nbgenerateSig].stID.pszID, temp, strlen (temp));

                    l_pSign[nbgenerateSig].stID.pszID[strlen (temp)] = '\0';

                     printf ("\tKey algo : %s\n",l_pSign[nbgenerateSig].stID.pszAlgo);
                     printf ("\tKey ID   : %s\n",l_pSign[nbgenerateSig].stID.pszID);
                     printf ("\tData     : %s\n", l_pSign[nbgenerateSig].data);

                    nbgenerateSig++;
                }
            }
            break;

        case 'e':
            if (argv[l_nArg][2] == ':')
            {
                if (nbgenerateEnc < g_nMaxObjects - 1)
                {
                    printf ("Encryption : %s\n", &(argv[l_nArg][3]));
                    int size = strlen (&argv[l_nArg][3]);
                    int pos = size - strlen (strchr (&(argv[l_nArg][3]), ':'));
                    l_pEncrypt[nbgenerateEnc].stID.pszAlgo = (CK_CHAR_PTR)malloc (pos);
                    strncpy ((char *)l_pEncrypt[nbgenerateEnc].stID.pszAlgo, &argv[l_nArg][3], pos);
                    l_pEncrypt[nbgenerateEnc].stID.pszAlgo[pos] = '\0';

                    char *temp = strchr (&(argv[l_nArg][3]) + pos + 1, ':');
                    pos = size - strlen (temp) - 1;
                    temp += 1;

                    l_pEncrypt[nbgenerateEnc].data = (CK_BYTE_PTR)malloc (strlen (temp));
                    strncpy ((char *)l_pEncrypt[nbgenerateEnc].data, temp, strlen (temp));
                    l_pEncrypt[nbgenerateEnc].data[strlen (temp)] = '\0';

                    pos = strlen ((char *)l_pEncrypt[nbgenerateEnc].stID.pszAlgo) + 1;
                    size = size - pos - strlen ((char *)l_pEncrypt[nbgenerateEnc].data) - 1;
                    temp = &(argv[l_nArg][3]) + pos;
                    temp[size] = '\0';

                    l_pEncrypt[nbgenerateEnc].stID.pszID = (CK_CHAR_PTR)malloc (strlen (temp));
                    strncpy ((char *)l_pEncrypt[nbgenerateEnc].stID.pszID, temp, strlen (temp));

                    l_pEncrypt[nbgenerateEnc].stID.pszID[strlen (temp)] = '\0';

                    printf ("\tKey algo : %s\n", l_pEncrypt[nbgenerateEnc].stID.pszAlgo);
                    printf ("\tKey ID   : %s\n", l_pEncrypt[nbgenerateEnc].stID.pszID);
                    printf ("\tData     : %s\n", l_pEncrypt[nbgenerateEnc].data);

                    nbgenerateEnc++;
                }
            }
            break;

        case 'd':
            if (argv[l_nArg][2] == ':')
            {
                if (nbgenerateDec < g_nMaxObjects - 1)
                {
                    printf ("Decryption : %s\n", &(argv[l_nArg][3]));
                    int size = strlen (&argv[l_nArg][3]);
                    int pos = size - strlen (strchr (&(argv[l_nArg][3]), ':'));
                    l_pDecrypt[nbgenerateDec].stID.pszAlgo = (CK_CHAR_PTR)malloc (pos);
                    strncpy ((char *)l_pDecrypt[nbgenerateDec].stID.pszAlgo, &argv[l_nArg][3], pos);
                    l_pDecrypt[nbgenerateDec].stID.pszAlgo[pos] = '\0';

                    char *temp = strchr (&(argv[l_nArg][3]) + pos + 1, ':');
                    pos = size - strlen (temp) - 1;
                    temp += 1;

                    l_pDecrypt[nbgenerateDec].data = (CK_BYTE_PTR)malloc (strlen (temp) + 1);
                    strncpy ((char *)l_pDecrypt[nbgenerateDec].data, temp, strlen (temp));
                    l_pDecrypt[nbgenerateDec].data[strlen (temp)] = '\0';

                    pos = strlen ((char *)l_pDecrypt[nbgenerateDec].stID.pszAlgo) + 1;
                    size = size - pos - strlen ((char *)l_pDecrypt[nbgenerateDec].data) - 1;
                    temp = &(argv[l_nArg][3]) + pos;
                    temp[size] = '\0';

                    l_pDecrypt[nbgenerateDec].stID.pszID = (CK_CHAR_PTR)malloc (strlen (temp));
                    strncpy ((char *)l_pDecrypt[nbgenerateDec].stID.pszID, temp, strlen (temp));

                    l_pDecrypt[nbgenerateDec].stID.pszID[strlen (temp)] = '\0';

                    printf ("\tKey algo : %s\n", l_pDecrypt[nbgenerateDec].stID.pszAlgo);
                    printf ("\tKey ID   : %s\n", l_pDecrypt[nbgenerateDec].stID.pszID);
                    printf ("\tData     : %s\n", l_pDecrypt[nbgenerateDec].data);

                    nbgenerateDec++;
                }
            }
            break;

        case 'c':
            l_aes_cmac = TRUE;
            break;

        case 'g':
            l_random = TRUE;
            break;

        case 'a':   // all tests
            l_all = TRUE;
            if (argv[l_nArg][2] == ':')
            {
                char *temp = &(argv[l_nArg][3]);
                temp[strlen (&(argv[l_nArg][3]))] = '\0';

                nbiteration = atol (temp);
                printf ("all Test Iteration number : %d\n", nbiteration);
            }
            break;

        default:
            usage ();
            break;
        }
    }


    /* ---- Load dynamically DLL and retrieve function list pointer -- */
    if ((l_hModule = DLOPEN (g_szDLLName)) == 0)
    {
#ifdef WIN32
        printf ("DLOPEN Error : %s not found  (erc = %d)!\n", g_szDLLName, GetLastError ());
#else
        printf ("DLOPEN Error : %s not found  (erc = %s)!\n", g_szDLLName, dlerror());
#endif
        exit (0);
    }
    if ((pC_GetFunctionList = (CK_RV (*) (CK_FUNCTION_LIST_PTR_PTR))DLSYM(l_hModule, "C_GetFunctionList")) == NULL)
    {
        printf ("DLSYM Error\n");
        exit (0);
    }

    /* ---- Cryptoki library standard initialization ---- */
    if ((l_ulErc = pC_GetFunctionList (&l_pFunctions)) != CKR_OK)
    {
        CKRLOG ("C_GetFunctionList", l_ulErc);
        exit (0);
    }
    l_ulErc = (*l_pFunctions->C_Initialize) (NULL_PTR);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("C_Initialize", l_ulErc);
        exit (0);
    }

    if (!l_fIsSlotEnter)
    {
        CK_ULONG    l_ulI = 0;
        char        l_szChoice[5];

        /* Get number of slots in system */
        l_ulErc = (*l_pFunctions->C_GetSlotList) (CK_TRUE, NULL, &l_ulCount);
        if (l_ulErc != CKR_OK)
        {
            CKRLOG ("C_GetSlotList", l_ulErc);
            goto end;
        }
        /* no slot found */
        if (0 == l_ulCount)
        {
            printf ("No slot found !\n");
            goto end;
        }

        l_pSlotList = (CK_SLOT_ID_PTR)calloc (l_ulCount, sizeof(CK_SLOT_ID));
        l_pSlotList[0] = 42;

        /* Get First Slot ID, with Token if possible */
        l_ulErc = (*l_pFunctions->C_GetSlotList) (CK_TRUE, l_pSlotList, &l_ulCount);
        if (l_ulErc != CKR_OK)
        {
            CKRLOG ("C_GetSlotList", l_ulErc);
            free (l_pSlotList);
            goto end;
        }

        printf ("\nTotal number of slot(s) found : %lu\n", l_ulCount);
        for (l_ulI = 0; l_ulI < l_ulCount; l_ulI++)
        {
            CK_SLOT_INFO    l_stSlotInfo;

            if ((l_ulErc = (*l_pFunctions->C_GetSlotInfo) (l_pSlotList[l_ulI], &l_stSlotInfo)) != CKR_OK)
            {
                CKRLOG ("C_GetSlotInfo", l_ulErc);
                goto end;
            }
            l_stSlotInfo.slotDescription[sizeof(l_stSlotInfo.slotDescription) - 1] = '\0';
            printf ("\tSlot ID : %lu - %s\n", l_pSlotList[l_ulI], l_stSlotInfo.slotDescription);
        }
        printf ("\n");

        free (l_pSlotList);

        printf ("Enter the ID of the slot to use : ");
        if (fgets (l_szChoice, sizeof(l_szChoice), stdin) == NULL_PTR)
            goto end;

        if (sscanf (l_szChoice, "%lu", &g_ulSlotID) != 1)
            return CKR_CANCEL;

        printf ("Using slot ID : %lu\n", g_ulSlotID);
    }

    // Open a session with the token
    printf ("\nOpening a new session ... ");
    l_ulErc = (*l_pFunctions->C_OpenSession) (g_ulSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              NULL_PTR, NULL_PTR, &l_hSession);
    if (l_ulErc != CKR_OK)
    {
        printf ("failed !\n");
        CKRLOG ("C_OpenSession", l_ulErc);
        goto end;
    }
    else
        printf ("successful.\n");

    if (strlen ((char *)g_szPinCode) == 0)
    {
        char        l_szChoice[sizeof(g_szPinCode)];

        printf ("\nEnter the user PIN of the token : ");
        if (fgets (l_szChoice, sizeof(l_szChoice), stdin) == NULL_PTR)
            goto end;

        l_szChoice[strlen (l_szChoice) - 1] = '\0';   // remove '\n'
        if (strlen ((char *)l_szChoice) != 0)
        {
            strncpy ((char *)g_szPinCode, l_szChoice, sizeof(g_szPinCode));
            g_szPinCode[sizeof(g_szPinCode) - 2] = '\0';
        }
    }

    // Login only if a PIN code is presented.
    if (strlen ((char *)g_szPinCode))
    {
        printf ("Login into the token using PIN '%s' ... ", g_szPinCode);
        l_ulErc = (*l_pFunctions->C_Login) (l_hSession, CKU_USER, g_szPinCode, (CK_ULONG)
                                            strlen ((const char *)g_szPinCode));
        /*
        rv = (*p->C_Login)(hSession, CKU_SO, szPinCode, (CK_ULONG)
                             strlen ((const char *)szPinCode));
        */
        if (l_ulErc != CKR_OK)
        {
            printf ("Failed !\n");
            CKRLOG ("C_Login", l_ulErc);
            goto end;
        }
        else
            printf ("successful.\n");
    }

    // Dump all objects
    if (l_printAll)
	 l_ulErc = dumpAll (l_pFunctions, l_hSession);

    if(l_ecdh)
    {

        l_ulErc = computeECDH(l_pFunctions, l_hSession);
        if (l_ulErc != CKR_OK)
        {
            CKRLOG ("\tECDH secret computed... fail ", l_ulErc);
        }
        else
            printf ("\tECDH secret computed... successful .\n");
    }

    // Remove all objects form the token
    if (l_removeObject)
    {
        if (nbObjectID > 0)
        {
            for (i = 0; i < nbObjectID; i++)
            {
                delete(l_pFunctions, l_hSession,l_pObject[i],strlen ((char *)l_pObject[i]));
                free (l_pObject[i]);
            }
        }
        else
            l_ulErc = deleteAll (l_pFunctions, l_hSession);
    }

    if (l_aes_cmac)
    {
        // AES CMAC 128-bit test
        performAESCMACTest( l_pFunctions, l_hSession, 0 );
        performAESCMACTest_InputLength0( l_pFunctions, l_hSession, 0 );
        performAESCMACTest_InputLength16( l_pFunctions, l_hSession, 0 );
        performAESCMACTest_InputLength40( l_pFunctions, l_hSession, 0 );
        performAESCMACTest_InputLength64( l_pFunctions, l_hSession, 0 );
    }

    //printf("Generate a KEY PAIR REMY, bnGenerateKeypair %d", nbgenerateKey);
    // Geenerate a key/key pair
    for (i = 0; i < nbgenerateKey; i++)
    {
        printf("Generate a KEY PAIR REMY step 1");
        tolowercase (l_pKey[i].stID.pszAlgo);
        if (strstr ((const char *)l_pKey[i].stID.pszAlgo, "rsa") != NULL)
        {
            printf ("\nGenerating RSA key pair ...\n");
            l_ulErc = genRSAKeyPair (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pKey[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pKey[i].stID.pszID), l_pKey[i].size);
            if (l_ulErc != CKR_OK)
            {
                CKRLOG ("\tgenRSAKeyPair ", l_ulErc);
            }
            else
                printf ("\tRSA key pair successfully generated.\n");

        }
        else if (strstr ((const char *)l_pKey[i].stID.pszAlgo, "aes") != NULL)
        {
            printf ("Generating AES key ...\n");
            l_ulErc = genAESKey (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pKey[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pKey[i].stID.pszID), l_pKey[i].size);
            if (l_ulErc != CKR_OK)
            {
                CKRLOG ("gen AES Key ", l_ulErc);
            }
            else
                printf ("\tAES key successfully generated.\n");
        }
         else if (strstr ((const char *)l_pKey[i].stID.pszAlgo, "ecc") != NULL)
        {
            //REMY ADDED ECC 
            printf ("Generating ECC key ...\n");
            l_ulErc = genECDSAKeyPair (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pKey[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pKey[i].stID.pszID), l_pKey[i].size);
            if (l_ulErc != CKR_OK)
            {
                CKRLOG ("gen ECC Key ", l_ulErc);
            }
            else
                printf ("\tECC key successfully generated.\n");
        }
        else
        {
            printf ("Key algo '%s' not supported !\n", l_pKey[i].stID.pszAlgo);
        }

        free (l_pKey[i].stID.pszID);
        free (l_pKey[i].stID.pszAlgo);
    }

    // Signature + verification
    if (nbgenerateSig > 0)
    {
        CK_ULONG    l_ulBufferLen = 256;
        CK_BYTE     l_pbBuffer[256];

        for (i = 0; i < nbgenerateSig; i++)
        {
            tolowercase (l_pSign[i].stID.pszAlgo);
            if (strstr ((char *)l_pSign[i].stID.pszAlgo, "rsa") != NULL)
            {
                printf ("\nSigning data using RSA private key ...\n");
                l_ulErc = signRSAData (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pSign[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pSign[i].stID.pszID),
                                       (CK_BYTE_PTR)l_pSign[i].data, (CK_ULONG)strlen ((char *)l_pSign[i].data), (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
                if (l_ulErc != CKR_OK)
                {
                    CKRLOG ("\tRSA signature failed !\n", l_ulErc);
                }
                else
                {
                    printf ("\tSignature : \n");
                    HexDump ((unsigned char *)&l_pbBuffer, (unsigned long)l_ulBufferLen);

                    printf ("\nVerifying signature ...\n");
                    l_ulErc = verifyRSASignature (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pSign[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pSign[i].stID.pszID),
                                                  (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)l_pSign[i].data, (CK_ULONG)strlen ((char *)l_pSign[i].data));
                    if (l_ulErc != CKR_OK)
                    {
                        CKRLOG ("\tSignature verification failed !\n", l_ulErc);
                    }
                    else
                        printf ("\tSignature verification successful.\n");
                }
            }
            else if((strstr ((char *)l_pSign[i].stID.pszAlgo, "ecc") != NULL)) 
            {
                printf ("\nSigning data using ECC private key REMY ...\n");
                l_ulErc = signECDSA(l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pSign[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pSign[i].stID.pszID),
                                       (CK_BYTE_PTR)l_pSign[i].data, (CK_ULONG)strlen(l_pSign[i].data), (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
                if (l_ulErc != CKR_OK)
                {
                    CKRLOG ("\tECC signature failed !\n", l_ulErc);
                }
                else
                {
                    printf ("\tSignature : \n");
                    HexDump ((unsigned char *)&l_pbBuffer, (unsigned long)l_ulBufferLen);

                    printf ("\nVerifying signature ...\n");
                    l_ulErc = verifyECDSASignature (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pSign[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pSign[i].stID.pszID),
                                                  (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)l_pSign[i].data, (CK_ULONG)strlen ((char *)l_pSign[i].data));
                    if (l_ulErc != CKR_OK)
                    {
                        CKRLOG ("\tSignature verification failed !\n", l_ulErc);
                    }
                    else
                        printf ("\tSignature verification successful.\n");
                }
            }
            else
            {
                printf ("Signature algo %s not supported !\n", l_pSign[i].stID.pszAlgo);
            }

            free (l_pSign[i].stID.pszID);
            free (l_pSign[i].stID.pszAlgo);
            free (l_pSign[i].data);
        }
    }

    // Encryption
    if (nbgenerateEnc > 0)
    {
        CK_ULONG  l_ulBufferLen = 256;
        CK_BYTE   l_pbBuffer[256];
        CK_ULONG  l_ulDecryptBufferLen = 256;
        CK_BYTE   l_pbDecryptBuffer[256];

        for (i = 0; i < nbgenerateEnc; i++)
        {
            tolowercase (l_pEncrypt[i].stID.pszAlgo);
            if (strstr ((char *)l_pEncrypt[i].stID.pszAlgo, "rsa") != NULL)
            {
                printf ("\nEncrypting data using RSA public key ...\n");
                l_ulErc = encryptRSA (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pEncrypt[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pEncrypt[i].stID.pszID),
                                      (CK_BYTE_PTR)l_pEncrypt[i].data, (CK_ULONG)strlen ((char *)l_pEncrypt[i].data), (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
                if (l_ulErc != CKR_OK)
                {
                    CKRLOG ("\tEncryption failed !\n", l_ulErc);
                }
                else
                {
                    printf ("\tEncrypted data : \n");
                    HexDump ((unsigned char *)l_pbBuffer, (unsigned long)l_ulBufferLen);

                    printf ("\nDecrypting data using RSA private key ...\n");
                    l_ulErc = decryptRSA (l_pFunctions, l_hSession, (CK_CHAR_PTR)l_pEncrypt[i].stID.pszID, (CK_ULONG)strlen ((char *)l_pEncrypt[i].stID.pszID),
                                          (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)l_pbDecryptBuffer, (CK_ULONG_PTR)&l_ulDecryptBufferLen);
                    if (l_ulErc != CKR_OK)
                    {
                        CKRLOG ("\tDecryption failed \n", l_ulErc);
                    }
                    else
                    {
                        printf ("\tDecrypted data: \n");
                        HexDump ((unsigned char *)l_pbDecryptBuffer, (unsigned long)l_ulDecryptBufferLen);
                    }
                }
            }
            else
            {
                printf ("Encryption algo '%s' not supported !\n", l_pEncrypt[i].stID.pszAlgo);
            }

            free (l_pEncrypt[i].data);
            free (l_pEncrypt[i].stID.pszAlgo);
            free (l_pEncrypt[i].stID.pszID);
        }
    }

    // Random generation
    if (l_random)
    {
        performRandomTest (l_pFunctions, l_hSession);
    }

    // All tests
    if (l_all)
    {
        for (i = 0; i < nbiteration; i++)
        {
            l_ulErc = performAllTests (l_pFunctions, l_hSession, i);
            if (l_ulErc != CKR_OK)
                break;
        }
    }

   if(l_signAll)
   {
	    CK_BYTE keyID[20] = {0};
	    CK_ULONG    l_ulBufferLen = 256;
        CK_BYTE     l_pbBuffer[256];
	    unsigned char data[5] = "hello";
	    int offset = 0;

     	printf ("\nSigning data using ECC private key  ...\n");
	    for(int i = 0; i < 3; i++) //Only 3 keys for now, all of them ECC
	    {
          //Sign + verif         
    		  memcpy(keyID, &myKey[offset], 20);
         	  l_ulErc = signECDSA(l_pFunctions, l_hSession, (CK_CHAR_PTR)keyID, (CK_ULONG)20,
                                 (CK_BYTE_PTR)data, (CK_ULONG)strlen ((char *)data), (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG_PTR)&l_ulBufferLen);
         	 if (l_ulErc != CKR_OK)
         	 {
             	 CKRLOG ("\tECC signature failed !\n", l_ulErc);
          	}
          	else
          	{
             	 printf ("\tSignature : \n");
              	HexDump ((unsigned char *)&l_pbBuffer, (unsigned long)l_ulBufferLen);

              	printf ("\nVerifying signature ...\n");
              	l_ulErc = verifyECDSASignature (l_pFunctions, l_hSession, (CK_CHAR_PTR)keyID, (CK_ULONG)20,
                                            (CK_BYTE_PTR)l_pbBuffer, (CK_ULONG)l_ulBufferLen, (CK_BYTE_PTR)data, (CK_ULONG)strlen ((char *)data));
             	if (l_ulErc != CKR_OK)
               	{
                 	 CKRLOG ("\tSignature verification failed !\n", l_ulErc);
              	}
             	else
                  printf ("\tSignature verification successful.\n");
            }
    	    offset += 20; //next key
           	memset(keyID, 0, 20*sizeof(*keyID));
             
   	    }

   }

    printf ("\nClosing the session ... ");
    l_ulErc = (*l_pFunctions->C_CloseSession) (l_hSession);
    if (l_ulErc != CKR_OK)
    {
        printf ("failed !\n");
        CKRLOG ("C_CloseSession", l_ulErc);
    }
    else
        printf ("successful.\n");

end:
    /*---- Tidy up ----*/
    (*l_pFunctions->C_Finalize) (NULL_PTR);

    if (l_hModule != 0) DLCLOSE (l_hModule);

    return 0;
}

