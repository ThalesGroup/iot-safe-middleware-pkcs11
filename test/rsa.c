/**
* Copyright (c) 2015 GEMALTO. All Rights Reserved.
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
#include "digest.h"
#include "rsa.h"




CK_RV findRSAKeyById (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                      CK_CHAR *p_pszId, CK_ULONG p_ulIdLen, CK_BBOOL p_fPrivateKey, CK_OBJECT_HANDLE_PTR p_phRSAKey
                      )
{
    CK_RV l_ulErc = CKR_OK;
    CK_ULONG l_ulCount = 0;
    CK_BBOOL l_fIsToken = TRUE;
    CK_OBJECT_CLASS l_ulObjectClass = p_fPrivateKey ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_KEY_TYPE l_ulKeyType = CKK_RSA;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_CLASS, &l_ulObjectClass, sizeof(CK_OBJECT_CLASS) },
        { CKA_TOKEN, &l_fIsToken, sizeof(CK_BBOOL) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof(CK_KEY_TYPE) },
        { CKA_ID, p_pszId, p_ulIdLen }
    };

    *p_phRSAKey = NULL_PTR;

    // Find a RSA Private key that matches the given template
    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit) (p_hSession, l_arstKeyTemplate, 4)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects) (p_hSession, p_phRSAKey, 1, &l_ulCount)) != CKR_OK)
    {
        CKRLOG ("C_FindObjects", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal) (p_hSession)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsFinal", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}


CK_RV findRSAKeyByModulus (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                           CK_BYTE_PTR p_pbModulus, CK_ULONG p_ulModulusLen, CK_BBOOL p_fPrivateKey, CK_OBJECT_HANDLE_PTR p_phRSAKey
                           )
{
    CK_RV l_ulErc = CKR_OK;
    CK_ULONG l_ulCount = 0;
    CK_BBOOL l_fIsToken = TRUE;
    CK_OBJECT_CLASS l_ulObjectClass = p_fPrivateKey ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_KEY_TYPE l_ulKeyType = CKK_RSA;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_CLASS, &l_ulObjectClass, sizeof(CK_OBJECT_CLASS) },
        { CKA_TOKEN, &l_fIsToken, sizeof(CK_BBOOL) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof(CK_KEY_TYPE) },
        { CKA_MODULUS, p_pbModulus, p_ulModulusLen }
    };

    *p_phRSAKey = NULL_PTR;

    // Find a RSA Private key that matches the given template
    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit) (p_hSession, l_arstKeyTemplate, 4)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects) (p_hSession, p_phRSAKey, 1, &l_ulCount)) != CKR_OK)
    {
        CKRLOG ("C_FindObjects", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal) (p_hSession)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsFinal", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;

}


/*****************************************************************************
* genRSAKeyPair
*
*****************************************************************************/
CK_RV genRSAKeyPair (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_ULONG p_ulKeyBitsSize)
{
    CK_RV l_ulErc = CKR_OK;



    CK_BYTE l_pbKeyModulus[MAX_KEY_BITS / 8];
    CK_ULONG l_ulKeySize;
    CK_OBJECT_HANDLE l_hPubKey, l_hPrivKey;
    CK_BBOOL l_fTrue = TRUE;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_ATTRIBUTE l_pstPubKeyTemplate[] = {
        { CKA_MODULUS_BITS, &l_ulKeySize, sizeof(CK_ULONG) },
        { CKA_PUBLIC_EXPONENT, "\x01\x00\x01", 3 },
        { CKA_TOKEN, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };
    CK_ATTRIBUTE l_pstPrivKeyTemplate[] = {
        { CKA_TOKEN, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };
    CK_ATTRIBUTE l_stGetModulusTemplate[] = {
        { CKA_MODULUS, l_pbKeyModulus, sizeof(l_pbKeyModulus) }
    };

    // Check parameters validity
    l_ulKeySize = p_ulKeyBitsSize;
    /*  if (!((l_ulKeySize == 1024) || (l_ulKeySize == 2048)))
          return CKR_ARGUMENTS_BAD;*/

    if ((p_pszKeyId == NULL_PTR) || (p_ulKeyIdLen > 64)) return CKR_ARGUMENTS_BAD;

    logDebug (("\nGenerating RSA key pair ... "));

    // Set the RSA key generation mechanism
    l_stMechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    l_stMechanism.pParameter = NULL_PTR;
    l_stMechanism.ulParameterLen = 0;

    double startTime = getCurrentTime ();

    // Generate RSA key pair
    l_ulErc = (*p_pFunctions->C_GenerateKeyPair) (p_hSession,        // Session handle
                                                  &l_stMechanism,                    // RSA Key Gen. mechanism
                                                  l_pstPubKeyTemplate,               // Template for RSA Public key
                                                  4,                                 // Attributes count
                                                  l_pstPrivKeyTemplate,              // Template for RSA Private key
                                                  4,                                 // Attributes count
                                                  &l_hPubKey,                        // Handle of Public key, returned
                                                  &l_hPrivKey                        // Handle of Private key, returned
                                                  );
    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;
    logElapsedTime ("%s C_GenerateKeyPair, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_GenerateKeyPair", l_ulErc);
        return l_ulErc;
    } else logDebug (("successful.\n"));

    // Display Modulus Value
    l_ulErc = (*p_pFunctions->C_GetAttributeValue) (p_hSession,             // Session handle
                                                    l_hPubKey,              // Handle of Public Key
                                                    l_stGetModulusTemplate, // Modulus template
                                                    1                       // Number of attributes
                                                    );
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("C_GetAttributeValue", l_ulErc);
        return l_ulErc;
    }

    logDebug (("Modulus value : \n"));
    logDump (_DEBUG_, l_stGetModulusTemplate->pValue, l_stGetModulusTemplate->ulValueLen);

    return l_ulErc;
}


CK_RV deleteRSAKeyPair (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                        CK_CHAR *p_pszId, CK_ULONG p_ulIdLen
                        )
{
    CK_RV               l_ulErc = CKR_OK;
    CK_OBJECT_HANDLE    l_hKey;

    // Find a private key for this ID
    l_ulErc = findRSAKeyById (p_pFunctions, p_hSession, p_pszId, p_ulIdLen, TRUE, &l_hKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findRSAKeyById", l_ulErc);
        return l_ulErc;
    }

    // Delete this private key
    if (l_hKey != 0)
    {
        if ((l_ulErc = (*p_pFunctions->C_DestroyObject) (p_hSession, l_hKey)) != CKR_OK)
        {
            CKRLOG ("C_DestroyObject", l_ulErc);
            return l_ulErc;
        }
    }

    // Find a public key for this ID
    l_ulErc = findRSAKeyById (p_pFunctions, p_hSession, p_pszId, p_ulIdLen, FALSE, &l_hKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findRSAKeyById", l_ulErc);
        return l_ulErc;
    }

    // Delete this public key
    if (l_hKey != 0)
    {
        if ((l_ulErc = (*p_pFunctions->C_DestroyObject) (p_hSession, l_hKey)) != CKR_OK)
        {
            CKRLOG ("C_DestroyObject", l_ulErc);
            return l_ulErc;
        }
    }

    return l_ulErc;
}


CK_RV verifyRSASignature (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                          CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_BYTE_PTR p_signature,
                          CK_ULONG p_usignatureLen, CK_BYTE_PTR p_Data, CK_ULONG  p_dataLen)
{

    CK_RV l_ulErc = CKR_OK;

    CK_OBJECT_HANDLE    l_hPubKey;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_BYTE l_pHash[64];
    CK_ULONG l_ulHashLen = sizeof(l_pHash);

    // Find a public key for this ID
    l_ulErc = findRSAKeyById (p_pFunctions, p_hSession, p_pszKeyId, p_ulKeyIdLen, FALSE, &l_hPubKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findRSAKeyById", l_ulErc);
        return l_ulErc;
    }

    // compute digest

    //---- Hash the data ----
    l_stMechanism.mechanism = CKM_SHA_1;

    l_ulErc = digestData (p_pFunctions, p_hSession, &l_stMechanism, p_Data,
                          p_dataLen, (CK_BYTE_PTR) & l_pHash, (CK_ULONG_PTR) & l_ulHashLen);

    // PKCS #1 v1.5 RSA mechanism
    l_stMechanism.mechanism = CKM_RSA_PKCS;

    double startTime = getCurrentTime ();

    // verify init
    l_ulErc = (*p_pFunctions->C_VerifyInit) (p_hSession,        // Session handle
                                             &l_stMechanism,            // RSA sign . mechanism
                                             l_hPubKey                 // Handle of Public key
                                             );

    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;
    logElapsedTime ("%s C_VerifyInit , %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_VerifyInit", l_ulErc);
        return l_ulErc;
    }

    startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_VerifyUpdate) (p_hSession,           // Session handle
                                               (CK_BYTE_PTR) & l_pHash,    // hash of data to be verified
                                               l_ulHashLen);

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;
    logElapsedTime ("%s C_VerifyUpdate, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_VerifyUpdate", l_ulErc);
        return l_ulErc;
    }

    startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_VerifyFinal) (p_hSession,           // Session handle
                                              p_signature,                  // signature
                                              p_usignatureLen);           // signalture len

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;
    logElapsedTime ("%s C_VerifyFinal, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_VerifyFinal", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;

}


CK_RV signRSAData (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen,
                   CK_BYTE_PTR data, CK_ULONG p_dataLen, CK_BYTE_PTR signature, CK_ULONG_PTR  p_signatureLen)
{
    CK_RV l_ulErc = CKR_OK;

    CK_OBJECT_HANDLE    l_hPrivKey;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_BYTE l_pHash[64];
    CK_ULONG l_ulHashLen = sizeof(l_pHash);

    // Find a private key for this ID
    l_ulErc = findRSAKeyById (p_pFunctions, p_hSession, p_pszKeyId, p_ulKeyIdLen, TRUE, &l_hPrivKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findRSAKeyById", l_ulErc);
        return l_ulErc;
    }

    //---- Hash the data ----
    l_stMechanism.mechanism = CKM_SHA_1;

    l_ulErc = digestData (p_pFunctions, p_hSession, &l_stMechanism, data,
                          p_dataLen, (CK_BYTE_PTR) & l_pHash, (CK_ULONG_PTR) & l_ulHashLen);

    // PKCS #1 v1.5 RSA mechanism
    l_stMechanism.mechanism = CKM_RSA_PKCS;

    double startTime = getCurrentTime ();

    // sign init
    l_ulErc = (*p_pFunctions->C_SignInit) (p_hSession,        // Session handle
                                           &l_stMechanism,            // RSA sign . mechanism
                                           l_hPrivKey                 // Handle of Private key, returned
                                           );

    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_SignInit, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_SignInit", l_ulErc);
        return l_ulErc;
    }

    // signUpdate
    startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_SignUpdate) (p_hSession,           // Session handle
                                             (CK_BYTE_PTR) & l_pHash,    // hash of data to be signed
                                             l_ulHashLen);

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_SignUpdate, %f", p_pszKeyId, elapsedTime);
    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_SignUpdate", l_ulErc);
        return l_ulErc;
    }

    startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_SignFinal) (p_hSession,           // Session handle
                                            signature,                  // signature returned
                                            p_signatureLen);

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_SignFinal, %f", p_pszKeyId, elapsedTime);
    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_SignUpdate", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}


// encrypt with public key
CK_RV encryptRSA (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                  CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_BYTE_PTR p_data,
                  CK_ULONG p_dataLen, CK_BYTE_PTR p_encdata, CK_ULONG_PTR  p_encdataLen)
{
    CK_RV l_ulErc = CKR_OK;

    CK_OBJECT_HANDLE    l_hPubKey = 0;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };

    // Find a public key for this ID
    l_ulErc = findRSAKeyById (p_pFunctions, p_hSession, p_pszKeyId, p_ulKeyIdLen, FALSE, &l_hPubKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findRSAKeyById", l_ulErc);
        return l_ulErc;
    }

    // PKCS #1 v1.5 RSA mechanism
    l_stMechanism.mechanism = CKM_RSA_PKCS;

    double startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_EncryptInit) (p_hSession,       // Session handle
                                              &l_stMechanism,   // RSA mecanism . mechanism
                                              l_hPubKey         // Handle of Public key
                                              );

    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_EncryptInit, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_EncryptInit", l_ulErc);
        return l_ulErc;
    }

    startTime = getCurrentTime ();

    // PKCS #1 v1.5 RSA mechanism : Only a single part operation is supported
    l_ulErc = (*p_pFunctions->C_Encrypt) (p_hSession,               // Session handle
                                          (CK_BYTE_PTR)p_data,      //  data to be encrypted
                                          p_dataLen,
                                          p_encdata,
                                          p_encdataLen);            // data  len

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_Encrypt, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_EncryptUpdate", l_ulErc);
        return l_ulErc;
    }

    /*
    printf ("encrpt rsa data len  : %d\n",(int)p_dataLen);
    HexDump((unsigned char*)p_data,(unsigned long)p_dataLen);

    printf ("encrpt rsa result len   %d\n",(int)*p_encdataLen);
    HexDump(p_encdata,*p_encdataLen);
    */

    return l_ulErc;
}


// decrypt with private key
CK_RV decryptRSA (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                  CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_BYTE_PTR p_encdata,
                  CK_ULONG p_encdataLen, CK_BYTE_PTR p_cleardata, CK_ULONG_PTR  p_cleardataLen)
{

    CK_RV l_ulErc = CKR_OK;

    CK_OBJECT_HANDLE    l_hPrivKey;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };

    // Find a private key for this ID
    l_ulErc = findRSAKeyById (p_pFunctions, p_hSession, p_pszKeyId, p_ulKeyIdLen, TRUE, &l_hPrivKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findRSAKeyById", l_ulErc);
        return l_ulErc;
    }

    // PKCS #1 v1.5 RSA mechanism
    l_stMechanism.mechanism = CKM_RSA_PKCS;

    // init
    double startTime = getCurrentTime ();
    l_ulErc = (*p_pFunctions->C_DecryptInit) (p_hSession,               // Session handle
                                              &l_stMechanism,           // RSA mecanism . mechanism
                                              l_hPrivKey                // Handle of Private key
                                              );

    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;
    logElapsedTime ("%s C_DecryptInit, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_DecryptInit", l_ulErc);
        return l_ulErc;
    }

    // PKCS #1 v1.5 RSA mechanism : Only a single part operation is supported
    startTime = getCurrentTime ();
    l_ulErc = (*p_pFunctions->C_Decrypt) (p_hSession,                   // Session handle
                                          (CK_BYTE_PTR)p_encdata,       // data to be decrypted
                                          p_encdataLen,                 // data len
                                          p_cleardata,                  // plain data returned
                                          p_cleardataLen
                                          );

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;
    logElapsedTime ("%s C_Decrypt, %f", p_pszKeyId, elapsedTime);

    /*/
    printf ("encrypted rsa data len  : %d\n", (int)p_encdataLen);
    HexDump (p_encdata, p_encdataLen);
    */

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_Decrypt", l_ulErc);
        return l_ulErc;
    }

    /*
    printf ("decrypted rsa data len  : %d\n", (int)*p_cleardataLen);
    HexDump (p_cleardata, *p_cleardataLen);
    */

    return l_ulErc;
}
