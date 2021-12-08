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
#include "aes.h"


CK_RV findAESKeyById (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                      CK_CHAR *p_pszId, CK_ULONG p_ulIdLen, CK_OBJECT_HANDLE_PTR p_pAESKey
                      )
{
    CK_RV l_ulErc = CKR_OK;
    CK_ULONG l_ulCount = 0;
    CK_BBOOL l_fIsToken = TRUE;
    CK_OBJECT_CLASS l_ulObjectClass = CKO_SECRET_KEY;
    CK_KEY_TYPE l_ulKeyType = CKK_AES;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_CLASS, &l_ulObjectClass, sizeof(CK_OBJECT_CLASS) },
        { CKA_TOKEN, &l_fIsToken, sizeof(CK_BBOOL) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof(CK_KEY_TYPE) },
        { CKA_ID, p_pszId, p_ulIdLen }
    };

    *p_pAESKey = NULL_PTR;

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit) (p_hSession, l_arstKeyTemplate, 4)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects) (p_hSession, p_pAESKey, 1, &l_ulCount)) != CKR_OK)
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


CK_RV genAESKey (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_ULONG p_ulKeyBitsSize)
{
    CK_RV l_ulErc = CKR_OK;

    CK_ULONG l_ulKeySize = p_ulKeyBitsSize / 8;
    CK_OBJECT_HANDLE l_hKey;
    CK_BBOOL l_fTrue = TRUE;
    CK_KEY_TYPE l_tkeytype = CKK_AES;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };

    CK_ATTRIBUTE l_pstKeyTemplate[] = {
        { CKA_TOKEN, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, &l_fTrue, sizeof(CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen },
        { CKA_KEY_TYPE, &l_tkeytype, sizeof(l_tkeytype) },
        { CKA_VALUE_LEN, &l_ulKeySize, sizeof(l_ulKeySize) }
    };

    // Check parameters validity
    if (!((p_ulKeyBitsSize == 128) || (p_ulKeyBitsSize == 192) || (p_ulKeyBitsSize == 256)))
        return CKR_ARGUMENTS_BAD;

    if ((p_pszKeyId == NULL_PTR) || (p_ulKeyIdLen > 64))
        return CKR_ARGUMENTS_BAD;

    // Set the RSA key generation mechanism
    l_stMechanism.mechanism = CKM_AES_KEY_GEN;
    l_stMechanism.pParameter = NULL_PTR;
    l_stMechanism.ulParameterLen = 0;

    // Generate RSA key pair
    l_ulErc = (*p_pFunctions->C_GenerateKey) (p_hSession,           // Session handle
                                              &l_stMechanism,       // AES Key Gen. mechanism
                                              l_pstKeyTemplate,     // Template for AES  key
                                              6,                    // Attributes count
                                              &l_hKey               // Handle of  key, return
                                              );
    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_GenerateAESKey", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}


CK_RV deleteAESKey (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                    CK_CHAR *p_pszId, CK_ULONG p_ulIdLen
                    )
{
    CK_RV               l_ulErc = CKR_OK;
    CK_OBJECT_HANDLE    l_hKey;

    // Find a private key for this ID
    l_ulErc = findAESKeyById (p_pFunctions, p_hSession, p_pszId, p_ulIdLen, &l_hKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findAESKeyById", l_ulErc);
        return l_ulErc;
    }

    // Delete this AES key
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

CK_RV signAESCMAC (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                   CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen,
                   CK_BYTE_PTR p_pbData, CK_ULONG p_ulDataLen,
                   CK_BYTE_PTR p_pbSignature, CK_ULONG_PTR p_pulSignatureLen)
{
    double startTime   = 0;
    double stopTime    = 0;
    double elapsedTime = 0;

    CK_RV l_ulErc = CKR_OK;

    /* Find AES Key
     */
    CK_OBJECT_HANDLE p_pAESKey[1] = {0};
    CK_ULONG l_ulCount = 0;
    CK_BBOOL l_fIsToken = TRUE;
    CK_OBJECT_CLASS l_ulObjectClass = CKO_SECRET_KEY;
    CK_KEY_TYPE l_ulKeyType = CKK_AES;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_CLASS, &l_ulObjectClass, sizeof(CK_OBJECT_CLASS) },
        { CKA_TOKEN, &l_fIsToken, sizeof(CK_BBOOL) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof(CK_KEY_TYPE) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit) (p_hSession, l_arstKeyTemplate, 4)) != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects) (p_hSession, (CK_OBJECT_HANDLE_PTR) &p_pAESKey, 1, &l_ulCount)) != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_FindObjects", l_ulErc);
        return l_ulErc;
    }

    if (l_ulCount == 0)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_FindObjects does not find the specified key ID", l_ulErc);
        (*p_pFunctions->C_FindObjectsFinal) (p_hSession);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal) (p_hSession)) != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_FindObjectsFinal", l_ulErc);
        return l_ulErc;
    }

    /* Signature Initialization
     */
    CK_MAC_GENERAL_PARAMS l_ulSignatureLength = 16;
    CK_MECHANISM l_stMechanism = {
        CKM_AES_CMAC_GENERAL,
        &l_ulSignatureLength,
        sizeof(CK_MAC_GENERAL_PARAMS)
    };

    startTime = getCurrentTime();

    l_ulErc = (*p_pFunctions->C_SignInit) (p_hSession, &l_stMechanism, p_pAESKey[0]);

    stopTime = getCurrentTime();
    elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_SignInit, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_SignInit", l_ulErc);
        return l_ulErc;
    }

    /* Signature
     */
    startTime = getCurrentTime();

    l_ulErc = (*p_pFunctions->C_Sign) (p_hSession, p_pbData, p_ulDataLen, p_pbSignature, p_pulSignatureLen);

    stopTime = getCurrentTime();
    elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_Sign, %f", p_pszKeyId, elapsedTime);
    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_Sign", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}
