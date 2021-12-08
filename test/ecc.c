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
#include "ecc.h"
#include "ecdh_openssl.h"

unsigned char g_pbECC256k1_OID[7] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};
unsigned char g_pbECC256_OID[10] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
unsigned char g_pbECC384_OID[7] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
unsigned char g_pbECC521_OID[7] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};


CK_RV findECCKeyByKeyType ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                            CK_BBOOL p_fPrivateKey, CK_OBJECT_HANDLE_PTR p_phECCKey
                       )
{
    CK_RV l_ulErc = CKR_OK;
    CK_ULONG l_ulCount = 0;
    CK_BBOOL ckTrue = TRUE;
    CK_OBJECT_CLASS l_ulObjectClass = p_fPrivateKey ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_KEY_TYPE l_ulKeyType = CKK_EC;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_CLASS, &l_ulObjectClass, sizeof(CK_OBJECT_CLASS) },
        { CKA_TOKEN, &ckTrue, sizeof(CK_BBOOL) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof(CK_KEY_TYPE) },
    };

    *p_phECCKey = NULL_PTR;

    // Find a ECC Private key that matches the given template
    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit)(p_hSession, l_arstKeyTemplate, 3)) != CKR_OK)
    {
        CKRLOG("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects)(p_hSession, p_phECCKey, 1, &l_ulCount)) != CKR_OK)
    {
        CKRLOG("C_FindObjects", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal)(p_hSession)) != CKR_OK)
    {
        CKRLOG("C_FindObjectsFinal", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}

CK_RV findECCKeyById ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                         CK_CHAR *p_pszId, CK_ULONG p_ulIdLen, CK_BBOOL p_fPrivateKey, CK_OBJECT_HANDLE_PTR p_phECCKey
                       )
{
    CK_RV l_ulErc = CKR_OK;
    CK_ULONG l_ulCount = 0;
    CK_BBOOL l_fIsToken = TRUE;
    CK_OBJECT_CLASS l_ulObjectClass = p_fPrivateKey ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_KEY_TYPE l_ulKeyType = CKK_EC;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_CLASS, &l_ulObjectClass, sizeof(CK_OBJECT_CLASS) },
        { CKA_TOKEN, &l_fIsToken, sizeof(CK_BBOOL) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof(CK_KEY_TYPE) },
        { CKA_ID, p_pszId, p_ulIdLen }
    };

    *p_phECCKey = NULL_PTR;

    // Find a RSA Private key that matches the given template
    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit)(p_hSession, l_arstKeyTemplate, 4)) != CKR_OK)
    {
        CKRLOG("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects)(p_hSession, p_phECCKey, 1, &l_ulCount)) != CKR_OK)
    {
        CKRLOG("C_FindObjects", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal)(p_hSession)) != CKR_OK)
    {
        CKRLOG("C_FindObjectsFinal", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}


CK_RV verifyECDSASignature ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                             CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_BYTE_PTR p_pbSignature,
                             CK_ULONG p_ulSignatureLen, CK_BYTE_PTR p_pbData, CK_ULONG p_ulDataLen)
{
    CK_RV l_ulErc = CKR_OK;

    CK_OBJECT_HANDLE  l_hPubKey;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_BYTE l_pbHash[64];
    CK_ULONG l_ulHashLen = sizeof(l_pbHash);

    if(strstr  (p_pszKeyId, "any")){
        l_ulErc = findECCKeyByKeyType (p_pFunctions, p_hSession, FALSE, &l_hPubKey);
    }
    else{
        // Find a public key for this ID
        l_ulErc = findECCKeyById (p_pFunctions, p_hSession, p_pszKeyId, p_ulKeyIdLen, FALSE, &l_hPubKey);
    }
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findECCKeyById", l_ulErc);
        return l_ulErc;
    }

    // Compute the digest
   l_stMechanism.mechanism = CKM_SHA256;

    l_ulErc = digestData ( p_pFunctions, p_hSession, &l_stMechanism, p_pbData,
                           p_ulDataLen, (CK_BYTE_PTR) & l_pbHash, (CK_ULONG_PTR) & l_ulHashLen);

     // Set the signature mechanism
    l_stMechanism.mechanism = CKM_ECDSA;

    double startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_VerifyInit) (p_hSession, &l_stMechanism, l_hPubKey);

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

    l_ulErc = (*p_pFunctions->C_VerifyUpdate) (p_hSession, (CK_BYTE_PTR)&l_pbHash, l_ulHashLen);

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

    l_ulErc = (*p_pFunctions->C_VerifyFinal) (p_hSession, p_pbSignature, p_ulSignatureLen);

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


CK_RV signECDSA (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen,
                 CK_BYTE_PTR data, CK_ULONG p_dataLen, CK_BYTE_PTR p_pbSignature, CK_ULONG_PTR p_pulSignatureLen)
{
    CK_RV l_ulErc = CKR_OK;

    CK_OBJECT_HANDLE    l_hPrivKey;
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_BYTE l_pHash[64];
    CK_ULONG l_ulHashLen = sizeof(l_pHash);

    if(strstr  (p_pszKeyId, "any")){
    l_ulErc = findECCKeyByKeyType (p_pFunctions, p_hSession, TRUE, &l_hPrivKey);
    }
    else{
        // Find a private key for this ID
        l_ulErc = findECCKeyById (p_pFunctions, p_hSession, p_pszKeyId, p_ulKeyIdLen, TRUE, &l_hPrivKey);
    }
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("findECCKeyById", l_ulErc);
        return l_ulErc;
    }

    // Compute the SHA1 digest
    l_stMechanism.mechanism = CKM_SHA256;

    l_ulErc = digestData (p_pFunctions, p_hSession, &l_stMechanism, data,
                          p_dataLen, (CK_BYTE_PTR) & l_pHash, (CK_ULONG_PTR) & l_ulHashLen);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("digestData", l_ulErc);
        return l_ulErc;
    }

    // Set the signature mechanism
    l_stMechanism.mechanism = CKM_ECDSA;

    double startTime = getCurrentTime ();

    // Signature initialization
    l_ulErc = (*p_pFunctions->C_SignInit) (p_hSession, &l_stMechanism, l_hPrivKey);

    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_SignInit, %f", p_pszKeyId, elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_SignInit", l_ulErc);
        return l_ulErc;
    }

    // Signature update
    startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_SignUpdate) (p_hSession,                 // Session handle
                                             (CK_BYTE_PTR)&l_pHash,    // hash of data to be signed
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
                                            p_pbSignature,            // signature returned
                                            p_pulSignatureLen);

    stopTime = getCurrentTime ();
    elapsedTime = stopTime - startTime;

    logElapsedTime ("%s C_SignFinal, %f", p_pszKeyId, elapsedTime);
    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_SignFinal", l_ulErc);
        return l_ulErc;
    }

    return l_ulErc;
}

static CK_OBJECT_HANDLE l_hPrivKey;

CK_RV genECDHEKeyPair (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_ULONG p_ulKeyBitsSize)
{
    CK_RV l_ulErc = CKR_OK;

    CK_ULONG l_ulKeySize;
    CK_OBJECT_HANDLE l_hPubKey;// l_hPrivKey;
    CK_BBOOL l_fTrue = TRUE;

    // DER-encoding of ANSI X9.62 EC Point value Q
    CK_BYTE l_pbKeyValue[256];

    //CK_ULONG l_ulKeyType = CKK_DH;
    CK_ULONG l_ulKeyType = CKK_EC;
    CK_OBJECT_CLASS l_ulKeyPubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS l_ulKeyPrivClass = CKO_PRIVATE_KEY;

    // Do not change the attributes order
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_ATTRIBUTE l_pstPubKeyTemplate[] = {
        { CKA_CLASS, &l_ulKeyPubClass, sizeof (CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof (CK_ULONG) },
        { CKA_EC_PARAMS, NULL_PTR, 0 },
        { CKA_TOKEN, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };
    CK_ATTRIBUTE l_pstPrivKeyTemplate[] = {
        { CKA_CLASS, &l_ulKeyPrivClass, sizeof (CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof (CK_ULONG) },
        { CKA_TOKEN, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_PRIVATE, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_SENSITIVE, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };
    CK_ATTRIBUTE l_stKeyValueTemplate[] = {
        { CKA_EC_POINT, l_pbKeyValue, sizeof (l_pbKeyValue) }
    };

    // Check parameters validity
    if ((p_pszKeyId == NULL_PTR) || (p_ulKeyIdLen > 64))
        return CKR_ARGUMENTS_BAD;

    l_ulKeySize = p_ulKeyBitsSize;

    switch (l_ulKeySize)
    {
        case 256 :
            l_pstPubKeyTemplate[2].pValue = &g_pbECC256_OID;
            l_pstPubKeyTemplate[2].ulValueLen = sizeof (g_pbECC256_OID);
            break;
        case 384 :
            l_pstPubKeyTemplate[2].pValue = &g_pbECC384_OID;
            l_pstPubKeyTemplate[2].ulValueLen = sizeof (g_pbECC384_OID);
            break;
        case 521 :
            l_pstPubKeyTemplate[2].pValue = &g_pbECC521_OID;
            l_pstPubKeyTemplate[2].ulValueLen = sizeof (g_pbECC521_OID);
            break;
        default:
            return CKR_ARGUMENTS_BAD;
    }

    logDebug (("\nGenerating ECDHE key pair ... "));

    // Set the ECDHE key generation mechanism
    //l_stMechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
    l_stMechanism.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
    
    l_stMechanism.pParameter = NULL_PTR;
    l_stMechanism.ulParameterLen = 0;

    double startTime= getCurrentTime ();

    // Generate ECDHE key pair
    l_ulErc = (*p_pFunctions->C_GenerateKeyPair)(p_hSession,        // Session handle
                                 &l_stMechanism,                    // ECC Key Gen. mechanism
                                 l_pstPubKeyTemplate,               // Template for ECC Public key
                                 5,                                 // Attributes count
                                 l_pstPrivKeyTemplate,              // Template for ECC Private key
                                 6,                                 // Attributes count
                                 &l_hPubKey,                        // Handle of Public key, returned
                                 &l_hPrivKey                        // Handle of Private key, returned
                                 );

    double stopTime= getCurrentTime();
    double elapsedTime=stopTime-startTime;
    logElapsedTime("%s C_GenerateKeyPair, %f",p_pszKeyId,elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_GenerateKeyPair", l_ulErc);
        return l_ulErc;
    }
    else
        logDebug (("successful.\n"));

         printf ("\t->ECDHE 256 ephemeral private key handle at generation %ld  .\n", l_hPrivKey);  

    // Display the key value
    l_ulErc = (*p_pFunctions->C_GetAttributeValue)( p_hSession,             // Session handle
                                                    l_hPubKey,              // Handle of Public Key
                                                    l_stKeyValueTemplate,   // Key value template
                                                    1                       // Number of attributes
                                                   );
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("C_GetAttributeValue", l_ulErc);
        return l_ulErc;
    }

    logInfo (("\tDER-encoding of ANSI X9.62 EC Point value Q : \n"));
    logDump (_INFO_, l_stKeyValueTemplate->pValue, l_stKeyValueTemplate->ulValueLen);

    return l_ulErc;
}

CK_RV computeECDH (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession)
{
    /*Generate key pair context*/
    CK_RV     l_ulErc = CKR_OK;
    char      l_pszKeyID[20] = {0x04 , 0x00} ; // Using ID 04 for container ECDHE Keypair;
    char      *publicServerKey;
    CK_ULONG  l_ulBufferLen = 256;
    CK_BYTE   l_pbBuffer[256];
    CK_OBJECT_HANDLE l_hPubKey;
    CK_OBJECT_HANDLE l_hPrivateKey;
    // To retrieve public key value
    CK_BYTE l_pbKeyValue[256];
    CK_ATTRIBUTE l_stKeyValueTemplate[] = {
        { CKA_EC_POINT, l_pbKeyValue, sizeof (l_pbKeyValue) }
    };
    
    // To retrieve secret key value
    CK_BYTE l_pbSecretKeyValue[32];
    CK_ATTRIBUTE l_stSecretKeyValueTemplate[] = {
        { CKA_VALUE, l_pbSecretKeyValue, sizeof (l_pbSecretKeyValue) }
    };
    

    /*Derive key context*/
    CK_KEY_TYPE            keyType = CKK_GENERIC_SECRET;
    CK_OBJECT_HANDLE       client_secret = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretKeyClass  = CKO_SECRET_KEY;
    CK_BBOOL ckFalse, ckTrue;
    CK_MECHANISM           mech;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_ULONG               secSz;
    CK_ATTRIBUTE           tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_SENSITIVE,   &ckTrue,        sizeof(CK_TRUE)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(CK_TRUE)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(CK_TRUE)         },
        { CKA_VALUE_LEN,   &secSz,          sizeof(secSz)          }
    };
    CK_ULONG               tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    printf ("\nGenerating DH secret ...\n");

    // ECC 256 Tests
    //--------------
    printf ("\n\t->Generating ECDHE 256 Key Pair ...\n");
    l_ulErc = genECDHEKeyPair (p_pFunctions, p_hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID), 256);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("\t->genECDHEKeyPair... fail", l_ulErc);
        return l_ulErc;
    }
    else
    {
        printf ("\t->ECDHE 256 Key Pair generation successful.\n");

        const char *server_ecdh_ppubkey = "\x04\x20\x3B\x81\xA0\xAC\xCC\xBE\xA0\x6F\xF0\x84\xB2\x84\x33\x09\x1D\x6D\x34\xAC\xEC\x3C\xF9\xAF\x70\x7C\xEE\x75\xCA\xBB\xC2\x32\xFD\xC8\xB0\x7E\xDE\xE5\xF2\x66\x09\x39\xA9\xF7\x1B\x45\x54\x91\x27\x89\x66\xE7\x25\x4B\x24\x4D\x71\x09\xB7\x27\x7B\x6A\xAE\xCB\xBF";
          
        //public key
        //l_ulErc = findECCKeyByKeyType (p_pFunctions, p_hSession, l_pszKeyID, l_ulBufferLen, TRUE, &l_hPrivateKey);
        
        logInfo (("\tSEARCH  FOR PUBLIC KEY: \n"));
        l_ulErc = findECCKeyById (p_pFunctions, p_hSession,(CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID), FALSE, &l_hPubKey);
        if (l_ulErc != CKR_OK)
        {
            CKRLOG ("FAILED TO GET THE EC KEY FROM DERIVATIION", l_ulErc);
            //return l_ulErc;
        }
        if(l_hPubKey == NULL || l_hPubKey == CKR_OBJECT_HANDLE_INVALID) {
            printf("invalid public key handle\n");
        }
        else{
              printf("OK public key handle is %d\n", l_hPubKey);
                  // DER-encoding of ANSI X9.62 EC Point value Q
             
                // Display the key value
                l_ulErc = (*p_pFunctions->C_GetAttributeValue)( p_hSession,             // Session handle
                                                                l_hPubKey,              // Handle of Public Key
                                                                l_stKeyValueTemplate,   // Key value template
                                                                1                       // Number of attributes
                                                            );
                if (l_ulErc != CKR_OK)
                {
                    CKRLOG ("C_GetAttributeValue", l_ulErc);
                   
                }
                else 
                {
                    logInfo (("\tDER-encoding of ANSI X9.62 EC Point value Q : \n"));
                    logDump (_INFO_, l_stKeyValueTemplate->pValue, l_stKeyValueTemplate->ulValueLen);
                }

        }

        //private key
        logInfo (("\tSEARCH  FOR PRIVATE KEY: \n"));
        l_ulErc = findECCKeyById (p_pFunctions, p_hSession, (CK_CHAR_PTR)l_pszKeyID, (CK_ULONG)strlen (l_pszKeyID), TRUE, &l_hPrivateKey);
        if (l_ulErc != CKR_OK)
        {
            CKRLOG ("FAILED TO GET THE EC KEY FROM DERIVATIION", l_ulErc);
            //return l_ulErc;
        }
        if(l_hPrivateKey == NULL || l_hPrivateKey == CKR_OBJECT_HANDLE_INVALID) {
            printf("invalid private key handle\n");
        }
        else{
              printf("OK private key handle is %d\n", l_hPrivateKey);
        }

        
	    
        
        params.kdf             = CKD_NULL;
        params.pSharedData     = NULL;
        params.ulSharedDataLen = 0;

 
        //  Generate EC Key pair using OpenSSL to simulate server sider
        EVP_PKEY *server_key = gen_ec_keypair();
        unsigned char *server_pubkey = NULL;
        size_t p_len =0;
	    get_ec_pubkey_der(server_key, &server_pubkey, &p_len);
        // Currently it simulated, it is suposed to be server edch public key.
        params.pPublicData     = server_pubkey; //server_ecdh_ppubkey; 
        params.ulPublicDataLen = p_len; //strlen(server_ecdh_ppubkey);
        mech.mechanism      = CKM_ECDH1_DERIVE;
        mech.ulParameterLen = sizeof(params);
        mech.pParameter     = &params;
        
        l_ulErc = (*p_pFunctions->C_DeriveKey)(p_hSession, &mech, l_hPrivateKey,
                                                    tmpl, tmplCnt, &client_secret);


        if (l_ulErc != CKR_OK) 
        {
            printf ("\t->Derive Key... fail.\n", l_ulErc);
        }
        else
        {
            printf ("\t->Derive Key... successful.\n");
              
            // Display the key value
            l_ulErc = (*p_pFunctions->C_GetAttributeValue)( p_hSession,             // Session handle
                                                            client_secret,              // Handle of Secret Key
                                                            l_stSecretKeyValueTemplate,   // Key value template
                                                            1                       // Number of attributes
                                                        );
            if (l_ulErc != CKR_OK)
            {
                CKRLOG ("C_GetAttributeValue", l_ulErc);
                
        }  
            else 
            {
                logInfo (("\tShared Secret (Client Side) Key : \n"));
                logDump (_INFO_, l_stSecretKeyValueTemplate->pValue, l_stSecretKeyValueTemplate->ulValueLen);
            }
        }  


        // To simulate server side key derivation use OpenSSL to derive ECDH secret key and compare
        EVP_PKEY *pp_client_pub_key = NULL;
	    size_t secret_len = 32;
        unsigned char *pub_der = (unsigned char *) l_stKeyValueTemplate->pValue;
        pub_der += 2; // Skip two bytes of Tag Len to get uncompressed key 04 X(32 bytes), Y (32 bytes)
        int ret = get_ec_pubkey_from_der(&pp_client_pub_key, pub_der, l_stKeyValueTemplate->ulValueLen-2);
        if (ret == 0)
        {
            unsigned char *shared_secret = key_agreement_ecdh(server_key, pp_client_pub_key,&secret_len);
            if (shared_secret != NULL) 
            {
                logInfo (("\tShared Secret (Server Side) Key : \n"));
                logDump (_INFO_, shared_secret, secret_len);
                int keys_match = TRUE;
                for (size_t l=0;  l < secret_len ;l++)
                {
                        if (shared_secret[l] != ((unsigned char *)l_stSecretKeyValueTemplate->pValue)[l])
                        {
                          keys_match = FALSE;
                          break;    
                        }
                }
                if (keys_match == TRUE)
                {
                     logInfo (("Success: Key Agreement Shared Keys match \n")); 
                }
                else 
                {
                     logErr (("\tError: Key Agreement failed Shared Keys do not match \n")); 
                }
                OPENSSL_free(shared_secret);  
            }
            else
                logErr (("\tError: Key Agreement failed with OpenSSL \n")); 
            
            EVP_PKEY_free(pp_client_pub_key);  
            EVP_PKEY_free(server_key); 
        }
        else 
        {
                logErr (("\tError: Cannot construct EC Pub Key from DER \n"));    
        }

        return l_ulErc;
        
    }
}


CK_RV genECDSAKeyPair (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_ULONG p_ulKeyBitsSize)
{
    CK_RV l_ulErc = CKR_OK;

    CK_ULONG l_ulKeySize;
    CK_OBJECT_HANDLE l_hPubKey, l_hPrivKey;
    CK_BBOOL l_fTrue = TRUE;

    // DER-encoding of ANSI X9.62 EC Point value Q
    CK_BYTE l_pbKeyValue[256];

    CK_ULONG l_ulKeyType = CKK_EC;
    CK_OBJECT_CLASS l_ulKeyPubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS l_ulKeyPrivClass = CKO_PRIVATE_KEY;

    // Do not change the attributes order
    CK_MECHANISM l_stMechanism = { 0, NULL_PTR, 0 };
    CK_ATTRIBUTE l_pstPubKeyTemplate[] = {
        { CKA_CLASS, &l_ulKeyPubClass, sizeof (CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof (CK_ULONG) },
        { CKA_EC_PARAMS, NULL_PTR, 0 },
        { CKA_TOKEN, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };
    CK_ATTRIBUTE l_pstPrivKeyTemplate[] = {
        { CKA_CLASS, &l_ulKeyPrivClass, sizeof (CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &l_ulKeyType, sizeof (CK_ULONG) },
        { CKA_TOKEN, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_PRIVATE, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_SENSITIVE, &l_fTrue, sizeof (CK_BBOOL) },
        { CKA_ID, p_pszKeyId, p_ulKeyIdLen }
    };
    CK_ATTRIBUTE l_stKeyValueTemplate[] = {
        { CKA_EC_POINT, l_pbKeyValue, sizeof (l_pbKeyValue) }
    };

    // Check parameters validity
    if ((p_pszKeyId == NULL_PTR) || (p_ulKeyIdLen > 64))
        return CKR_ARGUMENTS_BAD;

    l_ulKeySize = p_ulKeyBitsSize;

    switch (l_ulKeySize)
    {
        case 256 :
            l_pstPubKeyTemplate[2].pValue = &g_pbECC256_OID;
            l_pstPubKeyTemplate[2].ulValueLen = sizeof (g_pbECC256_OID);
            break;
        case 384 :
            l_pstPubKeyTemplate[2].pValue = &g_pbECC384_OID;
            l_pstPubKeyTemplate[2].ulValueLen = sizeof (g_pbECC384_OID);
            break;
        case 521 :
            l_pstPubKeyTemplate[2].pValue = &g_pbECC521_OID;
            l_pstPubKeyTemplate[2].ulValueLen = sizeof (g_pbECC521_OID);
            break;
        default:
            return CKR_ARGUMENTS_BAD;
    }

    logDebug (("\nGenerating ECDSA key pair ... "));

    // Set the ECDSA key generation mechanism
    l_stMechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
    l_stMechanism.pParameter = NULL_PTR;
    l_stMechanism.ulParameterLen = 0;

    double startTime= getCurrentTime ();

    // Generate ECDSA key pair
    l_ulErc = (*p_pFunctions->C_GenerateKeyPair)(p_hSession,        // Session handle
                                 &l_stMechanism,                    // ECC Key Gen. mechanism
                                 l_pstPubKeyTemplate,               // Template for ECC Public key
                                 5,                                 // Attributes count
                                 l_pstPrivKeyTemplate,              // Template for ECC Private key
                                 6,                                 // Attributes count
                                 &l_hPubKey,                        // Handle of Public key, returned
                                 &l_hPrivKey                        // Handle of Private key, returned
                                 );

    double stopTime= getCurrentTime();
    double elapsedTime=stopTime-startTime;
    logElapsedTime("%s C_GenerateKeyPair, %f",p_pszKeyId,elapsedTime);

    if (l_ulErc != CKR_OK)
    {
        logErr (("Failed ! "));
        CKRLOG ("C_GenerateKeyPair", l_ulErc);
        return l_ulErc;
    }
    else
        logDebug (("successful.\n"));

    // Display the key value
    l_ulErc = (*p_pFunctions->C_GetAttributeValue)( p_hSession,             // Session handle
                                                    l_hPubKey,              // Handle of Public Key
                                                    l_stKeyValueTemplate,   // Key value template
                                                    1                       // Number of attributes
                                                   );
    if (l_ulErc != CKR_OK)
    {
        CKRLOG ("C_GetAttributeValue", l_ulErc);
        return l_ulErc;
    }

    logInfo (("\tDER-encoding of ANSI X9.62 EC Point value Q : \n"));
    logDump (_INFO_, l_stKeyValueTemplate->pValue, l_stKeyValueTemplate->ulValueLen);

     //l_ulErc = (*p_pFunctions->C_GetAttributeValue)( p_hSession,             // Session handle
                                                   // l_hPubKey,              // Handle of Public Key
                                                   // l_stKeyValueTemplate_static,   // Key value template
                                                   // 1                       // Number of attributes
                                                 //  );
   // if (l_ulErc != CKR_OK)
    //{
     //   CKRLOG ("C_GetAttributeValue", l_ulErc);
     //   return l_ulErc;
   // }

    //logInfo (("\tDER-encoding of ANSI X9.62 EC Point value Q (static) : \n"));
    //logDump (_INFO_, l_stKeyValueTemplate_static->pValue, l_stKeyValueTemplate_static->ulValueLen);

    return l_ulErc;
}


CK_RV deleteECCKeyPair ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                          CK_CHAR *p_pszId, CK_ULONG p_ulIdLen
                       )
{
    CK_RV               l_ulErc = CKR_OK;
    CK_OBJECT_HANDLE    l_hKey = 0;

    // Find a private key for this ID
    l_ulErc = findECCKeyById (p_pFunctions, p_hSession, p_pszId, p_ulIdLen, TRUE, &l_hKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG("findECCKeyById", l_ulErc);
        return l_ulErc;
    }

    // Delete this private key
    if (l_hKey != 0)
    {
        if ((l_ulErc = (*p_pFunctions->C_DestroyObject)(p_hSession, l_hKey)) != CKR_OK)
        {
            CKRLOG ("C_DestroyObject", l_ulErc);
            return l_ulErc;
        }
    }
    else
        return CKR_OBJECT_HANDLE_INVALID;

    // Find a public key for this ID
    l_ulErc = findECCKeyById (p_pFunctions, p_hSession, p_pszId, p_ulIdLen, FALSE, &l_hKey);
    if (l_ulErc != CKR_OK)
    {
        CKRLOG("findECCKeyById", l_ulErc);
        return l_ulErc;
    }

    // Delete this public key
    if (l_hKey != 0)
    {
        if ((l_ulErc = (*p_pFunctions->C_DestroyObject)(p_hSession, l_hKey)) != CKR_OK)
        {
            CKRLOG ("C_DestroyObject", l_ulErc);
            return l_ulErc;
        }
    }
    else
        return CKR_OBJECT_HANDLE_INVALID;

    return l_ulErc;
}


