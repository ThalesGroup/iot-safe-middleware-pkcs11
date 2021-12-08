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

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif


CK_RV findECCKeyById ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                       CK_CHAR *p_pszId, CK_ULONG p_ulIdLen, CK_BBOOL p_fPrivateKey, CK_OBJECT_HANDLE_PTR p_phRSAKey
                     );

CK_RV genECDSAKeyPair ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                        CK_CHAR_PTR p_pszKeyId, CK_ULONG p_ulKeyIdLen, CK_ULONG p_ulKeyBitsSize
                      );

CK_RV deleteECCKeyPair ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                         CK_CHAR *p_pszId, CK_ULONG p_ulIdLen
                       );


CK_RV signECDSA ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                  CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen,CK_BYTE_PTR data,
                  CK_ULONG p_dataLen,CK_BYTE_PTR signature,CK_ULONG_PTR  p_signatureLen);

CK_RV verifyECDSASignature ( CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                             CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen,CK_BYTE_PTR p_signature,
                             CK_ULONG p_usignatureLen,CK_BYTE_PTR p_Data,CK_ULONG  p_dataLen);

/*
CK_RV encryptRSA(CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                 CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen,CK_BYTE_PTR p_data,
                  CK_ULONG p_dataLen,CK_BYTE_PTR p_encdata,CK_ULONG_PTR  p_encdataLen);


CK_RV decryptRSA(CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                 CK_CHAR_PTR  p_pszKeyId, CK_ULONG p_ulKeyIdLen,CK_BYTE_PTR p_encdata,
                  CK_ULONG p_encdataLen,CK_BYTE_PTR p_cleardata,CK_ULONG_PTR  p_cleardataLen);
*/

#ifdef __cplusplus
}
#endif

