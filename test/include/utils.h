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

#include <time.h> 

#include "cryptoki.h"

#ifdef WIN32
struct timespec { long tv_sec; long tv_nsec; };
#endif
//-----------------------------------------------------------------------------
// Utility macros
//-----------------------------------------------------------------------------
#ifdef __cplusplus
extern "C"
{
#endif

// Vendor defined error values
#define CKR_CERTIFICATE_DOESNOTMATCH_KEYPAIR        CKR_VENDOR_DEFINED + 1
#define CKR_CERTIFICATE_DATA_INVALID                CKR_VENDOR_DEFINED + 2
#define CKR_CERTIFICATE_ALREADY_EXISTS              CKR_VENDOR_DEFINED + 3
#define CKR_CERTIFICATE_NOT_FOUND                   CKR_VENDOR_DEFINED + 4

// Logging ....
typedef enum
{
    _NONE_,
    _CRIT_,
    _ERROR_,
    _WARN_,
    _INFO_,
    _DEBUG_,
    _ALL_
} LOGGING_LEVEL, * PLOGGING_LEVEL;

LOGGING_LEVEL getLoggingLevel (void);
void setLoggingLevel (LOGGING_LEVEL p_nLevel);

#define logCrit(_x_)        {if (getLoggingLevel () >= _CRIT_) printf _x_; fflush (stdout);}
#define logErr(_x_)         {if (getLoggingLevel () >= _ERROR_) printf _x_; fflush (stdout);}
#define logWarn(_x_)        {if (getLoggingLevel () >= _WARN_) printf _x_; fflush (stdout);}
#define logInfo(_x_)        {if (getLoggingLevel () >= _INFO_) printf _x_; fflush (stdout);}
#define logDebug(_x_)       {if (getLoggingLevel () >= _DEBUG_) printf _x_; fflush (stdout);}

void logDump (LOGGING_LEVEL p_nLevel, unsigned char* p_pbData, unsigned long p_ulDataSize);
void HexDump (unsigned char* p_pbData, unsigned long p_ulDataSize);

#define CKRLOG(fct, rv) logErr(("%s:%d " fct "() exited with Cryptoki error 0x%08lX: \n", __FILE__, __LINE__, rv))

CK_RV base64Encode ( unsigned char* p_pbData, unsigned long p_ulDataLen,
                     unsigned char* p_pbBase64Data, unsigned long* p_pulBase64DataLen
                   );

CK_RV base64Decode ( unsigned char* p_pbBase64Data, unsigned long p_ulBase64DataLen, 
                     unsigned char* p_pbData, unsigned long* p_pulDataLen
                   );

CK_RV toHexString (unsigned char* p_pbData, unsigned long p_ulDataSize, char* p_pszOutBuffer, unsigned long* p_pulOutBufferLen);

void logElapsedTime(const char * format, ...);

double getCurrentTime();

void tolowercase(unsigned char* p_pbuffer);

int bytesToHexstr(unsigned char *bytes, unsigned int bytesLen, unsigned char *hexstr, unsigned int *hexstrLen);

int hexstrToBytes(unsigned char *hexstr, unsigned int hexstrLen, unsigned char *bytes, unsigned int *bytesLen);

#ifdef __cplusplus
}
#endif
