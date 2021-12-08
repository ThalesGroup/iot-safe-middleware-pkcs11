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

#include <time.h>
#include "utils.h"
#include "random.h"


CK_RV generateRandom (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession,
                      CK_BYTE_PTR p_pRandomData, CK_ULONG p_ulRandomLen)
{
    CK_RV l_ulErc = CKR_OK;

    if (p_pRandomData == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    double startTime = getCurrentTime ();

    l_ulErc = (*p_pFunctions->C_GenerateRandom) (p_hSession, p_pRandomData, p_ulRandomLen);

    double stopTime = getCurrentTime ();
    double elapsedTime = stopTime - startTime;
    logElapsedTime ("C_GenerateRandom, %f", elapsedTime);

    return l_ulErc;
}



