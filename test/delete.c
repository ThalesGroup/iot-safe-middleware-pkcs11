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
#include "delete.h"



CK_RV delete (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession, CK_CHAR *p_pszId, CK_ULONG p_ulIdLen)
{

    CK_RV               l_ulErc = CKR_OK;
    CK_OBJECT_HANDLE    l_phObject[12];
    CK_ULONG            l_ulFound;
    CK_BBOOL l_fIsToken = TRUE;
    CK_ATTRIBUTE l_arstKeyTemplate[] = {
        { CKA_TOKEN, &l_fIsToken, sizeof(CK_BBOOL) },
        { CKA_ID, p_pszId, p_ulIdLen }
    };

    printf ("\nDeleting objects with identifier '%s' stored in the token ...\n ", p_pszId);

    /*---- Search for an object ----*/
    // Find a RSA Private key that matches the given template
    if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit) (p_hSession, l_arstKeyTemplate, 2)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsInit", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjects) (p_hSession, l_phObject, sizeof (l_phObject), &l_ulFound))
        != CKR_OK)
    {
        CKRLOG ("C_FindObjects", l_ulErc);
        return l_ulErc;
    }

    if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal) (p_hSession)) != CKR_OK)
    {
        CKRLOG ("C_FindObjectsFinal", l_ulErc);
        return l_ulErc;
    }

    if (l_ulFound > 0)
    {
        /*---- Get user confirmation ----*/
        char    l_szInput[32];
        do
        {
            printf ("\t%lu objects with identifier '%s' will be deleted. OK ? [y|n] : ", l_ulFound, p_pszId);
        }
        while (fgets (l_szInput, sizeof(l_szInput), stdin) != NULL_PTR);
        l_szInput[strlen (l_szInput) - 1] = '\0';   // remove '\n'
        printf ("\n");
        if (strcmp (l_szInput, "y") != 0)
            return l_ulErc;

        for (int nI = 0; nI < (int)l_ulFound; nI++)
        {
            if ((l_ulErc = (*p_pFunctions->C_DestroyObject) (p_hSession, l_phObject[nI])) != CKR_OK)
            {
                CKRLOG ("C_DestroyObject", l_ulErc);
                return l_ulErc;
            }
        }

        printf ("\t%lu objects successfully deleted.\n", l_ulFound);
    }
    else
        printf ("\tNo object found with identifier '%s' !\n", p_pszId);

    return l_ulErc;
}


CK_RV deleteAll (CK_FUNCTION_LIST_PTR p_pFunctions, CK_SESSION_HANDLE p_hSession)
{
    CK_RV               l_ulErc = CKR_OK;
    CK_OBJECT_HANDLE    l_hObject;
    CK_ULONG            l_ulFound;
    int                 l_nI = 0;

    /*---- Get user confirmation ----*/
    char    l_szInput[32];
    do
    {
        printf ("\nAll objects in token will be deleted. OK ? [y|n]: ");
    } while (fgets (l_szInput, sizeof(l_szInput), stdin) == NULL_PTR);
    l_szInput[strlen (l_szInput) - 1] = '\0';   // remove '\n'
    printf ("\n");
    if (strcmp (l_szInput, "y") != 0)
        return l_ulErc;

    printf ("\nDeleting all objects stored in the token ... ");

    do
    {
        /*---- Search for an object ----*/
        if ((l_ulErc = (*p_pFunctions->C_FindObjectsInit) (p_hSession, NULL_PTR, 0)) != CKR_OK)
        {
            CKRLOG ("C_FindObjectsInit", l_ulErc);
            return l_ulErc;
        }
        if ((l_ulErc = (*p_pFunctions->C_FindObjects) (p_hSession, &l_hObject, 1, &l_ulFound))
            != CKR_OK)
        {
            CKRLOG ("C_FindObjects", l_ulErc);
            return l_ulErc;
        }
        if ((l_ulErc = (*p_pFunctions->C_FindObjectsFinal) (p_hSession)) != CKR_OK)
        {
            CKRLOG ("C_FindObjectsFinal", l_ulErc);
            return l_ulErc;
        }
        if (l_ulFound == 1)
        {
            /*---- It's curtains for the object----*/
            double startTime = getCurrentTime ();
            l_ulErc = (*p_pFunctions->C_DestroyObject) (p_hSession, l_hObject);
            double stopTime = getCurrentTime ();
            double elapsedTime = stopTime - startTime;

            logElapsedTime ("C_DestroyObject, %f", elapsedTime);

            if (l_ulErc != CKR_OK)
            {
                CKRLOG ("C_DestroyObject", l_ulErc);
                return l_ulErc;
            }

            l_nI++;
        }
    }
    while (l_ulFound == 1);

    printf ("\t%d objects deleted.\n", l_nI);

    return l_ulErc;
}

