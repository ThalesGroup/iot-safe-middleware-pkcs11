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
#ifdef WIN32
#include <windows.h>
#include <conio.h>
#ifndef _WINDOWS
#define _WINDOWS
#endif
#else
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#endif
#ifndef WIN32
#define min(a,b) (((a)<(b))?(a):(b))
#else
#define BILLION  (1E9)
static BOOL g_first_time = 1;
static LARGE_INTEGER g_counts_per_sec;
#endif
#include "utils.h"

#ifdef DEBUG
static LOGGING_LEVEL G_nLoggingLevel = _ALL_;
#else
static LOGGING_LEVEL G_nLoggingLevel = _CRIT_;
#endif

void setLoggingLevel (LOGGING_LEVEL p_nLevel)
{
    if ((p_nLevel >= _NONE_) && (p_nLevel <= _ALL_))
        G_nLoggingLevel = p_nLevel;
}


LOGGING_LEVEL getLoggingLevel (void)
{
    return (G_nLoggingLevel);
}


#define LOG_DUMP_NBCHARINLINE   16
// LOG_DUMP_LINESIZE
// (2 Hexa digits + 1 space) * 16 bytes + 1 dash + 16 chars + 1 LF + 1 '\0'
//
#define LOG_DUMP_LINESIZE       (16*3 + 1 + 16 + 1 + 1)

void CharToHexa2 (unsigned char* p_pbHexPos, unsigned char p_bByte2Dump)
{
    // Convert the current character to hexa : 1rst the low byte
    if ((p_bByte2Dump & 0x0f) > 9)
        p_pbHexPos[1] = (unsigned char)((p_bByte2Dump & 0x0F) + 0x37);
    else
        p_pbHexPos[1] = (unsigned char)((p_bByte2Dump & 0x0F) + 0x30);

    // Transfert high byte to low byte
    p_bByte2Dump >>= 4;

    if (p_bByte2Dump > 9)
        p_pbHexPos[0] = (unsigned char)(p_bByte2Dump + 0x37);
    else
        p_pbHexPos[0] = (unsigned char)(p_bByte2Dump + 0x30);
}


void HexDump (unsigned char* p_pbData, unsigned long p_ulDataSize)
{
    char    l_szPrintFormat[] = "\t%04X  %s\n";
    char    l_szPrintBufferRef [LOG_DUMP_LINESIZE] = "                       -                         D               ";

    char            l_szPrintBuffer [LOG_DUMP_LINESIZE];
    unsigned long   l_ulOffset = 0;
    unsigned long   l_ulChars = 0;
    unsigned char   l_bDumpedByte;

    memcpy (l_szPrintBuffer, l_szPrintBufferRef, LOG_DUMP_LINESIZE);

    for (; p_ulDataSize; p_ulDataSize--)
    {
        if (l_ulChars >= LOG_DUMP_NBCHARINLINE)
        {
            printf (l_szPrintFormat, l_ulOffset, l_szPrintBuffer);

            l_ulChars = 0;
            p_pbData += LOG_DUMP_NBCHARINLINE;
            l_ulOffset += LOG_DUMP_NBCHARINLINE;
            memcpy (l_szPrintBuffer, l_szPrintBufferRef, LOG_DUMP_LINESIZE);
        }

        l_bDumpedByte = p_pbData [l_ulChars];

        l_szPrintBuffer [l_ulChars * 3] = ' ';
        CharToHexa2 ((unsigned char*)&l_szPrintBuffer [l_ulChars * 3], l_bDumpedByte);

        if (l_bDumpedByte < 0x20 || l_bDumpedByte >= 0x7F)
            l_szPrintBuffer [16 * 3 + 1 + l_ulChars] = '.';
        else
            l_szPrintBuffer [16 * 3 + 1 + l_ulChars] = l_bDumpedByte;

        l_ulChars ++;
    }

    if (l_ulChars)
    {
        if (l_ulChars <= 8)
            l_szPrintBuffer [8 * 3 - 1] = ' ';

        printf (l_szPrintFormat, l_ulOffset, l_szPrintBuffer);
    }
}

// get time in millisecondes

double  getCurrentTime()
{
 struct timespec s_ts;
 double current_time;
 #ifdef WIN32
    LARGE_INTEGER count;
    if (g_first_time)
    {
        g_first_time = 0;

        if (0 == QueryPerformanceFrequency(&g_counts_per_sec))
        {
            g_counts_per_sec.QuadPart = 0;
        }
    }

    if ( (g_counts_per_sec.QuadPart <= 0) ||
            (0 == QueryPerformanceCounter(&count)))
    {
        return -1;
    }

    s_ts.tv_sec = count.QuadPart / g_counts_per_sec.QuadPart;
    s_ts.tv_nsec = ((count.QuadPart % g_counts_per_sec.QuadPart) * BILLION) / g_counts_per_sec.QuadPart;
    current_time=((double)s_ts.tv_sec * 1000) + ((double)s_ts.tv_nsec/1000000) ;
    return current_time;

 #else
    clock_gettime(CLOCK_MONOTONIC, &s_ts);
    current_time=((double)s_ts.tv_sec * 1000) + ((double)s_ts.tv_nsec/1000000);
    return current_time;
#endif

}


void logElapsedTime (const char *format, ...)
{
    char szExePath[512] = { 0 };
    char szfileName[] = "elapsedTime.log";
    va_list args;

#ifdef _WIN32

    GetModuleFileName (NULL, szExePath, 512);
#else
    if (readlink ("/proc/self/exe", szExePath, 512) == -1)
        return;
#endif

    memcpy (szExePath, szfileName, sizeof(szfileName));

    FILE *pLog = fopen (szExePath, "a");
    if (pLog)
    {
        // Write the message to the log file
        va_start (args, format);
        vfprintf (pLog, format, args);
        va_end (args);
        fprintf (pLog, "\n");

        // Close the file
        fclose (pLog);
    }
}


void logDump (LOGGING_LEVEL p_nLevel, unsigned char *p_pbData, unsigned long p_ulDataSize)
{
    if ((p_nLevel <= G_nLoggingLevel) && (p_pbData != 0))
        HexDump (p_pbData, p_ulDataSize);
}


CK_RV toHexString (unsigned char* p_pbData, unsigned long p_ulDataSize, char* p_pszOutBuffer, unsigned long* p_pulOutBufferLen)
{
    unsigned long   l_ulChars = 0;
    unsigned char   l_bDumpedByte;

    // Check the size of the out buffer
    if (*p_pulOutBufferLen < (2 * p_ulDataSize))
        return CKR_BUFFER_TOO_SMALL;

    for (; p_ulDataSize; p_ulDataSize--, l_ulChars++)
    {
        l_bDumpedByte = p_pbData [l_ulChars];
        CharToHexa2 ((unsigned char*)(p_pszOutBuffer + (l_ulChars * 2)), l_bDumpedByte);
    }

    *p_pulOutBufferLen = l_ulChars * 2;

    return CKR_OK;
}


static const char g_szBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

CK_RV base64Encode ( unsigned char* p_pbData, unsigned long p_ulDataLen,
                     unsigned char* p_pbBase64Data, unsigned long* p_pulBase64DataLen
                   )
{
    CK_RV           l_ulErc = CKR_OK;
    unsigned char*  l_pbBase64Data = NULL;
    unsigned long   l_ulBase64DataLen = 0;
    unsigned long   l_ulI = 0;

    // Allocate the working buffer
    l_pbBase64Data = (unsigned char*)malloc (2 * p_ulDataLen);
    if (l_pbBase64Data == NULL_PTR)
        return CKR_HOST_MEMORY;

    // Encode the buffer
    for (l_ulI = 0; l_ulI < (p_ulDataLen - p_ulDataLen % 3); l_ulI += 3)
    {
        if ((l_ulI % 48 == 0) && (l_ulBase64DataLen != 0))
            l_pbBase64Data[l_ulBase64DataLen++] = '\n';
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & (p_pbData[l_ulI] >> 2)];
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & ((p_pbData[l_ulI] << 4) + (p_pbData[l_ulI + 1] >> 4))];
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & ((p_pbData[l_ulI + 1] << 2) + (p_pbData[l_ulI + 2] >> 6))];
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & (p_pbData[l_ulI + 2])];
    }

    // Deal with the end conditions
    if ((p_ulDataLen % 3) == 1)
    {
        if (l_ulI % 48 == 0)
            l_pbBase64Data[l_ulBase64DataLen++] = '\n';
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & (p_pbData[l_ulI] >> 2)];
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & (p_pbData[l_ulI] << 4)];
        l_pbBase64Data[l_ulBase64DataLen++] = '=';
        l_pbBase64Data[l_ulBase64DataLen++] = '=';
    }
    else if ((p_ulDataLen % 3) == 2)
    {
        if (l_ulI % 48 == 0)
            l_pbBase64Data[l_ulBase64DataLen++] = '\n';
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & (p_pbData[l_ulI] >> 2)];
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[(0x3F & (p_pbData[l_ulI] << 4)) + (p_pbData[l_ulI + 1] >> 4)];
        l_pbBase64Data[l_ulBase64DataLen++] = g_szBase64[0x3F & (p_pbData[l_ulI + 1] << 2)];
        l_pbBase64Data[l_ulBase64DataLen++] = '=';
    }
    l_pbBase64Data[l_ulBase64DataLen++] = '\n';

    // Return the data
    if (l_ulBase64DataLen > *p_pulBase64DataLen)
    {
        l_ulErc =  CKR_BUFFER_TOO_SMALL;
    }
    else
    {
        memcpy (p_pbBase64Data, l_pbBase64Data, l_ulBase64DataLen);
        *p_pulBase64DataLen = l_ulBase64DataLen;
    }

    free (l_pbBase64Data);
    return l_ulErc;
}


CK_RV base64Decode ( unsigned char* p_pbBase64Data, unsigned long p_ulBase64DataLen,
                     unsigned char* p_pbData, unsigned long* p_pulDataLen
                  )
{
    CK_RV           l_ulErc = CKR_OK;

    return l_ulErc;
}


void tolowercase(unsigned char* p_pbuffer)
{
	int counter=0;

	while (p_pbuffer[counter])
	{
           p_pbuffer[counter]=tolower(p_pbuffer[counter]);
            counter++;
	}
}

int bytesToHexstr(unsigned char *bytes, unsigned int bytesLen, unsigned char *hexstr, unsigned int *hexstrLen)
{
    if (!bytes | !hexstr | !hexstrLen)
    {
        return 0;
    }

    if (*hexstrLen < bytesLen * 2)
    {
        return 0;
    }

    const unsigned char* hex = (const unsigned char*) "0123456789ABCDEF";

    for (unsigned int i = 0; i < bytesLen; i++)
    {
        *hexstr++ = hex[(bytes[i] >> 4) & 0xF];
        *hexstr++ = hex[bytes[i] & 0xF];
    }

    *hexstrLen = bytesLen * 2;

    return 1;
}

int hexstrToBytes(unsigned char *hexstr, unsigned int hexstrLen, unsigned char *bytes, unsigned int *bytesLen)
{
    if (!hexstr | !bytes | !bytesLen)
    {
        return 0;
    }

    if (hexstrLen | 1 != 0)
    {
        return 0;
    }

    if (hexstrLen < *bytesLen * 2)
    {
        return 0;
    }

    for (unsigned int i = 0; i < hexstrLen;)
    {
        unsigned char d = 0;

        // Handle the first nibble.
        if ((hexstr[i] >= '0') && (hexstr[i] <= '9'))
        {
            d |= hexstr[i] - '0';
        }
        else if ((hexstr[i] >= 'a') && (hexstr[i] <= 'f'))
        {
            d |= hexstr[i] - 'a' + 10;
        }
        else if ((hexstr[i] >= 'A') && (hexstr[i] <= 'F'))
        {
            d |= hexstr[i] - 'A' + 10;
        }

        // Handle the second nibble.
        d <<= 4;
        i++;
        if ((hexstr[i] >= '0') && (hexstr[i] <= '9'))
        {
            d |= hexstr[i] - '0';
        }
        else if ((hexstr[i] >= 'a') && (hexstr[i] <= 'f'))
        {
            d |= hexstr[i] - 'a' + 10;
        }
        else if ((hexstr[i] >= 'A') && (hexstr[i] <= 'F'))
        {
            d |= hexstr[i] - 'A' + 10;
        }

        *bytes++ = d;
        i++;
    }

    *bytesLen = hexstrLen >> 1;

    return 1;
}
