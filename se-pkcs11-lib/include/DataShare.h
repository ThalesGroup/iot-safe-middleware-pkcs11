/*
*  PKCS#11 library for IoT Safe
*  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
*  Copyright (C) 2009-2021 Thales
*
*  This library is free software; you can redistribute it and/or
*  modify it under the terms of the GNU Lesser General Public
*  License as published by the Free Software Foundation; either
*  version 2.1 of the License, or (at your option) any later version.
*
*  This library is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*  Lesser General Public License for more details.
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
*/
#ifndef _include_DataShare_h
#define _include_DataShare_h

#ifndef WIN32
#include "wintypes.h"
#endif

#define BYTE_TYPE       (0x01)
#define BOOL_TYPE       (0x02)
#define DWORD_TYPE      (0x03)
#define LONG_TYPE       (0x04)
#define BYTE_ARRAY_TYPE (0x05)


#ifdef _WIN32
#define SHM_HANDLE           HANDLE
#define SHM_INVALID_HANDLE   NULL
#else
#define SHM_HANDLE           int
#define SHM_INVALID_HANDLE   -1
#endif

#ifdef __cplusplus
extern "C" 
{
#endif

#define DS_IsValid(hShm)	(hShm != SHM_INVALID_HANDLE)

#define DS_Invalidate(hShm)	(hShm = SHM_INVALID_HANDLE)


SHM_HANDLE DS_Initialize(LPCTSTR szDataName, BYTE bType, DWORD dwMaxLen);


void* DS_OpenMemoryMapping(SHM_HANDLE hFM, int length);


void DS_FlushMemoryMapping(void* ptr, int length);

void DS_CloseMemoryMapping(void* ptr, int length);


void  DS_Finalize(LPCTSTR szDataName, SHM_HANDLE hFM);

void  DS_SetByte(LPCTSTR szDataName, BYTE bValue);
void  DS_GetByte(LPCSTR szDataName, BYTE* pbValue);

void  DS_SetBool(LPCTSTR szDataName, BOOL isValue);
void  DS_GetBool(LPCSTR szDataName, BOOL* pisValue);

void  DS_SetDword(LPCTSTR szDataName, DWORD dwValue);
void DS_GetDword(LPCSTR szDataName, DWORD* pdwValue);

void  DS_SetLong(LPCTSTR szDataName, LONG lValue);
void  DS_GetLong(LPCSTR szDataName, LONG* plValue);

void  DS_SetByteArray(LPCTSTR szDataName, BYTE* pValue, DWORD dwLen);
void  DS_GetByteArray(LPCTSTR szDataName, BYTE* pValue, DWORD* pdwLen);

#ifdef __cplusplus
}
#endif


#endif