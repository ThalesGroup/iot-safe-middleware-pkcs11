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

#if !defined(CACHE_INCLUDED_)
#define CACHE_INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#include <windows.h>
#else
#include "wintypes.h"
#endif

#ifdef _WIN32
#define _DATA_SEG_NAME "data_cachecm_gem_ex"
#else
#define _DATA_SEG_NAME "/gemalto_idprime_sdata_ex"
#endif
//
// Static definitions
//
#define MAX_CACHE             (256)
#define CACHE_ENTRY_LEN       (128)
#define INVALID_CACHE_INDEX   (-1)

void InitCache      (void);
void FinalizeCache	(void);
int  GetCacheIndex  (
#ifdef _WIN32
                     LPCWSTR       wszReaderName, 
#else
                     LPCSTR       wszReaderName, 
#endif
                     LPCSTR       pbOID
                    );	    
BOOL IsSameCacheData(int           iCacheIdx, 
                     LPCBYTE       pData, 
                     DWORD         dwDataLen
                    );
BOOL GetCacheData   (
#ifdef _WIN32
                     LPCWSTR       wszReaderName, 
#else
                     LPCSTR       wszReaderName, 
#endif
					 LPCSTR       pbOID, 
                     LPBYTE        pData, 
                     LPDWORD       pdwDataLen
                    );
BOOL SetCacheData   (
#ifdef _WIN32
                     LPCWSTR       wszReaderName, 
#else
                     LPCSTR       wszReaderName, 
#endif
                     LPCSTR       pbOID, 
                     LPCBYTE       pData, 
                     DWORD         dwDataLen
                    );
BOOL ClearCacheData (
#ifdef _WIN32
                     LPCWSTR       wszReaderName, 
#else
                     LPCSTR       wszReaderName, 
#endif
                     LPCSTR       pbOID
                    );

#ifdef _WIN32
void LoadCacheData (

					LPCWSTR       wszReaderName,
					LPCSTR        CSN,
					LPCBYTE        CARDCF,
					DWORD          dwCARDCFLen
				   );
BOOL IsPersistentCache();    
#endif 

#endif
