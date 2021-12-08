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
#ifdef WIN32
#include <windows.h>
#include <sddl.h>
#include "Aclapi.h" // SE_KERNEL_OBJECT
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#else
#include <wintypes.h>
#endif

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

#endif

#include "DataShare.h"

// ------------------------------------------------------
// Normalize data name ??
// ------------------------------------------------------
LPSTR  DS_Normalize(LPCSTR szDataName)
{
	static char g_szNormalizedName[1024];
#ifdef _WIN32	
    strcpy(g_szNormalizedName, szDataName);
#else    	
    char* ptr;
	 // add '/' at the begining
    if (szDataName[0] == '/')
        strcpy(g_szNormalizedName, szDataName);
    else
	{
        strcpy(g_szNormalizedName, "/");
        strcat(g_szNormalizedName, szDataName);        
    }
    
#ifdef __APPLE__
    /* On Mac OS X, the maximum length of a shared memory segment
     * name is SHM_NAME_MAX (instead of NAME_MAX or PATH_MAX as
     * defined by the standard).  Unfortunately, Apple sets this
     * value so small (30 characters) that it is useless for
     * actual names.
     */
    if (strlen(g_szNormalizedName) > 30)
    {
        unsigned char digest[16];
        MD5_CTX ctx;
        BIGNUM *n = BN_new();
        
        MD5_Init(&ctx);
        MD5_Update(&ctx, g_szNormalizedName, strlen(g_szNormalizedName));
        MD5_Final(digest, &ctx);
        
        BN_bin2bn(digest, 16, n);
        char* hexVal = BN_bn2hex(n);
        
        strcpy(g_szNormalizedName, "/");
        
        if (strlen(hexVal) <= 29)
        {
            strcat(g_szNormalizedName, hexVal);
        }
        else
        {
            // take the last 29 characters
            strcat(g_szNormalizedName, &hexVal[strlen(hexVal) - 29]);
        }
        
        OPENSSL_free(hexVal);
        BN_free(n);
    }
    
#endif
	 
	 // remove any space character
	 ptr = &g_szNormalizedName[0];
	 char c;
	 while ((c = *ptr))
	 {
		 if (c == ' ') *ptr = '_';
		 ptr++;
	 }
	 	 
#endif
	 return g_szNormalizedName;
}

// ------------------------------------------------------
// Create or Open shared data
// ------------------------------------------------------

SHM_HANDLE DS_Initialize(LPCTSTR szDataName, BYTE bType, DWORD dwMaxLen)
{
	DWORD dwLen = dwMaxLen;
	// Data Len
	switch (bType)
	{
		case BYTE_TYPE:
		    dwLen = sizeof(BYTE);
		    break;

		case BOOL_TYPE:
		    dwLen = sizeof(BOOL);
		    break;

		case DWORD_TYPE:
		    dwLen = sizeof(DWORD);
		    break;

		case LONG_TYPE:
		    dwLen = sizeof(LONG);
		    break;

		case BYTE_ARRAY_TYPE:
		    dwLen = dwMaxLen + 4;
		    break;

		default:
		    dwLen = dwMaxLen;
	}	

#ifdef _WIN32
    HANDLE hFM = NULL;
	LPSTR szFileMappingName = DS_Normalize(szDataName);
    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, szFileMappingName);

    // Create File Mapping if not exists
    if (hFM == NULL)
    {		
        SECURITY_ATTRIBUTES lpAttr;
        SECURITY_DESCRIPTOR lpDesc;
		PSECURITY_DESCRIPTOR pLowIntegritySecDesc = NULL;
		PACL pSacl = NULL;

		// the following are needed for absolute SD conversion
		SECURITY_DESCRIPTOR SDAbsolute = {0};
		DWORD dwAbsoluteSDSize = sizeof(SECURITY_DESCRIPTOR);
		PACL pDACL = NULL;
		DWORD dwDACLSize = 0;
		PACL pAbsSACL = NULL;
		DWORD dwSACLSize = 0;
		PSID pOwnerSID = NULL;
		DWORD dwOwnerSIDSize = 0;
		PSID pGroupSID = NULL;
		DWORD dwGroupSIDSize = 0;

        // File Mapping Security
        InitializeSecurityDescriptor(&lpDesc, SECURITY_DESCRIPTOR_REVISION);

		// Add SACL to make the shared memory accessible from low integrity processes
		if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
			 "S:(ML;;NW;;;LW)", // this means "low integrity"
			 SDDL_REVISION_1,
			 &pLowIntegritySecDesc,
			 NULL)
		   )
		{
			// Convert Relative SD to Absolute SD
			if (!MakeAbsoluteSD(pLowIntegritySecDesc, &SDAbsolute, &dwAbsoluteSDSize, 
							pDACL, &dwDACLSize, pAbsSACL, &dwSACLSize, 
							pOwnerSID, &dwOwnerSIDSize, pGroupSID, &dwGroupSIDSize))
			{
				pDACL = (PACL) LocalAlloc(0, dwDACLSize);
				pAbsSACL = (PACL) LocalAlloc(0, dwSACLSize);
				pOwnerSID = (PSID) LocalAlloc(0, dwOwnerSIDSize);
				pGroupSID = (PSID) LocalAlloc(0, dwGroupSIDSize);

				if (MakeAbsoluteSD(pLowIntegritySecDesc, &SDAbsolute, &dwAbsoluteSDSize, 
								pDACL, &dwDACLSize, pAbsSACL, &dwSACLSize, 
								pOwnerSID, &dwOwnerSIDSize, pGroupSID, &dwGroupSIDSize))
				{
					BOOL bSaclPresent = FALSE;
					BOOL bSaclDefaulted = FALSE;
					if (  GetSecurityDescriptorSacl(
							  &SDAbsolute,
							  &bSaclPresent,
							  &pSacl,
							  &bSaclDefaulted) 
						&& bSaclPresent
					   )
					{
						SetSecurityDescriptorSacl(&lpDesc, TRUE, pSacl, FALSE);
					}
				}
			}
		}

		SetSecurityDescriptorDacl(&lpDesc, TRUE, NULL, FALSE);

        lpAttr.nLength              = sizeof(lpAttr);
        lpAttr.lpSecurityDescriptor = &lpDesc;
        lpAttr.bInheritHandle       = FALSE;

        // Create File Mappings
        hFM = CreateFileMappingA(INVALID_HANDLE_VALUE,
                                &lpAttr,
                                PAGE_READWRITE,
                                0,
                                dwLen,
                                szFileMappingName
                               );
		if (hFM)
		{
			// Grant anyone access
			SetNamedSecurityInfoA(szFileMappingName, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, (PACL) NULL, NULL);
		}

		if (pLowIntegritySecDesc) LocalFree(pLowIntegritySecDesc);
		if (pDACL) LocalFree(pDACL);
		if (pAbsSACL) LocalFree(pAbsSACL);
		if (pOwnerSID) LocalFree(pOwnerSID);
		if (pGroupSID) LocalFree(pGroupSID);
    }

	return hFM;
#else
	char* pFileName = DS_Normalize(szDataName);
	DWORD dwPageSize = sysconf(_SC_PAGESIZE);
	int shmid, flag = O_RDWR, mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
	if(dwPageSize == (DWORD) -1)
		dwPageSize = 4096; /* default value */

	shmid = shm_open(pFileName,flag,mode);
	if(shmid == -1)
	{
		/* doesn't exist */
		
		/* store old process umask */
		mode_t old_umask = umask(0);
		
		shmid = shm_open(pFileName,flag | O_CREAT,mode);
		if(shmid != -1)
		{			
			/* set the size */
			DWORD maxSize = dwLen;
			if(maxSize % dwPageSize)
			  maxSize += dwPageSize - (maxSize % dwPageSize);

			ftruncate(shmid,maxSize);
		}

		/* restore old process umask */
		umask(old_umask);
	}
	return shmid;
#endif
}


void* DS_OpenMemoryMapping(SHM_HANDLE hShm, int length)
{
#ifdef _WIN32
	if (hShm)
		return MapViewOfFile(hShm, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	else
		return NULL;
#else
	if (hShm != -1)
	{
		return mmap(NULL, length,PROT_READ | PROT_WRITE, MAP_SHARED, hShm,0);
	}
	else
		return NULL;
#endif
}

void DS_FlushMemoryMapping(void* ptr, int length)
{
#ifdef _WIN32
	FlushViewOfFile(ptr, length);
#else
	msync(ptr,length,MS_SYNC|MS_INVALIDATE);
#endif
}

void DS_CloseMemoryMapping(void* ptr, int length)
{
#ifdef _WIN32
	UnmapViewOfFile(ptr);
#else
	munmap(ptr, length);
#endif
}

// ------------------------------------------------------
// Finalize (release) shared data
// ------------------------------------------------------

void  DS_Finalize(LPCTSTR szDataName, SHM_HANDLE hShm)
{
#ifdef _WIN32
   if (hShm)
	   CloseHandle(hShm);
#else
   if (hShm != -1)
   {
      char* pFileName = DS_Normalize(szDataName);
      shm_unlink(pFileName);
	   close(hShm);
   }
#endif
}

#ifndef _WIN32
void SHM_ValueOperation(LPCSTR szDataName, LPBYTE pbValue, DWORD& dwValueLen, bool bRead, bool bIsByteArray)
{
	char* pFileName = (char*) DS_Normalize(szDataName);
	int shmid, flag = O_RDWR, prot = PROT_READ | PROT_WRITE, mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

	shmid = shm_open(pFileName,flag,mode);
	if(shmid != -1)	
	{			
	   size_t mmapLen = dwValueLen;
	   if (bIsByteArray)
	   {
		   mmapLen += sizeof(DWORD);
		}

		void* retVal = mmap(NULL, mmapLen,prot, MAP_SHARED, shmid,0);
		if(MAP_FAILED != retVal)
		{
    		LPBYTE ptr = (LPBYTE) retVal;
    		
    		if (bRead)
    		{
    			if (bIsByteArray)
    			{
    				memcpy(&dwValueLen, ptr, sizeof(DWORD));
    				if (pbValue)
    					memcpy(pbValue, ptr + sizeof(DWORD), dwValueLen);
    			}
    			else
    			{    		
    				memcpy(pbValue, ptr, dwValueLen);
    			}
    		}
    		else
    		{
    			if (bIsByteArray)
    			{
			 		memcpy(ptr, &dwValueLen, sizeof(DWORD));	    			
			 		memcpy(ptr + sizeof(DWORD), pbValue, dwValueLen);		 		
			 		msync(ptr,dwValueLen + sizeof(DWORD),MS_SYNC|MS_INVALIDATE);    				
    			}
    			else
    			{
			 		memcpy(ptr, pbValue, dwValueLen);		 		
			 		msync(ptr,dwValueLen,MS_SYNC|MS_INVALIDATE);
			 	}
			}
    		munmap(ptr,mmapLen);			
		}
		
		close(shmid);
	}

}

#define SHM_GetValue(szDataNam, pbValue, dwValueLen) SHM_ValueOperation(szDataNam, pbValue, dwValueLen, true, false)
#define SHM_SetValue(szDataNam, pbValue, dwValueLen) SHM_ValueOperation(szDataNam, pbValue, dwValueLen, false, false)

#define SHM_GetByteArray(szDataNam, pbValue, dwValueLen) SHM_ValueOperation(szDataNam, pbValue, dwValueLen, true, true)
#define SHM_SetByteArray(szDataNam, pbValue, dwValueLen) SHM_ValueOperation(szDataNam, pbValue, dwValueLen, false, true)

#endif

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_SetByte(LPCSTR szDataName, BYTE bValue)
{
	 
#ifdef _WIN32
    HANDLE hFM = NULL;    
	 LPBYTE ptr = NULL;
	
    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(ptr, &bValue, sizeof(BYTE));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(BYTE);
	 SHM_SetValue(szDataName, &bValue, dwLen);
#endif    
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_GetByte(LPCSTR szDataName, BYTE* pbValue)
{
    
#ifdef _WIN32    
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(pbValue, ptr, sizeof(BYTE));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
    DWORD dwLen = (DWORD) sizeof(BYTE);
	 SHM_GetValue(szDataName, pbValue, dwLen);
#endif    

}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_SetBool(LPCSTR szDataName, BOOL isValue)
{
#ifdef _WIN32
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(ptr, &isValue, sizeof(BOOL));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(BOOL);
	 SHM_SetValue(szDataName, (LPBYTE) &isValue, dwLen);
#endif
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_GetBool(LPCSTR szDataName, BOOL* pisValue)
{
#ifdef _WIN32    
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(pisValue, ptr, sizeof(BOOL));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(BOOL);
	 SHM_GetValue(szDataName, (LPBYTE) pisValue, dwLen);
#endif
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_SetDword(LPCSTR szDataName, DWORD dwValue)
{
#ifdef _WIN32
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(ptr, &dwValue, sizeof(DWORD));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(DWORD);
	 SHM_SetValue(szDataName, (LPBYTE) &dwValue, dwLen);
#endif    
}

// ------------------------------------------------------
// ------------------------------------------------------
void DS_GetDword(LPCSTR szDataName, DWORD* pdwValue)
{
#ifdef _WIN32    
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(pdwValue, ptr, sizeof(DWORD));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(DWORD);
	 SHM_GetValue(szDataName, (LPBYTE) pdwValue, dwLen);
#endif
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_SetLong(LPCSTR szDataName, LONG lValue)
{
#ifdef _WIN32
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(ptr, &lValue, sizeof(LONG));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(LONG);
	 SHM_SetValue(szDataName, (LPBYTE) &lValue, dwLen);
#endif    
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_GetLong(LPCSTR szDataName, LONG* plValue)
{
#ifdef _WIN32    
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(plValue, ptr, sizeof(LONG));

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 DWORD dwLen = (DWORD) sizeof(LONG);
    SHM_GetValue(szDataName, (LPBYTE) plValue, dwLen);
#endif
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_SetByteArray(LPCSTR szDataName, BYTE* pValue, DWORD dwLen)
{
#ifdef _WIN32
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(ptr, &dwLen, sizeof(DWORD));
    memcpy(ptr + sizeof(DWORD), pValue, dwLen);

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else	 
	 SHM_SetByteArray(szDataName, pValue, dwLen);
#endif    
}

// ------------------------------------------------------
// ------------------------------------------------------
void  DS_GetByteArray(LPCSTR szDataName, BYTE* pValue, DWORD* pdwLen)
{
#ifdef _WIN32
    DWORD dwLen = 0;
    HANDLE hFM = NULL;
    LPBYTE ptr = NULL;

    // Try to open existing File Mapping
    hFM = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, DS_Normalize(szDataName));

    if (hFM == NULL)
    {
        return;
    }

    ptr = (LPBYTE) MapViewOfFile(hFM, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    memcpy(&dwLen, ptr, sizeof(DWORD));

    *pdwLen = dwLen;

    if (pValue != NULL)
    {
        memcpy(pValue, ptr + sizeof(DWORD), dwLen);
    }

    UnmapViewOfFile((LPVOID)ptr);

    CloseHandle(hFM);
#else
	 SHM_GetByteArray(szDataName, pValue, *pdwLen);	 
#endif    
}
