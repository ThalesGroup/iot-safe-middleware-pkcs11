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
// Cache.cpp: interface for the Cache system.
#ifdef _WIN32
#pragma warning(disable:4201)
#pragma warning(disable:4995)
#else
#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
#endif

#include <string>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <io.h>      
#include <fcntl.h>      
#endif

#include "Cache.h"
#include "DataShare.h"
#include <openssl/md5.h>

#ifdef _WIN32
#include <strsafe.h>
#else
#define strcpy_s(strDestination,numberOfElements,strSource)	strcpy(strDestination,strSource)
#endif

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

//////////////////////////////////////////////////////////////////////
// Cache system
//////////////////////////////////////////////////////////////////////
#define DATA_SIGN_LEN         (16)

#pragma pack(push, smartcard, 1)

typedef struct _DATA_CACHE_
{
   char   DataOID[CACHE_ENTRY_LEN];
   BYTE  *pData;
   DWORD  dwDataLen;
#ifdef _WIN32
   WCHAR wszReaderName[256];
#else
   char  wszReaderName[256];
#endif
   BYTE   DataSignature[DATA_SIGN_LEN];
} DATA_CACHE;

/* specific structure for shared memory to avoid 64-bit/32-bit compativbility issue */
typedef struct _DATA_CACHE_SHM_
{
   char   DataOID[CACHE_ENTRY_LEN];
#ifdef _WIN32
	WCHAR wszReaderName[256];
#else
   char  wszReaderName[256];
#endif
   BYTE   DataSignature[DATA_SIGN_LEN];
} DATA_CACHE_SHM;

#ifdef _WIN32
DATA_CACHE  m_DataCache[MAX_CACHE] = {"", NULL, 0, L"", {0}};
#else
DATA_CACHE  m_DataCache[MAX_CACHE] = {"", NULL, 0, "", {0}};
#endif

#pragma pack(pop, smartcard)

static DATA_CACHE_SHM*  g_DataCache = NULL; // [MAX_CACHE] = {0};
static int	g_iFMSize = MAX_CACHE * sizeof(DATA_CACHE_SHM);


static SHM_HANDLE g_hFM = SHM_INVALID_HANDLE;

#ifdef _WIN32
char szCACHE_DIR[512] = "";

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
static int get_file_len(char *pFileName)
{
	int    fp;
	DWORD  nLen;
   
	fp = _open(pFileName, O_RDONLY);

	if (fp < 0)
	{
		return(0);
	}
	
	nLen = _filelength(fp);
	
	_close(fp);
   
	return(nLen);
}

#endif

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
void InitCache (void)
{
#ifndef _NO_CACHE	
     g_hFM = DS_Initialize(_DATA_SEG_NAME, 0, g_iFMSize);
	if (DS_IsValid(g_hFM))
	{
		g_DataCache = (DATA_CACHE_SHM*) DS_OpenMemoryMapping(g_hFM, g_iFMSize); 
	}

#ifdef _WIN32
	// Get Permanent Cache directory. No permanent cache is not set.
	{
		HKEY        hRegKey = NULL;
		DWORD       dwType;
		DWORD       dwLen;

		memset(szCACHE_DIR, 0x00, sizeof(szCACHE_DIR));

		// Open Minidriver Key
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
						"SOFTWARE\\Gemalto\\Cryptography\\MiniDriver", 
						0,
						KEY_READ, 
						&hRegKey
					);

		if (hRegKey != NULL)
		{
			 dwLen = sizeof(szCACHE_DIR);
			 dwType = REG_SZ;

			 RegQueryValueExA(hRegKey, 
							  "CacheDir", 
							  NULL, 
							  &dwType,
							  (BYTE *)szCACHE_DIR, 
							  &dwLen
							 );
		}

		if (hRegKey != NULL)
		{
			 RegCloseKey(hRegKey);
		}
	}
#endif
#endif
}

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
void FinalizeCache(void)
{
#ifndef _NO_CACHE
	if (g_DataCache)
	{
		DS_CloseMemoryMapping((void*) g_DataCache, g_iFMSize);
		g_DataCache = NULL;
	}

	if (DS_IsValid(g_hFM))
	{
		DS_Finalize(_DATA_SEG_NAME, g_hFM);
		DS_Invalidate(g_hFM);
	}
#endif
}

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
#ifdef _WIN32
void GetCacheConfig (void)
{
#ifndef _NO_CACHE	
	// Get Permanent Cache directory. No permanent cache is not set.
	{
		HKEY        hRegKey = NULL;
		DWORD       dwType;
		DWORD       dwLen;

		memset(szCACHE_DIR, 0x00, sizeof(szCACHE_DIR));

		// Open Minidriver Key
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
						"SOFTWARE\\Gemalto\\Cryptography\\MiniDriver", 
						0,
						KEY_READ, 
						&hRegKey
					);

		if (hRegKey != NULL)
		{
			 dwLen = sizeof(szCACHE_DIR);
			 dwType = REG_SZ;

			 RegQueryValueExA(hRegKey, 
							  "CacheDir", 
							  NULL, 
							  &dwType,
							  (BYTE *)szCACHE_DIR, 
							  &dwLen
							 );
		}

		if (hRegKey != NULL)
		{
			 RegCloseKey(hRegKey);
		}
	}
#endif
}
#endif

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
int GetCacheIndex(
#ifdef _WIN32
			LPCWSTR       wszReaderName, 
#else
			LPCSTR       wszReaderName, 
#endif
			LPCSTR pbOID)
{
   BOOL IsFoundLocal = FALSE;
   BOOL IsFoundShared = FALSE;
  // int  i;
  // int  j;
   size_t i,j;
#ifdef _NO_CACHE
   return(INVALID_CACHE_INDEX);
#endif 

   if (!g_DataCache)
	   return INVALID_CACHE_INDEX;

   // Search Empty Cache Entry
   if (strcmp(pbOID, "") == 0)
   {
      for (i = 0; i < MAX_CACHE; i++)
      {
         if (strcmp(pbOID, (const char *)m_DataCache[i].DataOID) == 0)
         {
            return((int)i);
         }
      }
   
      return (INVALID_CACHE_INDEX);
   }
   
   // Search in Local Cache
   for (i = 0; i < MAX_CACHE; i++)
   {
      if (  (strcmp(pbOID, (const char *)m_DataCache[i].DataOID) == 0)
#ifdef _WIN32
          &&(wcscmp(wszReaderName, m_DataCache[i].wszReaderName) == 0)
#else
          &&(strcmp((LPSTR)wszReaderName, (LPSTR)m_DataCache[i].wszReaderName) == 0)
#endif
         )
      {
         IsFoundLocal = TRUE;
         break;
      }
   }

   // Search in Shared Cache
   for (j = 0; j < MAX_CACHE; j++)
   {
      if (  (strcmp(pbOID, (const char *)g_DataCache[j].DataOID) == 0)
#ifdef _WIN32
          &&(wcscmp(wszReaderName, g_DataCache[j].wszReaderName) == 0)
#else
          &&(strcmp((LPSTR)wszReaderName, (LPSTR)g_DataCache[j].wszReaderName) == 0)
#endif
         )
      {
         IsFoundShared = TRUE;
         break;
      }
   }

   // Local Signature = Shared Signature -> Cached Data is valid
   if (  (IsFoundLocal)
       &&(IsFoundShared)
       &&(memcmp(m_DataCache[i].DataSignature, g_DataCache[j].DataSignature, DATA_SIGN_LEN) == 0)
      )
   {
      return((int)i);
   }
   
   // Flush Local Cache if found but not synchronized
   if (IsFoundLocal)
   {
      if (m_DataCache[i].pData)
      {
         free(m_DataCache[i].pData);  
         m_DataCache[i].pData = NULL;
      }
   
      memset(&m_DataCache[i], 0x00, sizeof(m_DataCache[i]));
   }
   
   return (INVALID_CACHE_INDEX);
}


//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
BOOL IsSameCacheData(int iCacheIdx, LPCBYTE pData, DWORD dwDataLen)
{
   // -----------------------------------------------------------------------------------------
   // No control on Cache synchronization, assumes that GetCacheIndex() has been called first !
   // -----------------------------------------------------------------------------------------
#ifdef _NO_CACHE
   return(FALSE);
#endif 

   if (  (dwDataLen == m_DataCache[(iCacheIdx)].dwDataLen)
         &&(memcmp(pData, m_DataCache[(iCacheIdx)].pData, (dwDataLen)) == 0)
      )
   {
      return(TRUE);
   }         

   return (FALSE);
}


//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
BOOL GetCacheData(
#ifdef _WIN32
   LPCWSTR wszReaderName, 
#else
   LPCSTR wszReaderName, 
#endif
   LPCSTR pbOID, LPBYTE pData, LPDWORD pdwDataLen)
{
   //int  i;
   size_t i;
   // -----------------------------------------------------------------------------------------
   // No control on Cache synchronization, assumes that GetCacheIndex() has been called first !
   // -----------------------------------------------------------------------------------------
#ifdef _NO_CACHE
   return(FALSE);
#endif 
   
   // Search in Local Cache
   for (i = 0; i < MAX_CACHE; i++)
   {
      if (  (strcmp(pbOID, (const char *)m_DataCache[i].DataOID) == 0)
#ifdef _WIN32
         &&(wcscmp(wszReaderName, m_DataCache[i].wszReaderName) == 0)
#else
          &&(strcmp((LPSTR)wszReaderName, (LPSTR)m_DataCache[i].wszReaderName) == 0)
#endif
         )
      {
         
         if (  (pData)
             &&(*pdwDataLen >= m_DataCache[i].dwDataLen)
            )
         {
            memcpy(pData, m_DataCache[i].pData, (m_DataCache[i].dwDataLen));
         }
                    
         *pdwDataLen = m_DataCache[i].dwDataLen;

         return(TRUE);
      }
   }

   return(FALSE);
}


//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
BOOL SetCacheData(
#ifdef _WIN32
     LPCWSTR       wszReaderName, 
#else
     LPCSTR       wszReaderName, 
#endif
     LPCSTR pbOID,
     LPCBYTE pData, DWORD dwDataLen, BOOL isPermanent
)
{
   UNREFERENCED_PARAMETER (isPermanent); 

   BOOL IsFoundLocal = FALSE;
   BOOL IsFoundShared = FALSE;
   //int  i;
   //int  j;
   size_t i,j;
   BYTE DataSignature[DATA_SIGN_LEN];
   MD5_CTX  md5;

#ifdef _NO_CACHE
   return(FALSE);
#endif 
      
   if (!g_DataCache)
	   return FALSE;
      
   // Search in Local Cache
   for (i = 0; i < MAX_CACHE; i++)
   {
      if (  (strcmp(pbOID, (const char *)m_DataCache[i].DataOID) == 0)
#ifdef _WIN32
         &&(wcscmp(wszReaderName, m_DataCache[i].wszReaderName) == 0)
#else
          &&(strcmp((LPSTR)wszReaderName, (LPSTR)m_DataCache[i].wszReaderName) == 0)
#endif
         )
      {
         IsFoundLocal = TRUE;
         break;
      }
   }

   // Search Empty Local Cache Entry if not found
   if (!IsFoundLocal)
   {
      for (i = 0; i < MAX_CACHE; i++)
      {
         if (strcmp("", (const char *)m_DataCache[i].DataOID) == 0)
         {
            IsFoundLocal = TRUE;
            break;
         }
      }
   }

   // Search in Shared Cache
   for (j = 0; j < MAX_CACHE; j++)
   {
      if (  (strcmp(pbOID, (const char *)g_DataCache[j].DataOID) == 0)
#ifdef _WIN32
         &&(wcscmp(wszReaderName, g_DataCache[j].wszReaderName) == 0)
#else
          &&(strcmp((LPSTR)wszReaderName, (LPSTR)g_DataCache[j].wszReaderName) == 0)
#endif
         )
      {
         IsFoundShared = TRUE;
         break;
      }
   }

   // Search Empty Local Cache Entry if not found
   if (!IsFoundShared)
   {
      for (j = 0; j < MAX_CACHE; j++)
      {
         if (strcmp("", (const char *)g_DataCache[j].DataOID) == 0)
         {
            IsFoundShared = TRUE;
            break;
         }
      }
   }
   
   // No free entry in cache -> Error !
   if (  (!IsFoundLocal)
       ||(!IsFoundShared)
      )
   {
      return (FALSE);
   }
   
   // Compute Data Signature (MD5 of Data)
   memset(DataSignature, 0x00, DATA_SIGN_LEN);
   
   if (dwDataLen > 0)
   {
      MD5_Init(&md5);
      MD5_Update(&md5, pData, dwDataLen);
      MD5_Final(DataSignature, &md5);
   }
      
   // Update Local Cache
   strcpy_s(m_DataCache[i].DataOID, sizeof(m_DataCache[i].DataOID), pbOID);   
   if (m_DataCache[i].pData)
   {
      free(m_DataCache[i].pData);  
      m_DataCache[i].pData = NULL;
   }
   if (dwDataLen > 0)
   {
      m_DataCache[i].pData = (LPBYTE)malloc((dwDataLen));
      memcpy(m_DataCache[i].pData, pData, (dwDataLen));
   }
   m_DataCache[i].dwDataLen = dwDataLen;
#ifdef _WIN32
   wcscpy_s(m_DataCache[i].wszReaderName, sizeof(m_DataCache[i].wszReaderName) / sizeof(WCHAR), wszReaderName);
#else
   strcpy(m_DataCache[i].wszReaderName, wszReaderName);
#endif
   memcpy(m_DataCache[i].DataSignature, DataSignature, DATA_SIGN_LEN);
   
   // Update Shared Cache (No Data value)
   strcpy_s((LPSTR)g_DataCache[j].DataOID, sizeof(g_DataCache[j].DataOID), (LPCSTR)pbOID);  
#ifdef _WIN32
   wcscpy_s(g_DataCache[j].wszReaderName, 
                  sizeof(g_DataCache[j].wszReaderName) / sizeof(WCHAR) , 
                  wszReaderName);
#else
   strcpy(g_DataCache[j].wszReaderName, wszReaderName);
#endif
   memcpy(g_DataCache[j].DataSignature, DataSignature, DATA_SIGN_LEN);
   
   DS_FlushMemoryMapping((void*) &g_DataCache[j], sizeof(DATA_CACHE_SHM));

#ifdef _WIN32
   // Update Cache file
   if (  (strlen(szCACHE_DIR) > 0)
	   &&(isPermanent)
	  )
   {
	   try
	   {
			WIN32_FIND_DATAA FindFileData;
			HANDLE hFind;
			char OID[CACHE_ENTRY_LEN];
			char CSN[CACHE_ENTRY_LEN];
			char szPath[256];
			FILE* fp;
			size_t i = 0;

			memset(OID, 0x00, sizeof(OID));
			memset(CSN, 0x00, sizeof(CSN));

			StringCchCopyA((LPSTR)OID, sizeof(OID), (STRSAFE_LPCSTR)pbOID);   

			while(  (OID[i] != '_')
				  &&(OID[i] != 0x00)
				  &&(i < strlen(OID))
				 )
			{
				CSN[i] = OID[i];

				i++;
			}

			sprintf(szPath, "%s\\%s\\*.*", szCACHE_DIR, CSN);

			hFind = FindFirstFileA(szPath, &FindFileData);

			if (hFind != INVALID_HANDLE_VALUE) 
			{
				sprintf(szPath, "%s\\%s\\%s", szCACHE_DIR, CSN, OID);

//				WriteLog(TRACE_LEVEL_CALL, "Create File: '%s'\n", szPath);
				
				fp = fopen(szPath, "wb");

				if (fp != NULL)
				{
					fwrite(pData, dwDataLen, 1, fp);

					fclose(fp);
				}

				FindClose(hFind);
			}
	   }
	   catch(...)
	   {
	   }
   }
#endif

   return(TRUE);
}
  
//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
BOOL SetCacheData(
#ifdef _WIN32
   LPCWSTR wszReaderName, 
#else
   LPCSTR wszReaderName, 
#endif
   LPCSTR pbOID, LPCBYTE pData, DWORD dwDataLen)
{
	return SetCacheData(wszReaderName, pbOID, pData, dwDataLen, TRUE);
}

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
BOOL ClearCacheData(
#ifdef _WIN32
   LPCWSTR wszReaderName, 
#else
   LPCSTR wszReaderName, 
#endif
   LPCSTR pbOID)
{
  // int i;
size_t i;
#ifdef _NO_CACHE
   return(FALSE);
#endif 

   if (!g_DataCache)
	   return FALSE;
   
   // Clear a specific entry
   if (pbOID)
   {
      // Clear Local Entry
      for (i = 0; i < MAX_CACHE; i++)
      {
         if (  (strcmp(pbOID, (const char *)m_DataCache[i].DataOID) == 0)
#ifdef _WIN32
            &&(wcscmp(wszReaderName, m_DataCache[i].wszReaderName) == 0)
#else
            &&(strcmp((LPSTR)wszReaderName, (LPSTR)m_DataCache[i].wszReaderName) == 0)
#endif
            )
         {
            if (m_DataCache[i].pData)
            {
               free(m_DataCache[i].pData);  
               m_DataCache[i].pData = NULL;
            }
            
            memset(&m_DataCache[i], 0x00, sizeof(m_DataCache[i]));
            
            break;
         }
      }

      // Clear Shared Entry
      for (i = 0; i < MAX_CACHE; i++)
      {
         if (  (strcmp(pbOID, (const char *)g_DataCache[i].DataOID) == 0)
#ifdef _WIN32
            &&(wcscmp(wszReaderName, g_DataCache[i].wszReaderName) == 0)
#else
            &&(strcmp((LPSTR)wszReaderName, (LPSTR)g_DataCache[i].wszReaderName) == 0)
#endif
            )
         {
            memset(&g_DataCache[i], 0x00, sizeof(DATA_CACHE_SHM));
            DS_FlushMemoryMapping((void*) &g_DataCache[i], sizeof(DATA_CACHE_SHM));
            break;
         }
      }

#ifdef _WIN32
	   // Clear Cache file
	   if (strlen(szCACHE_DIR) > 0)
	   {
		   try
		   {
				WIN32_FIND_DATAA FindFileData;
				HANDLE hFind;
				char OID[CACHE_ENTRY_LEN];
				char CSN[CACHE_ENTRY_LEN];
				char szPath[256];
				size_t i = 0;

				memset(OID, 0x00, sizeof(OID));
				memset(CSN, 0x00, sizeof(CSN));

				StringCchCopyA((LPSTR)OID, sizeof(OID), (STRSAFE_LPCSTR)pbOID);   

				while(  (OID[i] != '_')
					  &&(OID[i] != 0x00)
					  &&(i < strlen(OID))
					 )
				{
					CSN[i] = OID[i];

					i++;
				}

				sprintf(szPath, "%s\\%s\\*.*", szCACHE_DIR, CSN);

				hFind = FindFirstFileA(szPath, &FindFileData);

				if (hFind != INVALID_HANDLE_VALUE) 
				{
					sprintf(szPath, "%s\\%s\\%s", szCACHE_DIR, CSN, OID);

//					WriteLog(TRACE_LEVEL_CALL, "Delete File: '%s'\n", szPath);
				
					DeleteFileA(szPath);
				}

				FindClose(hFind);
		   }
		   catch(...)
		   {
		   }
	   }
#endif
   }
   
   // Clear a reader set of entries
   else if (wszReaderName)
   {
      // Clear Local Entries
      for (i = 0; i < MAX_CACHE; i++)
      {
#ifdef _WIN32
         if (wcscmp(wszReaderName, m_DataCache[i].wszReaderName) == 0)
#else
         if (strcmp(wszReaderName, m_DataCache[i].wszReaderName) == 0)
#endif
         {
            if (m_DataCache[i].pData)
            {
               free(m_DataCache[i].pData);  
               m_DataCache[i].pData = NULL;
            }
            
            memset(&m_DataCache[i], 0x00, sizeof(m_DataCache[i]));
         }
      }

      // Clear Shared Entry
      for (i = 0; i < MAX_CACHE; i++)
      {
#ifdef _WIN32
         if (wcscmp(wszReaderName, g_DataCache[i].wszReaderName) == 0)
#else
         if (strcmp(wszReaderName, g_DataCache[i].wszReaderName) == 0)
#endif
         {
            memset(&g_DataCache[i], 0x00, sizeof(DATA_CACHE_SHM));
			DS_FlushMemoryMapping((void*) &g_DataCache[i], sizeof(g_DataCache[i]));
         }
      }
   }
   
   // Clear All entries
   else
   {
      for (i = 0; i < MAX_CACHE; i++)
      {
         if (m_DataCache[i].pData)
         {
            free(m_DataCache[i].pData);  
            m_DataCache[i].pData = NULL;
         }            
      }

      memset(m_DataCache, 0x00, sizeof(m_DataCache));

      memset(g_DataCache, 0x00, g_iFMSize);

	  DS_FlushMemoryMapping((void*) g_DataCache, g_iFMSize);
   }
   
   return(TRUE);
}

#ifdef _WIN32
//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
void LoadCacheData (LPCWSTR        wszReaderName, 
	                LPCSTR        CSN,
					LPCBYTE        CARDCF,
					DWORD          dwCARDCFLen
				   )
{
   if (strlen(szCACHE_DIR) > 0)
   {
	    char szCSN[CACHE_ENTRY_LEN];
		char szPath[256];
		WIN32_FIND_DATAA FindFileData;
		HANDLE hFind;
		int nbFiles = 0;
		BOOL isSync = FALSE;

		StringCchCopyA(szCSN, sizeof(szCSN), CSN);   

		// Check if 'cardcf' is synchronised
		if (  (CARDCF != NULL)
			&&(dwCARDCFLen >= 6)
		   )
		{
			BYTE* data;
			int dwDataLen;
			FILE* fp;

			sprintf(szPath, "%s\\%s\\%s_root_cardcf", szCACHE_DIR, szCSN, szCSN);

			dwDataLen = get_file_len(szPath);

			if (dwDataLen == dwCARDCFLen)
			{
				data = (BYTE*)malloc((dwDataLen));

				fp = fopen(szPath, "rb");

				if (fp != NULL)
				{
					fread(data, dwDataLen, 1, fp);

					fclose(fp);

					// Check if real 'carcf' matches cached file
					if (memcmp(CARDCF, data, dwDataLen) == 0)
					{
						isSync = TRUE;
					}
				}

				free(data);
			}
		}

		// Scan directory for this card
		sprintf(szPath, "%s\\%s\\*.*", szCACHE_DIR, szCSN);

		hFind = FindFirstFileA(szPath, &FindFileData);

		// Directory exists
		if (hFind != INVALID_HANDLE_VALUE) 
		{
//			WriteLog(TRACE_LEVEL_CALL, "First file: '%s'\n", FindFileData.cFileName);
			nbFiles++;

			// Scan all files
			while (FindNextFileA(hFind, &FindFileData))
			{
//				WriteLog(TRACE_LEVEL_CALL, "Next file #%d: '%s'\n", nbFiles++, FindFileData.cFileName);

				if (  (FindFileData.cFileName[0] != '.')
					&&(memcmp(FindFileData.cFileName, szCSN, strlen(szCSN)) == 0)
				   )
				{
					char szOID[CACHE_ENTRY_LEN];
					BYTE* data;
					int dwDataLen;
					FILE* fp;

					sprintf(szOID, "%s", FindFileData.cFileName);
					sprintf(szPath, "%s\\%s\\%s", szCACHE_DIR, szCSN, szOID);
				
					// Cache is synchronised -> Add all files to cache
					if (isSync)
					{
						dwDataLen = get_file_len(szPath);

						data = (BYTE*)malloc((dwDataLen));

						fp = fopen(szPath, "rb");

						if (fp != NULL)
						{
							fread(data, dwDataLen, 1, fp);

							fclose(fp);

							SetCacheData(wszReaderName, szOID, data, dwDataLen, FALSE);
						}

						free(data);
					}

					// Cache is not synchronised -> Delete all cache files
					else
					{
						DeleteFileA(szPath);
					}
				}
			}

			FindClose(hFind);
		}

		// Card directory not exists -> Create it
		else
		{
//			WriteLog(TRACE_LEVEL_CALL, "NO CACHE FILES -> Create directory.\n");

			sprintf(szPath, "%s", szCACHE_DIR);

//			WriteLog(TRACE_LEVEL_CALL, "Create Directory: '%s'\n", szPath);

			if (!CreateDirectoryA(szPath, NULL))
			{ 
//				WriteLog(TRACE_LEVEL_CALL, "Cache storage creation failed: 0x%08X!\n", GetLastError());
			} 

			sprintf(szPath, "%s\\%s", szCACHE_DIR, szCSN);

//			WriteLog(TRACE_LEVEL_CALL, "Create Directory: '%s'\n", szPath);

			if (!CreateDirectoryA(szPath, NULL))
			{ 
//				WriteLog(TRACE_LEVEL_CALL, "Cache storage creation failed: 0x%08X!\n", GetLastError());
			} 
		}
   }
}

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
BOOL IsPersistentCache()
{
	return (strlen(szCACHE_DIR) > 0);
}
#endif
