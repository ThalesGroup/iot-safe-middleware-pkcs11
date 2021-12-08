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
#include <cstring>
#include "ha_config.h"
#include "cr_random.h"
#include "cr_global.h"
//#include "cryptoki.h"
#include "digest.h"
#include <openssl/rand.h>

#ifndef WIN32
#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
#endif

int R_GenerateBytes(
    unsigned char *block,				/* block			*/
    unsigned int blockLen,				/* length of block	*/
    R_RANDOM_STRUCT *randomStruct)		/* random structure */
{
#ifdef _WIN32
   HCRYPTPROV hProv = (HCRYPTPROV) randomStruct->pContext;
   if (!hProv || !CryptGenRandom(hProv, blockLen, block))
      return (RE_NEED_RANDOM);
#else
   UNREFERENCED_PARAMETER (randomStruct);
   if (RAND_bytes(block, blockLen) <= 0)
      return (RE_NEED_RANDOM);
#endif

    return (0);
}


int R_RandomInit(R_RANDOM_STRUCT *randomStruct)
{
   randomStruct->pContext = NULL;
#ifdef _WIN32
   HCRYPTPROV hProv = NULL;
   if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
         CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

   randomStruct->pContext = (void*) hProv;
#endif

    return (0);
}


int R_RandomUpdate(
    R_RANDOM_STRUCT *randomStruct,            /* random structure			*/
    unsigned char *block,                     /* block of values to mix in	*/
    unsigned int blockLen)                    /* length of block			*/
{
#ifdef _WIN32
   HCRYPTPROV hProv = (HCRYPTPROV) randomStruct->pContext;
   if (!hProv)
   {
      if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
         CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

      randomStruct->pContext = (void*) hProv;
   }

   if (hProv)
   {
      unsigned char seedBuffer[64];
      unsigned int len;
      while (blockLen)
      {
         len = min (64, blockLen);
         memcpy(seedBuffer, block, len);
         CryptGenRandom(hProv, len, seedBuffer);
         memset (seedBuffer, 0, len);

         block += len;
         blockLen -= len;
      }      
   }
#else
   UNREFERENCED_PARAMETER (randomStruct);
   RAND_seed(block, blockLen);
#endif

    return (0);
}

void R_RandomFinal(R_RANDOM_STRUCT *randomStruct)
{
#ifdef _WIN32
   HCRYPTPROV hProv = (HCRYPTPROV) randomStruct->pContext;
   if (hProv)
   {
      CryptReleaseContext(hProv, 0);
      randomStruct->pContext = NULL;
   }
#else
   if (randomStruct->pContext)
      randomStruct->pContext = NULL;
#endif
}
