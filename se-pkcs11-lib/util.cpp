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
#include <cstdio>
#include <time.h>
#include "cryptoki.h"
#include "digest.h"
#include "PKCS11Exception.hpp"
#include "tdes.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

R_RANDOM_STRUCT Util::_randomStruct;

void Util::SeedRandom(  u1Array & seed)
{
    R_RandomInit(&_randomStruct);
    R_RandomUpdate(&_randomStruct, const_cast<unsigned char*>(seed.GetBuffer()), seed.GetLength());
}

R_RANDOM_STRUCT & Util::RandomStruct()
{
    return _randomStruct;
}

CK_ULONG Util::MakeULong(CK_BYTE_PTR buffer,CK_ULONG offset)
{
    return (CK_ULONG)(((CK_ULONG)buffer[offset] << 24) | ((CK_ULONG)buffer[offset+1] << 16) | ((CK_ULONG)buffer[offset+2] << 8) | buffer[offset+3]);
}


/*
*/
bool Util::compareByteArrays( const unsigned char* a_pBuffer1, const unsigned char* a_pBuffer2, const size_t& a_ulLen ) {

	if( 0 == memcmp( a_pBuffer1, a_pBuffer2, a_ulLen ) ) {

		return true;
	}

    /*for( CK_ULONG i = 0 ; i < a_ulLen ; ++i ) {

        if( a_pBuffer1[ i ] != a_pBuffer2[ i ] ) {

			return false;
		}
    }*/

    return false;
}


bool Util::compareU1Arrays( u1Array* abuffer, const unsigned char* bbuffer, const size_t& len ) {

    if( !abuffer && !bbuffer ) {

        return true;
    }

    if( abuffer && bbuffer ) {

        if( len == abuffer->GetLength( ) ) {

            return Util::compareByteArrays( abuffer->GetBuffer( ), bbuffer, len );
        }
    }

    return false;
}

bool Util::compareArraysAsBigIntegers( u1Array* abuffer, const unsigned char* bbuffer, const size_t& len ) {

    if( !abuffer && !bbuffer ) {

        return true;
    }

    if( abuffer && bbuffer ) {
		unsigned char* ptr1 = abuffer->GetBuffer();
		u4 len1 = abuffer->GetLength();

		unsigned char* ptr2 = (unsigned char*) bbuffer;
		u4 len2 = (u4) len;

		// skip any leading zeros from the two buffers
		while (len1 && (ptr1[0] == 0))
		{
			len1--;
			ptr1++;
		}

		while (len2 && (ptr2[0] == 0))
		{
			len2--;
			ptr2++;
		}

        if( len1 == len2 ) {

            return Util::compareByteArrays( ptr1, ptr2, len1 );
        }
    }

    return false;
}


bool Util::compareU4Arrays(  u4Array* abuffer, const unsigned char* bbuffer, const size_t& len ) {

    if( !abuffer &&  !bbuffer ) {

        return true;
    }

    if( abuffer && bbuffer ) {

        if( len == abuffer->GetLength( ) ) {

            return Util::compareByteArrays( (unsigned char*) abuffer->GetBuffer( ), bbuffer, len );
        }
    }

    return false;
}

void Util::PushULongInVector( std::vector<u1>* to, CK_ULONG value)
{
    to->push_back((u1)(value >> 24));
    to->push_back((u1)(value >> 16));
    to->push_back((u1)(value >> 8));
    to->push_back((u1)(value));
}

void Util::PushULongLongInVector( std::vector<u1>* to, u8 value)
{
    to->push_back((u1)(value >> 56));
    to->push_back((u1)(value >> 48));
    to->push_back((u1)(value >> 40));
    to->push_back((u1)(value >> 32));
    to->push_back((u1)(value >> 24));
    to->push_back((u1)(value >> 16));
    to->push_back((u1)(value >> 8));
    to->push_back((u1)(value));
}

void Util::PushBBoolInVector(std::vector<u1>* to, CK_BBOOL value)
{
    // push the value
    to->push_back(value);
}

void Util::PushByteArrayInVector(std::vector<u1>* to,  u1Array *value) {

    if( !value || !value->GetLength( ) ) {

        to->push_back( 0 );

    } else {

        int l = value->GetLength( );

        Util::PushLengthInVector( to, l );

        u1* buffer = (u1*)value->GetBuffer( );

        for (int i = 0 ; i < l; ++i ) {

            to->push_back( buffer[ i ] );
        }
    }
}


void Util::PushIntArrayInVector(std::vector<u1>* to,  u4Array *value) {

    if( !value || !value ) {

        to->push_back(0);

    } else {

        int l = value->GetLength( ) * 4;

        Util::PushLengthInVector( to, l );

        u1* buffer = (u1*)value->GetBuffer( );

        for( int i = 0 ; i < l ; ++i ) {

            to->push_back( buffer[ i ] );
        }
    }
}

 u1Array* Util::ReadByteArrayFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG len = Util::ReadLengthFromVector(from,idx);

    if(len == 0){
        return NULL_PTR;
    }

    u1Array* val = new u1Array(len);

    for(u4 i=0;i<len;i++){
        val->SetU1At(i,from.at(*idx));
        *idx = *idx + 1;
    }

    return val;
}

 u4Array* Util::ReadIntArrayFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG len = Util::ReadLengthFromVector(from,idx);

    if(len == 0){
        return NULL_PTR;
    }

     u4Array* val = new  u4Array(len/4);

    for(u4 i=0;i<(len/4);i++){

        u1 a = from.at(*idx);
        u1 b = from.at(*idx + 1);
        u1 c = from.at(*idx + 2);
        u1 d = from.at(*idx + 3);

        // make an int
        u4 anInt = (u4)(((u4)a << 24) | ((u4)b << 16) | ((u4)c << 8) | d);

        val->SetU4At(i,anInt);

        *idx = *idx + 4;
    }

    return val;
}

void Util::PushLengthInVector(std::vector<u1>* to, CK_ULONG len)
{
    if(len < (CK_ULONG)0x80){
        to->push_back(len & 0x7F);
    }else if(len <= (CK_ULONG)0xFF){
        to->push_back(0x81);
        to->push_back(len & 0xFF);
    }else{
        to->push_back(0x82);
        to->push_back((u1)((len >> 8) & 0x00FF));
        to->push_back((u1)(len));
    }
}

CK_ULONG Util::ReadLengthFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG val = (CK_ULONG)from.at(*idx);

    if(val < (CK_ULONG)0x80){
        *idx = *idx + 1;
        return val;
    }else if(val == 0x81){
        *idx = *idx + 1;
        val = from.at(*idx);
        *idx = *idx + 1;
        return val;
    }else if(val == 0x82){
        *idx = *idx + 1;
        val = (u2)(((u2)from.at(*idx)) << 8);
        *idx = *idx + 1;
        val = val | (u2)from.at(*idx);
        *idx = *idx + 1;
        return val;
    }

    //PKCS11_ASSERT(CK_FALSE);

    return 0;
}

CK_BBOOL Util::ReadBBoolFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_BBOOL val = (CK_BBOOL)from.at(*idx);
    *idx = *idx + 1;

    return val;
}


bool Util::ReadBoolFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    bool val = ( from.at( *idx ) != 0 ) ? true : false;

	*idx = *idx + 1;

    return val;
}

CK_ULONG Util::ReadULongFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG offset = *idx;

    CK_ULONG val = (CK_ULONG)(((CK_ULONG)from.at(offset) << 24) | ((CK_ULONG)from.at(offset+1) << 16) | ((CK_ULONG)from.at(offset+2) << 8) | from.at(offset+3));

    *idx = *idx + 4;

    return val;
}

u8 Util::ReadULongLongFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG offset = *idx;

    u8 val = (u8)(((u8)from.at(offset  ) << 56) | ((u8)from.at(offset+1) << 48) |
                  ((u8)from.at(offset+2) << 40) | ((u8)from.at(offset+3) << 32) |
                  ((u8)from.at(offset+4) << 24) | ((u8)from.at(offset+5) << 16) |
                  ((u8)from.at(offset+6) <<  8) | from.at(offset+7));

    *idx = *idx + 8;

    return val;
}

void Util::ConvAscii(u1 *pIn, u4 dwLen,u1 *pOut)
{
   #define tohex(x)  (((x) >= 0xA) ? ((x) - 0xA + 'A') : ((x) + '0'))
   register u4 i;

   for(i=0; i < dwLen; i++)
   {
      pOut[i*2] = tohex((pIn[i] >> 4) & 0xF);
      pOut[i*2+1] =  tohex(pIn[i] & 0xF);
   }
   #undef tohex
}

char* Util::ItoA(s4 value, char* str, s4 radix)
{

#ifdef WIN32

    return _itoa(value,str,radix);

#else

    s4  rem = 0;
    s4  pos = 0;
    char ch  = '!' ;

    do
    {
        rem    = value % radix ;
        value /= radix;
        if ( 16 == radix )
        {
            if( rem >= 10 && rem <= 15 )
            {
                switch( rem )
                {
                    case 10:
                        ch = 'a' ;
                        break;
                    case 11:
                        ch ='b' ;
                        break;
                    case 12:
                        ch = 'c' ;
                        break;
                    case 13:
                        ch ='d' ;
                        break;
                    case 14:
                        ch = 'e' ;
                        break;
                    case 15:
                        ch ='f' ;
                        break;
                }
            }
        }
        if( '!' == ch )
        {
            str[pos++] = (char) ( rem + 0x30 );
        }
        else
        {
            str[pos++] = ch ;
        }
    }while( value != 0 );

    str[pos] = '\0' ;

    int i = strlen(str);
    int t = !(i%2)? 1 : 0;      // check the length of the string .

    for(int j = i-1 , k = 0 ; j > (i/2 -t) ; j-- )
    {
        char ch2  = str[j];
        str[j]   = str[k];
        str[k++] = ch2;
    }

    return str;

#endif

}

u8 Util::MakeCheckValue(const unsigned char * pBuf, unsigned int length)
{
    CDigest* sha1 = CDigest::getInstance(CDigest::SHA1);
    u1 hash[20];
    sha1->hashUpdate(const_cast<unsigned char *>(pBuf), 0, length);
    sha1->hashFinal(hash);
    delete sha1;
    u8 val = 0;
    size_t l = sizeof(u8);
    for(size_t i = 0; i< l; ++i)
        val = (val << 8) | hash[i];
    return val;
}

u8 Util::MakeUniqueId()
{
    unsigned char buf[8];
    if(R_GenerateBytes(buf, 8, &_randomStruct))
        throw PKCS11Exception( CKR_FUNCTION_FAILED );
    u8 * value = reinterpret_cast<u8*>(buf);
    return *value;
}

std::string Util::MakeIntString(unsigned int number, int width)
{
    if(width < 1)
        return std::string();
    char temp[16];
    sprintf(temp, "%011d", number);
    std::string s(temp);
    return s.substr(s.size()-width, width);
}


/*
*/
void Util::toStringHex(  unsigned char a_ucIn, std::string& a_stOut ) {

    char h1 = a_ucIn / 16;
    h1 += ( ( h1 <= 9 ) ? '0' : ( 'a'- 10 ) );

    char h2 = a_ucIn % 16;
    h2 += ( ( h2 <= 9 ) ? '0' : ( 'a'- 10 ) );

    a_stOut += h1;
    a_stOut += h2;
}

static unsigned char fromHex(char c)
{
	if (c>='0' && c<= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return 0;
}

void Util::fromStringHex(const char* a_stHex, size_t hexLen, unsigned char* pOut)
{
	for (size_t i = 0; i < hexLen/2; i++)
	{
		*pOut = (unsigned char) ((fromHex(a_stHex[2*i]) << 4) | fromHex(a_stHex[2*i + 1]));
		pOut++;
	}
}

bool Util::AddCertToList(X509* cert, std::list<X509*>& certList)
{
	// check if it exists
	bool bFound = false;
	for (std::list<X509*>::iterator It = certList.begin(); It != certList.end(); It++)
	{
		if (X509_cmp(cert, *It) == 0)
		{
			bFound = true;
			break;
		}
	}

	if (!bFound)
		certList.push_back(cert);

	return !bFound;
}

bool Util::DeleteCertFromList(X509* cert, std::list<X509*>& certList)
{
	// check if it exists
	bool bFound = false;
	for (std::list<X509*>::iterator It = certList.begin(); It != certList.end();)
	{
		if (X509_cmp(cert, *It) == 0)
		{
			bFound = true;
			It = certList.erase(It);
		}
		else
			It++;
	}

	return bFound;
}

void Util::FreeCertList(std::list<X509*>& certList)
{
	if (!certList.empty())
	{
		for (std::list<X509*>::iterator It = certList.begin(); It != certList.end(); It++)
		{
			X509_free(*It);
		}

		certList.clear();
	}
}

bool Util::ParsePkcs7(unsigned char* pbData, int iLength, std::list<X509*>& certList)
{
	bool bRet = false;
	BIO *membio;
	PKCS7* p7;
	X509 *x;

	FreeCertList(certList);

	membio = BIO_new_mem_buf((void*) pbData, iLength);
	p7=d2i_PKCS7_bio(membio,NULL);
	if (p7)
	{
		STACK_OF(X509) *certs=NULL;

		int i=OBJ_obj2nid(p7->type);
		switch (i)
		{
		case NID_pkcs7_signed:
			certs=p7->d.sign->cert;
			break;
		case NID_pkcs7_signedAndEnveloped:
			certs=p7->d.signed_and_enveloped->cert;
			break;
		default:
			break;
		}

		if (certs)
		{
			bRet = true;
			for (i=0; i<sk_X509_num(certs); i++)
			{
				x=sk_X509_value(certs,i);
				certList.push_back(X509_dup(x));
			}
		}

		PKCS7_free(p7);
	}

	BIO_free_all(membio);
	return bRet;
}

bool Util::CreatePkcs7(const std::list<X509*>& certList, std::vector<unsigned char>& p7Bytes)
{
	bool bRet = false;
	BIO *membio;
	unsigned char *tmpbuf;
	long buflen;
	PKCS7* p7;
	PKCS7_SIGNED* p7s;
	STACK_OF(X509_CRL) *crl_stack = NULL;
	STACK_OF(X509) *cert_stack = NULL;

	p7=PKCS7_new();
	p7s=PKCS7_SIGNED_new();
	p7->type=OBJ_nid2obj(NID_pkcs7_signed);
	p7->d.sign=p7s;
	p7s->contents->type=OBJ_nid2obj(NID_pkcs7_data);

	ASN1_INTEGER_set(p7s->version,1);
	crl_stack=sk_X509_CRL_new_null();
	p7s->crl=crl_stack;

	cert_stack=sk_X509_new_null();
	p7s->cert=cert_stack;

	for (std::list<X509*>::const_iterator It = certList.begin(); It != certList.end(); It++)
	{
		sk_X509_push(cert_stack,X509_dup(*It));
	}

	membio = BIO_new(BIO_s_mem()); // memory BIO
	if (i2d_PKCS7_bio(membio,p7))
		bRet = true;

	// get internal buffer of memory BIO
	buflen = BIO_get_mem_data(membio, &tmpbuf);
	//copy it
	p7Bytes.resize(buflen);
	memcpy(&p7Bytes[0], tmpbuf, buflen);

	BIO_free_all(membio);
	PKCS7_free(p7);

	return bRet;
}

#ifndef _WIN32
/*
 */
std::string Util::toBase64(const unsigned char * pBuf, unsigned int length)
{
	BIO *membio, *bio, *b64;
	char *tmpbuf, *buffer;
	long buflen;

	b64 = BIO_new(BIO_f_base64());
	membio = BIO_new(BIO_s_mem()); // memory BIO
	bio = BIO_push(b64, membio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, pBuf, length);
	BIO_flush(bio);

	// get internal buffer of memory BIO
	buflen = BIO_get_mem_data(membio, &tmpbuf);
	//copy it
	buffer = (char*) malloc(buflen+1);
	memcpy(buffer, tmpbuf, buflen);
	buffer[buflen] = 0;
	std::string strResult = buffer;
	free(buffer);

	// free everything
	BIO_free_all(bio);

	return strResult;
}

/*
 */
std::vector<u1> Util::fromBase64(const char* szbase64)
{
	BIO *membio, *bio, *b64;
	int decodedLen = strlen(szbase64); // we over estimate the output length
	std::vector<unsigned char> res;
	res.resize(decodedLen + 1);

	membio = BIO_new_mem_buf((void*) szbase64, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, membio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	decodedLen = BIO_read(bio, &res[0], decodedLen);

	// free everything
	BIO_free_all(bio);

	res.resize(decodedLen);

	return res;
}
#endif

/*****************************************************
 * Memory encryption implementation
 *****************************************************/
#ifdef _WIN32

typedef DWORD (WINAPI *MemoryProtectionFn)(
               unsigned char* ptr,
               unsigned long length,
               unsigned long flags);

typedef BOOL (WINAPI *VistaMemoryProtectionFn)(
               unsigned char* ptr,
               unsigned long length,
               unsigned long flags);

MemoryProtectionFn EncryptMemoryPtr = NULL;
MemoryProtectionFn DecryptMemoryPtr = NULL;

VistaMemoryProtectionFn VistaEncryptMemory = NULL;
VistaMemoryProtectionFn VistaDecryptMemory = NULL;

HMODULE hCrypt32Dll = NULL;
HMODULE hAdvapi32Dll = NULL;

// Wrapper around the Vista API to convert its return value
static DWORD WINAPI VistaEncryptMemoryWrapper(
               unsigned char* ptr,
               unsigned long length,
               unsigned long flags)
{
   BOOL bStatus = VistaEncryptMemory(ptr, length, flags);
   if (bStatus)
   {
      return 0;
   }
   else
   {
      return GetLastError();
   }
}

static DWORD WINAPI VistaDecryptMemoryWrapper(
               unsigned char* ptr,
               unsigned long length,
               unsigned long flags)
{
   BOOL bStatus = VistaDecryptMemory(ptr, length, flags);
   if (bStatus)
   {
      return 0;
   }
   else
   {
      return GetLastError();
   }
}

#else
typedef int (*MemoryProtectionFn)(
               unsigned char* ptr,
               unsigned long length,
               unsigned long flags);

MemoryProtectionFn EncryptMemoryPtr = NULL;
MemoryProtectionFn DecryptMemoryPtr = NULL;

#endif

static unsigned char g_protectionKey[32];
static unsigned char g_protectionIV[16];
static bool g_keyInitialized = false;

static void InitializeLocalKey()
{
   if (!g_keyInitialized)
   {
	  // initialize random
	  R_RANDOM_STRUCT encRng;
	  time_t t = time(NULL);
	  clock_t cl = clock();
	  R_RandomInit(&encRng);
	  R_RandomUpdate(&encRng, (unsigned char*)(&t), sizeof(t));
	  R_RandomUpdate(&encRng, (unsigned char*)(&cl), sizeof(cl));

      R_GenerateBytes(g_protectionKey, 32, &encRng);
      R_GenerateBytes(g_protectionIV, 16, &encRng);

	  R_RandomFinal(&encRng);
      g_keyInitialized = true;
   }
}

#ifdef _WIN32
static DWORD WINAPI LocalEncryptMemory(
#else
static int          LocalEncryptMemory(
#endif
               unsigned char* ptr,
               unsigned long length,
               unsigned long /*flags*/)
{
	EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
	int iLen = (int) length;
	InitializeLocalKey();

	//EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_protectionKey, g_protectionIV);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, ptr, &iLen, ptr, length);
	EVP_CIPHER_CTX_free(ctx);

   return 0;

}

#ifdef _WIN32
static DWORD WINAPI LocalDecryptMemory(
#else
static int          LocalDecryptMemory(
#endif
               unsigned char* ptr,
               unsigned long length,
               unsigned long /*flags*/)
{
	EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
	int iLen = (int) length;

	InitializeLocalKey();

	//EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_protectionKey, g_protectionIV);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_DecryptUpdate(ctx, ptr, &iLen, ptr, length);
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

/********************************************************/
static void InitializeMemoryProtection()
{
   if (!EncryptMemoryPtr || !DecryptMemoryPtr)
   {
      bool bStatus = false;

#ifdef _WIN32
      char szPath[1024];
      //Look for the Vista version first
      if (GetSystemDirectory(szPath, 1024))
      {
         strcat(szPath, "\\crypt32.dll");
      }
      else
      {
         strcpy(szPath, "crypt32.dll");
      }

      hCrypt32Dll = LoadLibrary(szPath);
      if (hCrypt32Dll)
      {
         VistaEncryptMemory = (VistaMemoryProtectionFn) GetProcAddress(hCrypt32Dll, "CryptProtectMemory");
         VistaDecryptMemory = (VistaMemoryProtectionFn) GetProcAddress(hCrypt32Dll, "CryptUnprotectMemory");

         if (VistaEncryptMemory && VistaDecryptMemory)
         {
            EncryptMemoryPtr = VistaEncryptMemoryWrapper;
            DecryptMemoryPtr = VistaDecryptMemoryWrapper;
            bStatus = true;
         }
         else
         {
            FreeLibrary(hCrypt32Dll);
            hCrypt32Dll = NULL;
         }
      }

      if (!bStatus)
      {
         //Look for the standard version
         if (GetSystemDirectory(szPath, 1024))
         {
            strcat(szPath, "\\advapi32.dll");
         }
         else
         {
            strcpy(szPath, "advapi32.dll");
         }

         hAdvapi32Dll = LoadLibrary(szPath);
         if (hAdvapi32Dll)
         {
            // These functions are available starting from Windows 2000 SP3
            EncryptMemoryPtr = (MemoryProtectionFn) GetProcAddress(hAdvapi32Dll, "SystemFunction040");
            DecryptMemoryPtr = (MemoryProtectionFn) GetProcAddress(hAdvapi32Dll, "SystemFunction041");

            if (!EncryptMemoryPtr || !DecryptMemoryPtr)
            {
               EncryptMemoryPtr = NULL;
               DecryptMemoryPtr = NULL;
               FreeLibrary(hAdvapi32Dll);
               hAdvapi32Dll = NULL;
            }
            else
            {
               bStatus = true;
            }
         }
      }
#endif
      if (!bStatus)
      {
         // use our implementation
         EncryptMemoryPtr = LocalEncryptMemory;
         DecryptMemoryPtr = LocalDecryptMemory;
      }
   }
}


void EncryptMemory(unsigned char* ptr, unsigned long length)
{
   InitializeMemoryProtection();
   EncryptMemoryPtr(ptr, length, 0);
}

void DecryptMemory(unsigned char* ptr, unsigned long length)
{
   InitializeMemoryProtection();
   DecryptMemoryPtr(ptr, length, 0);
}

/*
 * Helpers functions for OAEP and PSS padding
 */

int MGF_Generic(unsigned char *mask, long len, const unsigned char *seed, long seedlen, const EVP_MD *dgst)
{
    long i, outlen = 0;
    unsigned char cnt[4];
    EVP_MD_CTX* c=EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE];
    int mdlen;
    int rv = -1;

    //EVP_MD_CTX_init(&c);
    mdlen = EVP_MD_size(dgst);
    if (mdlen < 0)
        goto err;
    for (i = 0; outlen < len; i++)
    {
        cnt[0] = (unsigned char)((i >> 24) & 255);
        cnt[1] = (unsigned char)((i >> 16) & 255);
        cnt[2] = (unsigned char)((i >> 8)) & 255;
        cnt[3] = (unsigned char)(i & 255);
        if (!EVP_DigestInit_ex(c,dgst, NULL)
            || !EVP_DigestUpdate(c, seed, seedlen)
            || !EVP_DigestUpdate(c, cnt, 4))
            goto err;
        if (outlen + mdlen <= len)
        {
            if (!EVP_DigestFinal_ex(c, mask + outlen, NULL))
                goto err;
            outlen += mdlen;
        }
        else
        {
            if (!EVP_DigestFinal_ex(c, md, NULL))
                goto err;
            memcpy(mask + outlen, md, len - outlen);
            outlen = len;
        }
    }
    rv = 0;
err:
    EVP_MD_CTX_free(c);
    return rv;
}

int MGF_SHA1(unsigned char *mask, long len, const unsigned char *seed, long seedlen)
{
    return MGF_Generic(mask, len, seed, seedlen, EVP_sha1());
}

int DecodeOAEP(unsigned char *to, int tlen,
    const unsigned char *from, int flen,
    int modulusLen, const EVP_MD *dgst,
    const unsigned char *param, int plen)
{
    int i, dblen, mlen = -1;
    const unsigned char *maskeddb;
    int lzero;
    unsigned char *db = NULL, seed[EVP_MAX_MD_SIZE], phash[EVP_MAX_MD_SIZE];
    unsigned char *padded_from;
    int bad = 0;
    int hashLen = EVP_MD_size(dgst);

    if (--modulusLen < 2 * hashLen + 1)
        /* 'num' is the length of the modulus, i.e. does not depend on the
        * particular ciphertext. */
        goto decoding_err;

    /* remove the leading zero if it exists */
    if (*from == 0)
    {
        from++;
        flen--;
    }

    lzero = modulusLen - flen;
    if (lzero < 0)
    {
        /* signalling this error immediately after detection might allow
        * for side-channel attacks (e.g. timing if 'plen' is huge
        * -- cf. James H. Manger, "A Chosen Ciphertext Attack on RSA Optimal
        * Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001),
        * so we use a 'bad' flag */
        bad = 1;
        lzero = 0;
        flen = modulusLen; /* don't overflow the memcpy to padded_from */
    }

    dblen = modulusLen - hashLen;
    db = (unsigned char*) OPENSSL_malloc(dblen + modulusLen);
    if (db == NULL)
    {
        return -1;
    }

    /* Always do this zero-padding copy (even when lzero == 0)
    * to avoid leaking timing info about the value of lzero. */
    padded_from = db + dblen;
    memset(padded_from, 0, lzero);
    memcpy(padded_from + lzero, from, flen);

    maskeddb = padded_from + hashLen;

    if (MGF_Generic(seed, hashLen, maskeddb, dblen, dgst))
        return -1;
    for (i = 0; i < hashLen; i++)
        seed[i] ^= padded_from[i];

    if (MGF_Generic(db, dblen, seed, hashLen, dgst))
        return -1;
    for (i = 0; i < dblen; i++)
        db[i] ^= maskeddb[i];

    if (!EVP_Digest((void *)param, plen, phash, NULL, dgst, NULL))
        return -1;

    if (memcmp(db, phash, hashLen) != 0 || bad)
        goto decoding_err;
    else
    {
        for (i = hashLen; i < dblen; i++)
            if (db[i] != 0x00)
                break;
        if (i == dblen || db[i] != 0x01)
            goto decoding_err;
        else
        {
            /* everything looks OK */

            mlen = dblen - ++i;
            if (tlen < mlen)
            {
                mlen = -1;
            }
            else
                memcpy(to, db + i, mlen);
        }
    }
    OPENSSL_free(db);
    return mlen;

decoding_err:
    /* to avoid chosen ciphertext attacks, the error message should not reveal
    * which kind of decoding error happened */
    if (db != NULL) OPENSSL_free(db);
    return -1;
}

int EncodeOAEP(unsigned char *to, int tlen /* tlen is modulus size in bytes*/,
    const unsigned char *from, int flen, const EVP_MD *dgst,
    const unsigned char *param, int plen)
{
    int i, emlen = tlen - 1;
    unsigned char *db, *seed;
    unsigned char *dbmask, seedmask[EVP_MAX_MD_SIZE];
    int hashLen = EVP_MD_size(dgst);

    if (flen > emlen - 2 * hashLen - 1)
    {
        return 0;
    }

    if (emlen < 2 * hashLen + 1)
    {
        return 0;
    }

    to[0] = 0;
    seed = to + 1;
    db = to + hashLen + 1;

    if (!EVP_Digest((void *)param, plen, db, NULL, dgst, NULL))
        return 0;
    memset(db + hashLen, 0,
        emlen - flen - 2 * hashLen - 1);
    db[emlen - flen - hashLen - 1] = 0x01;
    memcpy(db + emlen - flen - hashLen, from, (unsigned int) flen);

    R_RANDOM_STRUCT& rng = Util::RandomStruct();
    R_GenerateBytes (seed, hashLen, &rng);

    dbmask = (unsigned char*) OPENSSL_malloc(emlen - hashLen);
    if (dbmask == NULL)
    {
        return 0;
    }

    if (MGF_Generic(dbmask, emlen - hashLen, seed, hashLen, dgst) < 0)
        return 0;
    for (i = 0; i < emlen - hashLen; i++)
        db[i] ^= dbmask[i];

    if (MGF_Generic(seedmask, hashLen, db, emlen - hashLen, dgst) < 0)
        return 0;
    for (i = 0; i < hashLen; i++)
        seed[i] ^= seedmask[i];

    OPENSSL_free(dbmask);
    return 1;
}

static const unsigned char zeroes[] = {0,0,0,0,0,0,0,0};

int VerifyPSS(int modulusBitLength, const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    const unsigned char *EM, int saltLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    const unsigned char *H;
    unsigned char *DB = NULL;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    unsigned char H_[EVP_MAX_MD_SIZE];
   // EVP_MD_CTX_init(&ctx);

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_size(Hash);
    if (hLen < 0)
        goto err;

    MSBits = (modulusBitLength - 1) & 0x7;
    emLen = (modulusBitLength + 7) / 8;
    if (EM[0] & (0xFF << MSBits))
    {
        goto err;
    }
    if (MSBits == 0)
    {
        EM++;
        emLen--;
    }
    if (emLen < (hLen + saltLen + 2)) /* saltLen can be small negative */
    {
        goto err;
    }
    if (EM[emLen - 1] != 0xbc)
    {
        goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    DB = (unsigned char*) OPENSSL_malloc(maskedDBLen);
    if (!DB)
    {
        goto err;
    }
    if (MGF_Generic(DB, maskedDBLen, H, hLen, mgf1Hash) < 0)
        goto err;
    for (i = 0; i < maskedDBLen; i++)
        DB[i] ^= EM[i];
    if (MSBits)
        DB[0] &= 0xFF >> (8 - MSBits);
    for (i = 0; DB[i] == 0 && i < (maskedDBLen-1); i++) ;
    if (DB[i++] != 0x1)
    {
        goto err;
    }
    if (saltLen >= 0 && (maskedDBLen - i) != saltLen)
    {
        goto err;
    }
    if (!EVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVP_DigestUpdate(ctx, zeroes, sizeof zeroes)
        || !EVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (maskedDBLen - i)
    {
        if (!EVP_DigestUpdate(ctx, DB + i, maskedDBLen - i))
            goto err;
    }
    if (!EVP_DigestFinal_ex(ctx, H_, NULL))
        goto err;
    if (memcmp(H_, H, hLen))
    {
        ret = 0;
    }
    else
        ret = 1;

err:
    if (DB)
        OPENSSL_free(DB);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int EncodePSS(int modulusBitLength, unsigned char *EM,
    const unsigned char *mHash,	const EVP_MD *Hash,
    const EVP_MD *mgf1Hash, int saltLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    unsigned char *H, *salt = NULL, *p;
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    R_RANDOM_STRUCT& rng = Util::RandomStruct();

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_size(Hash);
    if (hLen < 0)
        goto err;

    MSBits = (modulusBitLength - 1) & 0x7;
    emLen = (modulusBitLength + 7) / 8;
    if (MSBits == 0)
    {
        *EM++ = 0;
        emLen--;
    }

    if (emLen < (hLen + saltLen + 2))
    {
        goto err;
    }
    if (saltLen > 0)
    {
        salt = (unsigned char*) OPENSSL_malloc(saltLen);
        if (!salt)
        {
            goto err;
        }

        R_GenerateBytes (salt, saltLen, &rng);
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    //EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVP_DigestUpdate(ctx, zeroes, sizeof zeroes)
        || !EVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (saltLen && !EVP_DigestUpdate(ctx, salt, saltLen))
        goto err;
    if (!EVP_DigestFinal_ex(ctx, H, NULL))
        goto err;
    EVP_MD_CTX_free(ctx);

    /* Generate dbMask in place then perform XOR on it */
    if (MGF_Generic(EM, maskedDBLen, H, hLen, mgf1Hash))
        goto err;

    p = EM;

    /* Initial PS XORs with all zeroes which is a NOP so just update
    * pointer. Note from a test above this value is guaranteed to
    * be non-negative.
    */
    p += emLen - saltLen - hLen - 2;
    *p++ ^= 0x1;
    if (saltLen > 0)
    {
        for (i = 0; i < saltLen; i++)
            *p++ ^= salt[i];
    }
    if (MSBits)
        EM[0] &= 0xFF >> (8 - MSBits);

    /* H is already in place so just set final 0xbc */

    EM[emLen - 1] = 0xbc;

    ret = 1;

err:
    if (salt)
        OPENSSL_free(salt);

    return ret;
}

#ifndef _WIN32
#ifdef __APPLE__
	#include <sys/types.h>
	#include <sys/sysctl.h>
#else
#include <sys/sysinfo.h>
#endif

u4 GetTickCount()
{
#ifdef __APPLE__
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 )
    {
        return -1;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);

    return (u4)(csec - bsec) * 1000;
#else
	struct sysinfo info;
	sysinfo(&info);
	return info.uptime * 1000;
#endif
}

#endif

void ComputeCryptogram (unsigned char* pbTripleDesKey, // 24 bytes
                        unsigned char* pbChallenge,
                        unsigned long challengeLength, // multiple of 8
                        unsigned char* pbCryptogram // same length as challenge
                      )
{
   CK_BYTE iv[ 8 ];
   memset( iv, 0, sizeof( iv ) );

   CTripleDES tdes;

   tdes.SetEncryptMode( ENCRYPT );

   tdes.SetIV( iv );

   tdes.SetCipherMode( CIPHER_MODE_ECB );

   tdes.SetPaddingMode( PADDING_MODE_NONE );

   tdes.SetKey( pbTripleDesKey, 24 );

   tdes.TransformFinalBlock( pbChallenge , 0, (long) challengeLength, pbCryptogram, 0 );
}
