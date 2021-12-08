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
#ifndef _include_util_h
#define _include_util_h

#ifdef WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <Windows.h>
#endif

#include <string>
#include <vector>
#include <list>

#ifndef NO_FILESYSTEM
#include <boost/archive/archive_exception.hpp>
#include <boost/serialization/split_member.hpp>
#include <boost/serialization/version.hpp>
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "Array.h"
#include "cr_random.h"
#include "cryptoki.h"
#include "Except.h"

// Very simple class similar to auto_ptr, but for arrays.
// It means that it calls delete[] instead of delete.
template<class T> class autoarray
{
public:
    autoarray(T* t) : _t(t) {}
    ~autoarray() { delete [] _t; }
    T * get() { return _t; }
    T & operator[](size_t index) { return _t[index]; }
    const T & operator[](size_t index) const { return _t[index]; }

private:
    T * _t;
};

template<typename T> void IntToLittleEndian(T t, unsigned char * buf, size_t offset = 0)
{
    size_t n = sizeof(T);
    for(size_t i = 0; i < n; i++)
    {
        buf[offset+i] = static_cast<unsigned char>(t & 0xFF);
        t >>= 8;
    }
}

template<typename T> T LittleEndianToInt(const unsigned char * buf, size_t offset = 0)
{
    size_t n = sizeof(T);
    T t = 0;
    for(size_t i = 0; i < n; i++)
    {
        t <<= 8;
        t |= buf[offset+n-i-1];
    }
    return t;
}


class Util
{

public:
    static void SeedRandom( u1Array & seed);
    static R_RANDOM_STRUCT & RandomStruct();
    static CK_ULONG MakeULong( unsigned char* pValue, CK_ULONG offset);
    static bool compareByteArrays( const unsigned char*, const unsigned char*, const size_t& );
	static bool compareU1Arrays( u1Array*, const unsigned char*, const size_t& );

	/** compare the two array as a big endian representation of an integer */
	static bool compareArraysAsBigIntegers( u1Array*, const unsigned char*, const size_t& );

	static bool compareU4Arrays( u4Array*, const unsigned char*, const size_t& );
	static void PushULongInVector( std::vector<u1>* to, CK_ULONG value);
	static void PushULongLongInVector( std::vector<u1>* to,u8 value);
	static void PushBBoolInVector( std::vector<u1>* to, CK_BBOOL value);
	static void PushByteArrayInVector( std::vector<u1>* to, u1Array* value);
    static void PushIntArrayInVector( std::vector<u1>* to, u4Array* value);
    static void PushLengthInVector( std::vector<u1>* to,/*CK_USHORT*/ CK_ULONG len);
	static CK_ULONG ReadLengthFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
	static CK_ULONG ReadULongFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
	static u8 ReadULongLongFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
	static CK_BBOOL ReadBBoolFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
	static  u1Array* ReadByteArrayFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
	static  u4Array* ReadIntArrayFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
    static void ConvAscii( unsigned char* pIn, u4 dwLen, unsigned char* pOut );
	static char* ItoA(s4 value, char* str, s4 radix);
	static u8 MakeCheckValue(const unsigned char * pBuf, unsigned int length);
	static u8 MakeUniqueId();
	static std::string MakeIntString(unsigned int number, int width);
	static bool ReadBoolFromVector(std::vector<u1> from, CK_ULONG_PTR idx);
    static void toStringHex( unsigned char a_ucIn, std::string& a_stOut );
	static void fromStringHex(const char* a_stHex, size_t hexLen, unsigned char* pOut);

	// return false if the certificate is already present on the list
	static bool AddCertToList(X509* cert, std::list<X509*>& certList);
	static bool DeleteCertFromList(X509* cert, std::list<X509*>& certList);
	static void FreeCertList(std::list<X509*>& certList);
	static bool ParsePkcs7(unsigned char* pbData, int iLength, std::list<X509*>& certList);
	static bool CreatePkcs7(const std::list<X509*>& certList, std::vector<unsigned char>& p7Bytes);
	
#ifndef _WIN32	
	static std::string toBase64(const unsigned char * pBuf, unsigned int length);
	static std::vector<u1> fromBase64(const char* szbase64);
#endif

private:
    static R_RANDOM_STRUCT _randomStruct;

};

void EncryptMemory(unsigned char* ptr, unsigned long length);
void DecryptMemory(unsigned char* ptr, unsigned long length);

#ifndef _WIN32
inline void* SecureZeroMemory (void* ptr, size_t cnt)
{
    char *vptr = (char *)ptr;

    while (cnt) {
        *vptr = 0;
        vptr++;
        cnt--;
    }
    return ptr;
}
#endif


class u1ArraySerializable
{
protected:
   mutable u1Array* m_array;
public:
   u1ArraySerializable() : m_array(NULL) {}
   explicit u1ArraySerializable(s4 nelement) : m_array(NULL) 
   {
      if (nelement) m_array = new u1Array(nelement);
   }
   u1ArraySerializable(u1Array& arr) : m_array(NULL) 
   {
      if (arr.GetLength())
         m_array = new u1Array(arr);
   }
   
   explicit u1ArraySerializable(u1Array* arr) : m_array(NULL) 
   {
      if (arr)
      {
         if (arr->GetLength())
         {
            m_array = new u1Array(*arr);
         }
          delete arr;
      }
   }
   
   u1ArraySerializable(const u1ArraySerializable& arr) : m_array(NULL)
   {     
      if (!arr.IsNull())
         m_array = new u1Array(*arr.m_array);
   }
   ~u1ArraySerializable()
   {
      reset();
   }

   u1ArraySerializable& operator = (const u1ArraySerializable& arr)
   {
      reset();
      if (arr.m_array && arr.m_array->GetLength())
         m_array = new u1Array(*arr.m_array);
      return *this;
   }

   bool IsNull() const
   {
      if (m_array && m_array->GetLength())
         return false;
      else
         return true;
   }


   inline void reset( void ) 
   { 
	   if (m_array) 
	   { 
		   delete m_array; 
		   m_array = NULL; 
	   }
   }

   inline void reset( unsigned int a_uiLength ) 
   {
      reset();
      if (a_uiLength) 
      {
         m_array = new u1Array(a_uiLength);
         unsigned char* buffer = new unsigned char[ a_uiLength ]; 
         memset( buffer, 0, a_uiLength );
         m_array->SetBuffer(buffer);
         delete [] buffer;
      }
   }

   inline void reset( u1Array* a_pArray ) 
   { 
      reset(); 
      if( a_pArray && a_pArray->GetLength()) 
      { 
         m_array = a_pArray;
      } 
      else
         delete a_pArray;
   }



   u1Array* GetArray() const 
   { 
      return (u1Array*) m_array;
   }
   
   u1Array* CloneArray() const 
   { 
      if (m_array)
         return new u1Array(*m_array);
      else
         return NULL;
   }

   u4  GetLength(void) const 
   { 
      if (m_array)
         return m_array->GetLength();
      else
         return 0;
   }
   void  SetBuffer(u1* buffer) 
   {
      if (m_array && m_array->GetLength())
         m_array->SetBuffer(buffer);
      else
         throw InvalidOperationException("");
   }
   u1*  GetBuffer(void) const 
   { 
      if (m_array && m_array->GetLength())
         return m_array->GetBuffer();
      else
         return NULL;
   }


	///////////////////////////
	// Disk cache management //
	//////////////////////////

#ifndef NO_FILESYSTEM

    // Serialization and deserialization of this array
    friend class boost::serialization::access;

	template< class Archive > void save( Archive& ar, const unsigned int /*version*/ ) const {

        u4 _length = GetLength();
		ar << _length ;
        if (_length)
		    ar.save_binary( GetBuffer(), GetLength() );
	}

	template< class Archive > void load( Archive& ar, const unsigned int version ) {

      u4 _length = 0;
      unsigned char* buffer = NULL;
      if (version != 128)
          throw boost::archive::archive_exception(boost::archive::archive_exception::unsupported_class_version);

      ar >> _length;		       
      reset();
      if( _length > 0 ) {

		   buffer = new unsigned char[ _length ];
		
		   ar.load_binary( buffer, _length );

         m_array = new u1Array(_length);
         m_array->SetBuffer(buffer);
         delete buffer;
      }
	}

	BOOST_SERIALIZATION_SPLIT_MEMBER( )

#endif
};

#ifndef NO_FILESYSTEM
BOOST_CLASS_VERSION( u1ArraySerializable,128 )
#endif

/****************************************
 * This class is used to erase sensitive 
 * PIN data held by u1Array when destructor
 * is called
 ****************************************/

 class u1ArraySecure : public u1Array
 {
 public:
	 u1ArraySecure(s4 nelement) : u1Array(nelement) {}
	 ~u1ArraySecure() { SecureZeroMemory(GetBuffer(), GetLength());}
 };


/*
 * SIZE must be a multiple of 16
 */

/*
 * This class implement a memory page that can handle
 * COUNT number of arrays each one having SIZE bytes
 * Arrays are positionned using a random permutation
 * An extra SIZE bytes array is allocated to implement
 * random start index
 */
template <int COUNT, int SIZE>
class CMemPage
{
protected:
   unsigned char* m_pbRealPage;
   unsigned char* m_pbPageStart;
   int            m_permutation[COUNT];
   bool           m_bTaken[COUNT];
   bool           m_bVirtualPage;

   void CreateRandomPermutation()
   {
      unsigned int seed = (unsigned int) time(NULL);
      srand(seed);
      for (int i = 0; i < COUNT; ++i) {
         int j = rand() % (i + 1);
         m_permutation[i] = m_permutation[j];
         m_permutation[j] = i;
      }
   }

#ifndef _WIN32
	#define MEM_DECOMMIT 0x4000
	#define MEM_RELEASE  0x8000
	
	// Dummy implementation for virtual memory functions
	void* VirtualAlloc(void* ,size_t , unsigned long ,unsigned long )
	{
		return NULL;
	}

	int VirtualLock(void* , size_t ) { return 0;}
	int VirtualUnlock(void* ,size_t ) { return 0;}
	int VirtualFree(void* , size_t , unsigned long ) { return 0;}
#endif

   void Initialize()
   {
      m_pbRealPage = (unsigned char*) VirtualAlloc(NULL, (COUNT + 1) * SIZE, 0x3000 /*MEM_COMMIT | MEM_RESERVE*/, 0x04 /*PAGE_READWRITE*/);
      if (m_pbRealPage)
      {
         m_bVirtualPage = true;
         VirtualLock(m_pbRealPage, (COUNT + 1) * SIZE);
      }
      else
      {
         m_bVirtualPage = false;
         m_pbRealPage = new unsigned char[(COUNT + 1) * SIZE];
      }
      for (int i=0; i < COUNT; i++)
         m_bTaken[i] = false;
      CreateRandomPermutation();
      m_pbPageStart = m_pbRealPage + (rand() % SIZE); // we will start from a random place
   }

public:
   CMemPage()
   {
      Initialize();
   }
   
   ~CMemPage()
   {
      memset(m_pbRealPage, 0, (COUNT + 1) * SIZE);
      if (m_bVirtualPage)
      {
         VirtualUnlock(m_pbRealPage, (COUNT + 1) * SIZE);
         VirtualFree(m_pbRealPage, 0, MEM_RELEASE);
      }
      else
      {
         delete [] m_pbRealPage;
      }
   }

   bool IsInRange(unsigned char* ptr)
   {
      return   (ptr >= m_pbPageStart)
            && (ptr <= (m_pbPageStart + ((COUNT - 1) * SIZE)))
            && ((ptr - m_pbPageStart) % SIZE == 0);
   }

   unsigned char* GetAddress()
   {
      int i = 0;
      for (i = 0; i < COUNT; i++)
      {
         if (!m_bTaken[i])
            break;
      }
      if (i == COUNT)
      {
         // no more place
         return NULL;
      }
      else
      {
         int index = m_permutation[i];
         m_bTaken[i] = true;
         return m_pbPageStart + (index * SIZE);
      }
   }

   void ReleaseAddress(unsigned char* ptr)
   {
      if ( IsInRange(ptr))
      {
         size_t index = (ptr - m_pbPageStart) / SIZE, i;
         for (i=0; i < COUNT; i++)
         {
            if (index == (size_t)m_permutation[i])
            {
               m_bTaken[i] = false;
               SecureZeroMemory(ptr, SIZE);
               break;
            }
         }
      }
   }
};

/*
 * This class implements a memory allocator that uses CMemPage
 * in order to allocate buffers of 512 bytes
 * The CMemPage template is instanciated with COUNT = 16
 */

class CSecureAllocator
{
protected:
   std::vector<CMemPage<16, 512>*> m_pMemoryPools;

   void Initialize()
   {
      m_pMemoryPools.push_back(new CMemPage<16, 512>());
   }

   void Finalize()
   {
      size_t count = m_pMemoryPools.size();
      for (size_t i=0; i<count; i++)
         delete m_pMemoryPools[i];
      m_pMemoryPools.clear();
   }

public:

   CSecureAllocator()
   {
      Initialize();    
   }

   ~CSecureAllocator()
   {
      Finalize();
   }

   unsigned char* Allocate()
   {
      unsigned char* ptr = NULL;
      size_t count = m_pMemoryPools.size();
      for (size_t i=0; i<count; i++)
      {
         ptr = m_pMemoryPools[i]->GetAddress();
         if (ptr != NULL)
         {
            break;
         }
      }
      if (!ptr)
      {
         CMemPage<16, 512>* pPage = new CMemPage<16, 512>();
         ptr = pPage->GetAddress();
         m_pMemoryPools.push_back(pPage);
      }

      return ptr;
   }

   void Free(unsigned char* ptr)
   {
      size_t count = m_pMemoryPools.size();
      for (size_t i=0; i<count; i++)
      {
         if (m_pMemoryPools[i]->IsInRange(ptr))
         {
            m_pMemoryPools[i]->ReleaseAddress(ptr);
            break;
         }
      }   
   }
};


/*
 * This class implements a String container whose content is always encrypted
 * The address of the internal buffer is randomized using the secure allocatore
 */

class CSecureString
{
protected:
   unsigned char *m_pbData;
   int            m_cbData;
   R_RANDOM_STRUCT m_encRng;
   static CSecureAllocator g_Allocator;
   
   void Allocate()
   {   	
      m_pbData = g_Allocator.Allocate();
	  // initialize random	  
	  time_t t = time(NULL);
	  clock_t cl = clock();
	  R_RandomInit(&m_encRng);
	  R_RandomUpdate(&m_encRng, (unsigned char*)(&t), sizeof(t));
	  R_RandomUpdate(&m_encRng, (unsigned char*)(&cl), sizeof(cl));
   }

public:
   CSecureString()
   {  
      Allocate();
      Reset();
   }

   CSecureString(const CSecureString& str)
   { 
      Allocate();
      m_cbData = str.m_cbData;
      memcpy(m_pbData, str.m_pbData, 512);
   }

   ~CSecureString()
   {
      g_Allocator.Free(m_pbData);
	  m_cbData = 0;
	  m_pbData = NULL;
	  R_RandomFinal(&m_encRng);
   }

   void Reset()
   {
      m_cbData = 0;
      //R_GenerateBytes(m_pbData, 512, &m_encRng);
   }

   void CopyFrom(const unsigned char* szText, unsigned long length)
   {
      if (length == 0)
         Reset();
      else
      {
         if (length > 512)
            length = 512;
         m_cbData = (int) length;
         memcpy(m_pbData, szText, length);
         EncryptMemory(m_pbData, 512);        
      }
   }

   void CopyTo(unsigned char* pbBuffer)
   {
      if (m_cbData > 0)
      {
         DecryptMemory(m_pbData, 512);
         memcpy(pbBuffer, m_pbData, m_cbData);
         EncryptMemory(m_pbData, 512);        
      }
   }

   int GetLength() const { return m_cbData;}
   bool IsEmpty() const { return m_cbData == 0;}

   CSecureString& operator = (const CSecureString& str)
   {
      m_cbData = str.m_cbData;
      memcpy(m_pbData, str.m_pbData, 512);
      return *this;
   }
};

/*
 * return the decoded message length or -1 on error
 */
int DecodeOAEP(unsigned char *to, int tlen,
                const unsigned char *from, int flen, 
                int modulusLen, const EVP_MD *dgst,
	            const unsigned char *param, int plen);

/*
 * return 1 on success, 0 on error
 */
int EncodeOAEP(unsigned char *to, int tlen /* tlen is modulus size in bytes*/,
	const unsigned char *from, int flen, const EVP_MD *dgst,
	const unsigned char *param, int plen);

/*
 * return 1 on success, 0 on error
 */
int VerifyPSS(int modulusBitLength, const unsigned char *mHash,
    const EVP_MD *Hash, const EVP_MD *mgf1Hash,
    const unsigned char *EM, int saltLen);

/*
 * return 1 on success, 0 on error
 */
int EncodePSS(int modulusBitLength, unsigned char *EM,
    const unsigned char *mHash,	const EVP_MD *Hash, 
    const EVP_MD *mgf1Hash, int saltLen);

#ifndef _WIN32

u4 GetTickCount();

#endif


/*
 * Compute the 3DES cryptogram used for External Authentication
 */
void ComputeCryptogram (   unsigned char* pbTripleDesKey, // 24 bytes
                           unsigned char* pbChallenge,
                           unsigned long challengeLength, // multiple of 8
                           unsigned char* pbCryptogram // same length as challenge
                        );



#endif

