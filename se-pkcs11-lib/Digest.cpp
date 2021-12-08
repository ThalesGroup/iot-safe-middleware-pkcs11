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
#include <Windows.h>
#endif

#include <cstdlib>
#include <cstring>
#include "digest.h"
#include <memory>

#include <openssl/sha.h>
#include <openssl/md5.h>

/*
 * MD5 implementation
 */
class CMD5 : public CDigest
{
protected:
    MD5_CTX m_ctx;

public:
    CMD5() : CDigest(CDigest::MD5, MD5_DIGEST_LENGTH, MD5_CBLOCK)
    {
        MD5_Init(&m_ctx);
    }

    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length)
    {
        if (length)
            MD5_Update(&m_ctx, data + offset, length);
    }

    virtual void hashFinal( unsigned char* hash)
    {
        MD5_Final(hash, &m_ctx);
    }

    void getHashContext(u1Array& intermediateHash, u1Array& hashCounter)
    {
	    u4 A,B,C,D;
	    u4 Nl,Nh;

        A = ToBigEndian(m_ctx.A);
        B = ToBigEndian(m_ctx.B);
        C = ToBigEndian(m_ctx.C);
        D = ToBigEndian(m_ctx.D);

        Nl = ToBigEndian(m_ctx.Nl);
        Nh = ToBigEndian(m_ctx.Nh);

        intermediateHash.Resize(16);
        u1* ptr = intermediateHash.GetBuffer();
        memcpy(ptr    , &A, 4);
        memcpy(ptr + 4, &B, 4);
        memcpy(ptr + 8, &C, 4);
        memcpy(ptr + 12, &D, 4);

        
        hashCounter.Resize(8);
        ptr = hashCounter.GetBuffer();
        memcpy(ptr, &Nh, 4);
        memcpy(ptr + 4, &Nl, 4);

    }
};

/*
 * SHA-1 implementation
 */
class CSHA1 : public CDigest
{
protected:
    SHA_CTX m_ctx;

public:
    CSHA1() : CDigest(CDigest::SHA1, SHA_DIGEST_LENGTH, SHA_CBLOCK)
    {
        SHA1_Init(&m_ctx);
    }

    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length)
    {
        if (length)
            SHA1_Update(&m_ctx, data + offset, length);
    }

    virtual void hashFinal( unsigned char* hash)
    {
        SHA1_Final(hash, &m_ctx);
    }

    void getHashContext(u1Array& intermediateHash, u1Array& hashCounter)
    {
	    u4 h0,h1,h2,h3,h4;
	    u4 Nl,Nh;

        h0 = ToBigEndian(m_ctx.h0);
        h1 = ToBigEndian(m_ctx.h1);
        h2 = ToBigEndian(m_ctx.h2);
        h3 = ToBigEndian(m_ctx.h3);
        h4 = ToBigEndian(m_ctx.h4);

        Nl = ToBigEndian(m_ctx.Nl);
        Nh = ToBigEndian(m_ctx.Nh);

        intermediateHash.Resize(20);
        u1* ptr = intermediateHash.GetBuffer();
        memcpy(ptr    , &h0, 4);
        memcpy(ptr + 4, &h1, 4);
        memcpy(ptr + 8, &h2, 4);
        memcpy(ptr + 12, &h3, 4);
        memcpy(ptr + 16, &h4, 4);

        
        hashCounter.Resize(8);
        ptr = hashCounter.GetBuffer();
        memcpy(ptr, &Nh, 4);
        memcpy(ptr + 4, &Nl, 4);
    }
};

/*
 * SHA-224 implementation
 */
class CSHA224 : public CDigest
{
protected:
    SHA256_CTX m_ctx;

public:
    CSHA224() : CDigest(CDigest::SHA224, SHA224_DIGEST_LENGTH, SHA256_CBLOCK)
    {
        SHA224_Init(&m_ctx);
    }

    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length)
    {
        if (length)
            SHA224_Update(&m_ctx, data + offset, length);
    }

    virtual void hashFinal( unsigned char* hash)
    {
        SHA224_Final(hash, &m_ctx);
    }

    void getHashContext(u1Array& intermediateHash, u1Array& hashCounter)
    {
	    u4 h0,h1,h2,h3,h4,h5,h6,h7;
	    u4 Nl,Nh;

        h0 = ToBigEndian(m_ctx.h[0]);
        h1 = ToBigEndian(m_ctx.h[1]);
        h2 = ToBigEndian(m_ctx.h[2]);
        h3 = ToBigEndian(m_ctx.h[3]);
        h4 = ToBigEndian(m_ctx.h[4]);
        h5 = ToBigEndian(m_ctx.h[5]);
        h6 = ToBigEndian(m_ctx.h[6]);
        h7 = ToBigEndian(m_ctx.h[7]);

        Nl = ToBigEndian(m_ctx.Nl);
        Nh = ToBigEndian(m_ctx.Nh);

        intermediateHash.Resize(32);
        u1* ptr = intermediateHash.GetBuffer();
        memcpy(ptr    , &h0, 4);
        memcpy(ptr + 4, &h1, 4);
        memcpy(ptr + 8, &h2, 4);
        memcpy(ptr + 12, &h3, 4);
        memcpy(ptr + 16, &h4, 4);
        memcpy(ptr + 20, &h5, 4);
        memcpy(ptr + 24, &h6, 4);
        memcpy(ptr + 28, &h7, 4);
        
        hashCounter.Resize(8);
        ptr = hashCounter.GetBuffer();
        memcpy(ptr, &Nh, 4);
        memcpy(ptr + 4, &Nl, 4);
    }
};

/*
 * SHA-256 implementation
 */
class CSHA256 : public CDigest
{
protected:
    SHA256_CTX m_ctx;

public:
    CSHA256() : CDigest(CDigest::SHA256, SHA256_DIGEST_LENGTH, SHA256_CBLOCK)
    {
        SHA256_Init(&m_ctx);
    }

    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length)
    {
        if (length)
            SHA256_Update(&m_ctx, data + offset, length);
    }

    virtual void hashFinal( unsigned char* hash)
    {
        SHA256_Final(hash, &m_ctx);
    }

    void getHashContext(u1Array& intermediateHash, u1Array& hashCounter)
    {
	    u4 h0,h1,h2,h3,h4,h5,h6,h7;
	    u4 Nl,Nh;

        h0 = ToBigEndian(m_ctx.h[0]);
        h1 = ToBigEndian(m_ctx.h[1]);
        h2 = ToBigEndian(m_ctx.h[2]);
        h3 = ToBigEndian(m_ctx.h[3]);
        h4 = ToBigEndian(m_ctx.h[4]);
        h5 = ToBigEndian(m_ctx.h[5]);
        h6 = ToBigEndian(m_ctx.h[6]);
        h7 = ToBigEndian(m_ctx.h[7]);

        Nl = ToBigEndian(m_ctx.Nl);
        Nh = ToBigEndian(m_ctx.Nh);

        intermediateHash.Resize(32);
        u1* ptr = intermediateHash.GetBuffer();
        memcpy(ptr    , &h0, 4);
        memcpy(ptr + 4, &h1, 4);
        memcpy(ptr + 8, &h2, 4);
        memcpy(ptr + 12, &h3, 4);
        memcpy(ptr + 16, &h4, 4);
        memcpy(ptr + 20, &h5, 4);
        memcpy(ptr + 24, &h6, 4);
        memcpy(ptr + 28, &h7, 4);
        
        hashCounter.Resize(8);
        ptr = hashCounter.GetBuffer();
        memcpy(ptr, &Nh, 4);
        memcpy(ptr + 4, &Nl, 4);
    }
};

/*
 * SHA-384 implementation
 */
class CSHA384 : public CDigest
{
protected:
    SHA512_CTX m_ctx;

public:
    CSHA384() : CDigest(CDigest::SHA384, SHA384_DIGEST_LENGTH, SHA512_CBLOCK)
    {
        SHA384_Init(&m_ctx);
    }

    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length)
    {
        if (length)
            SHA384_Update(&m_ctx, data + offset, length);
    }

    virtual void hashFinal( unsigned char* hash)
    {
        SHA384_Final(hash, &m_ctx);
    }

    void getHashContext(u1Array& intermediateHash, u1Array& hashCounter)
    {
	    u8 h0,h1,h2,h3,h4,h5,h6,h7;
	    u8 Nl,Nh;

        h0 = ToBigEndian(m_ctx.h[0]);
        h1 = ToBigEndian(m_ctx.h[1]);
        h2 = ToBigEndian(m_ctx.h[2]);
        h3 = ToBigEndian(m_ctx.h[3]);
        h4 = ToBigEndian(m_ctx.h[4]);
        h5 = ToBigEndian(m_ctx.h[5]);
        h6 = ToBigEndian(m_ctx.h[6]);
        h7 = ToBigEndian(m_ctx.h[7]);

        Nl = ToBigEndian(m_ctx.Nl);
        Nh = ToBigEndian(m_ctx.Nh);

        intermediateHash.Resize(64);
        u1* ptr = intermediateHash.GetBuffer();
        memcpy(ptr    , &h0, 8);
        memcpy(ptr + 8, &h1, 8);
        memcpy(ptr + 16, &h2, 8);
        memcpy(ptr + 24, &h3, 8);
        memcpy(ptr + 32, &h4, 8);
        memcpy(ptr + 40, &h5, 8);
        memcpy(ptr + 48, &h6, 8);
        memcpy(ptr + 56, &h7, 8);
        
        hashCounter.Resize(16);
        ptr = hashCounter.GetBuffer();
        memcpy(ptr, &Nh, 8);
        memcpy(ptr + 8, &Nl, 8);
    }
};

/*
 * SHA-512 implementation
 */
class CSHA512 : public CDigest
{
protected:
    SHA512_CTX m_ctx;

public:
    CSHA512() : CDigest(CDigest::SHA512, SHA512_DIGEST_LENGTH, SHA512_CBLOCK)
    {
        SHA512_Init(&m_ctx);
    }

    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length)
    {
        if (length)
            SHA512_Update(&m_ctx, data + offset, length);
    }

    virtual void hashFinal( unsigned char* hash)
    {
        SHA512_Final(hash, &m_ctx);
    }

    void getHashContext(u1Array& intermediateHash, u1Array& hashCounter)
    {
	    u8 h0,h1,h2,h3,h4,h5,h6,h7;
	    u8 Nl,Nh;

        h0 = ToBigEndian(m_ctx.h[0]);
        h1 = ToBigEndian(m_ctx.h[1]);
        h2 = ToBigEndian(m_ctx.h[2]);
        h3 = ToBigEndian(m_ctx.h[3]);
        h4 = ToBigEndian(m_ctx.h[4]);
        h5 = ToBigEndian(m_ctx.h[5]);
        h6 = ToBigEndian(m_ctx.h[6]);
        h7 = ToBigEndian(m_ctx.h[7]);

        Nl = ToBigEndian(m_ctx.Nl);
        Nh = ToBigEndian(m_ctx.Nh);

        intermediateHash.Resize(64);
        u1* ptr = intermediateHash.GetBuffer();
        memcpy(ptr    , &h0, 8);
        memcpy(ptr + 8, &h1, 8);
        memcpy(ptr + 16, &h2, 8);
        memcpy(ptr + 24, &h3, 8);
        memcpy(ptr + 32, &h4, 8);
        memcpy(ptr + 40, &h5, 8);
        memcpy(ptr + 48, &h6, 8);
        memcpy(ptr + 56, &h7, 8);
        
        hashCounter.Resize(16);
        ptr = hashCounter.GetBuffer();
        memcpy(ptr, &Nh, 8);
        memcpy(ptr + 8, &Nl, 8);
    }
};

/*
 * Factory implementation
 */

CDigest* CDigest::getInstance(HASH_TYPE digestType)
{
    switch(digestType)
    {
        case CDigest::MD5: return new CMD5(); break;
        case CDigest::SHA1: return new CSHA1(); break;
        case CDigest::SHA224: return new CSHA224(); break;
        case CDigest::SHA256: return new CSHA256(); break;
        case CDigest::SHA384: return new CSHA384(); break;
        case CDigest::SHA512: return new CSHA512(); break;
        default: return NULL;
    }
}