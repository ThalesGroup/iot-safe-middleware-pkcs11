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
#include "EccUtils.h"
#include <string.h>

#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>


CEcNamedCurve CEcNamedCurve::g_P256Curve(CEcNamedCurve::P_256);
CEcNamedCurve CEcNamedCurve::g_P384Curve(CEcNamedCurve::P_384);
CEcNamedCurve CEcNamedCurve::g_P521Curve(CEcNamedCurve::P_521);


/*
 * Under Windows 7, OpenSSL random generator has performance issues, so we use MS one
 */
CRandomGenerator::CRandomGenerator()
#ifdef _WIN32
    : m_hProv(NULL)
#endif
{
#ifdef _WIN32
    if (!CryptAcquireContext(&m_hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
#endif
    {
        // should never happen under Windows
        time_t t = time(NULL);
        RAND_seed(&t, sizeof(t));
    }
}

CRandomGenerator::~CRandomGenerator()
{
#ifdef _WIN32
    if (m_hProv)
        CryptReleaseContext(m_hProv, 0);
#endif
}

void CRandomGenerator::generate(unsigned char* pbRnd, unsigned long ulRndLength)
{
#ifdef _WIN32
    if (!m_hProv || !CryptGenRandom(m_hProv, ulRndLength, pbRnd))
#endif
        RAND_bytes(pbRnd, ulRndLength); // should never happen under Windows
}

#ifdef _WIN32
/*
 * Custom EC key generation implementation in order to use our own random generator for performance reason
 */
int generateOpensslEcKey(EC_GROUP* ecgroup, EC_KEY *eckey)
{	
    int	ok = 0;
    BN_CTX	*ctx = NULL;
    BIGNUM	*priv_key = NULL, *tmp = NULL, *order = NULL;
    EC_POINT *pub_key = NULL;
    unsigned char* buffer = NULL;
    int len;
    CRandomGenerator rng;

    if ((order = BN_new()) == NULL) goto err;
    if ((priv_key = BN_new()) == NULL) goto err;   
    if ((tmp = BN_new()) == NULL) goto err;   
    if ((ctx = BN_CTX_new()) == NULL) goto err;
    if ((pub_key = EC_POINT_new(ecgroup)) == NULL) goto err;

    if (!EC_GROUP_get_order(ecgroup, order, ctx))
        goto err;

    len = BN_num_bytes(order);
    buffer = (unsigned char*) OPENSSL_malloc(len);
    do
    {
        rng.generate(buffer, len);
        BN_bin2bn(buffer, len, tmp);
        BN_mod(priv_key, tmp, order, ctx);
    }
    while (BN_is_zero(priv_key));

    if (!EC_POINT_mul(ecgroup, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_public_key(eckey, pub_key);
    EC_KEY_set_private_key(eckey, priv_key);

    ok=1;

err:	
    if (buffer)
        OPENSSL_free(buffer);
    if (order)
        BN_free(order);
    if (pub_key  != NULL)
        EC_POINT_free(pub_key);
    if (priv_key != NULL)
        BN_free(priv_key);
    if (tmp != NULL)
        BN_free(tmp);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return(ok);
}
#endif


/*
 *
 */
u1Array CEcPoint::serialize(bool bCompress) const
{
    if (bCompress)
        return m_X;
    else
    {
        u1Array result(1 + m_X.GetLength() + m_Y.GetLength());
        u1* ptr = result.GetBuffer();
        *ptr = 0x04;
        memcpy(ptr + 1, m_X.GetBuffer(), m_X.GetLength());
        memcpy(ptr + 1 + m_X.GetLength(), m_Y.GetBuffer(), m_Y.GetLength());

        return result;
    }
}

bool CEcPoint::isEqual(const CEcPoint& point) const
{
    bool bStatus = false;
    BIGNUM *x, *y;
    BIGNUM *x1, *y1;

    x = BN_bin2bn(m_X.GetBuffer(), m_X.GetLength(), NULL);
    y = BN_bin2bn(m_Y.GetBuffer(), m_Y.GetLength(), NULL);
    x1 = BN_bin2bn(point.m_X.GetBuffer(), point.m_X.GetLength(), NULL);
    y1 = BN_bin2bn(point.m_Y.GetBuffer(), point.m_Y.GetLength(), NULL);

    bStatus = (0 == BN_cmp(x, x1)) && (0 == BN_cmp(y, y1));

    BN_free(x); BN_free(x1);
    BN_free(y); BN_free(y1);

    return bStatus;
}

bool CEcCurveBase::isEqual(const CEcCurveBase& curve) const
{
    bool bStatus = false;
    if ((m_bitSize == curve.m_bitSize) && ( m_pG->IsEqual(*curve.m_pG)) )
    {
        BIGNUM *p, *a, *b, *n, *h;
        BIGNUM *p1, *a1, *b1, *n1, *h1;

        p = BN_bin2bn(m_pPrime->GetBuffer(), m_pPrime->GetLength(), NULL);
        a = BN_bin2bn(m_pA->GetBuffer(), m_pA->GetLength(), NULL);
        b = BN_bin2bn(m_pB->GetBuffer(), m_pB->GetLength(), NULL);
        n = BN_bin2bn(m_pN->GetBuffer(), m_pN->GetLength(), NULL);
        h = BN_bin2bn(m_pH->GetBuffer(), m_pH->GetLength(), NULL);

        p1 = BN_bin2bn(curve.getP()->GetBuffer(), curve.getP()->GetLength(), NULL);
        a1 = BN_bin2bn(curve.getA()->GetBuffer(), curve.getA()->GetLength(), NULL);
        b1 = BN_bin2bn(curve.getB()->GetBuffer(), curve.getB()->GetLength(), NULL);
        n1 = BN_bin2bn(curve.getN()->GetBuffer(), curve.getN()->GetLength(), NULL);
        h1 = BN_bin2bn(curve.getH()->GetBuffer(), curve.getH()->GetLength(), NULL);

        bStatus = (0 == BN_cmp(p, p1)) && (0 == BN_cmp(a, a1)) && 
            (0 == BN_cmp(b, b1)) && (0 == BN_cmp(n, n1)) && (0 == BN_cmp(h, h1));

        BN_free(p); BN_free(a); BN_free(b); BN_free(n); BN_free(h);
        BN_free(p1); BN_free(a1); BN_free(b1); BN_free(n1); BN_free(h1);
    }

    return bStatus;
}

u1Array CEcCurveBase::serialize() const
{
    int bitSize = getBitSize();
    int componenetLength = (bitSize + 7) / 8;

    u1Array result(5 * componenetLength + 1 + m_pN->GetLength());

    u1* ptr = result.GetBuffer();
    memcpy(ptr                         , m_pPrime->GetBuffer(), componenetLength);
    memcpy(ptr +   componenetLength    , m_pA->GetBuffer(), componenetLength);
    memcpy(ptr + 2*componenetLength    , m_pB->GetBuffer(), componenetLength);
    memcpy(ptr + 3*componenetLength    , m_pG->GetBuffer(), 2*componenetLength + 1);
    memcpy(ptr + 5*componenetLength + 1, m_pN->GetBuffer(), m_pN->GetLength());

    return result;
}

CEcKey* CEcCurveBase::generateKey() const
{
    BIGNUM *p, *a, *b, *n, *h;

    p = BN_bin2bn(m_pPrime->GetBuffer(), m_pPrime->GetLength(), NULL);
    a = BN_bin2bn(m_pA->GetBuffer(), m_pA->GetLength(), NULL);
    b = BN_bin2bn(m_pB->GetBuffer(), m_pB->GetLength(), NULL);
    n = BN_bin2bn(m_pN->GetBuffer(), m_pN->GetLength(), NULL);
    h = BN_bin2bn(m_pH->GetBuffer(), m_pH->GetLength(), NULL);

    // create an OpenSSL EC curve
    bool bIsValid = false;
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP *ecgroup= EC_GROUP_new_curve_GFp(p, a, b, ctx);

    EC_POINT* Generator = EC_POINT_new(ecgroup);
    if (EC_POINT_oct2point(ecgroup, Generator, m_pG->GetBuffer(), m_pG->GetLength(), ctx))
    {
	    if (EC_GROUP_set_generator(ecgroup, Generator, n, h))
        {
            bIsValid = true;
        }
    }

    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(n);
    BN_free(h);
    EC_POINT_free(Generator);

    if (!bIsValid)
    {
        BN_CTX_free(ctx);
        EC_GROUP_free(ecgroup);
        return NULL;
    }

    
    // Generate random EC key with OpenSSL
    EC_KEY *eckey=EC_KEY_new();
    EC_KEY_set_group(eckey,ecgroup);
#ifdef _WIN32
    generateOpensslEcKey(ecgroup, eckey); 
#else
    EC_KEY_generate_key(eckey);
#endif

    // Get the public point
    const EC_POINT* pubPoint = EC_KEY_get0_public_key(eckey);
    
    unsigned long ulUncompressedPointLength = EC_POINT_point2oct(ecgroup, pubPoint, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    unsigned char* pbUncompressedPoint = new unsigned char[ulUncompressedPointLength];
    ulUncompressedPointLength = EC_POINT_point2oct(ecgroup, pubPoint, POINT_CONVERSION_UNCOMPRESSED, pbUncompressedPoint, ulUncompressedPointLength, ctx);

    // first byte is 0x04, so we skip it
    unsigned long ulComponentLength = (ulUncompressedPointLength - 1) / 2;
    CEcPoint publicPoint(pbUncompressedPoint + 1, pbUncompressedPoint + 1 + ulComponentLength, ulComponentLength);

    delete [] pbUncompressedPoint;
    BN_CTX_free(ctx);

    // Get the private value
    const BIGNUM* prvVal = EC_KEY_get0_private_key(eckey);
    unsigned long ulPrivateKeyLength = BN_num_bytes(prvVal);
    unsigned char* pbPrivateKey = new unsigned char[ulPrivateKeyLength];
    BN_bn2bin(prvVal, pbPrivateKey);

    CEcKey* privateKey = new CEcKey(this, publicPoint, pbPrivateKey, ulPrivateKeyLength);

    // free OpenSSL resources
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);

    //
    return privateKey;
}


CEcNamedCurve::CEcNamedCurve(CURVE_NAME curveName) : CEcCurveBase(), m_curveName(curveName), m_pOID(NULL)
{
    switch(curveName)
    {
        case P_256: m_bitSize = 256; break;
        case P_384: m_bitSize = 384; break;
        case P_521: m_bitSize = 521; break;
    }

    initOID();
    initP();
    initA();
    initB();
    initG();
    initN();
    initH();
}

void CEcNamedCurve::initOID()
{
    switch(m_curveName)
    {
    case P_256: m_pOID = new u1Array((u1*) ECC_256_OID, sizeof(ECC_256_OID) - 1); break;
    case P_384: m_pOID = new u1Array((u1*) ECC_384_OID, sizeof(ECC_384_OID) - 1); break;
    case P_521: m_pOID = new u1Array((u1*) ECC_521_OID, sizeof(ECC_521_OID) - 1); break;
    }
}

void CEcNamedCurve::initP()
{
    int componenetLength = (m_bitSize + 7) / 8;
    switch(m_curveName)
    {
    case P_256: m_pPrime = new u1Array((u1*) ECC_256_P, componenetLength); break;
    case P_384: m_pPrime = new u1Array((u1*) ECC_384_P, componenetLength); break;
    case P_521: m_pPrime = new u1Array((u1*) ECC_521_P, componenetLength); break;    
    }
}

void CEcNamedCurve::initA()
{
    int componenetLength = (m_bitSize + 7) / 8;
    switch(m_curveName)
    {
    case P_256: m_pA = new u1Array((u1*) ECC_256_A, componenetLength); break;
    case P_384: m_pA =  new u1Array((u1*) ECC_384_A, componenetLength); break;
    case P_521: m_pA =  new u1Array((u1*) ECC_521_A, componenetLength); break;
    }
}

void CEcNamedCurve::initB()
{
    int componenetLength = (m_bitSize + 7) / 8;
    switch(m_curveName)
    {
    case P_256: m_pB = new u1Array((u1*) ECC_256_B, componenetLength); break;
    case P_384: m_pB = new u1Array((u1*) ECC_384_B, componenetLength); break;
    case P_521: m_pB = new u1Array((u1*) ECC_521_B, componenetLength); break;
    }
}

void CEcNamedCurve::initG()
{
    int componenetLength = (m_bitSize + 7) / 8;
    switch(m_curveName)
    {
    case P_256: m_pG = new u1Array((u1*) ECC_256_GXY, 2*componenetLength + 1); break;
    case P_384: m_pG = new u1Array((u1*) ECC_384_GXY, 2*componenetLength + 1); break;
    case P_521: m_pG = new u1Array((u1*) ECC_521_GXY, 2*componenetLength + 1); break;
    }
}

void CEcNamedCurve::initN()
{
    int componenetLength = (m_bitSize + 7) / 8;
    switch(m_curveName)
    {
    case P_256: m_pN = new u1Array((u1*) ECC_256_N, componenetLength); break;
    case P_384: m_pN = new u1Array((u1*) ECC_384_N, componenetLength); break;
    case P_521: m_pN = new u1Array((u1*) ECC_521_N, componenetLength); break;
    }
}

void CEcNamedCurve::initH()
{
    switch(m_curveName)
    {
    case P_256: m_pH = new u1Array((u1*) ECC_256_H, 1); break;
    case P_384: m_pH = new u1Array((u1*) ECC_384_H, 1); break;
    case P_521: m_pH = new u1Array((u1*) ECC_521_H, 1); break;
    }
}


CEcGenericCurve::CEcGenericCurve(const unsigned char* pbPrime, unsigned long ulPrimeLength,
        const unsigned char* pbA, unsigned long ulA,
        const unsigned char* pbB, unsigned long ulB,
        const unsigned char* pbG, unsigned long ulG,
        const unsigned char* pbN, unsigned long ulN,
        const unsigned char* pbH, unsigned long ulH) : CEcCurveBase()
{
    m_pPrime = new u1Array(pbPrime, ulPrimeLength);
    m_pA = new u1Array(pbA, ulA);
    m_pB = new u1Array(pbB, ulB);
    m_pG = new u1Array(pbG, ulG);
    m_pN = new u1Array(pbN, ulN);
    m_pH = new u1Array(pbH, ulH);

    // compute bit size
    BIGNUM* p = BN_bin2bn(pbPrime, ulPrimeLength, NULL);
    m_bitSize = BN_num_bits(p);
    BN_free(p);
}

static EC_GROUP* createEcGroup(CEcKey* pEcKey)
{
    BIGNUM *p, *a, *b, *n, *h;
    const CEcCurveBase& curve = pEcKey->getCurve();

    p = BN_bin2bn(curve.getP()->GetBuffer(), curve.getP()->GetLength(), NULL);
    a = BN_bin2bn(curve.getA()->GetBuffer(), curve.getA()->GetLength(), NULL);
    b = BN_bin2bn(curve.getB()->GetBuffer(), curve.getB()->GetLength(), NULL);
    n = BN_bin2bn(curve.getN()->GetBuffer(), curve.getN()->GetLength(), NULL);
    h = BN_bin2bn(curve.getH()->GetBuffer(), curve.getH()->GetLength(), NULL);

    // create an OpenSSL EC curve
    bool bIsValid = false;
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP *ecgroup= EC_GROUP_new_curve_GFp(p, a, b, ctx);

    EC_POINT* Generator = EC_POINT_new(ecgroup);
    if (EC_POINT_oct2point(ecgroup, Generator, curve.getG()->GetBuffer(), curve.getG()->GetLength(), ctx))
    {
	    if (EC_GROUP_set_generator(ecgroup, Generator, n, h))
        {
            bIsValid = true;
        }
    }

    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(n);
    BN_free(h);
    BN_CTX_free(ctx);
    EC_POINT_free(Generator);

    if (!bIsValid)
    {
        EC_GROUP_free(ecgroup);
        return NULL;
    }
    else
        return ecgroup;
}


u1Array* CEcKey::deriveSharedSecret(const CEcPoint& peerPublicPoint)
{
    u1Array* result = NULL;
    
    EC_GROUP *ecgroup= createEcGroup(this);
    if (!ecgroup)
        return NULL;

    EC_KEY *eckey=EC_KEY_new();
    EC_KEY_set_group(eckey,ecgroup);

    // Set the public point value
    BN_CTX* ctx = BN_CTX_new();
    u1Array pPubPointArray = m_publicPoint.serialize();
    EC_POINT* pubPoint = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubPoint, pPubPointArray.GetBuffer(), pPubPointArray.GetLength(), ctx);

    EC_KEY_set_public_key(eckey, pubPoint);
    EC_POINT_free(pubPoint);

    // set the private key value
    BIGNUM* prvVal = BN_bin2bn(m_privateFactor.GetBuffer(), m_privateFactor.GetLength(), NULL);
    EC_KEY_set_private_key(eckey, prvVal);
    BN_free(prvVal);

    // construct peer point
    u1Array pointEncoding = peerPublicPoint.serialize();
    pubPoint = EC_POINT_new(ecgroup);
    if (EC_POINT_oct2point(ecgroup, pubPoint, pointEncoding.GetBuffer(), pointEncoding.GetLength(), ctx))
    {
        unsigned char ecdhVal[256];
        int ecdhLen = 256;
        ecdhLen = ECDH_compute_key(ecdhVal, ecdhLen, pubPoint, eckey, NULL);
        if (ecdhLen > 0)
        {
            result = new u1Array(ecdhVal, ecdhLen);
        }
    }

    EC_POINT_free(pubPoint);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    EC_GROUP_free(ecgroup);

    return result;
}


bool CEcKey::sign(const u1Array& hash, u1Array& signature)
{
    signature.Clear();

    EC_GROUP *ecgroup= createEcGroup(this);
    if (!ecgroup)
        return false;

    EC_KEY *eckey=EC_KEY_new();
    EC_KEY_set_group(eckey,ecgroup);

    // Set the public point value
    BN_CTX* ctx = BN_CTX_new();
    u1Array pPubPointArray = m_publicPoint.serialize();
    EC_POINT* pubPoint = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubPoint, pPubPointArray.GetBuffer(), pPubPointArray.GetLength(), ctx);
    BN_CTX_free(ctx);

    EC_KEY_set_public_key(eckey, pubPoint);
    EC_POINT_free(pubPoint);

    // set the private key value
    BIGNUM* prvVal = BN_bin2bn(m_privateFactor.GetBuffer(), m_privateFactor.GetLength(), NULL);
    EC_KEY_set_private_key(eckey, prvVal);
    BN_free(prvVal);

      
    ECDSA_SIG* sig = ECDSA_do_sign(hash.GetBuffer(), hash.GetLength(), eckey);
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);  
    
    if (!sig)
        return NULL;

    // fill the signature byte array by concatenating r and s
    int nLen = (getBitSize() + 7) / 8;
    signature.Resize(2 * nLen);
    u1* pbSignature = signature.GetBuffer(); 
    const BIGNUM *r=NULL,*s=NULL;
    ECDSA_SIG_get0(sig, &r, &s);	

    int rLen = BN_num_bytes(r);
    if (rLen == nLen)
        BN_bn2bin(r, pbSignature);
    else
    {
        memset(pbSignature, 0, nLen - rLen);
        BN_bn2bin(r, pbSignature + (nLen - rLen) );
    }

    int sLen = BN_num_bytes(s);
    if (sLen == nLen)
        BN_bn2bin(s, pbSignature + nLen);
    else
    {
        memset(pbSignature + nLen, 0, nLen - sLen);
        BN_bn2bin(s, pbSignature + nLen + (nLen - sLen));
    }

    ECDSA_SIG_free(sig);

    return true;
}


bool CEcKey::verify(const u1Array& hash, const u1Array& signature)
{
    EC_GROUP *ecgroup= createEcGroup(this);
    if (!ecgroup)
        return false;

    EC_KEY *eckey=EC_KEY_new();
    EC_KEY_set_group(eckey,ecgroup);

    // Set the public point value
    BN_CTX* ctx = BN_CTX_new();
    u1Array pPubPointArray = m_publicPoint.serialize();
    EC_POINT* pubPoint = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubPoint, pPubPointArray.GetBuffer(), pPubPointArray.GetLength(), ctx);
    BN_CTX_free(ctx);

    EC_KEY_set_public_key(eckey, pubPoint);
    EC_POINT_free(pubPoint);

    ECDSA_SIG* sig = ECDSA_SIG_new();
    const BIGNUM *r=NULL,*s=NULL;
    BIGNUM *rc=NULL,*sc=NULL;
    ECDSA_SIG_get0(sig, &r, &s);
    BN_copy(rc,r);
    BN_copy(sc,s);
    BN_bin2bn(signature.GetBuffer(), signature.GetLength()/2, rc);
    BN_bin2bn(signature.GetBuffer() + signature.GetLength()/2, signature.GetLength()/2, sc);

    int status = ECDSA_do_verify(hash.GetBuffer(), hash.GetLength(), sig, eckey);

    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);   
    ECDSA_SIG_free(sig);    

    return (status == 1);
}
