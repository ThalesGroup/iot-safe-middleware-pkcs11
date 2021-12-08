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
#pragma once

#ifdef _WIN32
#include <Windows.h>
#include <WinCrypt.h>
#endif

#include <string>
#include <stdexcept>
#include "Array.h"

#define ECC_256_OID                     ("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07")
#define ECC_256_P                       ("\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
#define ECC_256_A                       ("\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC")
#define ECC_256_B                       ("\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B")
#define ECC_256_GXY                     ("\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5")
#define ECC_256_N                       ("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51")
#define ECC_256_H                       ("\x01")

#define ECC_384_OID                     ("\x06\x05\x2B\x81\x04\x00\x22")
#define ECC_384_P                       ("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF")
#define ECC_384_A                       ("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC")
#define ECC_384_B                       ("\xB3\x31\x2F\xA7\xE2\x3E\xE7\xE4\x98\x8E\x05\x6B\xE3\xF8\x2D\x19\x18\x1D\x9C\x6E\xFE\x81\x41\x12\x03\x14\x08\x8F\x50\x13\x87\x5A\xC6\x56\x39\x8D\x8A\x2E\xD1\x9D\x2A\x85\xC8\xED\xD3\xEC\x2A\xEF")
#define ECC_384_GXY                     ("\x04\xAA\x87\xCA\x22\xBE\x8B\x05\x37\x8E\xB1\xC7\x1E\xF3\x20\xAD\x74\x6E\x1D\x3B\x62\x8B\xA7\x9B\x98\x59\xF7\x41\xE0\x82\x54\x2A\x38\x55\x02\xF2\x5D\xBF\x55\x29\x6C\x3A\x54\x5E\x38\x72\x76\x0A\xB7\x36\x17\xDE\x4A\x96\x26\x2C\x6F\x5D\x9E\x98\xBF\x92\x92\xDC\x29\xF8\xF4\x1D\xBD\x28\x9A\x14\x7C\xE9\xDA\x31\x13\xB5\xF0\xB8\xC0\x0A\x60\xB1\xCE\x1D\x7E\x81\x9D\x7A\x43\x1D\x7C\x90\xEA\x0E\x5F")
#define ECC_384_N                       ("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC7\x63\x4D\x81\xF4\x37\x2D\xDF\x58\x1A\x0D\xB2\x48\xB0\xA7\x7A\xEC\xEC\x19\x6A\xCC\xC5\x29\x73")
#define ECC_384_H                       ("\x01")

#define ECC_521_OID                     ("\x06\x05\x2B\x81\x04\x00\x23")
#define ECC_521_P                       ("\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
#define ECC_521_A                       ("\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC")
#define ECC_521_B                       ("\x00\x51\x95\x3E\xB9\x61\x8E\x1C\x9A\x1F\x92\x9A\x21\xA0\xB6\x85\x40\xEE\xA2\xDA\x72\x5B\x99\xB3\x15\xF3\xB8\xB4\x89\x91\x8E\xF1\x09\xE1\x56\x19\x39\x51\xEC\x7E\x93\x7B\x16\x52\xC0\xBD\x3B\xB1\xBF\x07\x35\x73\xDF\x88\x3D\x2C\x34\xF1\xEF\x45\x1F\xD4\x6B\x50\x3F\x00")
#define ECC_521_GXY                     ("\x04\x00\xC6\x85\x8E\x06\xB7\x04\x04\xE9\xCD\x9E\x3E\xCB\x66\x23\x95\xB4\x42\x9C\x64\x81\x39\x05\x3F\xB5\x21\xF8\x28\xAF\x60\x6B\x4D\x3D\xBA\xA1\x4B\x5E\x77\xEF\xE7\x59\x28\xFE\x1D\xC1\x27\xA2\xFF\xA8\xDE\x33\x48\xB3\xC1\x85\x6A\x42\x9B\xF9\x7E\x7E\x31\xC2\xE5\xBD\x66\x01\x18\x39\x29\x6A\x78\x9A\x3B\xC0\x04\x5C\x8A\x5F\xB4\x2C\x7D\x1B\xD9\x98\xF5\x44\x49\x57\x9B\x44\x68\x17\xAF\xBD\x17\x27\x3E\x66\x2C\x97\xEE\x72\x99\x5E\xF4\x26\x40\xC5\x50\xB9\x01\x3F\xAD\x07\x61\x35\x3C\x70\x86\xA2\x72\xC2\x40\x88\xBE\x94\x76\x9F\xD1\x66\x50")
#define ECC_521_N                       ("\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA\x51\x86\x87\x83\xBF\x2F\x96\x6B\x7F\xCC\x01\x48\xF7\x09\xA5\xD0\x3B\xB5\xC9\xB8\x89\x9C\x47\xAE\xBB\x6F\xB7\x1E\x91\x38\x64\x09")
#define ECC_521_H                       ("\x01")


class CRandomGenerator
{
#ifdef _WIN32
protected:
    HCRYPTPROV m_hProv;
#endif

public:
    CRandomGenerator();
    ~CRandomGenerator();
    void generate(unsigned char* pbRnd, unsigned long ulRndLength);
};


class CEcPoint
{
protected:
    u1Array m_X;
    u1Array m_Y;

public:
    CEcPoint(const unsigned char* pbX, const unsigned char* pbY, unsigned long length) : m_X(pbX, length), m_Y(pbY, length) {}
    CEcPoint(const CEcPoint& point) : m_X(point.m_X), m_Y(point.m_Y) {}
    ~CEcPoint() {}

    const u1Array& getX() const { return m_X;}
    const u1Array& getY() const { return m_Y;}

    /* 
     * if bCompress = true, return the coordinate m_X
     * if bCompress = false, return 0x04 || m_X || m_Y
     */
    u1Array serialize(bool bCompress = false) const ;

    bool isEqual(const CEcPoint& point) const;
};

class CEcKey;

class CEcCurveBase
{

protected:
    CEcCurveBase() : m_pPrime(NULL), m_pA(NULL), m_pB(NULL), m_pG(NULL), m_pN(NULL), m_pH(NULL), m_bitSize(0)
    {}
    CEcCurveBase(const CEcCurveBase& curve) : 
        m_pPrime(new u1Array(*curve.m_pPrime)),
        m_pA(new u1Array(*curve.m_pA)), 
        m_pB(new u1Array(*curve.m_pB)), 
        m_pG(new u1Array(*curve.m_pG)), 
        m_pN(new u1Array(*curve.m_pN)), 
        m_pH(new u1Array(*curve.m_pH)),
        m_bitSize(curve.m_bitSize)
    {}

public:
    virtual ~CEcCurveBase() 
    {
        if (m_pPrime) delete m_pPrime;
        if (m_pA) delete m_pA;
        if (m_pB) delete m_pB;
        if (m_pG) delete m_pG;
        if (m_pN) delete m_pN;
        if (m_pH) delete m_pH;
    }

    virtual CEcCurveBase* clone() const  = 0;
    virtual int getBitSize() const { return m_bitSize;}

    virtual bool isEqual(const CEcCurveBase& curve) const;

    /* return the curve parameters as arrays */
    virtual const u1Array* getP() const { return m_pPrime; }
    virtual const u1Array* getA() const { return m_pA; }
    virtual const u1Array* getB() const { return m_pB; }
    virtual const u1Array* getG() const { return m_pG; } /* 0x04 || Gx || Gy */
    virtual const u1Array* getN() const { return m_pN; }
    virtual const u1Array* getH() const { return m_pH; }

    u1Array serialize() const;

    /**/
    virtual CEcKey* generateKey() const;

protected:
    u1Array* m_pPrime;
    u1Array* m_pA;
    u1Array* m_pB;
    u1Array* m_pG;
    u1Array* m_pN;
    u1Array* m_pH;
    int m_bitSize;
};

class CEcNamedCurve : public CEcCurveBase
{
public:
    typedef enum { P_256, P_384, P_521} CURVE_NAME;

    static CEcNamedCurve g_P256Curve;
    static CEcNamedCurve g_P384Curve;
    static CEcNamedCurve g_P521Curve;

    CEcNamedCurve(CURVE_NAME curveName);
    CEcNamedCurve(const CEcNamedCurve& curve) : CEcCurveBase(curve), m_curveName(curve.m_curveName), m_pOID(new u1Array(*curve.m_pOID)) {}
    virtual ~CEcNamedCurve() 
    {
        if (m_pOID) delete m_pOID;    
    }

    virtual CEcCurveBase* clone() const { return new CEcNamedCurve(*this);};
    CURVE_NAME getName() const { return m_curveName;}    

    /* return the OID of the named curve */
    virtual const u1Array* getOID() const { return m_pOID; }

protected:

    void initOID();
    void initP();
    void initA();
    void initB();
    void initG();
    void initN();
    void initH();

    CURVE_NAME  m_curveName;
    u1Array* m_pOID;
};


class CEcGenericCurve : public CEcCurveBase
{
public:
    CEcGenericCurve(const CEcGenericCurve& curve) : CEcCurveBase(curve) {}
    CEcGenericCurve(const unsigned char* pbPrime, unsigned long ulPrimeLength,
        const unsigned char* pbA, unsigned long ulA,
        const unsigned char* pbB, unsigned long ulB,
        const unsigned char* pbG, unsigned long ulG, /* 0x04 || Gx || Gy */
        const unsigned char* pbN, unsigned long ulN,
        const unsigned char* pbH, unsigned long ulH);
    
    virtual ~CEcGenericCurve() {}

    virtual CEcCurveBase* clone() const { return new CEcGenericCurve(*this);};
 
};

class CEcKey
{
protected:
    CEcCurveBase*    m_curve;
    CEcPoint    m_publicPoint;
    u1Array m_privateFactor;

public:
    CEcKey(const CEcCurveBase* curve, const CEcPoint& publicPoint, const u1Array& privateFactor):
      m_curve(curve->clone()), m_publicPoint(publicPoint), m_privateFactor(privateFactor) {}

    CEcKey(const CEcCurveBase* curve, const CEcPoint& publicPoint, const unsigned char* pbPrivateFactor, unsigned long ulFactorLength):
      m_curve(curve->clone()), m_publicPoint(publicPoint), m_privateFactor(pbPrivateFactor, ulFactorLength) {}

    CEcKey(const CEcKey& key) : m_curve(key.m_curve), m_publicPoint(key.m_publicPoint), m_privateFactor(key.m_privateFactor) {}

    ~CEcKey() 
    {
        if (m_curve) delete m_curve;
    }

    const CEcCurveBase& getCurve() const { return *m_curve;}
    int getBitSize() const { return m_curve->getBitSize();}

    const CEcPoint& getPublicPoint() { return m_publicPoint;}

    u1Array* deriveSharedSecret(const CEcPoint& peerPublicPoint);

    bool sign(const u1Array& hash, u1Array& signature);
    bool verify(const u1Array& hash, const u1Array& signature);
};
