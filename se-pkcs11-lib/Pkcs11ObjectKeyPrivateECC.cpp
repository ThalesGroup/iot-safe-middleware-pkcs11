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
#include "Log.hpp"
#include "util.h"
#include "Pkcs11ObjectKeyPrivateECC.hpp"
#include "PKCS11Exception.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>

extern unsigned char g_pbECC256_OID[10];

extern unsigned char g_pbECC384_OID[7];

extern unsigned char g_pbECC521_OID[7];

/*
*/
ECCPrivateKeyObject :: ECCPrivateKeyObject( ) : PrivateKeyObject( ) {

    _keyType = CKK_EC;

    _mechanismType = CKM_EC_KEY_PAIR_GEN;

    _decrypt = CK_FALSE; // ECC key don't support decrypt
    _signRecover = CK_FALSE;
}


ECCPrivateKeyObject::ECCPrivateKeyObject( const ECCPrivateKeyObject* p ) : PrivateKeyObject( p ) {

    if( p ) {

        _keyType = p->_keyType;

        _mechanismType = p->_mechanismType;

        if( p->m_pParams.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pParams.get( )) );

            m_pParams.reset( e );

        } else {

            m_pParams.reset( );
        }

        if( p->m_pPrivateValue.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pPrivateValue.get( )) );

            m_pPrivateValue.reset( e );

        } else {

            m_pPrivateValue.reset( );
        }

        if (p->m_pPublicPoint.get())
        {
            u1Array* e = new u1Array( *(p->m_pPublicPoint.get( )) );
            m_pPublicPoint.reset(e);
        }

    } else {

        _keyType = CKK_EC;

        _mechanismType = CKM_EC_KEY_PAIR_GEN;
        m_pParams.reset( );
        m_pPrivateValue.reset( );
        m_pPublicPoint.reset();
    }
}


/*
*/
bool ECCPrivateKeyObject::compare( const CK_ATTRIBUTE& attribute ) {

    switch( attribute.type ) {

    case CKA_EC_PARAMS:
        return Util::compareU1Arrays(m_pParams.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_VALUE:
        return Util::compareU1Arrays(m_pPrivateValue.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    default:
        return PrivateKeyObject::compare( attribute );
    }
}


/*
*/
void ECCPrivateKeyObject::setAttribute( const CK_ATTRIBUTE& attribute, const bool& objCreation ) {

    if( !attribute.ulValueLen ) {

        return;
    }

    if( !objCreation ) {

        switch( attribute.type ) {

        case CKA_EC_PARAMS:
        case CKA_VALUE:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( attribute.type ) {

    case CKA_EC_PARAMS:
        m_pParams.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        if (    !Util::compareU1Arrays(m_pParams.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID))
            &&  !Util::compareU1Arrays(m_pParams.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID))
            &&  !Util::compareU1Arrays(m_pParams.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID))
           )
        {
            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }
        break;

    case CKA_VALUE:
        m_pPrivateValue.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );         
        break;

    default:
        PrivateKeyObject::setAttribute( attribute, objCreation );
        break;
    }
}


void ECCPrivateKeyObject::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

    case CKA_EC_PARAMS:
        StorageObject::putU1ArrayInAttribute( m_pParams.get( ), attribute );
        break;

    case CKA_VALUE:
        StorageObject::putU1ArrayInAttribute( m_pPrivateValue.get( ), attribute );
        break;

    default:
        PrivateKeyObject::getAttribute(attribute);
        break;
    }
}


/*
*/
void ECCPrivateKeyObject::serialize(std::vector<u1> *to)
{
    PrivateKeyObject::serialize(to);

    // since keys will reside in the key container we are not going
    // to marshal the key values except curve parameters

    Util::PushByteArrayInVector( to,m_pParams.get( ) );

    Util::PushByteArrayInVector( to,m_pPublicPoint.get( ) );
}


/*
*/
void ECCPrivateKeyObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    PrivateKeyObject::deserialize(from,idx);

    m_pParams.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_pPublicPoint.reset( Util::ReadByteArrayFromVector( from, idx ) );
}


/*
*/
void ECCPrivateKeyObject::print( void ) {

    PrivateKeyObject::print( );

    if( m_pParams.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_EC_PARAMS", m_pParams->GetBuffer( ), m_pParams->GetLength( ) );

    } else {

        Log::log( "CKA_EC_PARAMS <null>" );
    }

    if( m_pPrivateValue.get( ) ) {

        Log::log( "CKA_VALUE <Sensitive>" );

    } else {

        Log::log( "CKA_VALUE <null>" );
    }
}

CK_ULONG ECCPrivateKeyObject::getOrderBitLength()
{
    if (!m_pParams)
        return 0;

    if (Util::compareU1Arrays(m_pParams.get(), g_pbECC256_OID, 10))
        return 256;
    if (Util::compareU1Arrays(m_pParams.get(), g_pbECC384_OID, 7))
        return 384;
    if (Util::compareU1Arrays(m_pParams.get(), g_pbECC521_OID, 7))
        return 521;
    return 0;
}

void ECCPrivateKeyObject::computePublicPoint()
{
    if (!m_pParams || !m_pPrivateValue)
    {
        throw PKCS11Exception( CKR_TEMPLATE_INCOMPLETE );
    }

    // compute the public point
    int nid;

    if (Util::compareU1Arrays(m_pParams.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
    {
        nid = NID_X9_62_prime256v1;
    }
    else if (Util::compareU1Arrays(m_pParams.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
    {
        nid = NID_secp384r1;
    }
    else if (Util::compareU1Arrays(m_pParams.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
    {
        nid = NID_secp521r1;
    }
    else
    {
        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(nid);   
    EC_POINT* Q = EC_POINT_new(ecgroup);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* d = BN_bin2bn(m_pPrivateValue->GetBuffer(), m_pPrivateValue->GetLength(), NULL);

    EC_POINT_mul(ecgroup, Q, d, NULL, NULL, ctx);

    // Q is the public point
    CK_ULONG l = EC_POINT_point2oct(ecgroup, Q, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    CK_BYTE_PTR v = new CK_BYTE[l];
    l = EC_POINT_point2oct(ecgroup, Q, POINT_CONVERSION_UNCOMPRESSED, v, l, ctx);
    ASN1_OCTET_STRING* oct = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(oct, v, l);
    delete [] v;
    v = NULL;
    l = i2d_ASN1_OCTET_STRING(oct, &v);
    ASN1_OCTET_STRING_free(oct);

    // set its DER encoding
    m_pPublicPoint.reset(new u1Array(l));
    m_pPublicPoint->SetBuffer(v);

    delete [] v;

    BN_CTX_free(ctx);
    BN_free(d);
    EC_POINT_free(Q);
    EC_GROUP_free(ecgroup);
}