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
#include "Pkcs11ObjectKeyPublicECC.hpp"
#include "PKCS11Exception.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>

extern unsigned char g_pbECC256k1_OID[7];

extern unsigned char g_pbECC256_OID[10];

extern unsigned char g_pbECC384_OID[7];

extern unsigned char g_pbECC521_OID[7];

Pkcs11ObjectKeyPublicECC::Pkcs11ObjectKeyPublicECC( ) : Pkcs11ObjectKeyPublic( ) {

    _keyType = CKK_EC;

    _mechanismType = CKM_EC_KEY_PAIR_GEN;

    _encrypt = CK_FALSE; // ECC key don't support encrypt
    _verifyRecover = CK_FALSE;

}


Pkcs11ObjectKeyPublicECC::Pkcs11ObjectKeyPublicECC( const Pkcs11ObjectKeyPublicECC* p ) : Pkcs11ObjectKeyPublic( p ) {


    _keyType = CKK_EC;

    _mechanismType = CKM_EC_KEY_PAIR_GEN;

    if( p ) {

        if( p->m_pParams.get( ) ) {

            u1Array* x = new u1Array( *(p->m_pParams.get( )) );

            m_pParams.reset( x );

        } else {

            m_pParams.reset( );
        }

        if( p->m_pPublicPoint.get( ) ) {

            u1Array* x = new u1Array( *(p->m_pPublicPoint.get( )) );

            m_pPublicPoint.reset( x );

        } else {

            m_pPublicPoint.reset( );
        }
    } else {

        m_pParams.reset( );
        m_pPublicPoint.reset( );
    }
}

bool Pkcs11ObjectKeyPublicECC::isEqual( StorageObject * that) const
{
    if( m_Class != that->getClass( ) ) {

        return false;
    }

	CK_KEY_TYPE keyType = (CK_KEY_TYPE) -1;
	CK_ATTRIBUTE pAttr[] = {
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)}
	};

	that->getAttribute(pAttr);

	if (keyType != CKK_EC)
		return false;

    const Pkcs11ObjectKeyPublicECC * thatKey = static_cast< const Pkcs11ObjectKeyPublicECC* >( that );

	return Util::compareU1Arrays(m_pParams.get(), thatKey->m_pParams->GetBuffer(), thatKey->m_pParams->GetLength())
		&& Util::compareU1Arrays(m_pPublicPoint.get(), thatKey->m_pPublicPoint->GetBuffer(), thatKey->m_pPublicPoint->GetLength());
}


bool Pkcs11ObjectKeyPublicECC ::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

    case CKA_EC_PARAMS:
        return Util::compareU1Arrays(m_pParams.get( ), (unsigned char*)attribute.pValue,attribute.ulValueLen);

    case CKA_EC_POINT:
        return Util::compareU1Arrays(m_pPublicPoint.get( ), (unsigned char*)attribute.pValue,attribute.ulValueLen);

    default:
        return Pkcs11ObjectKeyPublic::compare(attribute);
    }
}

void Pkcs11ObjectKeyPublicECC ::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

    case CKA_EC_PARAMS:
        StorageObject::putU1ArrayInAttribute(m_pParams.get( ),attribute);
        break;

    case CKA_EC_POINT:
        StorageObject::putU1ArrayInAttribute(m_pPublicPoint.get( ),attribute);
        break;

    default:
        Pkcs11ObjectKeyPublic::getAttribute(attribute);
        break;
    }
}


/*
*/
void Pkcs11ObjectKeyPublicECC::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& a_bObjCreation ) {

    if( !a_Attribute.ulValueLen ) {

        return;
    }

    if( !a_bObjCreation ) {

        switch( a_Attribute.type ) {

        case CKA_EC_PARAMS:
        case CKA_EC_POINT:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( a_Attribute.type ) {

    case CKA_EC_PARAMS:
        m_pParams.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        break;

    case CKA_EC_POINT:
        m_pPublicPoint.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        break;

    default:
        Pkcs11ObjectKeyPublic::setAttribute( a_Attribute, a_bObjCreation );
    }
}


/*
*/
void Pkcs11ObjectKeyPublicECC::serialize( std::vector<u1> *to ) {

    Pkcs11ObjectKeyPublic::serialize(to);

    Util::PushByteArrayInVector(to,m_pParams.get( ) );

    Util::PushByteArrayInVector(to,m_pPublicPoint.get( ) );
}


/*
*/
void Pkcs11ObjectKeyPublicECC::deserialize( std::vector<u1>& from, CK_ULONG_PTR idx ) {

    Pkcs11ObjectKeyPublic::deserialize( from, idx );

    m_pParams.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_pPublicPoint.reset( Util::ReadByteArrayFromVector( from, idx ) );
}


/*
*/
void Pkcs11ObjectKeyPublicECC::print( void ) {

    Pkcs11ObjectKeyPublic::print( );

    if( m_pParams.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_EC_PARAMS", m_pParams->GetBuffer( ), m_pParams->GetLength( ) );

    } else {

        Log::log( "CKA_EC_PARAMS <null>" );
    }

    if( m_pPublicPoint.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_EC_POINT", m_pPublicPoint->GetBuffer( ), m_pPublicPoint->GetLength( ) );

    } else {

        Log::log( "CKA_EC_POINT <null>" );
    }
}

CK_ULONG Pkcs11ObjectKeyPublicECC::getOrderBitLength()
{
    if (!m_pParams)
        return 0;

   if (Util::compareU1Arrays(m_pParams.get(), g_pbECC256k1_OID, 7))
        return 256;
    else if (Util::compareU1Arrays(m_pParams.get(), g_pbECC256_OID, 10))
        return 256;
    else if (Util::compareU1Arrays(m_pParams.get(), g_pbECC384_OID, 7))
        return 384;
    else if (Util::compareU1Arrays(m_pParams.get(), g_pbECC521_OID, 7))
        return 521;
    return 0;
}

bool Pkcs11ObjectKeyPublicECC::verify(u1Array* dataToVerify, u1Array* signature)
{
    int nid;
	
	if (Util::compareU1Arrays(m_pParams.get(), g_pbECC256k1_OID, sizeof(g_pbECC256k1_OID)))
    {
        nid = NID_secp256k1;
    }
    else if (Util::compareU1Arrays(m_pParams.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
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
        throw PKCS11Exception(CKR_GENERAL_ERROR);
    }

    EC_KEY *eckey=EC_KEY_new();
    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(nid);
    assert(ecgroup != NULL);
    int set_group_status = EC_KEY_set_group(eckey,ecgroup);
    assert(set_group_status == 1);

    // Set the public point value
    const unsigned char* ptr = m_pPublicPoint->GetBuffer();
    long len = m_pPublicPoint->GetLength();
    ASN1_OCTET_STRING* oct = d2i_ASN1_OCTET_STRING(NULL, &ptr, len);
    if (oct)
    {
        ptr = oct->data;
        len = oct->length;
    }
    else
    {
        ptr = m_pPublicPoint->GetBuffer();
        len = m_pPublicPoint->GetLength();
    }

    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* pubPoint = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubPoint, ptr, len, ctx);
    if (oct) ASN1_OCTET_STRING_free(oct);
    BN_CTX_free(ctx);

    EC_KEY_set_public_key(eckey, pubPoint);
    EC_POINT_free(pubPoint);

    ECDSA_SIG* sig = ECDSA_SIG_new();
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    BN_bin2bn(signature->GetBuffer(), signature->GetLength()/2, sig->r);
    BN_bin2bn(signature->GetBuffer() + (signature->GetLength()/2), signature->GetLength()/2, sig->s);
   
#else    
    BIGNUM *r=NULL,*s=NULL;
    r=BN_bin2bn(signature->GetBuffer(), signature->GetLength()/2, r);
    s=BN_bin2bn(signature->GetBuffer() + (signature->GetLength()/2), signature->GetLength()/2, s);
    ECDSA_SIG_set0(sig,r,s);    
#endif
    
    int status = ECDSA_do_verify(dataToVerify->GetBuffer(), dataToVerify->GetLength(), sig, eckey);
    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);

    return (status == 1);
}