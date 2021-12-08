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
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "PKCS11Exception.hpp"


Pkcs11ObjectKeyPublicRSA::Pkcs11ObjectKeyPublicRSA( ) : Pkcs11ObjectKeyPublic( ) {

    m_ulModulusBits = 0;

    _keyType = CKK_RSA;

    _mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;
}


Pkcs11ObjectKeyPublicRSA::Pkcs11ObjectKeyPublicRSA( const Pkcs11ObjectKeyPublicRSA* p ) : Pkcs11ObjectKeyPublic( p ) {


    _keyType = CKK_RSA;

    _mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;

    if( p ) {

        m_ulModulusBits = p->m_ulModulusBits;

        if( p->m_pModulus.get( ) ) {

            u1Array* x = new u1Array( *(p->m_pModulus.get( )) );

            m_pModulus.reset( x );

        } else {

            m_pModulus.reset( );
        }

        if( p->m_pPublicExponent.get( ) ) {

            u1Array* x = new u1Array( *(p->m_pPublicExponent.get( )) );

            m_pPublicExponent.reset( x );

        } else {

            m_pPublicExponent.reset( );
        }
    } else {

        m_ulModulusBits = 0;

        m_pModulus.reset( );
        m_pPublicExponent.reset( );
    }
}

bool Pkcs11ObjectKeyPublicRSA::isEqual( StorageObject * that) const
{
    if( m_Class != that->getClass( ) ) {

        return false;
    }

	CK_KEY_TYPE keyType = (CK_KEY_TYPE) -1;
	CK_ATTRIBUTE pAttr[] = {
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)}
	};

	that->getAttribute(pAttr);

	if (keyType != CKK_RSA)
		return false;

    const Pkcs11ObjectKeyPublicRSA * thatKey = static_cast< const Pkcs11ObjectKeyPublicRSA* >( that );

	return ( (m_ulModulusBits == thatKey->m_ulModulusBits) 
		&& Util::compareArraysAsBigIntegers(m_pModulus.get(), thatKey->m_pModulus->GetBuffer(), thatKey->m_pModulus->GetLength())
		&& Util::compareArraysAsBigIntegers(m_pPublicExponent.get(), thatKey->m_pPublicExponent->GetBuffer(), thatKey->m_pPublicExponent->GetLength()) );
}


bool Pkcs11ObjectKeyPublicRSA ::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

    case CKA_MODULUS:
        return Util::compareArraysAsBigIntegers(m_pModulus.get( ), (unsigned char*)attribute.pValue,attribute.ulValueLen);

    case CKA_MODULUS_BITS:
        return (m_ulModulusBits == *(CK_ULONG*)attribute.pValue);

    case CKA_PUBLIC_EXPONENT:
        return Util::compareArraysAsBigIntegers(m_pPublicExponent.get( ), (unsigned char*)attribute.pValue,attribute.ulValueLen);

    default:
        return Pkcs11ObjectKeyPublic::compare(attribute);
    }
}

void Pkcs11ObjectKeyPublicRSA ::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

    case CKA_MODULUS:
        StorageObject::putU1ArrayInAttribute(m_pModulus.get( ),attribute);
        break;

    case CKA_MODULUS_BITS:
        StorageObject::putULongInAttribute(m_ulModulusBits,attribute);
        break;

    case CKA_PUBLIC_EXPONENT:
        StorageObject::putU1ArrayInAttribute(m_pPublicExponent.get( ),attribute);
        break;

    default:
        Pkcs11ObjectKeyPublic::getAttribute(attribute);
        break;
    }
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& a_bObjCreation ) {

    if( !a_Attribute.ulValueLen ) {

        return;
    }

    if( !a_bObjCreation ) {

        switch( a_Attribute.type ) {

        case CKA_PUBLIC_EXPONENT:
        case CKA_MODULUS:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        case CKA_MODULUS_BITS:
            if (a_Attribute.pValue && a_Attribute.ulValueLen != sizeof(CK_ULONG))
                throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( a_Attribute.type ) {

    case CKA_MODULUS:
        m_pModulus.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        m_ulModulusBits = m_pModulus->GetLength()*8;
        break;

    case CKA_PUBLIC_EXPONENT:
        m_pPublicExponent.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        break;

    case CKA_MODULUS_BITS:
        m_ulModulusBits = StorageObject::readULongFromAttribute( a_Attribute );
        break;

    default:
        Pkcs11ObjectKeyPublic::setAttribute( a_Attribute, a_bObjCreation );
    }
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::serialize( std::vector<u1> *to ) {

    Pkcs11ObjectKeyPublic::serialize(to);

    Util::PushByteArrayInVector(to,m_pModulus.get( ) );

    Util::PushByteArrayInVector(to,m_pPublicExponent.get( ) );

    Util::PushULongInVector(to,m_ulModulusBits);
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::deserialize( std::vector<u1>& from, CK_ULONG_PTR idx ) {

    Pkcs11ObjectKeyPublic::deserialize( from, idx );

    m_pModulus.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_pPublicExponent.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_ulModulusBits = Util::ReadULongFromVector( from, idx );
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::print( void ) {

    Pkcs11ObjectKeyPublic::print( );

    Log::log( "CKA_MODULUS_BITS <%ld>", m_ulModulusBits );

    if( m_pModulus.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_MODULUS", m_pModulus->GetBuffer( ), m_pModulus->GetLength( ) );

    } else {

        Log::log( "CKA_MODULUS <null>" );
    }

    if( m_pPublicExponent.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_PUBLIC_EXPONENT", m_pPublicExponent->GetBuffer( ), m_pPublicExponent->GetLength( ) );

    } else {

        Log::log( "CKA_PUBLIC_EXPONENT <null>" );
    }
}

/*
*/
void Pkcs11ObjectKeyPublicRSA::verifyHash( u1Array* messageToVerify, u1Array* dataToVerify, const unsigned int& modulusLen, const CK_ULONG& hashAlgo ) {

    const unsigned char* msg  = messageToVerify->GetBuffer( );

    // Check the decoded value against the expected data.
    if( ( msg[ 0 ] != 0x00 ) || ( msg[ 1 ] != 0x01 ) ) {

        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }

    unsigned char DER_SHA1_Encoding[ ]   = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };
    unsigned char DER_SHA256_Encoding[ ] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    unsigned char DER_SHA384_Encoding[ ] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };  
    unsigned char DER_SHA512_Encoding[ ] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
    unsigned char DER_MD5_Encoding[ ]    = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

    s4  DER_Encoding_Len = 0;
    unsigned char* DER_Encoding = NULL_PTR;
    const unsigned char* hash = dataToVerify->GetBuffer();
    unsigned int hashLen = dataToVerify->GetLength();

    switch(hashAlgo){
    case CKM_SHA_1:
        DER_Encoding_Len = sizeof(DER_SHA1_Encoding);
        DER_Encoding = DER_SHA1_Encoding;
        if (hashLen != 20)
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        break;

    case CKM_SHA256:
        DER_Encoding_Len = sizeof(DER_SHA256_Encoding);
        DER_Encoding = DER_SHA256_Encoding;
        if (hashLen != 32)
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        break;

    case CKM_SHA384:
        DER_Encoding_Len = sizeof(DER_SHA384_Encoding);
        DER_Encoding = DER_SHA384_Encoding;
        if (hashLen != 48)
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        break;

    case CKM_SHA512:
        DER_Encoding_Len = sizeof(DER_SHA512_Encoding);
        DER_Encoding = DER_SHA512_Encoding;
        if (hashLen != 64)
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        break;

    case CKM_MD5:
        DER_Encoding_Len = sizeof(DER_MD5_Encoding);
        DER_Encoding = DER_MD5_Encoding;
        if (hashLen != 16)
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        break;

    }

    if (modulusLen <= DER_Encoding_Len + hashLen)
        throw PKCS11Exception( CKR_SIGNATURE_INVALID );

    s4 posn = modulusLen - DER_Encoding_Len - hashLen;

    for(s4 i = 2; i < (posn - 1); i++)
    {
        if(msg[i] != 0xFF){
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }

    if(msg[posn - 1] != 0x00){
        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }

    if (0 != memcmp(&msg[posn], DER_Encoding, DER_Encoding_Len))
        throw PKCS11Exception( CKR_SIGNATURE_INVALID );

    if (0 != memcmp(&msg[posn + DER_Encoding_Len], hash, hashLen))
        throw PKCS11Exception( CKR_SIGNATURE_INVALID );

}


/*
*/
void Pkcs11ObjectKeyPublicRSA::verifyRSAX509( u1Array* messageToVerify, u1Array* dataToVerify, const unsigned int& modulusLen ) {

    // Reach the first non-zero bytes in data
    unsigned int usDataLen = dataToVerify->GetLength( );
    unsigned int pos1=0;
    const unsigned char* pData = dataToVerify->GetBuffer( );
    for( ; pos1 < usDataLen ; ++pos1 ) {

        if( pData[ pos1 ] ) {

            break;
        }
    }

    // Reach the first non-zero bytes in decrypted signature
    unsigned int usMessageLen = messageToVerify->GetLength( );
    const unsigned char* pMessage = messageToVerify->GetBuffer( );
    unsigned int pos2=0;
    for( ; pos2 < usMessageLen ; ++pos2 ) {

        if( pMessage[ pos2 ] ) {

            break;
        }
    }

    if( ( usDataLen - pos1 ) != ( modulusLen - pos2 ) ) {

        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }


    for( unsigned int i = pos1, j = pos2 ; i < ( modulusLen - pos2 ) ; ++i, ++j ) {

        if( pData[ i ] != pMessage[ j ] ) {

            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::verifyRSAPKCS1v15( u1Array* messageToVerify, u1Array* dataToVerify, const unsigned int& modulusLen ) {

    // Skip the PKCS block formatting data
    unsigned int pos = 2;
    const unsigned char* pMessage = messageToVerify->GetBuffer( ); 
    for( ; pos < modulusLen ; ++pos) {

        if( !pMessage[ pos ] ) { //== 0x00

            ++pos;
            break;
        }
    }

    if( dataToVerify->GetLength( ) != ( modulusLen - pos ) ) {

        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }

    const unsigned char* pData = dataToVerify->GetBuffer( ); 
    for( unsigned int i = 0, j = pos ; i < ( modulusLen - pos ) ; ++i, ++j ) {

        if( pData[ i ] != pMessage[ j ] ) {

            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }
}

