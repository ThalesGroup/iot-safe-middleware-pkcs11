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
#include "Pkcs11ObjectKeyPrivateRSA.hpp"
#include "PKCS11Exception.hpp"


/*
*/
RSAPrivateKeyObject :: RSAPrivateKeyObject( ) : PrivateKeyObject( ) {

    _keyType = CKK_RSA;

    _mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;
}


RSAPrivateKeyObject::RSAPrivateKeyObject( const RSAPrivateKeyObject* p ) : PrivateKeyObject( p ) {

    if( p ) {

        _keyType = p->_keyType;

        _mechanismType = p->_mechanismType;

        if( p->m_pPublicExponent.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pPublicExponent.get( )) );

            m_pPublicExponent.reset( e );

        } else {

            m_pPublicExponent.reset( );
        }

        if( p->m_pModulus.get( ) ) {

            u1Array* m = new u1Array( *(p->m_pModulus.get( )) );

            m_pModulus.reset( m );

        } else {

            m_pModulus.reset( );
        }

        if( p->m_pPrivateExponent.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pPrivateExponent.get( )) );

            m_pPrivateExponent.reset( e );

        } else {

            m_pPrivateExponent.reset( );
        }

        if( p->m_pPrime1.get( ) ) {

            u1Array* m = new u1Array( *(p->m_pPrime1.get( )) );

            m_pPrime1.reset( m );

        } else {

            m_pPrime1.reset( );
        }

        if( p->m_pPrime2.get( ) ) {

            u1Array* m = new u1Array( *(p->m_pPrime2.get( )) );

            m_pPrime2.reset( m );

        } else {

            m_pPrime2.reset( );
        }

        if( p->m_pExponent1.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pExponent1.get( )) );

            m_pExponent1.reset( e );

        } else {

            m_pExponent1.reset( );
        }

        if( p->m_pExponent2.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pExponent2.get( )) );

            m_pExponent2.reset( e );

        } else {

            m_pExponent2.reset( );
        }

        if( p->m_pCoefficient.get( ) ) {

            u1Array* e = new u1Array( *(p->m_pCoefficient.get( )) );

            m_pCoefficient.reset( e );

        } else {

            m_pCoefficient.reset( );
        }

    } else {

    _keyType = CKK_RSA;

    _mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;
        m_pPublicExponent.reset( );
        m_pModulus.reset( );
        m_pPrivateExponent.reset( );
        m_pPrime1.reset( );
        m_pPrime2.reset( );
        m_pExponent1.reset( );
        m_pExponent2.reset( );
        m_pCoefficient.reset( );
    }
}


/*
*/
bool RSAPrivateKeyObject::compare( const CK_ATTRIBUTE& attribute ) {

    switch( attribute.type ) {

    case CKA_MODULUS:
        return Util::compareArraysAsBigIntegers(m_pModulus.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_PUBLIC_EXPONENT:
        return Util::compareArraysAsBigIntegers(m_pPublicExponent.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_PRIVATE_EXPONENT:
        return Util::compareArraysAsBigIntegers(m_pPrivateExponent.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_PRIME_1:
        return Util::compareArraysAsBigIntegers(m_pPrime1.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_PRIME_2:
        return Util::compareArraysAsBigIntegers(m_pPrime2.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_EXPONENT_1:
        return Util::compareArraysAsBigIntegers(m_pExponent1.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_EXPONENT_2:
        return Util::compareArraysAsBigIntegers(m_pExponent2.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_COEFFICIENT:
        return Util::compareArraysAsBigIntegers(m_pCoefficient.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    default:
        return PrivateKeyObject::compare( attribute );
    }
}


/*
*/
void RSAPrivateKeyObject::setAttribute( const CK_ATTRIBUTE& attribute, const bool& objCreation ) {

    if( !attribute.ulValueLen ) {

        return;
    }

    if( !objCreation ) {

        switch( attribute.type ) {

        case CKA_PUBLIC_EXPONENT:
        case CKA_MODULUS:
        case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_COEFFICIENT:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( attribute.type ) {

    case CKA_MODULUS:
        m_pModulus.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_PUBLIC_EXPONENT:
        m_pPublicExponent.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_PRIVATE_EXPONENT:
        m_pPrivateExponent.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_EXPONENT_1:
        m_pExponent1.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_EXPONENT_2:
        m_pExponent2.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_PRIME_1:
        m_pPrime1.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_PRIME_2:
        m_pPrime2.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    case CKA_COEFFICIENT:
        m_pCoefficient.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
        break;

    default:
        PrivateKeyObject::setAttribute( attribute, objCreation );
        break;
    }
}


void RSAPrivateKeyObject::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

    case CKA_MODULUS:
        StorageObject::putU1ArrayInAttribute( m_pModulus.get( ), attribute );
        break;

    case CKA_PUBLIC_EXPONENT:
        StorageObject::putU1ArrayInAttribute( m_pPublicExponent.get( ), attribute );
        break;

    case CKA_PRIVATE_EXPONENT:
        if(_sensitive || !_extractable){
            attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
            throw PKCS11Exception( CKR_ATTRIBUTE_SENSITIVE );
        }
        StorageObject::putU1ArrayInAttribute(m_pPrivateExponent.get( ),attribute);
        break;

    case CKA_PRIME_1:
        if(_sensitive || !_extractable ){
            attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
            throw PKCS11Exception( CKR_ATTRIBUTE_SENSITIVE );
        }
        StorageObject::putU1ArrayInAttribute(m_pPrime1.get( ),attribute);
        break;

    case CKA_PRIME_2:
        if(_sensitive || !_extractable ){
            attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
            throw PKCS11Exception( CKR_ATTRIBUTE_SENSITIVE );
        }
        StorageObject::putU1ArrayInAttribute(m_pPrime2.get( ),attribute);
        break;

    case CKA_EXPONENT_1:
        if(_sensitive || !_extractable ){
            attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
            throw PKCS11Exception( CKR_ATTRIBUTE_SENSITIVE );
        }
        StorageObject::putU1ArrayInAttribute(m_pExponent1.get( ),attribute);
        break;

    case CKA_EXPONENT_2:
        if(_sensitive || !_extractable ){
            attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
            throw PKCS11Exception( CKR_ATTRIBUTE_SENSITIVE );
        }
        StorageObject::putU1ArrayInAttribute(m_pExponent2.get( ),attribute);
        break;

    case CKA_COEFFICIENT:
        if(_sensitive || !_extractable ){
            attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
            throw PKCS11Exception( CKR_ATTRIBUTE_SENSITIVE );
        }
        StorageObject::putU1ArrayInAttribute(m_pCoefficient.get( ),attribute);
        break;

    default:
        PrivateKeyObject::getAttribute(attribute);
        break;
    }
}


/*
*/
void RSAPrivateKeyObject::serialize(std::vector<u1> *to)
{
    PrivateKeyObject::serialize(to);

    // since keys will reside in the key container we are not going
    // to marshal the key values except modulus and public exponent

    Util::PushByteArrayInVector( to,m_pModulus.get( ) );

    Util::PushByteArrayInVector( to, m_pPublicExponent.get( ) );
}


/*
*/
void RSAPrivateKeyObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    PrivateKeyObject::deserialize(from,idx);

    m_pModulus.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_pPublicExponent.reset( Util::ReadByteArrayFromVector( from, idx ) );
}


/*
*/
void RSAPrivateKeyObject::print( void ) {

    PrivateKeyObject::print( );

    if( m_pPublicExponent.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_PUBLIC_EXPONENT", m_pPublicExponent->GetBuffer( ), m_pPublicExponent->GetLength( ) );

    } else {

        Log::log( "CKA_PUBLIC_EXPONENT <null>" );
    }

    if( m_pModulus.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_MODULUS", m_pModulus->GetBuffer( ), m_pModulus->GetLength( ) );

    } else {

        Log::log( "CKA_MODULUS <null>" );
    }

    if( m_pPrivateExponent.get( ) ) {

        Log::log( "CKA_PRIVATE_EXPONENT <Sensitive>");

    } else {

        Log::log( "CKA_PRIVATE_EXPONENT <null>" );
    }

    if( m_pPrime1.get( ) ) {

        Log::log( "CKA_PRIME_1 <Sensitive>" );

    } else {

        Log::log( "CKA_PRIME_1 <null>" );
    }

    if( m_pPrime2.get( ) ) {

        Log::log( "CKA_PRIME_2 <Sensitive>" );

    } else {

        Log::log( "CKA_PRIME_2 <null>" );
    }

    if( m_pExponent1.get( ) ) {

        Log::log( "CKA_EXPONENT_1 <Sensitive>");

    } else {

        Log::log( "CKA_EXPONENT_1 <null>" );
    }

    if( m_pExponent2.get( ) ) {

        Log::log( "CKA_EXPONENT_2 <Sensitive>" );

    } else {

        Log::log( "CKA_EXPONENT_2 <null>" );
    }

    if( m_pCoefficient.get( ) ) {

        Log::log( "CKA_COEFFICIENT <Sensitive>" );

    } else {

        Log::log( "CKA_COEFFICIENT <null>" );
    }
}

/*
*/
u1Array* RSAPrivateKeyObject::PadRSAPKCS1v15( u1Array* dataToSign, const CK_ULONG& modulusLen ) {

    u1Array* messageToSign = new u1Array( modulusLen );

    memset( messageToSign->GetBuffer( ), 0, modulusLen );

    messageToSign->SetU1At( 1, 1 );

    s4 offsetMessageToSign = modulusLen - dataToSign->GetLength( ) - 3;

    for( s4 i = 0 ; i < offsetMessageToSign ; ++i ) {

        messageToSign->SetU1At( 2 + i, 0xFF );
    }

    offsetMessageToSign += 3;

    memcpy( (unsigned char*)&messageToSign->GetBuffer( )[ offsetMessageToSign ], dataToSign->GetBuffer( ), dataToSign->GetLength( ) );

    return messageToSign;
}

/*
*/
u1Array* RSAPrivateKeyObject::PadRSAX509( u1Array* dataToSign, const CK_ULONG& modulusLen ) {

    u1Array* messageToSign = new u1Array( modulusLen );

    memset( messageToSign->GetBuffer( ), 0, modulusLen );

    s4 offsetMessageToSign = modulusLen - dataToSign->GetLength( );

    memcpy( (unsigned char*)&messageToSign->GetBuffer( )[ offsetMessageToSign ], dataToSign->GetBuffer( ), dataToSign->GetLength( ) );

    return messageToSign;
}


/*
*/
u1Array* RSAPrivateKeyObject::EncodeHashForSigning( u1Array* hashedData, const CK_ULONG& modulusLen, const CK_ULONG& hashAlgo ) {

    unsigned char DER_SHA1_Encoding[ ]   = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };

    unsigned char DER_SHA256_Encoding[ ] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

    unsigned char DER_SHA384_Encoding[ ] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
    
    unsigned char DER_SHA512_Encoding[ ] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

    unsigned char DER_MD5_Encoding[ ]    = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

    unsigned char* DER_Encoding = NULL_PTR;

    s4 DER_Encoding_Len = 0;

    switch( hashAlgo ) {

    case CKM_SHA_1:
        DER_Encoding_Len = sizeof(DER_SHA1_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_SHA1_Encoding,DER_Encoding_Len);
        break;

    case CKM_SHA256:
        DER_Encoding_Len = sizeof(DER_SHA256_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_SHA256_Encoding,DER_Encoding_Len);
        break;

    case CKM_SHA384:
        DER_Encoding_Len = sizeof(DER_SHA384_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len];
        memcpy(DER_Encoding,DER_SHA384_Encoding,DER_Encoding_Len);
        break;

    case CKM_SHA512:
        DER_Encoding_Len = sizeof(DER_SHA512_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_SHA512_Encoding,DER_Encoding_Len);
        break;

    case CKM_MD5:
        DER_Encoding_Len = sizeof(DER_MD5_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_MD5_Encoding,DER_Encoding_Len);
        break;

    }

    u1Array* messageToSign = new u1Array( modulusLen );

    memset( messageToSign->GetBuffer( ), 0, modulusLen );

    messageToSign->SetU1At( 1, 1 );

    // caluclate pos
    int pos = modulusLen - DER_Encoding_Len - hashedData->GetLength( );

    for( int i = 2 ; i < (pos - 1) ; ++i ) {

        messageToSign->SetU1At( i, 0xFF );
    }

    memcpy((unsigned char*)&messageToSign->GetBuffer()[pos],DER_Encoding,DER_Encoding_Len);
    memcpy((unsigned char*)&messageToSign->GetBuffer()[pos+DER_Encoding_Len],hashedData->GetBuffer(),hashedData->GetLength());

    delete DER_Encoding;

    return messageToSign;
}