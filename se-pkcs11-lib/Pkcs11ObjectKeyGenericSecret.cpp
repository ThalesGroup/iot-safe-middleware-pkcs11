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
#include "Pkcs11ObjectKeyGenericSecret.hpp"
#include "PKCS11Exception.hpp"
#include "digest.h"

GenericSecretKeyObject :: GenericSecretKeyObject( ) : SecretKeyObject( ) {

    _encrypt = CK_FALSE;
    _decrypt = CK_FALSE;
    _sign = CK_FALSE;
    _verify = CK_FALSE;
    _keyType = CKK_GENERIC_SECRET;
}


GenericSecretKeyObject :: GenericSecretKeyObject( const GenericSecretKeyObject* p ) : SecretKeyObject( p ) {

    if( p ) {

        m_pValue = p->m_pValue;
        _keyType = p->_keyType;
    } else {
        _encrypt = CK_FALSE;
        _decrypt = CK_FALSE;
        _sign = CK_FALSE;
        _verify = CK_FALSE;
        _keyType = CKK_GENERIC_SECRET;
    }
}



bool GenericSecretKeyObject::isEqual( StorageObject * that) const
{
    if( !SecretKeyObject::isEqual(that) ) {

        return false;
    }

    const GenericSecretKeyObject * key = static_cast< const GenericSecretKeyObject* >( that );

    return  (m_pValue->GetLength() == key->m_pValue->GetLength())
        &&  Util::compareU1Arrays(m_pValue.get(), key->m_pValue->GetBuffer(), key->m_pValue->GetLength());
}

bool GenericSecretKeyObject::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

        case CKA_VALUE:
            return (m_pValue->GetLength() == attribute.ulValueLen) 
                && (Util::compareU1Arrays(m_pValue.get(), 
                        (unsigned char*) attribute.pValue, 
                        attribute.ulValueLen));

        case CKA_VALUE_LEN:
            return (m_pValue->GetLength() == *(CK_ULONG*)attribute.pValue);

        default:
            return SecretKeyObject::compare(attribute);

    }
}

void GenericSecretKeyObject::getAttribute( CK_ATTRIBUTE_PTR attribute )
{
    switch(attribute->type){

        case CKA_VALUE:
            StorageObject::putU1ArrayInAttribute(m_pValue.get(), attribute);
        break;

        case CKA_VALUE_LEN:
            StorageObject::putULongInAttribute(m_pValue->GetLength(), attribute);
        break;

        default:
            SecretKeyObject::getAttribute(attribute);
        break;
    }
}


/*
*/
void GenericSecretKeyObject::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& objCreation ) {

/*
   if( !a_Attribute.ulValueLen )
   {
      return;
   }*/

   if( !objCreation && a_Attribute.type == CKA_VALUE_LEN)
   {
        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
   }

    switch(a_Attribute.type){

        case CKA_VALUE:
            {
                m_pValue.reset( StorageObject::readU1ArrayFromAttribute(a_Attribute) );
                CDigest* sha1 = CDigest::getInstance(CDigest::SHA1);
                CK_BYTE pHash[20];
                sha1->hashUpdate( m_pValue->GetBuffer(), 0, m_pValue->GetLength() );
                sha1->hashFinal( pHash );
                delete sha1;
                _checkValue = (pHash[0] << 16) + (pHash[1] << 8) + (pHash[2]);
            }
            break;

        case CKA_VALUE_LEN:
            m_pValue.reset(new u1Array(StorageObject::readULongFromAttribute(a_Attribute)));
            break;

        default:
            SecretKeyObject::setAttribute( a_Attribute, objCreation );
    }
}

void GenericSecretKeyObject::serialize(std::vector<u1> *to)
{
    SecretKeyObject::serialize(to);

    Util::PushByteArrayInVector(to, m_pValue.get());
}

void GenericSecretKeyObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    SecretKeyObject::deserialize(from,idx);

    m_pValue.reset( Util::ReadByteArrayFromVector(from, idx) );
}


/*
*/
void GenericSecretKeyObject::print( void ) {

    SecretKeyObject::print( );

    if( m_pValue.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_VALUE", m_pValue->GetBuffer( ), m_pValue->GetLength( ) );
        Log::log( "CKA_VALUE_LEN <%ld>", m_pValue->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_VALUE <null>" );
        Log::log( "CKA_VALUE_LEN <00>" );
    }
}

void GenericSecretKeyObject::NULL_drive(u1Array* DHAgreement)
{
    //Remy update
    if (!m_pValue || !m_pValue->GetLength())
    {
        u1Array* val = new u1Array(32);
        m_pValue.reset(val);
         
        //throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    u4 dhLen = DHAgreement->GetLength();
    u1* dhData = DHAgreement->GetBuffer();

    memset(m_pValue->GetBuffer(), 0, m_pValue->GetLength());

    if (dhLen <= m_pValue->GetLength())
    {
        memcpy(m_pValue->GetBuffer() + (m_pValue->GetLength() - dhLen), 
            dhData,
            dhLen);
    }
    else
    {
        memcpy(m_pValue->GetBuffer(), dhData + (dhLen - m_pValue->GetLength()), m_pValue->GetLength());
    }
}

void GenericSecretKeyObject::ANSI_X9_63_drive(u1Array* DHAgreement, 
        u1Array* SharedInfo)
{
    if (!m_pValue || !m_pValue->GetLength())
    {
        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    unsigned char *buffer = NULL, *output_buffer = NULL;
    u4 buffer_len, max_counter, i;
    u4 key_len = m_pValue->GetLength();
    u4 dh_len = DHAgreement->GetLength();
    u4 HashLen = 20;
    u4 counter;

    memset(m_pValue->GetBuffer(), 0, m_pValue->GetLength());

    buffer_len = dh_len + 4 + SharedInfo->GetLength();
    buffer = new unsigned char[buffer_len];

    max_counter = key_len/HashLen;
    if (key_len > max_counter * HashLen)
	    max_counter++;

    output_buffer = new unsigned char[max_counter * HashLen];

    /* Populate buffer with SharedSecret || Counter || [SharedInfo]
     * where Counter is 0x00000001 */
    counter = 1;
    memcpy(buffer, DHAgreement->GetBuffer(), dh_len);
    buffer[dh_len] = 0;
    buffer[dh_len + 1] = 0;
    buffer[dh_len + 2] = 0;
    buffer[dh_len + 3] = 1;
    if (SharedInfo->GetLength())
	    memcpy(&buffer[dh_len + 4], SharedInfo->GetBuffer(), SharedInfo->GetLength());

    for(i=0; i < max_counter; i++) {
        CDigest* sha1 = CDigest::getInstance(CDigest::SHA1);
        sha1->hashUpdate(buffer, 0, buffer_len);
        sha1->hashFinal(&output_buffer[i * HashLen]);
        delete sha1;

	    /* Increment counter (assumes max_counter < 255) */
        counter++;
        buffer[dh_len] = counter >> 24;
        buffer[dh_len + 1] = (counter >> 16) & 0x000000FF;
        buffer[dh_len + 2] = (counter >> 8) & 0x000000FF;
        buffer[dh_len + 3] = counter & 0x000000FF;
    }

    memcpy(m_pValue->GetBuffer(), output_buffer, key_len);
    
    delete [] buffer;
    delete [] output_buffer;
}