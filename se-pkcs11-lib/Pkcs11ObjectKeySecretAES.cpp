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
#include "Pkcs11ObjectKeySecretAES.hpp"
#include "PKCS11Exception.hpp"


SecretKeyObjectAES::SecretKeyObjectAES( ) : SecretKeyObject( ) {

    _keyType = CKK_AES;
    _key_len = 0;

}

SecretKeyObjectAES::SecretKeyObjectAES( const SecretKeyObjectAES* p ) : SecretKeyObject( p ) {

    if( p ) {

		_key_len = p->_key_len;

		if( p->_key.get( ) ) {

            u1Array* a = new u1Array( *( p->_key.get( ) ) );

            _key.reset( a );

        } else {

            _key.reset( );
        }

    } else {

		_key_len = 0;
		_key.reset( );

    }
}

bool SecretKeyObjectAES::isEqual( StorageObject * that) const
{
    if( m_Class != that->getClass( ) ) {

        return false;
    }

    const SecretKeyObjectAES * key = static_cast< const SecretKeyObjectAES* >( that );

    return ( (_keyType == key->_keyType) && (_checkValue == key->_checkValue) );
}

bool SecretKeyObjectAES::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

        case CKA_VALUE_LEN:
            return (_key_len == *(CK_ULONG*)attribute.pValue);

        case CKA_VALUE:
			// AES key value is usually not extractable and hence, always empty here.
			return _key.get( ) ?
					Util::compareU1Arrays( _key.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen ) :
					false;

        default:
            return SecretKeyObject::compare(attribute);

    }
}

void SecretKeyObjectAES::getAttribute( CK_ATTRIBUTE_PTR attribute )
{
    switch(attribute->type) {

		case CKA_VALUE_LEN:
			StorageObject::putULongInAttribute( _key_len, attribute );
			break;

		case CKA_VALUE:
			// AES key value is usually not extractable and hence, always empty here.
			if(_key.get( ))
				StorageObject::putU1ArrayInAttribute( _key.get( ), attribute );
			else
				attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
			break;

        default:
            SecretKeyObject::getAttribute(attribute);
        	break;

    }
}

void SecretKeyObjectAES::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& objCreation ) {

   if( !a_Attribute.ulValueLen )
   {
      return;
   }

    if( !objCreation )
    {
        switch( a_Attribute.type )
        {
			case CKA_VALUE_LEN:
                if (a_Attribute.pValue)
                {
                    if (a_Attribute.ulValueLen != sizeof(CK_ULONG))
                        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
                    if( *(CK_ULONG*)a_Attribute.pValue ) {

                        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
                    }
                }
                break;

			case CKA_VALUE:
				throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );

			default:
	            SecretKeyObject::setAttribute( a_Attribute, objCreation );
				break;
        }
    }

    switch(a_Attribute.type){
		case CKA_VALUE_LEN:
			_key_len = StorageObject::readULongFromAttribute( a_Attribute );
			break;

		case CKA_VALUE:
			_key.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
			break;

        default:
            SecretKeyObject::setAttribute( a_Attribute, objCreation );
			break;
    }
}

void SecretKeyObjectAES::serialize(std::vector<u1> *to)
{
    SecretKeyObject::serialize(to);

    Util::PushULongInVector(to,_key_len);

    Util::PushByteArrayInVector(to,_key.get( ));
}

void SecretKeyObjectAES::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    SecretKeyObject::deserialize(from,idx);

    _key_len = Util::ReadULongFromVector(from,idx);

    _key.reset( Util::ReadByteArrayFromVector(from,idx) );
}

void SecretKeyObjectAES::print( void ) {

    SecretKeyObject::print( );

    Log::log( "CKA_VALUE_LEN <%ld>", _key_len );

	if( _key.get( ) ) {

		Log::logCK_UTF8CHAR_PTR( "CKA_VALUE", _key->GetBuffer( ), _key->GetLength( ) );

	} else {

		Log::log( "CKA_VALUE <null>" );

	}

}
