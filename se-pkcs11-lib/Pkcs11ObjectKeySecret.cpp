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
#include "Pkcs11ObjectKeySecret.hpp"
#include "PKCS11Exception.hpp"


SecretKeyObject :: SecretKeyObject( ) : KeyObject( ) {

    m_Class = CKO_SECRET_KEY;
    _sensitive = CK_FALSE;
    _encrypt = CK_TRUE;
    _decrypt = CK_TRUE;
    _sign = CK_TRUE;
    _verify = CK_TRUE;
    _wrap = CK_FALSE;
    _unwrap = CK_FALSE;
    _extractable = CK_FALSE;
    _alwaysSensitive = CK_TRUE;
    _neverExtractable = CK_TRUE;
    _wrapWithTrusted = CK_FALSE;
    _trusted = CK_FALSE;
    _keyType = CK_UNAVAILABLE_INFORMATION;
    _checkValue = 0;
}


SecretKeyObject :: SecretKeyObject( const SecretKeyObject* p ) : KeyObject( p ) {

    if( p ) {

        m_Class = p->m_Class;
        _sensitive = p->_sensitive;
        _encrypt = p->_encrypt;
        _decrypt = p->_decrypt;
        _sign = p->_sign;
        _verify = p->_verify;
        _wrap = p->_wrap;
        _unwrap = p->_unwrap;
        _extractable = p->_extractable;
        _alwaysSensitive = p->_alwaysSensitive;
        _neverExtractable = p->_neverExtractable;
        _wrapWithTrusted = p->_wrapWithTrusted;
        _trusted = p->_trusted;
        _keyType  = p->_keyType;
        _checkValue = p->_checkValue;

    } else {

        m_Class = CKO_SECRET_KEY;
        _sensitive = CK_TRUE;
        _encrypt = CK_TRUE;
        _decrypt = CK_TRUE;
        _verify = CK_TRUE;
        _sign = CK_TRUE;
        _wrap = CK_FALSE;
        _unwrap = CK_FALSE;
        _extractable = CK_FALSE;
        _alwaysSensitive = CK_TRUE;
        _neverExtractable = CK_TRUE;
        _wrapWithTrusted = CK_FALSE;
        _trusted = CK_FALSE;
        _keyType = CK_UNAVAILABLE_INFORMATION;
        _checkValue = 0;
    }
}



bool SecretKeyObject::isEqual( StorageObject * that) const
{
    if( m_Class != that->getClass( ) ) {

        return false;
    }

    const SecretKeyObject * key = static_cast< const SecretKeyObject* >( that );

    return ( (_keyType == key->_keyType) && (_checkValue == key->_checkValue) );
}

bool SecretKeyObject::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

        case CKA_SENSITIVE:
            return (_sensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_ENCRYPT:
            return (_encrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_DECRYPT:
            return (_decrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_SIGN:
            return (_sign == *(CK_BBOOL*)attribute.pValue);

        case CKA_VERIFY:
            return (_verify == *(CK_BBOOL*)attribute.pValue);

        case CKA_WRAP:
            return (_wrap == *(CK_BBOOL*)attribute.pValue);

        case CKA_UNWRAP:
            return (_unwrap == *(CK_BBOOL*)attribute.pValue);

        case CKA_EXTRACTABLE:
            return (_extractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_ALWAYS_SENSITIVE:
            return (_alwaysSensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_NEVER_EXTRACTABLE:
            return (_neverExtractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_WRAP_WITH_TRUSTED:
            return (_wrapWithTrusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_TRUSTED:
            return (_trusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_CHECK_VALUE:
            {
                if (attribute.ulValueLen != 3) return false;
                return  (((_checkValue >> 16) & 0x00FF) == ((CK_BYTE*)attribute.pValue)[0])
                    &&  (((_checkValue >>  8) & 0x00FF) == ((CK_BYTE*)attribute.pValue)[1])
                    &&  (((_checkValue      ) & 0x00FF) == ((CK_BYTE*)attribute.pValue)[2]);
            }

        default:
            return KeyObject::compare(attribute);

    }
}

void SecretKeyObject::getAttribute( CK_ATTRIBUTE_PTR attribute )
{
    switch(attribute->type){

        case CKA_SENSITIVE:
            StorageObject::putBBoolInAttribute(_sensitive,attribute);
        break;

        case CKA_ENCRYPT:
            StorageObject::putBBoolInAttribute(_encrypt,attribute);
        break;

        case CKA_DECRYPT:
            StorageObject::putBBoolInAttribute(_decrypt,attribute);
        break;

        case CKA_SIGN:
            StorageObject::putBBoolInAttribute(_sign,attribute);
        break;

        case CKA_VERIFY:
            StorageObject::putBBoolInAttribute(_verify,attribute);
        break;

        case CKA_WRAP:
            StorageObject::putBBoolInAttribute(_wrap,attribute);
        break;

        case CKA_UNWRAP:
            StorageObject::putBBoolInAttribute(_unwrap,attribute);
        break;

        case CKA_EXTRACTABLE:
            StorageObject::putBBoolInAttribute(_extractable,attribute);
        break;

        case CKA_ALWAYS_SENSITIVE:
            StorageObject::putBBoolInAttribute(_alwaysSensitive,attribute);
        break;

        case CKA_NEVER_EXTRACTABLE:
            StorageObject::putBBoolInAttribute(_neverExtractable,attribute);
        break;

        case CKA_WRAP_WITH_TRUSTED:
            StorageObject::putBBoolInAttribute(_wrapWithTrusted,attribute);
        break;

        case CKA_TRUSTED:
            StorageObject::putBBoolInAttribute(_trusted,attribute);
        break;

        case CKA_CHECK_VALUE:
            {
                CK_BYTE tmp[3] = {(CK_BYTE)((_checkValue >> 16) & 0x00FF), (CK_BYTE)((_checkValue >> 8) & 0x00FF), (CK_BYTE)((_checkValue ) & 0x00FF)};

                StorageObject::putBytearrayInAttribute( tmp, 3, attribute );
                break;
            }

        default:
            KeyObject::getAttribute(attribute);
        break;
    }
}


/*
*/
void SecretKeyObject::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& objCreation ) {

   if( !a_Attribute.ulValueLen )
   {
      return;
   }

    if( !objCreation )
    {
        switch( a_Attribute.type )
        {
            case CKA_ALWAYS_SENSITIVE:
            case CKA_NEVER_EXTRACTABLE:
                if (a_Attribute.pValue && (a_Attribute.ulValueLen != sizeof(CK_BBOOL)))
                    throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
                throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );

            case CKA_ENCRYPT:
            case CKA_DECRYPT:
            case CKA_EXTRACTABLE:
            case CKA_SENSITIVE:
            case CKA_SIGN:
            case CKA_VERIFY:
            case CKA_WRAP:
            case CKA_UNWRAP:
            case CKA_WRAP_WITH_TRUSTED:
            case CKA_TRUSTED:
                if (a_Attribute.pValue)
                {
                    if (a_Attribute.ulValueLen != sizeof(CK_BBOOL))
                        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
                    if( *(CK_BBOOL*)a_Attribute.pValue ) {

                        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
                    }
                }
                break;
        }
    }

    switch(a_Attribute.type){

        case CKA_SENSITIVE:
            {
                CK_BBOOL btemp = StorageObject::readBBoolFromAttribute( a_Attribute );

                    if( !objCreation && _sensitive && !btemp ) {

                        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
                    
					}else{

                        _sensitive = btemp;

                        if( !btemp ){

                            _alwaysSensitive = CK_FALSE;
                        }
                    }
            }
            break;

        case CKA_ENCRYPT:
            _encrypt = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_DECRYPT:
            _decrypt = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_SIGN:
            _sign = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_VERIFY:
            _verify = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_WRAP:
            _wrap = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_UNWRAP:
            _unwrap = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_EXTRACTABLE:
            {
                CK_BBOOL btemp = StorageObject::readBBoolFromAttribute( a_Attribute );

                    if( !objCreation && !_extractable && btemp ) {

                        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );

                    } else {

                        _extractable = btemp;

                        if( btemp ) {

                            _neverExtractable = CK_FALSE;
                        }
                    }
            }
            break;

        case CKA_ALWAYS_SENSITIVE:
            _alwaysSensitive = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;


        case CKA_NEVER_EXTRACTABLE:
            _neverExtractable = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_WRAP_WITH_TRUSTED:
            _wrapWithTrusted = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_TRUSTED:
            _trusted = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_CHECK_VALUE:
            if (!a_Attribute.pValue || a_Attribute.ulValueLen != 3)
                throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
            else
            {
                _checkValue = (((CK_BYTE*) a_Attribute.pValue)[0] << 16) 
                    + (((CK_BYTE*) a_Attribute.pValue)[1] << 8)
                    + ((CK_BYTE*) a_Attribute.pValue)[2];
            }

            break;

        default:
            KeyObject::setAttribute( a_Attribute, objCreation );
    }
}

void SecretKeyObject::serialize(std::vector<u1> *to)
{
    KeyObject::serialize(to);

    Util::PushBBoolInVector(to,_sensitive);

    Util::PushBBoolInVector(to,_encrypt);

    Util::PushBBoolInVector(to,_decrypt);

    Util::PushBBoolInVector(to,_sign);

    Util::PushBBoolInVector(to,_verify);

    Util::PushBBoolInVector(to,_wrap);

    Util::PushBBoolInVector(to,_unwrap);

    Util::PushBBoolInVector(to,_extractable);

    Util::PushBBoolInVector(to,_alwaysSensitive);

    Util::PushBBoolInVector(to,_neverExtractable);

    Util::PushBBoolInVector(to,_wrapWithTrusted);

    Util::PushBBoolInVector(to,_trusted);

    Util::PushULongLongInVector(to,_checkValue);
}

void SecretKeyObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    KeyObject::deserialize(from,idx);

    _sensitive = Util::ReadBBoolFromVector(from,idx);

    _encrypt = Util::ReadBBoolFromVector(from,idx);

    _decrypt = Util::ReadBBoolFromVector(from,idx);

    _sign = Util::ReadBBoolFromVector(from,idx);

    _verify = Util::ReadBBoolFromVector(from,idx);

    _wrap = Util::ReadBBoolFromVector(from,idx);

    _unwrap = Util::ReadBBoolFromVector(from,idx);

    _extractable = Util::ReadBBoolFromVector(from,idx);

    _alwaysSensitive = Util::ReadBBoolFromVector(from,idx);

    _neverExtractable = Util::ReadBBoolFromVector(from,idx);

    _wrapWithTrusted = Util::ReadBBoolFromVector(from,idx);

    _trusted = Util::ReadBBoolFromVector(from,idx);

	_checkValue = Util::ReadULongLongFromVector(from,idx);
}


/*
*/
void SecretKeyObject::print( void ) {

    KeyObject::print( );

    Log::log( "CKA_SENSITIVE <%ld>", _sensitive );
    
    Log::log( "CKA_ENCRYPT <%ld>", _encrypt );

    Log::log( "CKA_DECRYPT <%ld>", _decrypt );

    Log::log( "CKA_SIGN <%ld>", _sign );

    Log::log( "CKA_VERIFY <%ld>", _verify );

    Log::log( "CKA_WRAP <%ld>", _wrap );

    Log::log( "CKA_UNWRAP <%ld>", _unwrap );

    Log::log( "CKA_EXTRACTABLE <%ld>", _extractable );

    Log::log( "CKA_ALWAYS_SENSITIVE <%ld>", _alwaysSensitive );

    Log::log( "CKA_NEVER_EXTRACTABLE <%ld>", _neverExtractable );

    Log::log( "CKA_WRAP_WITH_TRUSTED <%ld>", _wrapWithTrusted );

    Log::log( "CKA_TRUSTED <%ld>", _trusted );

    Log::log( "CKA_CHECK_VALUE <%.6X>", _checkValue );
}
