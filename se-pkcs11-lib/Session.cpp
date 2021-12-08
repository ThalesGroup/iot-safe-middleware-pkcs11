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
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <Windows.h>
#else
#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
#endif

#include "Template.hpp"
#include "Session.hpp"
#include "Slot.hpp"
#include "PKCS11Exception.hpp"
#include <boost/foreach.hpp>
#include "Pkcs11ObjectKeyPublicECC.hpp"
#include "Pkcs11ObjectKeyPrivateECC.hpp"
#include "Pkcs11ObjectKeyGenericSecret.hpp"
#include "attrcert.h"
#include "digest.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>


unsigned char Session::s_ucSessionObjectIndex = 0;

extern unsigned char g_pbECC256_OID[10];

extern unsigned char g_pbECC384_OID[7];

extern unsigned char g_pbECC521_OID[7];

/*
*/
Session::Session( Slot* a_pSlot, const CK_SESSION_HANDLE& a_hSession, const CK_BBOOL& a_bIsReadWrite ) {
    
	m_Slot = a_pSlot; 
	
	m_ulId = a_hSession;

	m_bIsReadWrite = a_bIsReadWrite;
	
	m_bIsSearchActive = false;
	
	m_bIsDigestActive = false;
	
	m_bIsDigestActiveKeyOp = false;
	
	m_bIsDigestVerificationActiveKeyOp = false;

	// The User or the SO has may be performed a login before to open this session
	// In this case the state of the session must be updated
    getState( );
}

/*
*/
Session::~Session( )
{
    SESSION_OBJECTS::iterator It;
    for (It = m_Objects.begin(); It != m_Objects.end(); It ++)
    {
        m_Slot->m_SessionObjects.erase(It->first);
    }
    m_Objects.clear();
}

/*
*/
CK_STATE Session::getState( void ) { 
    
    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    CK_USER_TYPE ulRole = m_Slot->getUserType( );

    updateState( ulRole );

    return m_ulState; 
}


/*
*/
void Session::updateState( const CK_ULONG& a_ulRoleLogged ) {

	if( m_bIsReadWrite ) {

		switch( a_ulRoleLogged ) {

		case CK_UNAVAILABLE_INFORMATION:
			m_ulState = CKS_RW_PUBLIC_SESSION;
			break;

		case CKU_USER:
			m_ulState = CKS_RW_USER_FUNCTIONS;
			break;

		case CKU_SO:
			m_ulState = CKS_RW_SO_FUNCTIONS;
			break;
		}

	} else {
		
		switch( a_ulRoleLogged ) {

		case CK_UNAVAILABLE_INFORMATION:
			m_ulState = CKS_RO_PUBLIC_SESSION;
			break;

		case CKU_USER:
			m_ulState = CKS_RO_USER_FUNCTIONS;
			break;

		case CKU_SO:
			throw PKCS11Exception( CKR_SESSION_READ_ONLY );
		}
	}
}


/*
*/
StorageObject* Session::getObject( const CK_OBJECT_HANDLE& a_hObject, bool bOwned ) {

    if (!bOwned)
        return m_Slot->getSessionObject(a_hObject);
    else
    {
	    if( !a_hObject ) {

		    throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	    }

	    // Find the targeted object
	    SESSION_OBJECTS::iterator i = m_Objects.find( a_hObject );

         if( i == m_Objects.end( ) ) {
	
		     throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	     }

	    return i->second;
    }
}


/*
*/
void Session::findObjects( CK_OBJECT_HANDLE_PTR a_phObject, const CK_ULONG& a_ulMaxObjectCount, CK_ULONG_PTR a_pulObjectCount ) {
    
    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    bool bIsNotAllowedToAccessPrivateObjects = !m_Slot->isAuthenticated( );

    Session::EXPLORED_HANDLES::iterator end = m_SessionObjectsReturnedInSearch.end( );

    // For each P11 object
    BOOST_FOREACH( const Slot::SESSION_OBJECTS::value_type& o, m_Slot->m_SessionObjects ) {

        // Check if the search has reached the allowed maximum of objects to search 
        if( *a_pulObjectCount >= a_ulMaxObjectCount ) {

            break;
        }

        // Check if this object has been already compared to the search template
        if( end != m_SessionObjectsReturnedInSearch.find( o->first ) ) {

            // This object has already been analysed by a previous call of findObjects for this template
            continue;
        }

        // If the object is private and the user is not logged in
        if( o->second->isPrivate( ) && bIsNotAllowedToAccessPrivateObjects )
        {
            // Then avoid this element. 
            // Do not add it the list of already explored objects (may be a C_Login can occur)
            continue;
        }

        // Add the object to the list of the objects compared to the search template
        m_SessionObjectsReturnedInSearch.insert( o->first );

        // If the template is NULL then return all objects
        if( !_searchTempl ) {

            a_phObject[ *a_pulObjectCount ] = o->first;

            ++(*a_pulObjectCount);

        } else {
            // The template is not NULL.
   
            bool match = true;

            // In this case the template attributes have to be compared to the objects ones.
            BOOST_FOREACH( CK_ATTRIBUTE& t, _searchTempl->getAttributes( ) ) {

                if( ! o->second->compare( t ) ) {

                    match = false;

                    break;
                }
            }

            // The attributes match
            if( match ) {

                // Add the object handle to the outgoing list
                a_phObject[ *a_pulObjectCount ] = o->first;

                // Increment the number of found objects
                ++(*a_pulObjectCount);
            }
        }
    }
}


/*
*/
void Session::deleteObject( const CK_OBJECT_HANDLE& a_hObject ) {

    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

	// Find the targeted object
	StorageObject* o = getObject( a_hObject, true );

	// if this is a readonly session and user is not logged 
	// then only public session objects can be created
	if( !m_bIsReadWrite && o->isToken( ) ) {

		throw PKCS11Exception( CKR_SESSION_READ_ONLY );
	}

	if( o->isPrivate( ) && !m_Slot->isAuthenticated( ) ) {
        
		throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
	}
	
	try {
    
        m_Objects.erase( a_hObject );
        m_Slot->m_SessionObjects.erase(a_hObject );
    
    } catch( ... ) {
    
        throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
    }
}


/*
*/
void Session::getAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Find the targeted object
	StorageObject* o = getObject( a_hObject );

	if( o->isPrivate( ) && !m_Slot->isAuthenticated( ) ) {
        
		for( u4 i = 0 ; i < a_ulCount ; ++i ) {

			a_pTemplate[ i ].ulValueLen = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
		}

		throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
	}

	for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {
		
		o->getAttribute( &a_pTemplate[ i ] );
	}
}


/*
*/
void Session::setAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Find the targeted object
	StorageObject* o = getObject( a_hObject );

	if( o->isPrivate( ) && !m_Slot->isAuthenticated( ) ) {
        
        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
	}

	for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

		o->setAttribute( a_pTemplate[ i ], false );
	}
}


/*
*/
CK_OBJECT_HANDLE Session::computeObjectHandle( const CK_OBJECT_CLASS& a_ulClass, const bool& a_bIsPrivate ) { 
    
    // Register the session object id (value from 0 to 255)
    unsigned char ucByte1 = ++s_ucSessionObjectIndex;

    // Register the object class and if the object is private:
	// Private Data	        1000 [08] = set class to CKO_DATA (0x00) and Private to TRUE (0x08)
	// Public Data	        0000 [00] = set class to CKO_DATA (0x00) and Private to FALSE (0x00)	
	// Private Certificate	1001 [09] = set class to CKO_CERTIFICATE (0x01) and Private to TRUE (0x08)
	// Public Certificate	0001 [01] = set class to CKO_CERTIFICATE (0x01) and Private to FALSE (0x00)		
	// Private Public Key	1010 [10] = set class to CKO_PUBLIC_KEY (0x02) and Private to TRUE (0x08)
	// Public Public Key	0010 [02] = set class to CKO_PUBLIC_KEY (0x02) and Private to FALSE (0x00)    
    // Private Private Key	1011 [11] = set class to CKO_PRIVATE_KEY (0x03) and Private to TRUE (0x08)			
	// Public Private Key	0011 [03] = set class to CKO_PRIVATE_KEY (0x03) and Private to FALSE (0x00)
	unsigned char ucByte2 = (unsigned char)a_ulClass + ( a_bIsPrivate ? 0x08 : 0x00 );

    // Register if the object is owned by the token (value 0) or the session (value corresponding to the session id from 1 to 255)
    unsigned char ucByte3 = (unsigned char) ( 0x000000FF & m_ulId );

    // Register the slot id
    unsigned char ucByte4 = (unsigned char) ( 0x000000FF & m_Slot->getSlotId( ) );

    // Compute the object handle: byte4 as Slot Id, byte3 as Token/Session, byte2 as attributes and byte1 as object Id					
    CK_OBJECT_HANDLE h = ( ucByte4 << 24 ) + ( ucByte3 << 16 ) + ( ucByte2 << 8 )+ ucByte1;

    return h; 
}


/*
*/
void Session::addObject( StorageObject* a_pObj, CK_OBJECT_HANDLE_PTR a_phObject ) { 
    
    *a_phObject = computeObjectHandle( a_pObj->getClass( ), a_pObj->isPrivate( ) ); 
    
    CK_OBJECT_HANDLE h = *a_phObject; 
    
    m_Objects.insert( SESSION_OBJECTS::value_type( h, a_pObj ) ); 
    m_Slot->m_SessionObjects.insert( h, a_pObj ); 
}

/*
*/
void Session::generateKeyPair( Pkcs11ObjectKeyPublic* a_pObjectPublicKey, PrivateKeyObject* a_pObjectPrivateKey, CK_OBJECT_HANDLE_PTR a_pHandlePublicKeyRSA, CK_OBJECT_HANDLE_PTR a_pHandlePrivateKeyRSA ) {

	UNREFERENCED_PARAMETER (a_pHandlePublicKeyRSA);
	UNREFERENCED_PARAMETER (a_pHandlePrivateKeyRSA);

	if (a_pObjectPublicKey->_keyType == CKK_RSA)
    {
        // We do not support generation of RSA key pair in the session
        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }
    Pkcs11ObjectKeyPublicECC* eccPubKey = (Pkcs11ObjectKeyPublicECC*) a_pObjectPublicKey;
    ECCPrivateKeyObject* eccPrvKey = (ECCPrivateKeyObject*) a_pObjectPrivateKey;

    int nid;
    unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
    boost::shared_ptr< u1Array > params = eccPubKey->m_pParams;

    if (Util::compareU1Arrays(params.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
    {
        ucKeySpec = MiniDriverContainer::KEYSPEC_ECDHE_256;
        nid = NID_X9_62_prime256v1;
    }
    else if (Util::compareU1Arrays(params.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
    {
        ucKeySpec = MiniDriverContainer::KEYSPEC_ECDHE_384;
        nid = NID_secp384r1;
    }
    else if (Util::compareU1Arrays(params.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
    {
        ucKeySpec = MiniDriverContainer::KEYSPEC_ECDHE_521;
        nid = NID_secp521r1;
    }
    else
    {
        throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
    }

	// Generate random EC key with OpenSSL
   EC_KEY *eckey=EC_KEY_new();
   EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(nid);
   assert(ecgroup != NULL);
   int set_group_status = EC_KEY_set_group(eckey,ecgroup);
   assert(set_group_status == 1);
   int gen_status = EC_KEY_generate_key(eckey);
   assert(gen_status == 1);

   // Get the public point
   const EC_POINT* pubPoint = EC_KEY_get0_public_key(eckey);
   BN_CTX* ctx = BN_CTX_new();
   CK_ULONG l = EC_POINT_point2oct(ecgroup, pubPoint, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
   CK_BYTE_PTR v = new CK_BYTE[l];
   l = EC_POINT_point2oct(ecgroup, pubPoint, POINT_CONVERSION_UNCOMPRESSED, v, l, ctx);
   ASN1_OCTET_STRING* oct = ASN1_OCTET_STRING_new();
   ASN1_OCTET_STRING_set(oct, v, l);
   delete [] v;
   v = NULL;
   l = i2d_ASN1_OCTET_STRING(oct, &v);
   ASN1_OCTET_STRING_free(oct);

   eccPubKey->m_pPublicPoint.reset(new u1Array(l));
   eccPubKey->m_pPublicPoint->SetBuffer(v);
   eccPrvKey->m_pPublicPoint = eccPubKey->m_pPublicPoint;

   OPENSSL_free(v);
   BN_CTX_free(ctx);

   // Get the private value
   const BIGNUM* prvVal = EC_KEY_get0_private_key(eckey);
   l = BN_num_bytes(prvVal);
   v = new CK_BYTE[l];
   BN_bn2bin(prvVal, v);
   eccPrvKey->m_pPrivateValue.reset(new u1Array(l));
   eccPrvKey->m_pPrivateValue->SetBuffer(v);
   delete [] v;

   // set the params of the private key
   eccPrvKey->m_pParams = eccPubKey->m_pParams;
 
   EC_KEY_free(eckey);
   EC_GROUP_free(ecgroup);

   a_pObjectPrivateKey->m_ucKeySpec = ucKeySpec;
   a_pObjectPublicKey->m_ucKeySpec = ucKeySpec;

   // Fill the PKCS#11 object with the information about the new key pair
   a_pObjectPublicKey->_local = CK_TRUE;

   // Copy these modulus and exponent in the private key component also
   a_pObjectPrivateKey->_local = CK_TRUE;      

   setDefaultAttributesKeyPrivate( a_pObjectPrivateKey );

   setDefaultAttributesKeyPublic( a_pObjectPublicKey );
}

/*
*/
void Session::deriveKey( PrivateKeyObject* a_pObjectPrivateKey, CK_ECDH1_DERIVE_PARAMS_PTR a_pEcdhParams, SecretKeyObject* a_pDerivedKey, CK_OBJECT_HANDLE_PTR a_pHandleDerivedKey)
{
	UNREFERENCED_PARAMETER (a_pHandleDerivedKey);

	if (a_pObjectPrivateKey->_keyType != CKK_EC || a_pDerivedKey->_keyType != CKK_GENERIC_SECRET)
    {
        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    ECCPrivateKeyObject* eccPrvKey = (ECCPrivateKeyObject*) a_pObjectPrivateKey;
    GenericSecretKeyObject* derivedKey = (GenericSecretKeyObject*) a_pDerivedKey;

    if (!eccPrvKey->m_pPrivateValue.get())
        throw PKCS11Exception( CKR_FUNCTION_FAILED );

    int nid;
    boost::shared_ptr< u1Array > params = eccPrvKey->m_pParams;

    if (Util::compareU1Arrays(params.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
    {
        nid = NID_X9_62_prime256v1;
    }
    else if (Util::compareU1Arrays(params.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
    {
        nid = NID_secp384r1;
    }
    else if (Util::compareU1Arrays(params.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
    {
        nid = NID_secp521r1;
    }
    else
    {
        throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    // Set the public point value
    const unsigned char* ptr = eccPrvKey->m_pPublicPoint->GetBuffer();
    long len = eccPrvKey->m_pPublicPoint->GetLength();
    ASN1_OCTET_STRING* oct = d2i_ASN1_OCTET_STRING(NULL, &ptr, len);
    if (oct && (ptr == eccPrvKey->m_pPublicPoint->GetBuffer() + len))
    {
        ptr = oct->data;
        len = oct->length;
    }
    else
    {
        ptr = eccPrvKey->m_pPublicPoint->GetBuffer();
        len = eccPrvKey->m_pPublicPoint->GetLength();
    }

    if (ptr[0] != 0x04)
    {
        if (oct) ASN1_OCTET_STRING_free(oct);
        throw PKCS11Exception(CKR_FUNCTION_FAILED);
    }

    EC_KEY *eckey=EC_KEY_new();
    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(nid);
    assert(ecgroup != NULL);
    int set_group_status = EC_KEY_set_group(eckey,ecgroup);
    assert(set_group_status == 1);

    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* pubPoint = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubPoint, ptr, len, ctx);
    if (oct) ASN1_OCTET_STRING_free(oct);
    BN_CTX_free(ctx);

    EC_KEY_set_public_key(eckey, pubPoint);
    EC_POINT_free(pubPoint);

    // set the private key value
    ptr = eccPrvKey->m_pPrivateValue->GetBuffer();
    len = eccPrvKey->m_pPrivateValue->GetLength();

    BIGNUM* prvVal = BN_bin2bn(ptr, len, NULL);
    EC_KEY_set_private_key(eckey, prvVal);
    BN_free(prvVal);

    // Set the other party public point
    ptr = a_pEcdhParams->pPublicData;
    len = a_pEcdhParams->ulPublicDataLen;
    oct = d2i_ASN1_OCTET_STRING(NULL, &ptr, len);
    if (oct && (ptr == a_pEcdhParams->pPublicData + len))
    {
        ptr = oct->data;
        len = oct->length;
    }
    else
    {
        ptr = a_pEcdhParams->pPublicData;
        len = a_pEcdhParams->ulPublicDataLen;
    }

    if (ptr[0] != 0x04)
    {
        if (oct) ASN1_OCTET_STRING_free(oct);
        EC_KEY_free(eckey);
        EC_GROUP_free(ecgroup);
        throw PKCS11Exception(CKR_MECHANISM_PARAM_INVALID);
    }

    ctx = BN_CTX_new();
    pubPoint = EC_POINT_new(ecgroup);
    EC_POINT_oct2point(ecgroup, pubPoint, ptr, len, ctx);
    if (oct) ASN1_OCTET_STRING_free(oct);
    BN_CTX_free(ctx);

    // compute ECDH value
    unsigned char ecdhVal[256];
    int ecdhLen = 256;
    ecdhLen = ECDH_compute_key(ecdhVal, ecdhLen, pubPoint, eckey, NULL);

    u1Array DHAgreement(ecdhLen);
    u1Array SharedInfo(a_pEcdhParams->ulSharedDataLen);

    DHAgreement.SetBuffer(ecdhVal);
    SharedInfo.SetBuffer(a_pEcdhParams->pSharedData);

    if (a_pEcdhParams->kdf == CKD_NULL)
    {
        derivedKey->NULL_drive(&DHAgreement);
    }
    else
    {
        derivedKey->ANSI_X9_63_drive(&DHAgreement, &SharedInfo);
    }

    EC_POINT_free(pubPoint);
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);

    derivedKey->_local = TRUE;
}

/*
*/
void Session::setDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublic* a_pObject ) {

    if( !a_pObject ) {

        return;
    }

    if (a_pObject->_keyType == CKK_RSA)
    {
        Pkcs11ObjectKeyPublicRSA* a_pRsaKey = (Pkcs11ObjectKeyPublicRSA*) a_pObject;

        if( !a_pRsaKey->m_pModulus ) {

            return;
        }

        try {

            if( !a_pRsaKey->m_pLabel ) {

                generateLabel( a_pRsaKey->m_pModulus, a_pRsaKey->m_pLabel );
            }

            if( !a_pRsaKey->m_pID ) {

                generateID( a_pRsaKey->m_pModulus, a_pRsaKey->m_pID );
            }

        } catch( ... ) {

        }
    }
    else
    {
        Pkcs11ObjectKeyPublicECC* a_pEccKey = (Pkcs11ObjectKeyPublicECC*) a_pObject;

        if( !a_pEccKey->m_pPublicPoint ) {

            return;
        }

        try {

            if( !a_pEccKey->m_pLabel ) {

                generateLabel( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pLabel );
            }

            if( !a_pEccKey->m_pID ) {

                generateID( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pID );
            }

        } catch( ... ) {

        }
    }
}


/*
*/
void Session::setDefaultAttributesKeyPrivate( PrivateKeyObject* a_pObject ) {

    if( !a_pObject ) {

        return;
    }

    if (a_pObject->_keyType == CKK_RSA)
    {
        RSAPrivateKeyObject* a_pRsaKey = (RSAPrivateKeyObject*) a_pObject;

        if( !a_pRsaKey->m_pModulus ) {

            return;
        }

        try {



            // Compatibility with old P11
            unsigned char* p = a_pRsaKey->m_pModulus->GetBuffer( );
            unsigned int l = a_pRsaKey->m_pModulus->GetLength( );

            a_pObject->_checkValue = Util::MakeCheckValue( p, l );

            if( !a_pRsaKey->m_pLabel ) {

                generateLabel( a_pRsaKey->m_pModulus, a_pRsaKey->m_pLabel );
            }

            if( !a_pRsaKey->m_pID ) {

                generateID( a_pRsaKey->m_pModulus, a_pRsaKey->m_pID );
            }

        } catch( ... ) {

        }
    }
    else
    {
        ECCPrivateKeyObject* a_pEccKey = (ECCPrivateKeyObject*) a_pObject;

        if( !a_pEccKey->m_pPublicPoint ) {

            return;
        }

        try {

            // Compatibility with old P11
            unsigned char* p = a_pEccKey->m_pPublicPoint->GetBuffer( );
            unsigned int l = a_pEccKey->m_pPublicPoint->GetLength( );

            a_pObject->_checkValue = Util::MakeCheckValue( p, l );

            if( !a_pEccKey->m_pLabel ) {

                generateLabel( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pLabel );
            }

            if( !a_pEccKey->m_pID ) {

                generateID( a_pEccKey->m_pPublicPoint, a_pEccKey->m_pID );
            }

        } catch( ... ) {

        }
    }
}

/* Generate a default label from the public key modulus
*/
void Session::generateLabel( boost::shared_ptr< u1Array>& a_pModulus, boost::shared_ptr< u1Array>& a_pLabel ) {

    if( !a_pModulus ) {

        return;
    }

    std::string stLabel = CAttributedCertificate::DerivedUniqueName( a_pModulus->GetBuffer( ), a_pModulus->GetLength( ) );

    a_pLabel.reset( new u1Array( stLabel.size( ) ) );

    a_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

}


/* Generate a default id from the public key modulus
*/
void Session::generateID( boost::shared_ptr< u1Array>& a_pModulus, boost::shared_ptr< u1Array>& a_pID ) {

    if( !a_pModulus ) {

        return;
    }

    a_pID.reset( computeSHA1( a_pModulus->GetBuffer( ), a_pModulus->GetLength( ) ) );
}

/*
*/
u1Array* Session::computeSHA1( const unsigned char* a_pData, const size_t& a_uiLength ) {

    CDigest* sha1 = CDigest::getInstance(CDigest::SHA1);

    u1Array* pHash = new u1Array( sha1->hashLength() );

    sha1->hashUpdate( (unsigned char*)a_pData, 0, a_uiLength );

    sha1->hashFinal( pHash->GetBuffer( ) );

    delete sha1;

    return pHash;
}

/*
*/
void Session::sign( const KeyObject* privObj, u1Array* dataToSign, const CK_ULONG& mechanism, CK_BYTE_PTR pSignature ) {

    if (privObj->_keyType == CKK_RSA)
    {
        boost::shared_ptr< u1Array > messageToSign;

        RSAPrivateKeyObject* rsaKey = ( RSAPrivateKeyObject* ) privObj;

        if( !(rsaKey->m_pModulus) || !(rsaKey->m_pPrivateExponent)) {

            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        CK_ULONG modulusLen = rsaKey->m_pModulus->GetLength( );

        if( ( ( mechanism == CKM_RSA_PKCS ) && ( dataToSign->GetLength( ) > ( modulusLen - 11 ) ) ) || ( ( mechanism == CKM_RSA_X_509 ) && ( dataToSign->GetLength( ) > modulusLen ) ) ) {

            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        u1Array signatureData(modulusLen);

        unsigned char ucAlgo = 0;
        bool bIsPSS = false;

        switch( mechanism ) {

        case CKM_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::PadRSAPKCS1v15( dataToSign, modulusLen ) );
            break;

        case CKM_RSA_X_509:
            messageToSign.reset( RSAPrivateKeyObject::PadRSAX509( dataToSign, modulusLen ) );
            break;

        case CKM_SHA1_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA_1 ) );
            break;

        case CKM_SHA256_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA256 ) );
            break;

        case CKM_SHA384_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA384 ) );
            break;

        case CKM_SHA512_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA512 ) );
            break;

        case CKM_MD5_RSA_PKCS:
            messageToSign.reset( RSAPrivateKeyObject::EncodeHashForSigning( dataToSign, modulusLen, CKM_MD5 ) );
            break;

        case CKM_RSA_PKCS_PSS:
            bIsPSS = true;
            if (dataToSign->GetLength() == 20)
                ucAlgo = ALGO_SHA_1;
            else if (dataToSign->GetLength() == 32)
                ucAlgo = ALGO_SHA_256;
            else if (dataToSign->GetLength() == 48)
                ucAlgo = ALGO_SHA_384;
            else if (dataToSign->GetLength() == 64)
                ucAlgo = ALGO_SHA_512;
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
            bIsPSS = true;
            ucAlgo = ALGO_SHA_1;
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            bIsPSS = true;
            ucAlgo = ALGO_SHA_256;
            break;
        case CKM_SHA384_RSA_PKCS_PSS:
            bIsPSS = true;
            ucAlgo = ALGO_SHA_384;
            break;
        case CKM_SHA512_RSA_PKCS_PSS:
            bIsPSS = true;
            ucAlgo = ALGO_SHA_512;
            break;
        }

        // create the openssl RSA key
        RSA* rsa = RSA_new();
        BIGNUM* rsa_n = BN_bin2bn(rsaKey->m_pModulus->GetBuffer(), rsaKey->m_pModulus->GetLength(), NULL);
        BIGNUM *rsa_d = BN_bin2bn(rsaKey->m_pPrivateExponent->GetBuffer(), rsaKey->m_pPrivateExponent->GetLength(), NULL);
	
	BIGNUM *rsa_e=NULL,*rsa_p=NULL,*rsa_q=NULL,*rsa_dmp1=NULL,*rsa_dmq1=NULL,*rsa_iqmp=NULL;
        if (rsaKey->m_pPublicExponent)
            rsa_e = BN_bin2bn(rsaKey->m_pPublicExponent->GetBuffer(), rsaKey->m_pPublicExponent->GetLength(), NULL);
        if (rsaKey->m_pPrime1)
            rsa_p = BN_bin2bn(rsaKey->m_pPrime1->GetBuffer(), rsaKey->m_pPrime1->GetLength(), NULL);
        if (rsaKey->m_pPrime2)
            rsa_q = BN_bin2bn(rsaKey->m_pPrime2->GetBuffer(), rsaKey->m_pPrime2->GetLength(), NULL);
        if (rsaKey->m_pExponent1)
            rsa_dmp1 = BN_bin2bn(rsaKey->m_pExponent1->GetBuffer(), rsaKey->m_pExponent1->GetLength(), NULL);
        if (rsaKey->m_pExponent2)
            rsa_dmq1 = BN_bin2bn(rsaKey->m_pExponent2->GetBuffer(), rsaKey->m_pExponent2->GetLength(), NULL);
        if (rsaKey->m_pCoefficient)
            rsa_iqmp = BN_bin2bn(rsaKey->m_pCoefficient->GetBuffer(), rsaKey->m_pCoefficient->GetLength(), NULL);

        RSA_set0_key(rsa,rsa_n,rsa_e,rsa_d);
	RSA_set0_factors(rsa,rsa_p,rsa_q);
	RSA_set0_crt_params(rsa,rsa_dmp1,rsa_dmq1,rsa_iqmp);

        int status;

        if (bIsPSS)
        {            
            const EVP_MD *Hash = NULL;
            switch (ucAlgo)
            {
                case ALGO_SHA_1: Hash = EVP_sha1(); break;
                case ALGO_SHA_256: Hash = EVP_sha256(); break;
                case ALGO_SHA_384: Hash = EVP_sha384(); break;
                case ALGO_SHA_512: Hash = EVP_sha512(); break;
            }
            const EVP_MD *mgf1Hash = Hash; // we support only MGF1 based on the same hash function as the one specified

            messageToSign.reset(new u1Array(modulusLen));
            status = EncodePSS(BN_num_bits(rsa_n), messageToSign->GetBuffer(), dataToSign->GetBuffer(), Hash, mgf1Hash, EVP_MD_size(Hash));
            if (status == 1)
            {
                status = RSA_private_encrypt(messageToSign->GetLength(), messageToSign->GetBuffer(), signatureData.GetBuffer(), rsa, RSA_NO_PADDING);
            }

        }
        else
        {
            status = RSA_private_encrypt(messageToSign->GetLength(), messageToSign->GetBuffer(), signatureData.GetBuffer(), rsa, RSA_NO_PADDING);
        }

        RSA_free(rsa);
        if( status <= 0 ) {

            throw PKCS11Exception( CKR_FUNCTION_FAILED );
        }

        memcpy( pSignature, signatureData.GetBuffer( ), signatureData.GetLength( ) );
    }
    else
    {
        ECCPrivateKeyObject* eccKey = ( ECCPrivateKeyObject* ) privObj;

        if( !(eccKey->m_pParams) || !(eccKey->m_pPrivateValue)) {

            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }

        int nid;
        boost::shared_ptr< u1Array > params = eccKey->m_pParams;

        int nLen = (eccKey->getOrderBitLength() + 7) / 8;

        if (Util::compareU1Arrays(params.get(), g_pbECC256_OID, sizeof(g_pbECC256_OID)))
        {
            nid = NID_X9_62_prime256v1;
        }
        else if (Util::compareU1Arrays(params.get(), g_pbECC384_OID, sizeof(g_pbECC384_OID)))
        {
            nid = NID_secp384r1;
        }
        else if (Util::compareU1Arrays(params.get(), g_pbECC521_OID, sizeof(g_pbECC521_OID)))
        {
            nid = NID_secp521r1;
        }
        else
        {
            throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
        }

       EC_KEY *eckey=EC_KEY_new();
       EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(nid);
       assert(ecgroup != NULL);
       int set_group_status = EC_KEY_set_group(eckey,ecgroup);
       assert(set_group_status == 1);

        const unsigned char* ptr = NULL;
        long len = 0;
       // Set the public point value
       if (eccKey->m_pPublicPoint != NULL)
       {
            ptr = eccKey->m_pPublicPoint->GetBuffer();
            len = eccKey->m_pPublicPoint->GetLength();
       ASN1_OCTET_STRING* oct = d2i_ASN1_OCTET_STRING(NULL, &ptr, len);
       if (oct && (ptr == eccKey->m_pPublicPoint->GetBuffer() + len))
       {
           ptr = oct->data;
           len = oct->length;
       }
       else
       {
           ptr = eccKey->m_pPublicPoint->GetBuffer();
           len = eccKey->m_pPublicPoint->GetLength();
       }

       BN_CTX* ctx = BN_CTX_new();
       EC_POINT* pubPoint = EC_POINT_new(ecgroup);
       EC_POINT_oct2point(ecgroup, pubPoint, ptr, len, ctx);
       if (oct) ASN1_OCTET_STRING_free(oct);
       BN_CTX_free(ctx);

       EC_KEY_set_public_key(eckey, pubPoint);
       EC_POINT_free(pubPoint);
       }
       // set the private key value
       ptr = eccKey->m_pPrivateValue->GetBuffer();
       len = eccKey->m_pPrivateValue->GetLength();

       BIGNUM* prvVal = BN_bin2bn(ptr, len, NULL);
       EC_KEY_set_private_key(eckey, prvVal);
       BN_free(prvVal);

      
       ECDSA_SIG* sig = ECDSA_do_sign(dataToSign->GetBuffer(), dataToSign->GetLength(), eckey);
       EC_KEY_free(eckey);
       EC_GROUP_free(ecgroup);

       if (!sig)
           throw PKCS11Exception(CKR_FUNCTION_FAILED);

       // fill the signature byte array by concatenating r and s
       const BIGNUM *r=NULL,*s=NULL;
       ECDSA_SIG_get0(sig, &r, &s);
       int rLen = BN_num_bytes(r);
       if (rLen == nLen)
           BN_bn2bin(r, pSignature);
       else
       {
           memset(pSignature, 0, nLen - rLen);
           BN_bn2bin(r, pSignature + (nLen - rLen) );
       }

       int sLen = BN_num_bytes(s);
       if (sLen == nLen)
           BN_bn2bin(s, pSignature + nLen);
       else
       {
           memset(pSignature + nLen, 0, nLen - sLen);
           BN_bn2bin(s, pSignature + nLen + (nLen - sLen));
       }

       ECDSA_SIG_free(sig);
    }
}

void Session::verify( const StorageObject* pubObj, u1Array* dataToVerify, const CK_ULONG& mechanism, u1Array* signature )
{
    Pkcs11ObjectKeyPublic* pubKey = (Pkcs11ObjectKeyPublic*) pubObj;
    if (pubKey->_keyType == CKK_RSA)
    {
        throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
    }

    Pkcs11ObjectKeyPublicECC* eccKey = (Pkcs11ObjectKeyPublicECC*) pubObj;
    u4 nLen = (eccKey->getOrderBitLength() + 7) / 8;
    u4 ulExpectedSigLen = 2 * nLen;

    if (mechanism == CKM_ECDSA)
    {
        if (dataToVerify->GetLength() != 20 && dataToVerify->GetLength() != 32 && dataToVerify->GetLength() != 48 && dataToVerify->GetLength() != 64)
        {
            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }
    }

    if( (signature->GetLength() == 0) || (signature->GetLength( ) > ulExpectedSigLen) || (signature->GetLength() % 2 != 0)){

        throw PKCS11Exception(CKR_SIGNATURE_LEN_RANGE);
    }

    if (!eccKey->verify(dataToVerify, signature))
        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
}

void Session::decrypt( const StorageObject* privObj, u1Array* dataToDecrypt, const CK_ULONG& mechanism, unsigned char algo, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen ) {

    RSAPrivateKeyObject* rsaKey = (RSAPrivateKeyObject*)privObj;

    if (!rsaKey->m_pModulus || !rsaKey->m_pPrivateExponent)
    {
        throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
    }

    RSA* rsa = RSA_new();
    BIGNUM* rsa_n = BN_bin2bn(rsaKey->m_pModulus->GetBuffer(), rsaKey->m_pModulus->GetLength(), NULL);
    BIGNUM* rsa_d = BN_bin2bn(rsaKey->m_pPrivateExponent->GetBuffer(), rsaKey->m_pPrivateExponent->GetLength(), NULL);
    BIGNUM *rsa_e=NULL,*rsa_p=NULL,*rsa_q=NULL,*rsa_dmp1=NULL,*rsa_dmq1=NULL,*rsa_iqmp=NULL;
    if (rsaKey->m_pPublicExponent)
         rsa_e = BN_bin2bn(rsaKey->m_pPublicExponent->GetBuffer(), rsaKey->m_pPublicExponent->GetLength(), NULL);
    if (rsaKey->m_pPrime1)
         rsa_p = BN_bin2bn(rsaKey->m_pPrime1->GetBuffer(), rsaKey->m_pPrime1->GetLength(), NULL);
    if (rsaKey->m_pPrime2)
         rsa_q = BN_bin2bn(rsaKey->m_pPrime2->GetBuffer(), rsaKey->m_pPrime2->GetLength(), NULL);
    if (rsaKey->m_pExponent1)
         rsa_dmp1 = BN_bin2bn(rsaKey->m_pExponent1->GetBuffer(), rsaKey->m_pExponent1->GetLength(), NULL);
    if (rsaKey->m_pExponent2)
         rsa_dmq1 = BN_bin2bn(rsaKey->m_pExponent2->GetBuffer(), rsaKey->m_pExponent2->GetLength(), NULL);
    if (rsaKey->m_pCoefficient)
         rsa_iqmp = BN_bin2bn(rsaKey->m_pCoefficient->GetBuffer(), rsaKey->m_pCoefficient->GetLength(), NULL);
	
     RSA_set0_key(rsa,rsa_n,rsa_e,rsa_d);
     RSA_set0_factors(rsa,rsa_p,rsa_q);
     RSA_set0_crt_params(rsa,rsa_dmp1,rsa_dmq1,rsa_iqmp);

    int modulusLen = RSA_size(rsa);
    u1Array data(modulusLen);
    int opensslPadding = RSA_NO_PADDING;
    if (CKM_RSA_PKCS == mechanism)
        opensslPadding = RSA_PKCS1_PADDING;
    int l = RSA_private_decrypt(dataToDecrypt->GetLength(), dataToDecrypt->GetBuffer(), data.GetBuffer(), rsa, opensslPadding);
    RSA_free(rsa);

    if (l < 0)
    {
        throw PKCS11Exception( CKR_ENCRYPTED_DATA_INVALID );
    }

    unsigned char* p = (unsigned char*)data.GetBuffer( );

    if( CKM_RSA_PKCS_OAEP == mechanism ) {

        /* perform specific OAEP decoding */
        u1Array decodedData(modulusLen);
        const EVP_MD* dgst = NULL;
        switch(algo)
        {
            case ALGO_SHA_1: dgst = EVP_sha1(); break;
            case ALGO_SHA_256: dgst = EVP_sha256(); break;
            case ALGO_SHA_384: dgst = EVP_sha384(); break;
            case ALGO_SHA_512: dgst = EVP_sha512(); break;        
        }

        int decodedLen = DecodeOAEP(decodedData.GetBuffer(), decodedData.GetLength(), p, l, modulusLen, dgst, NULL, 0);
        if (decodedLen < 0)
        {
            throw PKCS11Exception( CKR_ENCRYPTED_DATA_INVALID );
        }

        memcpy(p, decodedData.GetBuffer(), decodedLen);
        l = decodedLen;
    }

    if ( *pulDataLen >= (CK_ULONG) l ) {

        memset( pData, 0, *pulDataLen );

        memcpy( pData, p, l );

        *pulDataLen = l;
    } else {

        *pulDataLen = l;

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }
}

