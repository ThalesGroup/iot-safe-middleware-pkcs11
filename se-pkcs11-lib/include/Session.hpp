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
#ifndef __GEMALTO_SESSION__
#define __GEMALTO_SESSION__


#include "Template.hpp"
#include "digest.h"
#include "Pkcs11ObjectKeyPublic.hpp"
#include "Pkcs11ObjectKeyPrivate.hpp"
#include "Pkcs11ObjectKeySecret.hpp"
#include <set>
#include <vector>
#include <map>
#include <boost/smart_ptr.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include "Array.h"
#include "cryptoki.h"
#include "util.h"


class Slot;


/*
*/
class CryptoOperation {
       
    //StorageObject* m_pObject;
    u1Array m_pParams;
    CK_ULONG m_ulMechanism;
    CK_OBJECT_HANDLE m_hObject;
public:

    //CryptoOperation( const CK_ULONG& a_ulMechanism, StorageObject* a_pObject ) : m_ulMechanism( a_ulMechanism ), m_pObject( a_pObject ) { }
    CryptoOperation( CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hObject ) : m_pParams(a_pMechanism->ulParameterLen > 0 && a_pMechanism->ulParameterLen <= 256 ? a_pMechanism->ulParameterLen : 0 ), m_ulMechanism( a_pMechanism->mechanism ), m_hObject( a_hObject ) 
    { 
        if (m_pParams.GetLength())
        {
            m_pParams.SetBuffer((u1*) a_pMechanism->pParameter);
        }
    }

    //virtual ~CryptoOperation( ) { };

public:

    inline const CK_ULONG& getMechanism( void ) { return m_ulMechanism; }

    //inline StorageObject* getObject( void ) { return m_pObject; }
    inline CK_OBJECT_HANDLE& getObject( void ) { return m_hObject; }

    inline CK_VOID_PTR getParameters( void ) { if ( m_pParams.GetLength() ) return (CK_VOID_PTR) m_pParams.GetBuffer(); else return NULL;}

};



/*
*/
class Session {

public:

    typedef std::set< CK_OBJECT_HANDLE > EXPLORED_HANDLES;

    typedef std::map< CK_OBJECT_HANDLE, StorageObject* > SESSION_OBJECTS;

    Session( Slot*, const CK_SESSION_HANDLE&, const CK_BBOOL& );

    virtual ~Session( );

    inline CK_BBOOL isReadWrite( void ) { return m_bIsReadWrite; }

    inline CK_FLAGS getFlags( void ) { return ( ( m_bIsReadWrite ? CKF_RW_SESSION : 0 ) | CKF_SERIAL_SESSION ); }

    CK_STATE getState( void ); // { return m_ulState; }

    CDigest* getDigest( void ) { return m_Digest.get( ); }

    inline CSecureString* getPinSO( void ) { return m_PinSO.get( ); }

    inline void setSearchTemplate( Template* templ ) { _searchTempl.reset( templ ); m_bIsSearchActive = true; m_SessionObjectsReturnedInSearch.clear( ); }

    inline void removeSearchTemplate( void ) {_searchTempl.reset( ); m_bIsSearchActive = false; }

    inline bool isDecryptionActive( void ) { return (bool)_decryption; }

    inline bool isSignatureActive( void ) { return (bool)m_Signature; }

    void updateState( const CK_ULONG& );

    inline bool isSearchActive( void ) { return m_bIsSearchActive; }

    inline bool isDigestActive( void ) { return m_bIsDigestActive; }

    inline bool isDigestActiveKeyOp( void ) { return m_bIsDigestActiveKeyOp; }

    inline bool isDigestVerificationActiveKeyOp( void ) { return m_bIsDigestVerificationActiveKeyOp; }

    void addObject( StorageObject*, CK_OBJECT_HANDLE_PTR );

    void generateKeyPair( Pkcs11ObjectKeyPublic*, PrivateKeyObject*, CK_OBJECT_HANDLE_PTR , CK_OBJECT_HANDLE_PTR );

    void deriveKey( PrivateKeyObject*, CK_ECDH1_DERIVE_PARAMS_PTR, SecretKeyObject*, CK_OBJECT_HANDLE_PTR );

    static void setDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublic* );

    static void setDefaultAttributesKeyPrivate( PrivateKeyObject* );

    static void generateLabel( boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    static void generateID(boost::shared_ptr< u1Array>&, boost::shared_ptr< u1Array>& );

    static u1Array* computeSHA1( const unsigned char* a_pData, const size_t& a_uiLength );

    void sign( const KeyObject*, u1Array*, const CK_ULONG&, CK_BYTE_PTR );

    void verify( const StorageObject*, u1Array*, const CK_ULONG&, u1Array* );

    void decrypt( const StorageObject*, u1Array*, const CK_ULONG&, unsigned char, CK_BYTE_PTR , CK_ULONG_PTR );

    void deleteObject( const CK_OBJECT_HANDLE& );

    void findObjects( CK_OBJECT_HANDLE_PTR, const CK_ULONG&, CK_ULONG_PTR);

    void getAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    void setAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    inline void setSlot( boost::shared_ptr< Slot > a_pSlot ) { m_Slot = a_pSlot.get( ); }

    StorageObject* getObject( const CK_OBJECT_HANDLE& a_hObject, bool bOwned = false );

    inline boost::shared_ptr< CryptoOperation >& getSignature( void ) { return m_Signature; }

    inline void setEncryptionOperation( CryptoOperation *encryption ) { _encryption.reset( encryption ); }

    inline void removeEncryptionOperation( void ) { _encryption.reset( ); }

    inline bool isEncryptionActive( void ) { return (_encryption.get( ) != NULL_PTR); }

    inline void setVerificationOperation( CryptoOperation *verification ) { _verification.reset( verification ); }

    inline void removeVerificationOperation( void ) { _verification.reset( ); }

    inline bool isVerificationActive( void ) { return (_verification.get( ) != NULL_PTR); }

    inline void setDecryptionOperation( CryptoOperation *decryption ) { _decryption.reset( decryption ); }

    inline void removeDecryptionOperation( void ) { _decryption.reset( ); }

    inline void setSignatureOperation( const boost::shared_ptr< CryptoOperation >& co ) { m_Signature = co; }

    inline void removeSignatureOperation( void ) { m_Signature.reset( ); }

    inline void setPinSO( u1Array& a ) { m_PinSO.reset( new CSecureString() ); m_PinSO->CopyFrom( a.GetBuffer( ), a.GetLength( ) ); }

    inline void setDigest(CDigest *digest) { m_Digest.reset( digest ); m_bIsDigestActive = true; }

    inline void removeDigest( void ) { m_Digest.reset( ); m_bIsDigestActive = false; }

    inline void setDigestKeyOp( CDigest *digest ) { _digestKeyOp.reset( digest ); m_bIsDigestActiveKeyOp = true; }

    inline void removeDigestKeyOp( void ) { _digestKeyOp.reset( ); m_bIsDigestActiveKeyOp = false; }

    inline void setDigestKeyVerification( CDigest *digest ) { _digestKeyVerification.reset( digest ); m_bIsDigestVerificationActiveKeyOp = true; }

    inline void removeDigestKeyVerification( void ) { _digestKeyVerification.reset( ); m_bIsDigestVerificationActiveKeyOp = false; }

    //private:
    static unsigned char s_ucSessionObjectIndex;

    CK_OBJECT_HANDLE computeObjectHandle( const CK_OBJECT_CLASS& a_ulClass, const bool& a_bIsPrivate ); 

    CK_BBOOL m_bIsReadWrite;

    CK_ULONG m_ulState;

    SESSION_OBJECTS m_Objects;

    std::set< CK_OBJECT_HANDLE > m_TokenObjectsReturnedInSearch;

    boost::shared_ptr< Template > _searchTempl;

    boost::shared_ptr< CDigest > m_Digest;

    boost::shared_ptr< CDigest > _digestKeyOp;

    boost::shared_ptr< CDigest > _digestKeyVerification;

    EXPLORED_HANDLES m_SessionObjectsReturnedInSearch;

    boost::shared_ptr< CryptoOperation > m_Signature;

    boost::shared_ptr< CryptoOperation > _decryption;

    boost::shared_ptr< CryptoOperation > _verification;

    boost::shared_ptr< CryptoOperation > _encryption;

    bool m_bIsSearchActive;

    bool m_bIsDigestActive;

    bool m_bIsDigestActiveKeyOp;

    bool m_bIsDigestVerificationActiveKeyOp;

    CK_ULONG m_ulId;

    Slot* m_Slot;

    boost::shared_ptr< u1Array > m_AccumulatedDataToSign;

    boost::shared_ptr< u1Array > m_AccumulatedDataToVerify;

    boost::shared_ptr< u1Array > m_LastBlockToSign;

    // The CardModule interface requires cryptogram as part of ChangeReferenceData method whereas
    // PKCS#11 first log SO in and then call InitPIN. InitPIN does not have any information about 
    // SO PIN so what we do here is to cache it momentarily. Basically during Login (as SO) we 
    // cache it and destroy it during closing of session
    boost::shared_ptr< CSecureString > m_PinSO;

};

#endif // __GEMALTO_SESSION__
