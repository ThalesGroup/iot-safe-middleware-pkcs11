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
#ifndef __GEMALTO_MINIDRIVER_CONTAINER__
#define __GEMALTO_MINIDRIVER_CONTAINER__


#include <utility>
#include <memory>
#include <string>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/archive/archive_exception.hpp>
#include <boost/shared_ptr.hpp>
#include "Log.hpp"
#include "Array.h"
#include "cardmod.h"
#include "MiniDriverAuthentication.hpp"


/*
*/
class MiniDriverContainer {

public:

    typedef enum { KEYSPEC_EXCHANGE = 0x01, KEYSPEC_SIGNATURE = 0x02, KEYSPEC_ECDSA_256 = 0x03, KEYSPEC_ECDSA_384 = 0x04, KEYSPEC_ECDSA_521 = 0x05, KEYSPEC_ECDHE_256 = 0x06, KEYSPEC_ECDHE_384 = 0x07, KEYSPEC_ECDHE_521 = 0x08} KEYSPEC;

    typedef enum { CMAPFILE_FLAG_EMPTY = 0x00, CMAPFILE_FLAG_VALID = 0x01, CMAPFILE_FLAG_VALID_AND_DEFAULT = 0x03 } FLAG;

    typedef enum { TAG_PUB_EXP = 0x01, TAG_MODULUS = 0x02, TAG_KEY_TYPE = 0x03, TAG_EC_X = 0x04, TAG_EC_Y = 0x05} CI_TAG;

    MiniDriverContainer( );

    void clear( const unsigned char& );

    void setContainerMapRecord( CONTAINER_MAP_RECORD* );

    void setContainerInformation( const boost::shared_ptr< u1Array >& );

    void setGUID( const std::string& a_stGUID );

    inline void setFlags( const FLAG& a_ucFlags ) { m_ContainerMapRecord.bFlags = (unsigned char)a_ucFlags; }

    inline bool empty( void ) const { return ( !m_ContainerMapRecord.wSigKeySizeBits && !m_ContainerMapRecord.wKeyExchangeKeySizeBits ); }

    inline const CONTAINER_MAP_RECORD& getContainerMapRecord( void ) { print( ); return m_ContainerMapRecord; }

    inline unsigned char getFlags( void ) const { return m_ContainerMapRecord.bFlags; }

    inline WORD getKeyExchangeSizeBits( void ) const { return m_ContainerMapRecord.wKeyExchangeKeySizeBits; }

    inline WORD getKeySignatureSizeBits( void ) const { return m_ContainerMapRecord.wSigKeySizeBits; }

    inline void setKeyExchangeSizeBits( const WORD& a_wSize ) { m_ContainerMapRecord.wKeyExchangeKeySizeBits = a_wSize; }

    inline void setKeySignatureSizeBits( const WORD& a_wSize ) { m_ContainerMapRecord.wSigKeySizeBits = a_wSize; }

    inline const boost::shared_ptr< u1Array >& getSignaturePublicKeyExponent( void ) const { return m_pSignaturePublicKeyExponent; }

    inline const boost::shared_ptr< u1Array >& getSignaturePublicKeyModulus( void ) const { return m_pSignaturePublicKeyModulus; }

    inline const boost::shared_ptr< u1Array >& getExchangePublicKeyExponent( void ) const { return m_pExchangePublicKeyExponent; }

    inline const boost::shared_ptr< u1Array >& getExchangePublicKeyModulus( void ) const { return m_pExchangePublicKeyModulus; }

    inline const boost::shared_ptr< u1Array >& getEcdsaX( void ) const { return m_pEcdsaX; }

    inline const boost::shared_ptr< u1Array >& getEcdsaY( void ) const { return m_pEcdsaY; }

    inline const boost::shared_ptr< u1Array >& getEcdheX( void ) const { return m_pEcdheX; }

    inline const boost::shared_ptr< u1Array >& getEcdheY( void ) const { return m_pEcdheY; }

    inline const boost::shared_ptr< u1Array >& getEcdsaPointDER( void ) const { return m_pEcdsaPointDER; }

    inline const boost::shared_ptr< u1Array >& getEcdhePointDER( void ) const { return m_pEcdhePointDER; }

    inline unsigned char getEcdsaKeySpec( void ) const { return m_ucEcdsaKeySpec;}

    inline unsigned char getEcdheKeySpec( void ) const { return m_ucEcdheKeySpec;}

    inline bool getFlagSmartCardLogon( void ) const { return m_bIsSmartCardLogon; }

    inline void setFlagSmartCardLogon( const bool& a_bIsSmartCardLogon ) { m_bIsSmartCardLogon = a_bIsSmartCardLogon; }


    inline void setContainerTypeForSignatureKey( const unsigned char& a_ContainerTypeForSignatureKey ) { m_ucSignatureContainerType = a_ContainerTypeForSignatureKey; }

    inline void setContainerTypeForExchangeKey( const unsigned char& a_ContainerTypeForExchangeKey ) { m_ucExchangeContainerType = a_ContainerTypeForExchangeKey; }

    inline void setPinIdentifier( const MiniDriverAuthentication::ROLES& a_ContainerPinIdentifier ) { m_PinIdentifier = a_ContainerPinIdentifier; }

    inline bool isImportedSignatureKey( void ) const { return ( m_ucSignatureContainerType == 0x00 ); }

    inline bool isImportedExchangeKey( void ) const { return ( 0x00 == m_ucExchangeContainerType ); }

    inline MiniDriverAuthentication::ROLES getPinIdentifier( void ) const { return m_PinIdentifier; }

    static u1Array* computeUncompressedEcPointDER(u1Array* x, u1Array* y);

	bool Validate ();

private:

    CONTAINER_MAP_RECORD m_ContainerMapRecord;

    boost::shared_ptr< u1Array > m_pSignaturePublicKeyExponent;

    boost::shared_ptr< u1Array > m_pSignaturePublicKeyModulus;

    boost::shared_ptr< u1Array > m_pExchangePublicKeyExponent;

    boost::shared_ptr< u1Array > m_pExchangePublicKeyModulus;

    boost::shared_ptr< u1Array > m_pEcdsaX;

    boost::shared_ptr< u1Array > m_pEcdsaY;

    boost::shared_ptr< u1Array > m_pEcdheX;

    boost::shared_ptr< u1Array > m_pEcdheY;

    boost::shared_ptr< u1Array > m_pEcdsaPointDER;

    boost::shared_ptr< u1Array > m_pEcdhePointDER;

    unsigned char m_ucEcdsaKeySpec;
    unsigned char m_ucEcdheKeySpec;

    // The following memebers are used for serialization because
    // we can't use locally allocated variable for serialization
    // since they can have the same memory address across calls and thus
    // boost will not serialize them (it thinks it was already done!!!) causing inconstente
    // data when deserializing.
    boost::shared_ptr< u1ArraySerializable > m_sigExpSerializable;
    boost::shared_ptr< u1ArraySerializable > m_sigModSerializable;
    boost::shared_ptr< u1ArraySerializable > m_exchExpSerializable;
    boost::shared_ptr< u1ArraySerializable > m_exchModSerializable;

    boost::shared_ptr< u1ArraySerializable > m_pEcdsaXSerializable;
    boost::shared_ptr< u1ArraySerializable > m_pEcdsaYSerializable;
    boost::shared_ptr< u1ArraySerializable > m_pEcdheXSerializable;
    boost::shared_ptr< u1ArraySerializable > m_pEcdheYSerializable;


    bool m_bIsSmartCardLogon;

    unsigned char m_ucSignatureContainerType;

    unsigned char m_ucExchangeContainerType;

    MiniDriverAuthentication::ROLES m_PinIdentifier;

    void print( void );    

    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int version ) {

       if (version != 128)
          throw boost::archive::archive_exception(boost::archive::archive_exception::unsupported_class_version);

        ar & m_sigModSerializable;
        ar & m_sigExpSerializable;
        ar & m_exchExpSerializable;
        ar & m_exchModSerializable;
        ar & m_pEcdsaXSerializable;
        ar & m_pEcdsaYSerializable;
        ar & m_pEcdheXSerializable;
        ar & m_pEcdheYSerializable;
        ar & m_ContainerMapRecord.bFlags;
        ar & m_ContainerMapRecord.bReserved;
        ar & m_ContainerMapRecord.wKeyExchangeKeySizeBits;
        ar & m_ContainerMapRecord.wSigKeySizeBits;
        ar & m_ContainerMapRecord.wszGuid;
        ar & m_bIsSmartCardLogon;
        ar & m_ucSignatureContainerType;
        ar & m_ucExchangeContainerType;  
        ar & m_ucEcdsaKeySpec;
        ar & m_ucEcdheKeySpec;

        if (m_sigModSerializable.get())
        {
           if (m_pSignaturePublicKeyModulus.get())
           {
              //compare
              if (   (m_sigModSerializable->GetLength() != m_pSignaturePublicKeyModulus->GetLength())
                 ||  (m_sigModSerializable->GetLength() && memcmp(m_sigModSerializable->GetBuffer(), m_pSignaturePublicKeyModulus->GetBuffer(), m_sigModSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pSignaturePublicKeyModulus.reset(new u1Array(*m_sigModSerializable->GetArray()));
              }
           }
           else
           {
              m_pSignaturePublicKeyModulus.reset(new u1Array(*m_sigModSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pSignaturePublicKeyModulus.get())
              m_pSignaturePublicKeyModulus.reset();
        }

        if (m_sigExpSerializable.get())
        {
           if (m_pSignaturePublicKeyExponent.get())
           {
              //compare
              if (   (m_sigExpSerializable->GetLength() != m_pSignaturePublicKeyExponent->GetLength())
                 ||  (m_sigExpSerializable->GetLength() && memcmp(m_sigExpSerializable->GetBuffer(), m_pSignaturePublicKeyExponent->GetBuffer(), m_sigExpSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pSignaturePublicKeyExponent.reset(new u1Array(*m_sigExpSerializable->GetArray()));
              }
           }
           else
           {
              m_pSignaturePublicKeyExponent.reset(new u1Array(*m_sigExpSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pSignaturePublicKeyExponent.get())
              m_pSignaturePublicKeyExponent.reset();
        }

        if (m_exchModSerializable.get())
        {
           if (m_pExchangePublicKeyModulus.get())
           {
              //compare
              if (   (m_exchModSerializable->GetLength() != m_pExchangePublicKeyModulus->GetLength())
                 ||  (m_exchModSerializable->GetLength() && memcmp(m_exchModSerializable->GetBuffer(), m_pExchangePublicKeyModulus->GetBuffer(), m_exchModSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pExchangePublicKeyModulus.reset(new u1Array(*m_exchModSerializable->GetArray()));
              }
           }
           else
           {
              m_pExchangePublicKeyModulus.reset(new u1Array(*m_exchModSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pExchangePublicKeyModulus.get())
              m_pExchangePublicKeyModulus.reset();
        }

        if (m_exchExpSerializable.get())
        {
           if (m_pExchangePublicKeyExponent.get())
           {
              //compare
              if (   (m_exchExpSerializable->GetLength() != m_pExchangePublicKeyExponent->GetLength())
                 ||  (m_exchExpSerializable->GetLength() && memcmp(m_exchExpSerializable->GetBuffer(), m_pExchangePublicKeyExponent->GetBuffer(), m_exchExpSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pExchangePublicKeyExponent.reset(new u1Array(*m_exchExpSerializable->GetArray()));
              }
           }
           else
           {
              m_pExchangePublicKeyExponent.reset(new u1Array(*m_exchExpSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pExchangePublicKeyExponent.get())
              m_pExchangePublicKeyExponent.reset();
        }    

        if (m_pEcdsaXSerializable.get())
        {
           if (m_pEcdsaX.get())
           {
              //compare
              if (   (m_pEcdsaXSerializable->GetLength() != m_pEcdsaX->GetLength())
                 ||  (m_pEcdsaXSerializable->GetLength() && memcmp(m_pEcdsaXSerializable->GetBuffer(), m_pEcdsaX->GetBuffer(), m_pEcdsaXSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pEcdsaX.reset(new u1Array(*m_pEcdsaXSerializable->GetArray()));
              }
           }
           else
           {
              m_pEcdsaX.reset(new u1Array(*m_pEcdsaXSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pEcdsaX.get())
              m_pEcdsaX.reset();
        }

        if (m_pEcdsaYSerializable.get())
        {
           if (m_pEcdsaY.get())
           {
              //compare
              if (   (m_pEcdsaYSerializable->GetLength() != m_pEcdsaY->GetLength())
                 ||  (m_pEcdsaYSerializable->GetLength() && memcmp(m_pEcdsaYSerializable->GetBuffer(), m_pEcdsaY->GetBuffer(), m_pEcdsaYSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pEcdsaY.reset(new u1Array(*m_pEcdsaYSerializable->GetArray()));
              }
           }
           else
           {
              m_pEcdsaY.reset(new u1Array(*m_pEcdsaYSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pEcdsaY.get())
              m_pEcdsaY.reset();
        }

        if (m_pEcdheXSerializable.get())
        {
           if (m_pEcdheX.get())
           {
              //compare
              if (   (m_pEcdheXSerializable->GetLength() != m_pEcdheX->GetLength())
                 ||  (m_pEcdheXSerializable->GetLength() && memcmp(m_pEcdheXSerializable->GetBuffer(), m_pEcdheX->GetBuffer(), m_pEcdheXSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pEcdheX.reset(new u1Array(*m_pEcdheXSerializable->GetArray()));
              }
           }
           else
           {
              m_pEcdheX.reset(new u1Array(*m_pEcdheXSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pEcdheX.get())
              m_pEcdheX.reset();
        }

        if (m_pEcdheYSerializable.get())
        {
           if (m_pEcdheY.get())
           {
              //compare
              if (   (m_pEcdheYSerializable->GetLength() != m_pEcdheY->GetLength())
                 ||  (m_pEcdheYSerializable->GetLength() && memcmp(m_pEcdheYSerializable->GetBuffer(), m_pEcdheY->GetBuffer(), m_pEcdheYSerializable->GetLength()))
                 )
              {
                 // content changed
                 m_pEcdheY.reset(new u1Array(*m_pEcdheYSerializable->GetArray()));
              }
           }
           else
           {
              m_pEcdheY.reset(new u1Array(*m_pEcdheYSerializable->GetArray()));
           }
        }
        else
        {
           if (m_pEcdheY.get())
              m_pEcdheY.reset();
        }

        if (m_pEcdsaX.get())
            m_pEcdsaPointDER.reset(computeUncompressedEcPointDER(m_pEcdsaX.get(), m_pEcdsaY.get()));
        else
            m_pEcdsaPointDER.reset();
        if (m_pEcdheX.get())
            m_pEcdhePointDER.reset(computeUncompressedEcPointDER(m_pEcdheX.get(), m_pEcdheY.get()));
        else
            m_pEcdhePointDER.reset();
    }

};

BOOST_CLASS_VERSION( MiniDriverContainer, 128 )

#endif // __GEMALTO_MINIDRIVER_CONTAINER__
