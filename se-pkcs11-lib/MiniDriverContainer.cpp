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
#endif

#include "MiniDriverContainer.hpp"
#include <boost/foreach.hpp>
#include <memory>
#include "Log.hpp"


const unsigned char g_ucPublicKeyExponentLen = 4;
const unsigned char g_ucPublicKeyModulusLen = 4;
#define CONTAINER_MAP_RECORD_GUID_SIZE 40 * sizeof( WCHAR )


/*
*/
MiniDriverContainer::MiniDriverContainer( ) {

    clear( 0 );
}


/*
*/
void MiniDriverContainer::clear( const unsigned char& a_ucKeySpec ) {

	if (a_ucKeySpec == 0 || a_ucKeySpec == KEYSPEC_EXCHANGE || a_ucKeySpec == KEYSPEC_ECDHE_256 || a_ucKeySpec == KEYSPEC_ECDHE_384 || a_ucKeySpec == KEYSPEC_ECDHE_521)
	{
		m_ContainerMapRecord.wKeyExchangeKeySizeBits = 0;
		m_ucExchangeContainerType = 0;
		m_ucEcdheKeySpec = 0;
		m_bIsSmartCardLogon = false;
	}
	if (a_ucKeySpec == 0 || a_ucKeySpec == KEYSPEC_SIGNATURE || a_ucKeySpec == KEYSPEC_ECDSA_256 || a_ucKeySpec == KEYSPEC_ECDSA_384 || a_ucKeySpec == KEYSPEC_ECDSA_521)
	{
		m_ContainerMapRecord.wSigKeySizeBits = 0;
		m_ucSignatureContainerType = 0;
		m_ucEcdsaKeySpec = 0;
	}

	if (m_ContainerMapRecord.wKeyExchangeKeySizeBits == 0 && m_ContainerMapRecord.wSigKeySizeBits == 0)
	{
		memset( &m_ContainerMapRecord, 0, sizeof( CONTAINER_MAP_RECORD ) );
		m_PinIdentifier = MiniDriverAuthentication::PIN_NONE;
		m_bIsSmartCardLogon = false;
	}    
}


/*
*/
void MiniDriverContainer::setContainerMapRecord( CONTAINER_MAP_RECORD* a_pContainerMapRecord ) {

    Log::begin( "MiniDriverContainer::setContainerMapRecord" );

    if (    ((a_pContainerMapRecord->bFlags & 0xFC) != 0) // only the two lowest bits can be set
        ||  ((a_pContainerMapRecord->wKeyExchangeKeySizeBits != 0) && (a_pContainerMapRecord->wKeyExchangeKeySizeBits < 256 || a_pContainerMapRecord->wKeyExchangeKeySizeBits > 4096))
        ||  ((a_pContainerMapRecord->wSigKeySizeBits != 0) && (a_pContainerMapRecord->wSigKeySizeBits < 256 || a_pContainerMapRecord->wSigKeySizeBits > 4096))
        )
    {
        memset( m_ContainerMapRecord.wszGuid, 0, CONTAINER_MAP_RECORD_GUID_SIZE );
    }
    else {       
        m_ContainerMapRecord.bFlags = a_pContainerMapRecord->bFlags;

        m_ContainerMapRecord.wKeyExchangeKeySizeBits = a_pContainerMapRecord->wKeyExchangeKeySizeBits;

        m_ContainerMapRecord.wSigKeySizeBits = a_pContainerMapRecord->wSigKeySizeBits;

        if( a_pContainerMapRecord->wszGuid ) {

            memcpy( m_ContainerMapRecord.wszGuid, a_pContainerMapRecord->wszGuid, CONTAINER_MAP_RECORD_GUID_SIZE );
        
        } else {

            memset( m_ContainerMapRecord.wszGuid, 0, CONTAINER_MAP_RECORD_GUID_SIZE );
        }
    }

    //print( );
    Log::end( "MiniDriverContainer::setContainerMapRecord" );
}


/*
*/
void MiniDriverContainer::setContainerInformation( const boost::shared_ptr< u1Array >& a_pContainerInformation ) {

    Log::begin( "MiniDriverContainer::setContainerInformation" );
    std::string s;
    Log::toString( a_pContainerInformation->GetBuffer( ), a_pContainerInformation->GetLength( ), s );
    Log::log( "ContainerInformation <%s>", s.c_str( ) );

    // The container information is a byte array blob containing the public key(s) in the selected container. 
    // The blob is formatted as follows:  Blob = [Signature_Pub_Key] | [Exchange_Pub_Key] 
    // Signature_Pub_Key and Exchange_Pub_Key are optional depending on which key exists in the container and it’s a sequence of 3 TLV formatted as follows: 
    
    //T_Key_Type = 0x03 
    //L_Key_Type = 0x01 
    //V_Key_Type = 0x01 for Exchange_Pub_Key, 0x02 for Signature_Pub_Key and following values for EC keys
    
    //T_Key_Pub_Exp = 0x01                                              T_KEY_X = 0x04
    //L_Key_Pub_Exp = 0x04                                              L_KEY_X = Length of the X coordinate
    //V_Key_Pub_Exp = Value of Public key Exponent on 4 bytes.          V_KEY_X = value of the X coordinate
    
    //T_Key_Modulus = 0x02                                                  T_KEY_Y = 0x05
    //L_Key_Modulus = Key_Size_Bytes >> 4 (1 byte !)                        L_KEY_Y = Length of the Y coordinate
    //V_Key_Modulus = Value of Public key Modulus on Key_Size_Bytes bytes.  V_KEY_Y = value of the Y coordinate

    // Get the first public key  type
    unsigned int iOffset = 0;
    unsigned char ucKeyType;

	// clear all internal pointers before parsing the container data
	m_pExchangePublicKeyExponent.reset( );
	m_exchExpSerializable.reset();
	m_pExchangePublicKeyModulus.reset();
	m_exchModSerializable.reset();

	m_pSignaturePublicKeyExponent.reset( );
	m_sigExpSerializable.reset();
	m_pSignaturePublicKeyModulus.reset();   
	m_sigModSerializable.reset();

	m_pEcdheX.reset( );
	m_pEcdheXSerializable.reset();
	m_pEcdheY.reset( );
	m_pEcdheYSerializable.reset();
	m_pEcdhePointDER.reset();

	m_pEcdsaX.reset();
	m_pEcdsaXSerializable.reset();
	m_pEcdsaY.reset();   
	m_pEcdsaYSerializable.reset();
	m_pEcdsaPointDER.reset();

    while (iOffset < a_pContainerInformation->GetLength())
    {    
        iOffset += 2;
        ucKeyType = a_pContainerInformation->ReadU1At( iOffset );
        iOffset += 2;

        if (ucKeyType <= KEYSPEC_SIGNATURE)
        {
            // Read the first public key exponent value
            unsigned int uiPublicKeyExponentLength = a_pContainerInformation->ReadU1At( iOffset );

            // Read the first public key exponent value
            iOffset += 1;
            u1Array* pPublicKeyExponent = new u1Array( g_ucPublicKeyExponentLen );
    
            // The exponent must be a 4 bytes buffer.
            if( uiPublicKeyExponentLength < g_ucPublicKeyExponentLen ) {
    
                // Add zero at the head of the buffer
                memset( pPublicKeyExponent->GetBuffer( ), 0, g_ucPublicKeyExponentLen );
    
                int iPaddingLength = g_ucPublicKeyExponentLen - uiPublicKeyExponentLength;

                memcpy( pPublicKeyExponent->GetBuffer( ) + iPaddingLength, a_pContainerInformation->GetBuffer( ) + iOffset, uiPublicKeyExponentLength );

            } else {
    
                memcpy( pPublicKeyExponent->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, g_ucPublicKeyExponentLen );
            }

            // Read the first public key modulus len.
            // Keep in mind that the signature public key modulus len is stored as a 4 rigth-shifted byte (>>4) to pass the modulus length on 1 byte ofr values 64 to 256 (512 to 2048bits)
            iOffset += uiPublicKeyExponentLength + 1;
            int ucPublicKeyModulusLen = a_pContainerInformation->ReadU1At( iOffset ) << 4;

            // Read the first public key modulus value
            iOffset += 1;
            u1Array* pPublicKeyModulus = new u1Array( ucPublicKeyModulusLen );
            memcpy( pPublicKeyModulus->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, ucPublicKeyModulusLen );

            if( KEYSPEC_EXCHANGE == ucKeyType ) {

                m_pExchangePublicKeyExponent.reset( pPublicKeyExponent );
                m_exchExpSerializable.reset(new u1ArraySerializable(*pPublicKeyExponent));

                m_pExchangePublicKeyModulus.reset( pPublicKeyModulus );
                m_exchModSerializable.reset(new u1ArraySerializable(*pPublicKeyModulus));

            } else {

                m_pSignaturePublicKeyExponent.reset( pPublicKeyExponent );
                m_sigExpSerializable.reset(new u1ArraySerializable(*pPublicKeyExponent));

                m_pSignaturePublicKeyModulus.reset( pPublicKeyModulus );   
                m_sigModSerializable.reset(new u1ArraySerializable(*pPublicKeyModulus));
            }

            // Check if the second key information is present into the container information
            iOffset += ucPublicKeyModulusLen;

            m_ucEcdheKeySpec = ucKeyType;
        }
        else
        {
            // Read the X coordinate length
            unsigned int xLength = a_pContainerInformation->ReadU1At( iOffset );

            // Read the X coordinate value
            iOffset += 1;
            u1Array* pX = new u1Array( xLength );   
    
            memcpy( pX->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, xLength );

            // Read the Y coordinate length
            iOffset += xLength + 1;
            int yLength = a_pContainerInformation->ReadU1At( iOffset ) ;

            // Read the first public key modulus value
            iOffset += 1;
            u1Array* pY = new u1Array( yLength );
            memcpy( pY->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, yLength );

            if(     KEYSPEC_ECDHE_256 == ucKeyType 
                ||  KEYSPEC_ECDHE_384 == ucKeyType
                ||  KEYSPEC_ECDHE_521 == ucKeyType
              ) {

                m_pEcdheX.reset( pX );
                m_pEcdheXSerializable.reset(new u1ArraySerializable(*pX));

                m_pEcdheY.reset( pY );
                m_pEcdheYSerializable.reset(new u1ArraySerializable(*pY));

                m_pEcdhePointDER.reset(computeUncompressedEcPointDER(m_pEcdheX.get(), m_pEcdheY.get()));

                m_ucEcdheKeySpec = ucKeyType;
            } else {

                m_pEcdsaX.reset( pX );
                m_pEcdsaXSerializable.reset(new u1ArraySerializable(*pX));

                m_pEcdsaY.reset( pY );   
                m_pEcdsaYSerializable.reset(new u1ArraySerializable(*pY));

                m_pEcdsaPointDER.reset(computeUncompressedEcPointDER(m_pEcdsaX.get(), m_pEcdsaY.get()));

                m_ucEcdsaKeySpec = ucKeyType;
            }

            // Check if the second key information is present into the container information
            iOffset += yLength;
        }
    }

    //print( );
    Log::end( "MiniDriverContainer::setContainerInformation" );
}


/*
*/ 
void MiniDriverContainer::print( void ) {

    if( !Log::s_bEnableLog ) {
    
        return;
    }

    Log::log( "MiniDriverContainer - ===" );

    Log::log( "MiniDriverContainer - [SmartCard Logon <%d>]", m_bIsSmartCardLogon );

    Log::log( "MiniDriverContainer - Flag <%#02x>", m_ContainerMapRecord.bFlags );

    Log::log( "MiniDriverContainer - wKeyExchangeKeySizeBits <%#02x>", m_ContainerMapRecord.wKeyExchangeKeySizeBits );

    Log::log( "MiniDriverContainer - wSigKeySizeBits <%#02x>", m_ContainerMapRecord.wSigKeySizeBits );

    std::string s;
    Log::toString( (const unsigned char*)m_ContainerMapRecord.wszGuid, (size_t)sizeof( m_ContainerMapRecord.wszGuid ), s );
    Log::log( "MiniDriverContainer - wszGuid <%s>", s.c_str( ) );

    s = "";
    if( m_pSignaturePublicKeyExponent ) {

        Log::toString( m_pSignaturePublicKeyExponent->GetBuffer( ), m_pSignaturePublicKeyExponent->GetLength( ), s );
        Log::log( "MiniDriverContainer - SignaturePublicKeyExponent <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - SignaturePublicKeyExponent <0>" );
    }

    if( m_pSignaturePublicKeyModulus ) {

        Log::toString( m_pSignaturePublicKeyModulus->GetBuffer( ), m_pSignaturePublicKeyModulus->GetLength( ), s );
        Log::log( "MiniDriverContainer - SignaturePublicKeyModulus <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - SignaturePublicKeyModulus <0>" );
    }    

    if( m_pExchangePublicKeyExponent ) {

        Log::toString( m_pExchangePublicKeyExponent->GetBuffer( ), m_pExchangePublicKeyExponent->GetLength( ), s );
        Log::log( "MiniDriverContainer - ExchangePublicKeyExponent <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - ExchangePublicKeyExponent <0>" );
    }    

    if( m_pExchangePublicKeyModulus ) {

        Log::toString( m_pExchangePublicKeyModulus->GetBuffer( ), m_pExchangePublicKeyModulus->GetLength( ), s );
        Log::log( "MiniDriverContainer - ExchangePublicKeyModulus <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - ExchangePublicKeyModulus <0>" );
    }  
}


void MiniDriverContainer::setGUID( const std::string& a_stGUID ) { 
    
   memset( m_ContainerMapRecord.wszGuid, 0, sizeof( m_ContainerMapRecord.wszGuid ) );

   size_t length = ( a_stGUID.size( ) > 39 ) ? 39 : a_stGUID.size( );

    for( size_t i = 0 ; i < length; ++i ) {

        m_ContainerMapRecord.wszGuid[ i ] = (WCHAR)a_stGUID[ i ];
    }

   //for( size_t i = 0 ; i < length; ++i ) {

   //   // Convert to wchar, little endian.
   //   m_ContainerMapRecord.wszGuid[ 2*i ]  = a_stGUID[ i ]; 
   //}
}

u1Array* MiniDriverContainer::computeUncompressedEcPointDER(u1Array* x, u1Array* y)
{
    int xLen = x->GetLength();
    int yLen = y->GetLength();
    int encodingLen = 1 + xLen + yLen;
    u1Array* pointDer = NULL;
    if (encodingLen <= 127)
    {
        pointDer = new u1Array(1 + 1 + encodingLen);
        pointDer->SetU1At(0, 0x04);
        pointDer->SetU1At(1, (u1) encodingLen);
        pointDer->SetU1At(2, 0x04);
        memcpy(pointDer->GetBuffer() + 3, x->GetBuffer(), xLen);
        memcpy(pointDer->GetBuffer() + 3 + xLen, y->GetBuffer(), yLen);
    }
    else
    {
        pointDer = new u1Array(1 + 2 + encodingLen);
        pointDer->SetU1At(0, 0x04);
        pointDer->SetU1At(1, 0x81);
        pointDer->SetU1At(2, (u1) encodingLen);
        pointDer->SetU1At(3, 0x04);
        memcpy(pointDer->GetBuffer() + 4, x->GetBuffer(), xLen);
        memcpy(pointDer->GetBuffer() + 4 + xLen, y->GetBuffer(), yLen);
    }

    return pointDer;
}

bool MiniDriverContainer::Validate()
{
	WORD uiKeySize = getKeyExchangeSizeBits( );

	boost::shared_ptr< u1Array > pPublicKeyExponent = getExchangePublicKeyExponent( );
	boost::shared_ptr< u1Array > pPublicKeyModulus = getExchangePublicKeyModulus( );
	boost::shared_ptr< u1Array > pEccPublicKey = getEcdhePointDER();

	if( !uiKeySize )
	{
		pPublicKeyExponent = getSignaturePublicKeyExponent( );
		pPublicKeyModulus = getSignaturePublicKeyModulus( );
		pEccPublicKey = getEcdsaPointDER();
	}

	if (!pEccPublicKey.get() && (!pPublicKeyExponent.get() || !pPublicKeyModulus.get()))
		return false;
	else
		return true;
}
