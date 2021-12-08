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
#include <cstdlib>
#include <memory>
#include <exception>
#include <map>

#include <time.h>
#include <memory>
#include <string.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/ec.h>

#include "Device.hpp"
#include "CardManager.hpp"
#include "CardModuleApplet.h"
#include "digest.h"
#include "util.h"
#include "Log.hpp"
#include "PCSCMissing.h"

#include "Pkcs11ObjectKeyGenericSecret.hpp"
#include "Pkcs11ObjectKeySecretAES.hpp"
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "Pkcs11ObjectKeyPrivateRSA.hpp"
#include "Pkcs11ObjectKeyPublicECC.hpp"
#include "Pkcs11ObjectKeyPrivateECC.hpp"
#include "Pkcs11ObjectCertificateX509PublicKey.hpp"

#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
#define USE_LOGICAL_CHANNEL

// ------------------------------------------------------
// Constructors
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
DWORD CardModuleApplet::GetCardModel()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
bool CardModuleApplet::HasMemoryBug()
{
    return false;
}

// ------------------------------------------------------
// Constructors
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
CardModuleApplet::CardModuleApplet(string* readerName, string* uri)
{
	UNREFERENCED_PARAMETER (uri);

	m_channel = 0;
    m_uri = NULL;
    m_dataIn = NULL;
    m_dataOut = NULL;

	m_sDeviceName = *readerName;

	try
	{
		DeviceTransaction devLock (*readerName);
		init_context (0x00, m_uri);
	}
	catch(...)
	{
		reset_buffers();
		throw;
	}

      Log::log("Card module applet constructor -> END");
}

// ------------------------------------------------------
// ------------------------------------------------------
CardModuleApplet::~CardModuleApplet()
{
    close_logical_channel(m_channel);
    m_channel = 0;

    if (m_uri)
    {
        delete m_uri;
        m_uri = NULL;
    }

    //free memory private key
    if(m_auditStructure.privateKeyCount != 0){
        for(int i = 0; i<m_auditStructure.privateKeyCount; i++){
            if(m_auditStructure.priKeyInfo[i].label != NULL){
                delete(m_auditStructure.priKeyInfo[i].label);
                m_auditStructure.priKeyInfo[i].label = NULL;
            }
            if(m_auditStructure.priKeyInfo[i].id != NULL){
                delete(m_auditStructure.priKeyInfo[i].id);
                 m_auditStructure.priKeyInfo[i].id = NULL;
            }
        }
    }
    //free memory public key
    if(m_auditStructure.publicKeyCount != 0){
        for(int i = 0; i<m_auditStructure.publicKeyCount; i++){
            if(m_auditStructure.pubKeyInfo[i].label != NULL){
                delete(m_auditStructure.pubKeyInfo[i].label);
                m_auditStructure.pubKeyInfo[i].label = NULL;
            }
            if(m_auditStructure.pubKeyInfo[i].id != NULL){
                delete(m_auditStructure.pubKeyInfo[i].id);
                m_auditStructure.pubKeyInfo[i].id = NULL;
            }
        }
    }
     //free memory secret key
    if(m_auditStructure.secretKeyCount != 0){
        for(int i = 0; i<m_auditStructure.secretKeyCount; i++){
            if(m_auditStructure.secretKeyInfo[i].label != NULL){
                delete(m_auditStructure.secretKeyInfo[i].label);
                m_auditStructure.secretKeyInfo[i].label = NULL;
            }
            if(m_auditStructure.secretKeyInfo[i].id != NULL){
                delete(m_auditStructure.secretKeyInfo[i].id);
                m_auditStructure.secretKeyInfo[i].id = NULL;
            }
        }
    }
    //free memory file
    if(m_auditStructure.fileCount != 0){
        for(int i = 0; i<m_auditStructure.fileCount; i++){
            if(m_auditStructure.fileInfo[i].label != NULL){
                delete(m_auditStructure.fileInfo[i].label);
                m_auditStructure.fileInfo[i].label = NULL;
            }
            if(m_auditStructure.fileInfo[i].id != NULL){
                delete(m_auditStructure.fileInfo[i].id);
                m_auditStructure.fileInfo[i].id = NULL;
            }
        }
    }

    reset_buffers();
}

// ------------------------------------------------------
// Private Initialization Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::reset_buffers()
{
    m_SW1SW2 = 0x9000;

    if (m_dataIn)
    {
		// clear potential sensitive data
		SecureZeroMemory(m_dataIn->GetBuffer(), m_dataIn->GetLength());
        delete m_dataIn;
        m_dataIn = NULL;
    }

    if (m_dataOut)
    {
        delete m_dataOut;
        m_dataOut = NULL;
    }
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::close_all_logical_channel()
{
    #ifdef USE_LOGICAL_CHANNEL
    m_SW1SW2 = 0x9000;
    int channel = 1;
    while(m_SW1SW2 == 0x9000){
        m_dataIn = new u1Array(5);
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = 0x00;
        m_dataIn->GetBuffer()[1] = 0x70;
        m_dataIn->GetBuffer()[2] = 0x80;
        m_dataIn->GetBuffer()[3] = channel;
        m_dataIn->GetBuffer()[4] = 0x00;

        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

        if(m_SW1SW2 == 0x9000)
        {
            channel++;
        }
    }
    #endif
}
void CardModuleApplet::close_logical_channel(BYTE channel)
{
    #ifdef USE_LOGICAL_CHANNEL
        m_dataIn = new u1Array(5);
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = 0x00;
        m_dataIn->GetBuffer()[1] = 0x70;
        m_dataIn->GetBuffer()[2] = 0x80;
        m_dataIn->GetBuffer()[3] = channel;
        m_dataIn->GetBuffer()[4] = 0x00;

        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

        if (m_SW1SW2 != 0x9000){
                Log::log("error closing the logical channel");
        }
	#endif
}
void CardModuleApplet::setup_logical_channel()
{
    #ifdef USE_LOGICAL_CHANNEL
        close_all_logical_channel();
        m_dataIn = new u1Array(5);
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = m_channel;
        m_dataIn->GetBuffer()[1] = 0x70;
        m_dataIn->GetBuffer()[2] = 0x00;
        m_dataIn->GetBuffer()[3] = 0x00;
        m_dataIn->GetBuffer()[4] = 0x01;

        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

        if (m_SW1SW2 == 0x9000){
                m_channel = m_dataOut->GetBuffer()[0];
        }
	#endif
}
void CardModuleApplet::init_context(BYTE channel, u1Array* uri)
{
	UNREFERENCED_PARAMETER (channel);
	UNREFERENCED_PARAMETER (uri);

	u1Array *pDummy=nullptr;
    bool bAppletSelected = false;

    // Remember context
    m_channel = 0x00;

    if (m_uri)
    {
        delete m_uri;
        m_uri = NULL;
    }

    setup_logical_channel();

    m_uri = new u1Array(CARD_APPLET_AID_LEN);
    m_uri->SetBuffer((u1*)CARD_APPLET_AID);

    try
    {
        reset_buffers();

        m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN);
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = m_channel;
        m_dataIn->GetBuffer()[1] = 0xA4;
        m_dataIn->GetBuffer()[2] = 0x04;
        m_dataIn->GetBuffer()[3] = 0x00;
        m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);
        memcpy (&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch(...)
    {
        reset_buffers();

        throw;
    }

    reset_buffers();

    /* Select to remove the card transmit error */
    m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN);
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xA4;
    m_dataIn->GetBuffer()[2] = 0x04;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);
    memcpy (&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

    CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

    reset_buffers();

	ForceGarbageCollector();

    auditCard(true);


    Log::log( "Init context done");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::getRsaPublicKey(u1 keyId)
{
    // Not yet implemented.
    return nullptr;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::getEccPublicKey(u1 keyId)
{
    u1Array* container = NULL;
    u1 EFID = keyId;

    Log::log(" CardModuleApplet::getEccPublicKey KeyId = %d", keyId);

    //ckeck if found in key containerGet
     for(int i = 0; i < m_auditStructure.pubKeyInfo.size(); i++){
        BYTE cid = m_auditStructure.pubKeyInfo[i].id_byte;
        BYTE keyType = m_auditStructure.pubKeyInfo[i].keyType;
        if(cid == keyId){
             Log::log(" CardModuleApplet::getEccPublicKeyContainer - Reading from Card");
             container = getPublicKeyFromKeyContainer(keyId);
		     return container;
        }
     }


    Log::log(" CardModuleApplet::getEccPublicKey from file - Reading from Card");
    container = getCertificateDataFromContainer(keyId);
    if (container != NULL)
    {
        // Convert DER cert to Pub Key
       u1Array *pub_key =  convertDERtoX509(container);
       delete container;
       return pub_key;
    }

    return NULL;

}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::GetPinId(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------

void CardModuleApplet::getStaticRoles(std::list<u1>& roles)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
BOOL CardModuleApplet::isPinInValidPeriod(u1 /*role*/)
{
     return TRUE; // Always true for the time being
}

// ------------------------------------------------------
// PC/SC Management Methods
// ------------------------------------------------------

bool CardModuleApplet::GetPinPadSupported ()
{
    // Not applicable.
    throw ArgumentException("");
}

void CardModuleApplet::SetPinPadSupported (bool bIsPinPad)
{
    // Not applicable.
    throw ArgumentException("");
}

bool CardModuleApplet::HasSSO () const
{
    // Not applicable.
    return false;
}

// ------------------------------------------------------
// Authentication Management Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::get_AdminPersonalized()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::get_UserPersonalized()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::VerifyPin(u1 role, u1Array* pin)
{
    // DO nothing for timebeing

}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::LogOut(u1 role)
{
    // Not applicable.
    //throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetChallenge()
{
    // Not applicable.
    throw ArgumentException("");
}


// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::ExternalAuthenticate(u1Array* response)
{
    // Not applicable.
    throw ArgumentException("");
}


// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::ChangeReferenceData(u1 mode, u1 role, u1Array* oldPin, u1Array* newPin, s4 maxTries)
{
    // Not applicable.
    throw ArgumentException("");
}

// ----------------------
void CardModuleApplet::SetPinInitialized(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
s4 CardModuleApplet::GetTriesRemaining(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::get_MaxPinRetryCounter()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::IsAuthenticated(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
s8 CardModuleApplet::get_AuthenticationDelay()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetTriesRemaining(u1 role, u1 tryNb)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetAuthenticated(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetDeauthenticated(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::GetCardPinId(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}


// ------------------------------------------------------
// ------------------------------------------------------
bool CardModuleApplet::IsPinPromptAlways(u1 role)
{
    // Not applicable.
    return false;
}

bool CardModuleApplet::IsPinSMRequiredForVerify(u1 role)
{
    // Not applicable.
    return false;
}

bool CardModuleApplet::IsPinSMRequiredForUnblock(u1 role)
{
    // Not applicable.
    return false;
}

bool CardModuleApplet::IsPinSMRequiredForChange(u1 role)
{
    // Not applicable.
    return false;
}

// ------------------------------------------------------
// Container Management Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::CreateCAPIContainer(u1 ctrIndex, u1 keyImport, u1 keySpec, s4 keySize, u1Array* keyValue, u1 role)
{
    Log::log("CREATE CONTAINER IN CARD MODULE APPLET");

    /* Select applet.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN); // CLA-Lc 5 bytes + Data AID length bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xA4;
    m_dataIn->GetBuffer()[2] = 0x04;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);

    memcpy(&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Generate key pair.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + GEN_KEY_PAIR_DATA_LEN);
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xB9;
    m_dataIn->GetBuffer()[2] = 0x00;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(GEN_KEY_PAIR_DATA_LEN);
    memcpy (&(m_dataIn->GetBuffer()[5]), (u1*)GEN_KEY_PAIR_DATA_IN, GEN_KEY_PAIR_DATA_LEN);
    m_dataIn->GetBuffer()[7] = ctrIndex; // Set correct ID

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            Log::log("Key pair has been generated successfuly");
            break;

        case 0x6A80:
        case 0x6A86:
            throw ArgumentException("");

        case 0x6982:
            throw UnauthorizedAccessException("");

        case 0x6985:
            throw Exception("0x80100022");

        case 0x6D00:
            throw RemotingException("");

        default:
            throw RemotingException("");
    }

    Log::log("Updating the container");
    Log::log("Key Container length = %d ", m_dataOut->GetLength());

    // Parse the return public Key
    // Format : 84 01 <PrivKey ID> 85 01 <PubKey ID > 34 45 49 43 86 41 04 < 32 byes X > < 32 bytes Y>
    Log::log("Priv Key ID = %d , Pub Key ID = %d , ECPoint Len = %d ", m_dataOut->GetBuffer()[2], m_dataOut->GetBuffer()[5], m_dataOut->GetBuffer()[11]);

    auditCard(false);
    reset_buffers();
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::DeleteCAPIContainer(u1 ctrIndex, u1 keySpec)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
bool CardModuleApplet::IsReadOnly(u1 ctrIndex)
{
    return true;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetCAPIContainer(u1 ctrIndex)
{
    BOOL isUsed = FALSE;
    u1Array* container = NULL;
    WORD keyExcSize = 0;
    WORD keySigSize = 0;
    BYTE keyExcSpec = 0;
    BYTE keySigSpec = 0;
    u1 keyType = 0;
    BYTE tmpBuff[2048];
    DWORD dwLen = 0;
    u1 keyId = 0;
    bool found = false;

    Log::log( "CardModuleApplet::GetCAPIContainer index = %d", ctrIndex);
      if(ctrIndex == 0) //auto allocated container index if the key has been generated after the init context
         ctrIndex = 0x04;

    try
    {
        reset_buffers();
        for (int i = 0; i < m_auditStructure.priKeyInfo.size(); i++)
        {
                BYTE cid = m_auditStructure.priKeyInfo[i].id_byte;
                if(cid == ctrIndex){
                    BYTE keyType = m_auditStructure.priKeyInfo[i].keyType;
                    if  (keyType == 19)  { //19 decimal = 13h = ecc , 20 decimal , 14h = ecdh
                        isUsed =  TRUE;
                        keySigSize =  256;
                        keyExcSize = 256;
                        keySigSpec = ECDSA_256;
                        keyExcSpec = ECDSA_256;
                        found = true;
                        break;
                    }
                    else if (keyType == 20) {
                        isUsed =  TRUE;
                        keySigSize =  256;
                        keyExcSize = 256;
                        keySigSpec = ECDHE_256;
                        keyExcSpec = ECDHE_256;
                        found = true;
                        break;
                    }


                }
        }

        if (isUsed)
        {
            reset_buffers();

            try
            {
                // ------------
                // Exchange Key
                // ------------

                // ECC type
                if (keyExcSpec >= ECDSA_256)
                {
                    int keyLen = 0x20;
                    BYTE keyType = ECDHE_256_PREFIX;
                    u1Array* Q = NULL;
                    u1Array* OID = NULL;

                    if (keyExcSpec == ECDSA_256)
                    {
                        keyLen = 0x20;
                        keyType = ECDSA_256_PREFIX;
                    }
                    else
                    {
                        keyLen = 0x20;
                        BYTE keyType = ECDSA_256_PREFIX;
                    }

                    if (keyExcSpec == ECDSA_256)
                    {
                        keyLen = 0x20;
                        keyType = ECDSA_256_PREFIX;
                    }
                    else if (keyExcSpec == ECDSA_384)
                    {
                        keyLen = 0x30;
                        keyType = ECDSA_384_PREFIX;
                    }
                    else if (keyExcSpec == ECDSA_521)
                    {
                        keyLen = 0x42;
                        keyType = ECDSA_521_PREFIX;
                    }
                    else if (keyExcSpec == ECDHE_256)
                    {
                        keyLen = 0x20;
                        keyType = ECDHE_256_PREFIX;
                    }
                    else if (keyExcSpec == ECDHE_384)
                    {
                        keyLen = 0x30;
                        keyType = ECDHE_384_PREFIX;
                    }
                    else if (keyExcSpec == ECDHE_521)
                    {
                        keyLen = 0x42;
                        keyType = ECDHE_521_PREFIX;
                    }

                    // Default key id
                    keyId =   ctrIndex ;


                    Q = getEccPublicKey(keyId);

                    if (  (Q != NULL)
                        &&(Q->GetLength() > 0)
                        )
                    {
                        // Key Type TLV
                        tmpBuff[dwLen++] = 0x03;
                        tmpBuff[dwLen++] = 0x01;
                        tmpBuff[dwLen++] = keyExcSpec;

                        // X TLV
                        tmpBuff[dwLen++] = 0x04;
                        tmpBuff[dwLen++] = keyLen;
                        memcpy(&tmpBuff[dwLen], &(Q->GetBuffer()[1]), keyLen);
                        dwLen += keyLen;

                        // Y TLV
                        tmpBuff[dwLen++] = 0x05;
                        tmpBuff[dwLen++] = keyLen;
                        memcpy(&tmpBuff[dwLen], &(Q->GetBuffer()[1 + keyLen]), keyLen);
                        dwLen += keyLen;
                    }

                    if (Q != NULL)
                    {
                        delete Q;
                        Q = NULL;
                    }

                    if (OID != NULL)
                    {
                        delete OID;
                        OID = NULL;
                    }

                }


                // -------------
                // Signature Key
                // -------------


                // ECC type
                if (keySigSpec >= ECDSA_256)
                {
                    int keyLen = 0x20;
                    BYTE keyType = ECDHE_256_PREFIX;
                    u1Array* Q = NULL;
                    u1Array* OID = NULL;

                    if (keySigSpec == ECDSA_256)
                    {
                        keyLen = 0x20;
                        keyType = ECDSA_256_PREFIX;
                    }
                    else if (keySigSpec == ECDSA_384)
                    {
                        keyLen = 0x30;
                        keyType = ECDSA_384_PREFIX;
                    }
                    else if (keySigSpec == ECDSA_521)
                    {
                        keyLen = 0x42;
                        keyType = ECDSA_521_PREFIX;
                    }
                    else if (keySigSpec == ECDHE_256)
                    {
                        keyLen = 0x20;
                        keyType = ECDHE_256_PREFIX;
                    }
                    else if (keySigSpec == ECDHE_384)
                    {
                        keyLen = 0x30;
                        keyType = ECDHE_384_PREFIX;
                    }
                    else if (keySigSpec == ECDHE_521)
                    {
                        keyLen = 0x42;
                        keyType = ECDHE_521_PREFIX;
                    }

                    // Default key id
                    keyId = ctrIndex ;


                    Q = getEccPublicKey(keyId);

                    if (  (Q != NULL)
                        &&(Q->GetLength() > 0)
                        )
                    {

                        // Key Type TLV
                        tmpBuff[dwLen++] = 0x03;
                        tmpBuff[dwLen++] = 0x01;
                        tmpBuff[dwLen++] = keySigSpec;

                        // X TLV
                        tmpBuff[dwLen++] = 0x04;
                        tmpBuff[dwLen++] = keyLen;
                        memcpy(&tmpBuff[dwLen], &(Q->GetBuffer()[1]), keyLen);
                        dwLen += keyLen;

                        // Y TLV
                        tmpBuff[dwLen++] = 0x05;
                        tmpBuff[dwLen++] = keyLen;
                        memcpy(&tmpBuff[dwLen], &(Q->GetBuffer()[1 + keyLen]), keyLen);
                        dwLen += keyLen;
                    }

                    if (Q != NULL)
                    {
                        delete Q;
                        Q = NULL;
                    }

                    if (OID != NULL)
                    {
                        delete OID;
                        OID = NULL;
                    }

                }
            }
            catch(...)
            {
            }
        }

        else
        {
            throw ArgumentException("invalid_ctrIndex");
        }
    }
    catch(RemotingException&)
    {
        reset_buffers();

        throw ArgumentException("invalid_ctrIndex");;
    }
    catch(...)
    {
        reset_buffers();

        throw;
    }

    if (dwLen == 0)
    {
        throw ArgumentException("invalid_ctrIndex");
    }

    container = new u1Array(dwLen);

    container->SetBuffer(tmpBuff);

    return container;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::PrivateKeyDecrypt(u1 ctrIndex, u1 keyType, u1Array* encryptedData)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::PrivateKeyDecryptEx(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* encryptedData)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::PrivateKeySign(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter)
{
    for (int i = 0; i < m_auditStructure.privateKeyCount; i++)
    {
        if ((u1) std::atoi(m_auditStructure.priKeyInfo[i].id) == ctrIndex)
        {
            switch (m_auditStructure.priKeyInfo[i].keyType)
            {
                // RSA key.
                case 0x03:
                    return PrivateKeySignRSA(ctrIndex, keyType, paddingType, algo, data, intermediateHash, hashCounter);

                // ECC key.
                case 0x13:
                case 0x14:
                case 0x23:
                case 0x24:
                case 0x43:
                    return PrivateKeySignECC(ctrIndex, keyType, paddingType, algo, data, intermediateHash, hashCounter);
            }
        }
    }

    for (int i = 0; i < m_auditStructure.secretKeyCount; i++)
    {
        if ((u1) std::atoi(m_auditStructure.secretKeyInfo[i].id) == ctrIndex)
        {
            switch (m_auditStructure.secretKeyInfo[i].keyType)
            {
                // CMAC key.
                case 0xB0:
                    return PrivateKeySignCMAC(ctrIndex, keyType, paddingType, algo, data, intermediateHash, hashCounter);
            }
        }
    }

    return new u1Array(0);
}

u1Array* CardModuleApplet::PrivateKeySignCMAC(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter)
{
    /* Select applet.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN); // CLA-Lc 5 bytes + Data AID length bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xA4;
    m_dataIn->GetBuffer()[2] = 0x04;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);

    memcpy(&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Sign init command.
     */

    reset_buffers();
    m_dataIn = new u1Array(14); // CLA-Lc 5 bytes + Data 9 bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x2A;
    m_dataIn->GetBuffer()[2] = 0x00;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = 0x09;

    // Secret key ID TLV.
    m_dataIn->GetBuffer()[5] = 0x86;
    m_dataIn->GetBuffer()[6] = 0x01;
    m_dataIn->GetBuffer()[7] = (BYTE) ctrIndex; // ID value.

    // Operation mode TLV.
    m_dataIn->GetBuffer()[8] = 0xA1;
    m_dataIn->GetBuffer()[9] = 0x01;
    m_dataIn->GetBuffer()[10] = 0x01; // Full text processing.

    // Signature algorithm TLV.
    m_dataIn->GetBuffer()[11] = 0x92;
    m_dataIn->GetBuffer()[12] = 0x01;
    m_dataIn->GetBuffer()[13] = 0x08; // AES-128 CMAC.

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Sign update command.
     */

    const u4 maxBlockValue = 253; // Max length Lc 255 bytes - Tag Length 2 bytes -> Value 253 bytes.
    u1 *remainingData = data->GetBuffer();
    u4 remainingDataLen = data->GetLength();

    // First to before last block of data.
    while (remainingDataLen > maxBlockValue)
    {
        reset_buffers();
        m_dataIn = new u1Array(260); // CLA-Lc 5 bytes + Data 255 bytes.
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = m_channel;
        m_dataIn->GetBuffer()[1] = 0x2B;
        m_dataIn->GetBuffer()[2] = 0x00;
        m_dataIn->GetBuffer()[3] = 0x00;
        m_dataIn->GetBuffer()[4] = 0xFF; // Max length Lc 255 bytes.

        // CMAC data input TLV.
        m_dataIn->GetBuffer()[5] = 0x9F;
        m_dataIn->GetBuffer()[6] = (BYTE) maxBlockValue;
        memcpy(&(m_dataIn->GetBuffer()[7]), remainingData, (BYTE) maxBlockValue);

        try
        {
            CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
        }
        catch (...)
        {
            reset_buffers();
            throw;
        }

        switch (m_SW1SW2)
        {
            case 0x9000:
                break;
            default:
                reset_buffers();
                throw RemotingException("");
        }

        remainingDataLen -= maxBlockValue;
        remainingData += maxBlockValue;
    }

    // Last block of data.
    reset_buffers();
    m_dataIn = new u1Array(5U + 2U + remainingDataLen); // CLA-Lc 5 bytes + Tag Length 2 bytes + Remaining Data bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x2B;
    m_dataIn->GetBuffer()[2] = 0x80;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE) (2U + remainingDataLen); // Tag Length 2 bytes + Value bytes.

    // CMAC data input TLV.
    m_dataIn->GetBuffer()[5] = 0x9F;
    m_dataIn->GetBuffer()[6] = (BYTE) remainingDataLen;
    memcpy(&(m_dataIn->GetBuffer()[7]), remainingData, (BYTE) remainingDataLen);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    // Remove the Tag 0x33 Length 0x10 overhead from the signature.
    u1Array *result = new u1Array(m_dataOut->GetLength() - 2);
    result->SetBuffer(m_dataOut->GetBuffer() + 2);

    reset_buffers();

    return result;
}

u1Array* CardModuleApplet::PrivateKeySignECC(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter)
{
    // Only hash of SHA-256 data is supported.
    if (data->GetLength() != 32)
    {
        throw RemotingException("");
    }

    /* Select applet.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN); // CLA-Lc 5 bytes + Data AID length bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xA4;
    m_dataIn->GetBuffer()[2] = 0x04;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);

    memcpy(&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Sign init command.
     */

    reset_buffers();
    m_dataIn = new u1Array(18); // CLA-Lc 5 bytes + Data 13 bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x2A;
    m_dataIn->GetBuffer()[2] = 0x00;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = 0x0D;

    // Private key ID TLV.
    m_dataIn->GetBuffer()[5] = 0x84;
    m_dataIn->GetBuffer()[6] = 0x01;
    m_dataIn->GetBuffer()[7] = (BYTE) ctrIndex; // ID value.

    // Operation mode TLV.
    m_dataIn->GetBuffer()[8] = 0xA1;
    m_dataIn->GetBuffer()[9] = 0x01;
    m_dataIn->GetBuffer()[10] = 0x03; // Pad and sign processing.

    // Hash algorithm TLV.
    m_dataIn->GetBuffer()[11] = 0x91;
    m_dataIn->GetBuffer()[12] = 0x02;
    m_dataIn->GetBuffer()[13] = 0x00; // SHA-256.
    m_dataIn->GetBuffer()[14] = 0x01;

    // Signature algorithm TLV.
    m_dataIn->GetBuffer()[15] = 0x92;
    m_dataIn->GetBuffer()[16] = 0x01;
    m_dataIn->GetBuffer()[17] = 0x04; // ECDSA.

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Sign update command.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + 34); // CLA-Lc 5 bytes + Data 34 bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x2B;
    m_dataIn->GetBuffer()[2] = 0x80;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = 0x22;

    // Tag Length 2 bytes + Data 32 bytes hash of SHA-256.
    m_dataIn->GetBuffer()[5] = 0x9E;
    m_dataIn->GetBuffer()[6] = 0x20;
    memcpy (&(m_dataIn->GetBuffer()[7]), data->GetBuffer(), 32);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    // Remove the Tag 0x33 Length 0x40 overhead from the signature.
    u1Array *result = new u1Array(m_dataOut->GetLength() - 2);
    result->SetBuffer(m_dataOut->GetBuffer() + 2);

    reset_buffers();

    return result;
}

u1Array* CardModuleApplet::PrivateKeySignRSA(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter)
{
    // Only hash of SHA-256 data is supported.
    if (data->GetLength() != 32)
    {
        throw RemotingException("");
    }

    /* Select applet.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN); // CLA-Lc 5 bytes + Data AID length bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xA4;
    m_dataIn->GetBuffer()[2] = 0x04;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);

    memcpy(&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Sign init command.
     */

    reset_buffers();
    m_dataIn = new u1Array(18); // CLA-Lc 5 bytes + Data 13 bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x2A;
    m_dataIn->GetBuffer()[2] = 0x00;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = 0x0D;

    // Private key ID TLV.
    m_dataIn->GetBuffer()[5] = 0x84;
    m_dataIn->GetBuffer()[6] = 0x01;
    m_dataIn->GetBuffer()[7] = (BYTE) ctrIndex; // ID value.

    // Operation mode TLV.
    m_dataIn->GetBuffer()[8] = 0xA1;
    m_dataIn->GetBuffer()[9] = 0x01;
    m_dataIn->GetBuffer()[10] = 0x03; // Pad and sign processing.

    // Hash algorithm TLV.
    m_dataIn->GetBuffer()[11] = 0x91;
    m_dataIn->GetBuffer()[12] = 0x02;
    m_dataIn->GetBuffer()[13] = 0x00; // SHA-256.
    m_dataIn->GetBuffer()[14] = 0x01;

    // Signature algorithm TLV.
    m_dataIn->GetBuffer()[15] = 0x92;
    m_dataIn->GetBuffer()[16] = 0x01;
    m_dataIn->GetBuffer()[17] = 0x01; // RSA with padding according to RSASSA PKCS#1 v1.5.

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Sign update command.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + 34); // CLA-Lc 5 bytes + Data 34 bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x2B;
    m_dataIn->GetBuffer()[2] = 0x80;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = 0x22;

    // Tag Length 2 bytes + Data 32 bytes hash of SHA-256.
    m_dataIn->GetBuffer()[5] = 0x9E;
    m_dataIn->GetBuffer()[6] = 0x20;
    memcpy (&(m_dataIn->GetBuffer()[7]), data->GetBuffer(), 32);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        default:
            reset_buffers();
            throw RemotingException("");
    }

    // Remove the Tag 0x33 Length 0x10 0x00 overhead from the signature.
    u1Array *result = new u1Array(m_dataOut->GetLength() - 3);
    result->SetBuffer(m_dataOut->GetBuffer() + 3);

    reset_buffers();

    return result;
}

// ------------------------------------------------------
// ------------------------------------------------------

u1Array* CardModuleApplet::EncodePublicKeyECC(u1Array* pubkey)
{
    // See the IoTSAFE SRS for the TLV format.
    u1Array* encodedKey = new u1Array(4 + pubkey->GetLength());

    if (!encodedKey)
        return nullptr;

    encodedKey->GetBuffer()[0] = 0x49;
    encodedKey->GetBuffer()[1] = (2 + pubkey->GetLength());
    encodedKey->GetBuffer()[2] = 0x86;
    encodedKey->GetBuffer()[3] = pubkey->GetLength();
    memcpy(&(encodedKey->GetBuffer()[4]), pubkey->GetBuffer(), pubkey->GetLength());

    std::string stPubKey;
    Log::toString(encodedKey->GetBuffer(), encodedKey->GetLength(), stPubKey);
    Log::log( "Encoded ECC PubKey <%s>", stPubKey.c_str() );

    return encodedKey;
}

void CardModuleApplet::PutPublicKey(u1Array* keyID, u1Array* encodedPubKey)
{
    /* Put public key init command.
     */

    reset_buffers();
    m_dataIn = new u1Array(5U + 2U + keyID->GetLength()); // CLA-Lc 5 bytes + Tag Length 2 bytes + Remaining Data bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x24;
    m_dataIn->GetBuffer()[2] = 0x00;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = 2U + keyID->GetLength();

    // Public key ID TLV.
    m_dataIn->GetBuffer()[5] = 0x85;
    m_dataIn->GetBuffer()[6] = keyID->GetLength();
    memcpy(&(m_dataIn->GetBuffer()[7]), (u1*)keyID->GetBuffer(), keyID->GetLength()); // ID value.

    try
    {
        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch(...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        case 0x6985:
            Log::log("Condition not satisfied \n");
            reset_buffers();
            throw RemotingException("");
        case 0x6A80:
            Log::log("Incorrect data\n");
            reset_buffers();
            throw RemotingException("");
        case 0x6A86:
            Log::log("wrong p1 p2\n");
            reset_buffers();
            throw RemotingException("");
         case 0x6989:
            Log::log("wrong p1 p2\n");
            reset_buffers();
            throw RemotingException("");
        default:
            reset_buffers();
            throw RemotingException("");
    }

    /* Put public key update command.
     */

    const u4 maxBlockValue = 253; // Max length Lc 255 bytes - Tag Length 2 bytes -> Value 253 bytes.
    u1 *remainingData = encodedPubKey->GetBuffer();
    u4 remainingDataLen = encodedPubKey->GetLength();

    // First to before last block of data.
    while (remainingDataLen > maxBlockValue)
    {
        reset_buffers();
        m_dataIn = new u1Array(260); // CLA-Lc 5 bytes + Data 255 bytes.
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = m_channel;
        m_dataIn->GetBuffer()[1] = 0xD8;
        m_dataIn->GetBuffer()[2] = 0x00;
        m_dataIn->GetBuffer()[3] = 0x00;
        m_dataIn->GetBuffer()[4] = 0xFF; // Max length Lc 255 bytes.

        // Encoded key data input TLV.
        m_dataIn->GetBuffer()[5] = 0x34;
        m_dataIn->GetBuffer()[6] = (BYTE) maxBlockValue;
        memcpy(&(m_dataIn->GetBuffer()[7]), remainingData, (BYTE) maxBlockValue);

        try
        {
            CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
        }
        catch (...)
        {
            reset_buffers();
            throw;
        }

        switch (m_SW1SW2)
        {
            case 0x9000:
                break;
            default:
                reset_buffers();
                throw RemotingException("");
        }

        remainingDataLen -= maxBlockValue;
        remainingData += maxBlockValue;
    }

    // Last block of data.
    reset_buffers();
    m_dataIn = new u1Array(5U + 2U + remainingDataLen); // CLA-Lc 5 bytes + Tag Length 2 bytes + Remaining Data bytes.
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0xD8;
    m_dataIn->GetBuffer()[2] = 0x80;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE) (2U + remainingDataLen); // Tag Length 2 bytes + Value bytes.

    // Encoded key data input TLV.
    m_dataIn->GetBuffer()[5] = 0x34;
    m_dataIn->GetBuffer()[6] = (BYTE) remainingDataLen;
    memcpy(&(m_dataIn->GetBuffer()[7]), remainingData, (BYTE) remainingDataLen);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch (...)
    {
        reset_buffers();
        throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        case 0x6985:
            Log::log("Condition not satisfied \n");
            reset_buffers();
            throw RemotingException("");
        case 0x6A80:
            Log::log("Incorrect data\n");
            reset_buffers();
            throw RemotingException("");
        case 0x6A86:
            Log::log("wrong p1 p2\n");
            reset_buffers();
            throw RemotingException("");
        default:
            reset_buffers();
            throw RemotingException("");
    }

    reset_buffers();
}

u1Array* CardModuleApplet::ConstructDHAgreement(u1 ctrIndex, u1Array* dataQx, u1Array* dataQy)
{
    /* Put the peer public key in the card.
     */
    std::string secret;
    std::string key;
    // ECC public key encoding: 0x04 | X | Y.
    u1Array* peerPubKey = new u1Array(1 + dataQx->GetLength() + dataQy->GetLength());

    if (!peerPubKey)
        goto cleaning;

    peerPubKey->GetBuffer()[0] = 0x04;
    memcpy(&peerPubKey->GetBuffer()[1], dataQx->GetBuffer(), dataQx->GetLength());
    memcpy(&peerPubKey->GetBuffer()[1 + dataQx->GetLength()], dataQy->GetBuffer(), dataQy->GetLength());


    Log::toString( peerPubKey->GetBuffer(), peerPubKey->GetLength( ), key);
    Log::log( "Peer ECC public key <%s>", key.c_str( ) );

    // IoTSAFE applet ECC public key encoding.
    u1Array* encodedKey;
    encodedKey = EncodePublicKeyECC(peerPubKey);

    if (!encodedKey)
        goto cleaning;

    // IoTSAFE applet key container for placing the peer public key.
    u1Array* peerKeyID;
    peerKeyID = new u1Array(1);

    if (!peerKeyID)
        goto cleaning;

    peerKeyID->GetBuffer()[0] = 0x05; // Container 0x05 for peer key.

    try
    {
        PutPublicKey(peerKeyID, encodedKey);
    }
    catch(...)
    {
        goto cleaning;
    }

    /* Compute ECDH.
     */

    reset_buffers();
    m_dataIn = new u1Array(5 + COMPUTE_DH_DATAIN_IN_LEN + 1);
    m_dataOut = new u1Array(0);

    m_dataIn->GetBuffer()[0] = m_channel;
    m_dataIn->GetBuffer()[1] = 0x46;
    m_dataIn->GetBuffer()[2] = 0x00;
    m_dataIn->GetBuffer()[3] = 0x00;
    m_dataIn->GetBuffer()[4] = (BYTE)(COMPUTE_DH_DATAIN_IN_LEN);
    memcpy(&(m_dataIn->GetBuffer()[5]), (u1*)COMPUTE_DH_DATAIN_IN, COMPUTE_DH_DATAIN_IN_LEN);

    try
    {
        CardManager::getInstance()->exchangeData(*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
    }
    catch(...)
    {
        reset_buffers();
        goto cleaning;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            break;
        case 0x6985:
            Log::log("Condition not satisfied \n");
            goto cleaning;
        case 0x6A80:
            Log::log("Incorrect data\n");
            goto cleaning;
        case 0x6A86:
            Log::log("wrong p1 p2\n");
            goto cleaning;
        default:
            goto cleaning;
    }

    u1Array* result;
    result = new u1Array(m_dataOut->GetLength());

    if (!result)
        goto cleaning;

    result->SetBuffer(m_dataOut->GetBuffer());


    Log::toString(result->GetBuffer(), result->GetLength(), secret);
    Log::log( "secret <%s>", secret.c_str() );

    reset_buffers();

cleaning:

    if (peerPubKey)
        delete peerPubKey;

    if (encodedKey)
        delete encodedKey;

    if (peerKeyID)
        delete peerKeyID;

    if (result)
        return result;
    else
        throw RemotingException("");
}

// ------------------------------------------------------
// Information Management Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* QueryCapabilities()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
s4Array* CardModuleApplet::QueryFreeSpace()
{
   s4Array* freeSpace = new s4Array(3);
	//temporary solution to use the limits for the key pair generation
    freeSpace->SetU4At(0, std::numeric_limits<u4>::max()/2);
    freeSpace->SetU4At(1, std::numeric_limits<u4>::max()/2);
    freeSpace->SetU4At(2, std::numeric_limits<u4>::max()/2);

	return freeSpace;
}

// ------------------------------------------------------
// ------------------------------------------------------
s4Array* CardModuleApplet::QueryKeySizes()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
s4Array* CardModuleApplet::QueryKeySizesEx(u1 keySpec)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::get_SerialNumber()
{
    return new u1Array(0);
}

// ------------------------------------------------------
// ------------------------------------------------------
string* CardModuleApplet::get_Version()
{
    return new string("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetHostVersion(u4 hostVersion)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::IsECC()
{
    return 1;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::hasOAEP_PSS()
{
    return 1;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::IsSha1Disabled()
{
    return 1;
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::getRSAMinMax( int &minRsa, int& maxRsa, int &minRsaGen, int &maxRsaGen, u1 role )
{
    maxRsa = 2048;
    maxRsaGen = 2048;
    minRsa = 2048;
    minRsaGen = 2048;
}


// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::getECCMinMax( int &minEcc, int& maxEcc, int &minEccGen, int &maxEccGen, u1 role )
{
    minEcc = 256;
    maxEcc = 256;
    minEccGen = 256;
    maxEccGen = 256;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::IsLastHashRoundSupported(CDigest::HASH_TYPE hashType)
{
    return 0;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::IsPlusCard()
{
    return 0;
}

// ------------------------------------------------------
// File System Management Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::CreateDirectory(string* path,u1Array* acls)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::DeleteDirectory(string* path)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::CreateFile(string* path, u1Array* acls, s4 initialSize)
{
    // Not applicable.
    // Nothing to write // throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::DeleteFile(string* path)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::WriteFile(string* path, u1Array* data)
{
    // Not applicable.
   // Nothing to write /// throw ArgumentException("");
}

//-------------------------------------------------------
//audit card
//-------------------------------------------------------

void CardModuleApplet::auditCard(BOOL select)
{
    m_objectlist = getObjectList(select);
    parseObjectList();
    m_auditStructure.privateKeyCount = m_auditStructure.priKeyInfo.size();
    if(m_auditStructure.privateKeyCount == 0)
        Log::log("No private key found");

    m_auditStructure.publicKeyCount = m_auditStructure.pubKeyInfo.size();
    if(m_auditStructure.publicKeyCount == 0)
        Log::log("No public key found");

     m_auditStructure.secretKeyCount = m_auditStructure.secretKeyInfo.size();
     if(m_auditStructure.secretKeyCount == 0)
        Log::log("No secret key found");

    m_auditStructure.fileCount = m_auditStructure.fileInfo.size();
    if( m_auditStructure.fileCount == 0)
        Log::log("No file found");

    for(int i = 0; i<m_auditStructure.fileCount; i++){
        if(m_auditStructure.fileInfo[i].usage == 0x02){
           m_auditStructure.certificateCount++;
        }
    }
     Log::log("%d certificate file found", m_auditStructure.certificateCount);
}

u1Array* CardModuleApplet::getObjectList(BOOL select){
     std::vector<u1> all_data_out;
    try
    {
        if(select){
            m_dataIn = new u1Array(5 + CARD_APPLET_AID_LEN);
            m_dataOut = new u1Array(0);

            Log::log("SELECT APPLET BEFORE GET DATA");
            m_dataIn->GetBuffer()[0] = m_channel;
            m_dataIn->GetBuffer()[1] = 0xA4;
            m_dataIn->GetBuffer()[2] = 0x04;
            m_dataIn->GetBuffer()[3] = 0x00;
            m_dataIn->GetBuffer()[4] = (BYTE)(CARD_APPLET_AID_LEN);
            std::memcpy (&(m_dataIn->GetBuffer()[5]), (u1*)CARD_APPLET_AID, CARD_APPLET_AID_LEN);
            CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
            reset_buffers();
        }

        Log::log("GET DATA");
        m_dataIn = new u1Array(4);
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = m_channel;
        m_dataIn->GetBuffer()[1] = 0xCB;
        m_dataIn->GetBuffer()[2] = 0x01;
        m_dataIn->GetBuffer()[3] = 0x00;
        m_dataIn->GetBuffer()[4] = 0x00;

        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

    }
    catch(...)
    {
            reset_buffers();
            throw;
    }

    switch (m_SW1SW2)
    {
        case 0x9000:
            Log::log("get data successful");
            return m_dataOut;
        break;

        case 0x6300:
            for(int i = 0; i< m_dataOut->GetLength(); i++)
                all_data_out.push_back(m_dataOut->GetBuffer()[i]);


            while(m_SW1SW2 != 0x9000){
                m_dataIn->GetBuffer()[3] = 0x01;//more data p2
                m_dataOut->Clear();

                CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);
               for(int i = 0; i< m_dataOut->GetLength(); i++)
                    all_data_out.push_back(m_dataOut->GetBuffer()[i]);

            }

            break;
        default:
            Log::log("get data not ok");
        break;
    }
    u1Array* getDataOutput = new u1Array(all_data_out.data(), all_data_out.size());

    return getDataOutput;
}

void CardModuleApplet::parseObjectList(){
    uint8_t c1len = 0;
    uint8_t c2len = 0;
    uint8_t c3len = 0;
    uint8_t c4len = 0;
    bool found = false;

    for(int i = 0; i < m_objectlist->GetLength();)
    {
        // Private key list.
        if(m_objectlist->GetBuffer()[i] == 0xC1)
        {
            Log::log("-----Discover Private Keys------");
            c1len = m_objectlist->GetBuffer()[i + 1];
            for(int j = i + 2; j <= i + 1 + c1len;)
            {
                // Prepare a buffer for the next TLV Value.
                BYTE buffer[m_objectlist->GetBuffer()[j + 1]] = {};

                // Proceed past the tag byte.
                uint8_t tag = m_objectlist->GetBuffer()[j++];

                // For identifying the next private key TLV in the list.
                if(tag == 0x74 || tag == 0x84)
                    found = true;
                else
                    found = false;

                // Proceed past the len byte.
                uint8_t len = m_objectlist->GetBuffer()[j++];

                // Proceed past the data bytes.
                j += tlvParse(tag, len, j, buffer);

                // Parse the current TLV.
                updateKeyBuffer(tag, len, buffer);

                // The next private key ID or label Tag indicates the end of the current private key TLV attributes.
                if((m_objectlist->GetBuffer()[j] == 0x74 || m_objectlist->GetBuffer()[j] == 0x84) && !found)
                {
                    Log::log("------------");
                    m_auditStructure.priKeyInfo.push_back(m_keyInfoBuffer);
                    m_keyInfoBuffer = KeyInfo();
                }
            }

            // Add the last private key.
            if(m_keyInfoBuffer.id != NULL)
            {
                m_auditStructure.priKeyInfo.push_back(m_keyInfoBuffer);
                m_keyInfoBuffer = KeyInfo();
            }

            // Proceed to the next object list Tag.
            i += 1 + c1len + 1;
        }
        // Public key list.
        else if(m_objectlist->GetBuffer()[i] == 0xC2)
        {
            Log::log("-----Discover Public Keys------");
            c2len = m_objectlist->GetBuffer()[i + 1];
            for(int j = i + 2; j <= i + 1 + c2len;)
            {
                // Prepare a buffer for the next TLV Value.
                BYTE buffer[m_objectlist->GetBuffer()[j + 1]] = {};

                // Proceed past the tag byte.
                uint8_t tag = m_objectlist->GetBuffer()[j++];

                // For identifying the next public key TLV in the list.
                if(tag == 0x75 || tag == 0x85)
                    found = true;
                else
                    found = false;

                // Proceed past the len byte.
                uint8_t len = m_objectlist->GetBuffer()[j++];

                // Proceed past the data bytes.
                j += tlvParse(tag, len, j, buffer);

                // Parse the current TLV.
                updateKeyBuffer(tag, len, buffer);

                // The next public key ID or label Tag indicates the end of the current public key TLV attributes.
                if((m_objectlist->GetBuffer()[j] == 0x75 || m_objectlist->GetBuffer()[j] == 0x85) && !found)
                {
                    Log::log("------------");
                    m_auditStructure.pubKeyInfo.push_back(m_keyInfoBuffer);
                    m_keyInfoBuffer = KeyInfo();
                }
            }

            // Add the last public key.
            if(m_keyInfoBuffer.id != NULL)
            {
                m_auditStructure.pubKeyInfo.push_back(m_keyInfoBuffer);
                m_keyInfoBuffer = KeyInfo();
            }

            // Proceed to the next object list Tag.
            i += 1 + c2len + 1;
        }
        // File list.
        else if(m_objectlist->GetBuffer()[i] == 0xC3)
        {
            Log::log("-----Discover Files------");
            c3len = m_objectlist->GetBuffer()[i + 1];
            for(int j = i + 2; j <= i + 1 + c3len;)
            {
                // Prepare a buffer for the next TLV Value.
                BYTE buffer[m_objectlist->GetBuffer()[j + 1]] = {};

                // Proceed past the tag byte.
                uint8_t tag = m_objectlist->GetBuffer()[j++];

                // For identifying the next file TLV in the list.
                if(tag == 0x73 || tag == 0x83)
                    found = true;
                else
                    found = false;

                // Proceed past the len byte.
                uint8_t len = m_objectlist->GetBuffer()[j++];

                // Proceed past the data bytes.
                j += tlvParse(tag, len, j, buffer);

                // Parse the current TLV.
                updateFileBuffer(tag, len, buffer);

                // The next file ID or label Tag indicates the end of the current file TLV attributes.
                if((m_objectlist->GetBuffer()[j] == 0x73 || m_objectlist->GetBuffer()[j] == 0x83) && !found)
                {
                    Log::log("------------");
                    m_auditStructure.fileInfo.push_back(m_fileInfoBuffer);
                    m_fileInfoBuffer = FileInfo();
                }
            }

            // Add the last file.
            if(m_fileInfoBuffer.id != NULL)
            {
                m_auditStructure.fileInfo.push_back(m_fileInfoBuffer);
                m_fileInfoBuffer = FileInfo();
            }

            // Proceed to the next object list Tag.
            i += 1 + c3len + 1;
        }
        // Secret key list.
        else if(m_objectlist->GetBuffer()[i] == 0xC4)
        {
            Log::log("-----Discover Secret Key------");
            c4len = m_objectlist->GetBuffer()[i + 1];
            for(int j = i + 2; j <= i + 1 + c4len;)
            {
                // Prepare a buffer for the next TLV Value.
                BYTE buffer[m_objectlist->GetBuffer()[j + 1]] = {};

                // Proceed past the tag byte.
                uint8_t tag = m_objectlist->GetBuffer()[j++];

                // For identifying the next secret key TLV in the list.
                if(tag == 0x76 || tag == 0x86)
                    found = true;
                else
                    found = false;

                // Proceed past the len byte.
                uint8_t len = m_objectlist->GetBuffer()[j++];

                // Proceed past the data bytes.
                j += tlvParse(tag, len, j, buffer);

                // Parse the current TLV.
                updateKeyBuffer(tag, len, buffer);

                // The next secret key ID or label Tag indicates the end of the current secret key TLV attributes.
                if((m_objectlist->GetBuffer()[j] == 0x76 || m_objectlist->GetBuffer()[j] == 0x86) && !found)
                {
                    Log::log("------------");
                    m_auditStructure.secretKeyInfo.push_back(m_keyInfoBuffer);
                    m_keyInfoBuffer = KeyInfo();
                }
            }

            // Add the last secret key.
            if(m_keyInfoBuffer.id != NULL)
            {
                m_auditStructure.secretKeyInfo.push_back(m_keyInfoBuffer);
                m_keyInfoBuffer = KeyInfo();
            }

            // Proceed to the next object list Tag.
            i += 1 + c4len + 1;
        }
    }
}

uint8_t CardModuleApplet::tlvParse(uint8_t tag, uint8_t len, int start, BYTE* buffer)
{
    uint8_t read = 0;
    for(int i = start, j = 0; i < start + len; i++, j++){
       buffer[j] = m_objectlist->GetBuffer()[i];
    }
    read = len;
    return read;
}

void CardModuleApplet::updateKeyBuffer(uint8_t tag, uint8_t len, BYTE* buffer)
{
    switch(tag){
        case 0x74:
            m_keyInfoBuffer.label = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_keyInfoBuffer.label[i*2],"%02X",buffer[i]);
            Log::log("Key Label [private]: %s", m_keyInfoBuffer.label);
            break;
        case  0x84:
            m_keyInfoBuffer.id = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_keyInfoBuffer.id[i*2],"%02X",buffer[i]);
            Log::log("Key ID [private]: %s" , m_keyInfoBuffer.id);

             //set the byte version - experimental
             m_keyInfoBuffer.id_byte = buffer[0];
            break;
        case  0x75:
            m_keyInfoBuffer.label = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_keyInfoBuffer.label[i*2],"%02X",buffer[i]);
            Log::log("Key Label [public]: %s", m_keyInfoBuffer.label);
            break;
        case 0x85:
            m_keyInfoBuffer.id = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_keyInfoBuffer.id[i*2],"%02X",buffer[i]);
            Log::log("Key ID [public]: %s" , m_keyInfoBuffer.id);

             //set the byte version - experimental
             m_keyInfoBuffer.id_byte = buffer[0];
            break;
        case 0x76:
             m_keyInfoBuffer.label = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_keyInfoBuffer.label[i*2],"%02X",buffer[i]);
            Log::log("Key Label [secret]: %s", m_keyInfoBuffer.label);
            break;
        case 0x86:
            m_keyInfoBuffer.id = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_keyInfoBuffer.id[i*2],"%02X",buffer[i]);
            Log::log("Key ID [secret]: %s" , m_keyInfoBuffer.id);
            break;
        case 0x60:
            m_keyInfoBuffer.accessCondition = buffer[0];
            Log::log("Access Condition: %02X", m_keyInfoBuffer.accessCondition);
            break;
        case 0x4A:
            m_keyInfoBuffer.state = buffer[0];
             Log::log("Object State: %02X", m_keyInfoBuffer.state);
            break;
        case 0x4B:
            m_keyInfoBuffer.keyType = buffer[0];
             Log::log("Key Type: %02X ", m_keyInfoBuffer.keyType);
            break;
        case 0x4E:
             m_keyInfoBuffer.usage = buffer[0];
              Log::log("Key Specific Usage: %02X ", m_keyInfoBuffer.usage);
             break;
        case 0x61:
             m_keyInfoBuffer.cryptoFunc = buffer[0];
              Log::log("Cryptographic Function: %02X ", m_keyInfoBuffer.cryptoFunc);
             break;
        case 0x92:
            m_keyInfoBuffer.signatureAlgo = buffer[0];
            Log::log("Supported Signature Algo: %02X ", m_keyInfoBuffer.signatureAlgo);
            break;
        case 0x91:
            std::memcpy(m_keyInfoBuffer.hashAlgo, buffer, len);
            Log::log("Supported Hash Algo");
            for(int i = 0; i < len; i++)
              Log::log("%02X", m_keyInfoBuffer.hashAlgo[i]);

            break;
        case 0x6F:
            m_keyInfoBuffer.keyAgreementAlgo = buffer[0];
             Log::log("Supported key Agreement Algo: %02X ", m_keyInfoBuffer.keyAgreementAlgo);
            break;
        default:
            break;
    }
}

void CardModuleApplet::updateFileBuffer(uint8_t tag, BYTE len, BYTE* buffer)
{
     char tmpSize[len * 2];
    switch(tag){
        case 0x73:
             m_fileInfoBuffer.label = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_fileInfoBuffer.label[i*2],"%02X",buffer[i]);
            Log::log("File Label: %s", m_fileInfoBuffer.label);
            break;
        case  0x83:
             m_fileInfoBuffer.id = new char[len * 2]; //todo free
            for(uint8_t i = 0; i < len; i++)
                sprintf(&m_fileInfoBuffer.id[i*2],"%02X",buffer[i]);
            Log::log("File ID: %s" , m_fileInfoBuffer.id);

            //set the byte version - experimental
             m_fileInfoBuffer.id_byte = buffer[0];

            break;
        case 0x60:
            m_fileInfoBuffer.accessCondition = buffer[0];
              Log::log("File Access Condition: %02X", m_fileInfoBuffer.accessCondition);
            break;
        case 0x4A:
            m_fileInfoBuffer.state = buffer[0];
             Log::log("File Object State: %02X", m_fileInfoBuffer.state);
            break;
        case 0x21:
             m_fileInfoBuffer.usage = buffer[0];
              Log::log("File Specific Usage: %02X", m_fileInfoBuffer.usage);
             break;
        case 0x20:
            for(uint8_t i = 0; i < len; i++)
                sprintf(&tmpSize[i*2],"%02X",buffer[i]);
            m_fileInfoBuffer.totalSize = stoi(tmpSize, 0, 16);


            //persitent
            std::memcpy(m_fileInfoBuffer.size, buffer, len);
            Log::log("File Size");
            for(int i = 0; i < len; i++)
                Log::log("%02X", m_fileInfoBuffer.size[i]);

            Log::log("Decimal File Size %d", m_fileInfoBuffer.totalSize);
            break;
        default:
            break;
    }
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::ReadFile(string* path, s4 maxBytesToRead)
{
    Log::begin ("CardModuleApplet::ReadFile");
    Log::log ("CardModuleApplet::ReadFile %s ", path->c_str());

    UNREFERENCED_PARAMETER(maxBytesToRead);

    /* Build file name and directory name from path.
     */
    u1Array* data = NULL;
    char szPathFileName[MAX_NAME_LEN];
    char szPathDirName[MAX_NAME_LEN];

    int pos = (int)path->find_last_of('\\');
    memset(szPathDirName, 0x00, sizeof(szPathDirName));
    memset(szPathFileName, 0x00, sizeof(szPathFileName));

    if (pos != (int)string::npos)
    {
        memcpy(szPathDirName, path->c_str(), pos);
        memcpy(szPathFileName, &(path->c_str()[pos + 1]), strlen(path->c_str()) - (pos + 1));
    }
    else
    {
        strcpy(szPathFileName, path->c_str());
    }

    Log::log ("CardModuleApplet::ReadFile path %s ", szPathFileName);

    /* Read file based on the received file name.
     */
    if (strcmp(path->c_str(), "cardcf") == 0)
    {
        Log::end ("CardModuleApplet::ReadFile");

        // Dummmy data.
        return new u1Array(6);
    }
    else if (strcmp(path->c_str(), "mscp\\msroots") == 0)
    {
        // Ignore, no msroots certificate for this applet.
    }
    else if (strcmp(path->c_str(), "mscp\\cmapfile") == 0)
    {
        CONTAINER_MAP_RECORD * cmap_ptr = NULL;
        data = new u1Array(16 * sizeof(CONTAINER_MAP_RECORD));
        cmap_ptr = (CONTAINER_MAP_RECORD *) data->GetBuffer();

        // Certificates.
        for (int i = 0; i < m_auditStructure.fileCount; i++)
        {
            // This denotes a certificate file.
            if (m_auditStructure.fileInfo[i].usage == 0x02)
            {
                BYTE cid = m_auditStructure.fileInfo[i].id_byte;
                cmap_ptr[cid].wSigKeySizeBits = 256;
                cmap_ptr[cid].bFlags =  CONTAINER_MAP_VALID_CONTAINER;
            }
        }

        // ECC public keys.
        for (int i = 0; i < m_auditStructure.publicKeyCount; i++)
        {
            BYTE cid = m_auditStructure.pubKeyInfo[i].id_byte;
            if (m_auditStructure.pubKeyInfo[i].keyType == 19)
            { // 19 decimal = 13 hex = ECC key type
               cmap_ptr[cid].wSigKeySizeBits = 256;
               cmap_ptr[cid].bFlags =  CONTAINER_MAP_VALID_CONTAINER;
            }
        }

        // ECC private keys.
        for (int i = 0; i < m_auditStructure.privateKeyCount; i++)
        {
            BYTE cid = m_auditStructure.priKeyInfo[i].id_byte;
            if (m_auditStructure.priKeyInfo[i].keyType == 19)
            { // 19 decimal = 13 hex = ECC key type
               cmap_ptr[cid].wSigKeySizeBits = 256;
               cmap_ptr[cid].bFlags = CONTAINER_MAP_VALID_CONTAINER;
            }
        }

        // AES secret keys.
        for (int i = 0; i < m_auditStructure.secretKeyCount; i++)
        {
            BYTE cid = m_auditStructure.secretKeyInfo[i].id_byte;
            cmap_ptr[cid].wSigKeySizeBits = 128;
            cmap_ptr[cid].bFlags = CONTAINER_MAP_VALID_CONTAINER;
        }

        Log::end ("CardModuleApplet::ReadFile");

        return data;
    }
    else if (strcmp(path->c_str(), "p11\\tinfo") == 0)
    {
        Log::end ("CardModuleApplet::ReadFile");

        // Dummy data.
        return new u1Array(16);
    }
    else
    {
        /* A long list of "if else" statements by using "for" loop.
         */

        // p11\\pubkscXX or mscp\\kscXX.
        for (int i = 0; i < m_auditStructure.fileCount; i++)
        {
            // This denotes a certificate file.
            if (m_auditStructure.fileInfo[i].usage == 0x02)
            {
                char certname_pub[9] = {}; // pubkscXX
                char certname_mscp[6] = {}; // kscXX
                char _path_pub[13] = {}; // p11\\pubkscXX
                char _path_mscp[11] = {}; // mscp\\kscXX

                strcpy(certname_pub,"pubksc");
                strcat(certname_pub, m_auditStructure.fileInfo[i].id);
                strcpy(_path_pub, "p11\\");
                strcat(_path_pub, certname_pub);

                strcpy(certname_mscp,"ksc");
                strcat(certname_mscp, m_auditStructure.fileInfo[i].id);
                strcpy(_path_mscp, "mscp\\");
                strcat(_path_mscp, certname_mscp);

                if (strcmp(path->c_str(), _path_pub) == 0)
                {
                    // p11\\pubkscXX returns the serialized PKCS11 object, while the mscp\\kscXX counterpart returns the certificate data.
                    X509PubKeyCertObject cert;

                    /* Fill the PKCS#11 storage object information.
                     */
                    cert.m_Token = CK_TRUE;
                    cert.m_Private = CK_FALSE;
                    cert.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.fileInfo[i].label);
                    cert.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    cert.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 certificate object information.
                     */
                    cert._certType = CKC_X_509;
                    cert._trusted = CK_TRUE;
                    cert._certCategory = 0; // CK_CERTIFICATE_CATEGORY_UNSPECIFIED
                    cert.m_pCheckSum.reset( new u1Array( 0 ) );
                    cert.m_pStartDate.reset( new u1Array( 0 ) );
                    cert.m_pEndDate.reset( new u1Array( 0 ) );

                    /* Fill the PKCS#11 X.509 public key certificate object information.
                     */
                    cert.m_pSubject.reset( new u1Array( 0 ) );

                    std::string stID = std::string(m_auditStructure.fileInfo[i].id);
                    cert.m_pID.reset( new u1Array( stID.size( ) ) );
                    cert.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    cert.m_pIssuer.reset( new u1Array( 0 ) );
                    cert.m_pSerialNumber.reset( new u1Array( 0 ) );

                    // No cert.m_pValue.reset() here because the certificate value will be read in the Token logic by reading the mscp\\kscXX counterpart;

                    cert.m_pURL.reset( new u1Array( 0 ) );
                    cert.m_pHashOfSubjectPubKey.reset( new u1Array( 0 ) );
                    cert.m_pHashOfIssuerPubKey.reset( new u1Array( 0 ) );

                    /* Fill non PKCS#11 object information.
                     */
                    cert.m_ucContainerIndex = std::atoi(m_auditStructure.fileInfo[i].id);
                    cert.m_ucKeySpec = MiniDriverContainer::KEYSPEC_ECDSA_256; // All certificates are ECDSA 256.

                    std::vector<u1> certVec;
                    cert.serialize(&certVec);

                    u1Array* certObj = new u1Array(certVec.data(), certVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return certObj;
                }
                else if (strcmp(path->c_str(), _path_mscp) == 0)
                {
                    // mscp\\kscXX returns the certificate data, while the p11\\pubkscXX counterpart returns the serialized PKCS11 object.
                    u1Array* certdata = getCertificateDataFromContainer(m_auditStructure.fileInfo[i].id_byte);

                    return certdata;
                }
            }
        }

        // p11\\pubpukXX.
        for (int i = 0; i < m_auditStructure.publicKeyCount; i++)
        {
            char keyname[9] = {}; // pubpukXX
            char _path[13] = {}; // p11\\pubpukXX

            strcpy(keyname, "pubpuk");
            strcat(keyname, m_auditStructure.pubKeyInfo[i].id);
            strcpy(_path, "p11\\");
            strcat(_path, keyname);

            if (strcmp(path->c_str(), _path) == 0)
            {
                u1Array* pubkey = getPublicKeyFromKeyContainer(m_auditStructure.pubKeyInfo[i].id_byte);

                if (m_auditStructure.pubKeyInfo[i].keyType == 0x03) // RSA key.
                {
                    Pkcs11ObjectKeyPublicRSA puk;

                    /* Fill the PKCS#11 storage object information.
                     */
                    puk.m_Token = CK_TRUE;
                    puk.m_Private = CK_FALSE;
                    puk.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.pubKeyInfo[i].label);
                    puk.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    puk.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 key object information.
                     */
                    std::string stID = std::string(m_auditStructure.pubKeyInfo[i].id);
                    puk.m_pID.reset( new u1Array( stID.size( ) ) );
                    puk.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    puk._derive = CK_FALSE;
                    puk._local = CK_FALSE;
                    puk._mechanismType = CK_UNAVAILABLE_INFORMATION;

                    /* Fill the PKCS#11 public key object information.
                     */
                    puk._encrypt = CK_FALSE;
                    puk._verify = CK_TRUE;
                    puk._verifyRecover = CK_FALSE;
                    puk._wrap = CK_FALSE;
                    puk._trusted = CK_FALSE;

                    /* Fill the PKCS#11 RSA public key object information.
                     */
                    puk.m_pModulus.reset( new u1Array(0) );
                    puk.m_ulModulusBits = 0;
                    puk.m_pPublicExponent.reset( new u1Array(0) );

                    /* Fill non PKCS#11 object information.
                     */
                    puk.m_ucContainerIndex = std::atoi(m_auditStructure.pubKeyInfo[i].id);
                    puk.m_ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

                    std::vector<u1> pukVec;
                    puk.serialize(&pukVec);

                    u1Array* pubKeyObj = new u1Array(pukVec.data(), pukVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return pubKeyObj;
                }
                else if ( // ECC key.
                    m_auditStructure.pubKeyInfo[i].keyType == 0x013 |
                    m_auditStructure.pubKeyInfo[i].keyType == 0x014 |
                    m_auditStructure.pubKeyInfo[i].keyType == 0x023 |
                    m_auditStructure.pubKeyInfo[i].keyType == 0x024 |
                    m_auditStructure.pubKeyInfo[i].keyType == 0x043
                        )
                {
                    Pkcs11ObjectKeyPublicECC puk;

                    /* Fill the PKCS#11 storage object information.
                     */
                    puk.m_Token = CK_TRUE;
                    puk.m_Private = CK_FALSE;
                    puk.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.pubKeyInfo[i].label);
                    puk.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    puk.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 key object information.
                     */
                    std::string stID = std::string(m_auditStructure.pubKeyInfo[i].id);
                    puk.m_pID.reset( new u1Array( stID.size( ) ) );
                    puk.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    puk._derive = m_auditStructure.pubKeyInfo[i].signatureAlgo == 0x01 ? CK_TRUE : CK_FALSE; // 0x01 denotes ECKA IEEE 1363.
                    puk._local = CK_FALSE;
                    puk._mechanismType = CK_UNAVAILABLE_INFORMATION;

                    /* Fill the PKCS#11 public key object information.
                     */
                    puk._encrypt = CK_FALSE;
                    puk._verify = m_auditStructure.pubKeyInfo[i].signatureAlgo == 0x04 ? CK_TRUE : CK_FALSE; // 0x04 denotes ECDSA.
                    puk._verifyRecover = CK_FALSE;
                    puk._wrap = CK_FALSE;
                    puk._trusted = CK_FALSE;

                    /* Fill the PKCS#11 ECC public key object information.
                     */
                    const u1 oid_brainpoolP256r1[11] = {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
                    const u1 oid_prime256v1[10] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

                    switch (m_auditStructure.pubKeyInfo[i].keyType)
                    {
                        // NIST secp256r1
                        case 0x13:
                        case 0x14:
                            puk.m_pParams.reset( new u1Array( (const u1*) &oid_prime256v1, 10) );
                            break;

                        // BrainpoolP256r1
                        case 0x23:
                        case 0x24:
                        case 0x43:
                        default:
                            puk.m_pParams.reset( new u1Array( (const u1*) &oid_brainpoolP256r1, 11) );
                            break;
                    }

                    u1 ecPoint[67] = {0x04 , 0x41}; // Tag + Length.
                    memcpy(&ecPoint[2], pubkey->GetBuffer(), 65);
                    puk.m_pPublicPoint.reset( new u1Array( (u1*) &ecPoint, 67));

                    /* Fill non PKCS#11 object information.
                     */
                    puk.m_ucContainerIndex = std::atoi(m_auditStructure.pubKeyInfo[i].id);
                    if (m_auditStructure.pubKeyInfo[i].signatureAlgo == 0x04) // 0x04 denotes ECDSA.
                    {
                        puk.m_ucKeySpec = MiniDriverContainer::KEYSPEC_ECDSA_256;
                    }
                    else if (m_auditStructure.pubKeyInfo[i].signatureAlgo == 0x01) // 0x01 denotes ECKA IEEE 1363.
                    {
                        puk.m_ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
                    }
                    else
                    {
                        puk.m_ucKeySpec = 0; // Don't care.
                    }

                    std::vector<u1> pukVec;
                    puk.serialize(&pukVec);

                    u1Array* pubKeyObj = new u1Array(pukVec.data(), pukVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return pubKeyObj;
                }
            }
        }

        // p11\\priprkXX.
        for (int i = 0; i < m_auditStructure.privateKeyCount; i++)
        {
            char keyname[9] = {}; // priprkXX
            char _path[13] = {}; // p11\\priprkXX

            strcpy(keyname, "priprk");
            strcat(keyname, m_auditStructure.priKeyInfo[i].id);
            strcpy(_path, "p11\\");
            strcat(_path, keyname);

            if (strcmp(path->c_str(), _path) == 0)
            {
                u1Array* pubkey = getPublicKeyFromKeyContainer(m_auditStructure.pubKeyInfo[i].id_byte);

                if (m_auditStructure.priKeyInfo[i].keyType == 0x03) // RSA key.
                {
                    RSAPrivateKeyObject prk;

                    /* Fill the PKCS#11 storage object information.
                     */
                    prk.m_Token = CK_TRUE;
                    prk.m_Private = CK_TRUE;
                    prk.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.priKeyInfo[i].label);
                    prk.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    prk.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 key object information.
                     */
                    std::string stID = std::string(m_auditStructure.priKeyInfo[i].id);
                    prk.m_pID.reset( new u1Array( stID.size( ) ) );
                    prk.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    prk._derive = CK_FALSE;
                    prk._local = CK_FALSE;
                    prk._mechanismType = CK_UNAVAILABLE_INFORMATION;

                    /* Fill the PKCS#11 private key object information.
                     */
                    prk.m_pSubject.reset( new u1Array(0) );
                    prk._sensitive = CK_TRUE;
                    prk._decrypt = CK_FALSE;
                    prk._sign = CK_TRUE;
                    prk._signRecover = CK_FALSE;
                    prk._unwrap = CK_FALSE;
                    prk._extractable = CK_FALSE;
                    prk._alwaysSensitive = CK_TRUE;
                    prk._neverExtractable = CK_TRUE;
                    prk._wrapWithTrusted = CK_FALSE;
                    prk._alwaysAuthenticate = CK_FALSE;
                    prk._checkValue = 0;

                    /* Fill the PKCS#11 RSA private key object information.
                     */
                    prk.m_pModulus.reset( new u1Array(0) );
                    prk.m_pPublicExponent.reset( new u1Array(0) );
                    prk.m_pPrivateExponent.reset( new u1Array(0) );
                    prk.m_pPrime1.reset( new u1Array(0) );
                    prk.m_pPrime2.reset( new u1Array(0) );
                    prk.m_pExponent1.reset( new u1Array(0) );
                    prk.m_pExponent2.reset( new u1Array(0) );
                    prk.m_pCoefficient.reset( new u1Array(0) );

                    /* Fill non PKCS#11 object information.
                     */
                    prk.m_ucContainerIndex = std::atoi(m_auditStructure.priKeyInfo[i].id);
                    prk.m_ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

                    std::vector<u1> prkVec;
                    prk.serialize(&prkVec);

                    u1Array* privKeyObj = new u1Array(prkVec.data(), prkVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return privKeyObj;
                }
                else if ( // ECC key.
                    m_auditStructure.priKeyInfo[i].keyType == 0x013 |
                    m_auditStructure.priKeyInfo[i].keyType == 0x014 |
                    m_auditStructure.priKeyInfo[i].keyType == 0x023 |
                    m_auditStructure.priKeyInfo[i].keyType == 0x024 |
                    m_auditStructure.priKeyInfo[i].keyType == 0x043
                        )
                {
                    ECCPrivateKeyObject prk;

                    /* Fill the PKCS#11 storage object information.
                     */
                    prk.m_Token = CK_TRUE;
                    prk.m_Private = CK_TRUE;
                    prk.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.priKeyInfo[i].label);
                    prk.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    prk.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 key object information.
                     */
                    std::string stID = std::string(m_auditStructure.priKeyInfo[i].id);
                    prk.m_pID.reset( new u1Array( stID.size( ) ) );
                    prk.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    prk._derive = m_auditStructure.priKeyInfo[i].signatureAlgo == 0x01 ? CK_TRUE : CK_FALSE; // 0x01 denotes ECKA IEEE 1363.
                    prk._local = CK_FALSE;
                    prk._mechanismType = CK_UNAVAILABLE_INFORMATION;

                    /* Fill the PKCS#11 private key object information.
                     */
                    prk.m_pSubject.reset( new u1Array(0) );
                    prk._sensitive = CK_TRUE;
                    prk._decrypt = CK_FALSE;
                    prk._sign = m_auditStructure.priKeyInfo[i].signatureAlgo == 0x04 ? CK_TRUE : CK_FALSE; // 0x04 denotes ECDSA.
                    prk._signRecover = CK_FALSE;
                    prk._unwrap = CK_FALSE;
                    prk._extractable = CK_FALSE;
                    prk._alwaysSensitive = CK_TRUE;
                    prk._neverExtractable = CK_TRUE;
                    prk._wrapWithTrusted = CK_FALSE;
                    prk._alwaysAuthenticate = CK_FALSE;
                    prk._checkValue = 0;

                    /* Fill the PKCS#11 ECC private key object information.
                     */
                    const u1 oid_brainpoolP256r1[11] = {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
                    const u1 oid_prime256v1[10] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

                    switch (m_auditStructure.pubKeyInfo[i].keyType)
                    {
                        // NIST secp256r1
                        case 0x13:
                        case 0x14:
                            prk.m_pParams.reset( new u1Array( (const u1*) &oid_prime256v1, 10) );
                            break;

                        // BrainpoolP256r1
                        case 0x23:
                        case 0x24:
                        default:
                            prk.m_pParams.reset( new u1Array( (const u1*) &oid_brainpoolP256r1, 11) );
                            break;
                    }

                    // Don't show the private key value.
                    prk.m_pPrivateValue.reset( new u1Array(0) );

                    u1 ecPoint[67] = {0x04 , 0x41}; // Tag + Length.
                    memcpy(&ecPoint[2], pubkey->GetBuffer(), 65);
                    prk.m_pPublicPoint.reset( new u1Array( (u1*) &ecPoint, 67));

                    /* Fill non PKCS#11 object information.
                     */
                    prk.m_ucContainerIndex = std::atoi(m_auditStructure.priKeyInfo[i].id);
                    if (m_auditStructure.priKeyInfo[i].signatureAlgo == 0x04) // 0x04 denotes ECDSA.
                    {
                        prk.m_ucKeySpec = MiniDriverContainer::KEYSPEC_ECDSA_256;
                    }
                    else if (m_auditStructure.priKeyInfo[i].signatureAlgo == 0x01) // 0x01 denotes ECKA IEEE 1363.
                    {
                        prk.m_ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
                    }
                    else
                    {
                        prk.m_ucKeySpec = 0; // Don't care.
                    }

                    std::vector<u1> prkVec;
                    prk.serialize(&prkVec);

                    u1Array* privKeyObj = new u1Array(prkVec.data(), prkVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return privKeyObj;
                }
            }
        }

        // p11\\prisekXX.
        for (int i = 0; i < m_auditStructure.secretKeyCount; i++)
        {
            char keyname[9] = {}; // prisekXX
            char _path[13] = {}; // p11\\prisekXX

            strcpy(keyname, "prisek");
            strcat(keyname, m_auditStructure.secretKeyInfo[i].id);
            strcpy(_path, "p11\\");
            strcat(_path, keyname);

            if (strcmp(path->c_str(), _path) == 0)
            {
                if (m_auditStructure.secretKeyInfo[i].keyType == 0xA0) // HMAC key.
                {
                    GenericSecretKeyObject sek;

                    /* Fill the PKCS#11 storage object information.
                     */
                    sek.m_Token = CK_TRUE;
                    sek.m_Private = CK_TRUE;
                    sek.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.secretKeyInfo[i].label);
                    sek.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    sek.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 key object information.
                     */
                    std::string stID = std::string(m_auditStructure.secretKeyInfo[i].id);
                    sek.m_pID.reset( new u1Array( stID.size( ) ) );
                    sek.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    sek._derive = CK_TRUE;
                    sek._local = CK_FALSE;
                    sek._mechanismType = CK_UNAVAILABLE_INFORMATION;

                    /* Fill the PKCS#11 secret key object information.
                     */
                    sek._sensitive = CK_TRUE;
                    sek._encrypt = CK_FALSE;
                    sek._decrypt = CK_FALSE;
                    sek._sign = CK_FALSE;
                    sek._verify = CK_FALSE;
                    sek._wrap = CK_FALSE;
                    sek._unwrap = CK_FALSE;
                    sek._extractable = CK_FALSE;
                    sek._alwaysSensitive = CK_TRUE;
                    sek._neverExtractable = CK_TRUE;
                    sek._checkValue = 0;
                    sek._wrapWithTrusted = CK_FALSE;
                    sek._trusted = CK_FALSE;

                    /* Fill the PKCS#11 generic secret key object information.
                     */
                    // Don't show key value.
                    sek.m_pValue.reset( new u1Array(0) );

                    // No filling container index here because secret key container index will be filled in the Token logic.

                    std::vector<u1> soVec;
                    sek.serialize(&soVec);

                    u1Array* secKey = new u1Array(soVec.data(), soVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return secKey;
                }
                else if (m_auditStructure.secretKeyInfo[i].signatureAlgo == 0x08) // AES key.
                {
                    // The AES keys for this applet are only used for CMAC and are 128-bit length.
                    SecretKeyObjectAES sek;

                    /* Fill the PKCS#11 storage object information.
                     */
                    sek.m_Token = CK_TRUE;
                    sek.m_Private = CK_TRUE;
                    sek.m_Modifiable = CK_FALSE;

                    std::string stLabel = std::string(m_auditStructure.secretKeyInfo[i].label);
                    sek.m_pLabel.reset( new u1Array( stLabel.size( ) ) );
                    sek.m_pLabel->SetBuffer( (u1*)( stLabel.c_str( ) ) );

                    /* Fill the PKCS#11 key object information.
                     */
                    std::string stID = std::string(m_auditStructure.secretKeyInfo[i].id);
                    sek.m_pID.reset( new u1Array( stID.size( ) ) );
                    sek.m_pID->SetBuffer( (u1*)( stID.c_str( ) ) );

                    sek._derive = CK_FALSE;
                    sek._local = CK_FALSE;
                    sek._mechanismType = CK_UNAVAILABLE_INFORMATION;

                    /* Fill the PKCS#11 secret key object information.
                     */
                    sek._sensitive = CK_TRUE;
                    sek._encrypt = CK_FALSE;
                    sek._decrypt = CK_FALSE;
                    sek._sign = CK_TRUE;
                    sek._verify = CK_FALSE;
                    sek._wrap = CK_FALSE;
                    sek._unwrap = CK_FALSE;
                    sek._extractable = CK_FALSE;
                    sek._alwaysSensitive = CK_TRUE;
                    sek._neverExtractable = CK_TRUE;
                    sek._checkValue = 0;
                    sek._wrapWithTrusted = CK_FALSE;
                    sek._trusted = CK_FALSE;

                    /* Fill the PKCS#11 AES secret key object information.
                     */
                    sek._key_len = 16;
                    // Don't show key value.
                    sek._key.reset( new u1Array(0) );

                    // No filling container index here because secret key container index will be filled in the Token logic.

                    std::vector<u1> soVec;
                    sek.serialize(&soVec);

                    u1Array* secKey = new u1Array(soVec.data(), soVec.size());

                    Log::end ("CardModuleApplet::ReadFile");

                    return secKey;
                }
            }
        }
    }

    Log::log ("CardModuleApplet::ReadFile - File not found ! ");
    Log::end ("CardModuleApplet::ReadFile");

    throw FileNotFoundException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
StringArray* CardModuleApplet::GetFiles(string* path)
{
    u1Array* data = NULL;
    StringArray* list = NULL;

    // Build directory list.
    if (path->compare("root") == 0)
    {
        list = new StringArray(5);
        list->SetStringAt(0, new string("p11"));
        list->SetStringAt(1, new string("mscp"));
        list->SetStringAt(2, new string("cardcf"));
        list->SetStringAt(3, new string("cardid"));
        list->SetStringAt(4, new string("cardapps"));
    }
    else if (path->compare("mscp") == 0)
    {
        int index = 0;
        list = new StringArray(m_auditStructure.certificateCount + 1);

        // Certificates.
        for (int i = 0; i < m_auditStructure.fileCount; i++)
        {
            // This denotes a certificate file.
            if (m_auditStructure.fileInfo[i].usage == 0x02)
            {
                char certname[6] = {0}; // kscXX
                strcpy(certname, "ksc");
                strcat(certname, m_auditStructure.fileInfo[i].id);
                list->SetStringAt(index, new string(certname));
                index++;
            }
        }

        list->SetStringAt(index++, new string("cmapfile"));
    }
    else if (path->compare("p11") == 0)
    {
        int index = 0;

        list = new StringArray(m_auditStructure.secretKeyCount +
                               m_auditStructure.publicKeyCount +
                               m_auditStructure.privateKeyCount +
                               m_auditStructure.certificateCount);

        // Secret keys.
        for (int i = 0; i < m_auditStructure.secretKeyCount; i++)
        {
            char keyname[9] = {0}; // prisekXX
            strcpy(keyname,"prisek");
            strcat(keyname, m_auditStructure.secretKeyInfo[i].id);
            list->SetStringAt(index, new std::string(keyname));
            index++;
        }

        // Public keys.
        for (int i = 0; i < m_auditStructure.publicKeyCount; i++)
        {
            char keyname[9] = {0}; // pubpukXX
            strcpy(keyname,"pubpuk");
            strcat(keyname, m_auditStructure.pubKeyInfo[i].id);
            list->SetStringAt(index, new std::string(keyname));
            index++;
        }

        // Private keys.
        for (int i = 0; i < m_auditStructure.privateKeyCount; i++)
        {
            char keyname[9] = {0}; // priprkXX
            strcpy(keyname,"priprk");
            strcat(keyname, m_auditStructure.priKeyInfo[i].id);
            list->SetStringAt(index, new std::string(keyname));
            index++;
        }

        // Certificates.
        for (int i = 0; i < m_auditStructure.fileCount; i++)
        {
            // This denotes a certificate file.
            if (m_auditStructure.fileInfo[i].usage == 0x02)
            {
                char certname[9] = {0}; // pubkscXX
                strcpy(certname, "pubksc");
                strcat(certname, m_auditStructure.fileInfo[i].id);
                list->SetStringAt(index, new string(certname));
                index++;
            }
        }
    }

    if (!list)
    {
        list = new StringArray(0);
    }

    return list;
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetFileProperties(string* path)
{
    // Not applicable.
    throw ArgumentException("");
}


// ------------------------------------------------------
// Minidriver V6/V7 Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetChallengeEx(u1 role)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::AuthenticateEx(u1 mode, u1 role, u1Array* pin)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::DeauthenticateEx(u1 roles)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::ChangeAuthenticatorEx(u1 mode, u1 oldRole, u1Array* oldPin, u1 newRole, u1Array* newPin, s4 maxTries)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetContainerProperty(u1 ctrIndex, u1 property, u1 flags)
{
    UNREFERENCED_PARAMETER (flags);

    u1Array* data = NULL;
    u1Array* tmp = NULL;

    Log::log( "CardModuleApplet::GetContainerProperty index = %d, prop=%d", ctrIndex, property);
    try
    {
        reset_buffers();
        switch (property)
        {
            case CC_CONTAINER_INFO:
                return GetCAPIContainer(ctrIndex);

            case CC_PIN_IDENTIFIER:
            case CC_PIN_IDENTIFIER_EX:
                data = new u1Array(1);
                data->GetBuffer()[0] = 0x01;
                return data;

            case CC_CONTAINER_TYPE:
                data = new u1Array(2);
		if (ctrIndex % 2 == 0)
		{
                	data->GetBuffer()[0] = 0x00;
                	data->GetBuffer()[1] = 0x00;
		}
		else {
                	data->GetBuffer()[0] = 0x01;
                	data->GetBuffer()[1] = 0x01;
		}
                return data;

            default:
                break;
        }
    }
    catch(...)
    {
        if (data != NULL)
        {
            delete data;
            data = NULL;
        }

        if (tmp != NULL)
        {
            delete tmp;
            tmp = NULL;
        }

        reset_buffers();

        throw ArgumentException("invalid_ctrIndex");
    }

    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetContainerProperty(u1 ctrIndex, u1 property, u1Array* data, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetCardProperty(u1 property, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetCardProperty(u1 property, u1Array* data, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}


// ------------------------------------------------------
// GC Control Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
s4 CardModuleApplet::GetMemory()
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::ForceGarbageCollector()
{
    // Not applicable.
}


// ------------------------------------------------------
// Specific Methods
// ------------------------------------------------------

void CardModuleApplet::RestoreContext()
{
	try
	{
		reset_buffers();
		init_context(m_channel, m_uri);
	}
	catch(...)
	{}
}

void CardModuleApplet::VerifyContext()
{
    // Not applicable.
}

void CardModuleApplet::GetRandom(u1* pRnd, u4 rndLength)
{
	u1* ptr = pRnd;
         Log::log("CardModule::GetRandom");

	try
	{
		while (rndLength > 0)
		{
			reset_buffers();

			m_dataIn = new u1Array(5);
			m_dataOut = new u1Array(0);

			m_dataIn->GetBuffer()[0] = m_channel;
			m_dataIn->GetBuffer()[1] = 0x84;
			m_dataIn->GetBuffer()[2] = 0x00;
			m_dataIn->GetBuffer()[3] = 0x00;
			m_dataIn->GetBuffer()[4] = 0x1C;

            CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

			// Result
			if ((m_SW1SW2 & 0xFF00 ) == 0x9100)
                            m_SW1SW2 = 0x9000; // Pro-active command, success.
			switch (m_SW1SW2)
			{
				case 0x9000:
					if (rndLength >= 8)
					{
						memcpy(ptr, m_dataOut->GetBuffer(), 8);
						rndLength -= 8;
						ptr += 8;
					}
					else
					{
						memcpy(ptr, m_dataOut->GetBuffer(), rndLength);
						rndLength = 0;
						ptr += rndLength;
					}
					break;

				default:
					throw RemotingException("");
			}
		}
	}
	catch(...)
	{
		reset_buffers();

		throw;
	}


}


// ------------------------------------------------------
// SKI Methods
// ------------------------------------------------------

// ------------------------------------------------------
// ------------------------------------------------------
u1 CardModuleApplet::ImportSessionKey(u1 bContainerIndex, u1Array* paddingInfo, u1 algId, u1Array* data, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::GetKeyProperty(u1 keyId, u1 property, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::SetKeyProperty(u1 keyId, u1 property, u1Array* data, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::ProcessEncData(u1 keyId, u1 dataType, u1Array* data, u1 flags)
{
    // Not applicable.
    throw ArgumentException("");
}

// ------------------------------------------------------
// ------------------------------------------------------
void CardModuleApplet::DestroySessionKey(u1 keyId)
{
    // Not applicable.
    throw ArgumentException("");
}

u1Array* CardModuleApplet::getPublicKeyFromKeyContainer(u1 keyId)
{
    u1Array* pubKey = NULL;
    try
    {
        reset_buffers();

        m_dataIn = new u1Array(8);
        m_dataOut = new u1Array(0);

        m_dataIn->GetBuffer()[0] = m_channel;
        m_dataIn->GetBuffer()[1] = 0xCD;
        m_dataIn->GetBuffer()[2] = 0x00;
        m_dataIn->GetBuffer()[3] = 0x00;
        m_dataIn->GetBuffer()[4] = 0x03;
        m_dataIn->GetBuffer()[5] = 0x85;
        m_dataIn->GetBuffer()[6] = 0x01;
        m_dataIn->GetBuffer()[7] = keyId;

        CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

    }
    catch(...)
    {
        reset_buffers();

        throw;
    }

    // Result
    switch (m_SW1SW2)
    {
         case 0x9000:
          if (m_dataOut->GetBuffer()[0] == 0x34)
             {   // Corrects tags
                 pubKey = new u1Array(m_dataOut->GetLength()-6);
                memcpy(pubKey->GetBuffer(), &m_dataOut->GetBuffer()[6] , m_dataOut->GetLength()-6);
             } else
             {
                 // No tags
                 pubKey = new u1Array(m_dataOut->GetLength());
                 memcpy(pubKey->GetBuffer(), m_dataOut->GetBuffer() , m_dataOut->GetLength());
             }
            break;
        default:
        break;
    }

    return pubKey;

}


/**
* Convert DER Coded certificate into X.509 cert and extract Pub Key in PEM format
* Reference : https://www.openssl.org/docs/man1.1.0/man3/d2i_X509.html
*/
u1Array* CardModuleApplet::convertDERtoX509(u1Array* cert_in)
{
	X509 *x;
    EC_KEY *parsedKey = NULL;

    unsigned char* buf = NULL;
 	const unsigned char *p = NULL;

     buf = (unsigned char*) malloc(sizeof(unsigned char) * cert_in->GetLength());
    if ( buf == NULL ) {
        return 0;
    }
    memcpy(buf, cert_in->GetBuffer(), cert_in->GetLength( ));
    p = buf;

	x = d2i_X509(NULL, &p, cert_in->GetLength( ));
        if (x == NULL)
        {
            Log::log("Error converting to x509");
            free(buf);
            return NULL;
        }
        else
        {
            EVP_PKEY* pkey = X509_get_pubkey(x);
            parsedKey = EVP_PKEY_get0_EC_KEY(pkey);
            unsigned char *ppubkey;
            size_t p_len = EC_KEY_key2buf(parsedKey, POINT_CONVERSION_UNCOMPRESSED,
                                            &ppubkey, NULL);
            u1Array *data =  new u1Array(p_len);
            memcpy(data->GetBuffer(), ppubkey, p_len);
            std::string stPubKey;
            Log::toString( data->GetBuffer( ), data->GetLength( ), stPubKey);
            Log::log( "PubKey <%s>", stPubKey.c_str( ) );
            if(buf!=NULL)
                free(buf);
            if(x != NULL)
                X509_free(x);
            return data;
        }



}


// ------------------------------------------------------
// ------------------------------------------------------
u1Array* CardModuleApplet::readFile(u1 EFID, u2 offset, u2 length)
{
    u1Array* desc = NULL;
    u1Array* data = NULL;
    u2 dataOffset = 0;
    u2 readLen = length;
    u2 readOffset = offset;
    u2 blockId = 0;
    u2 maxBlock = 0;
    u2 lastBlockSize = 0;
    u2 blockSize = 256;

    try
    {
        if (readLen == 0)
        {
            readLen = 512;

            for (int i = 0; i < m_auditStructure.fileCount; i++)
            {
                if (m_auditStructure.fileInfo[i].id_byte == EFID) // A certificate
                {
                    readLen = m_auditStructure.fileInfo[i].totalSize;
                    break;
                }
            }
        }

        data = new u1Array(readLen);

        memset(data->GetBuffer(), 0x00, readLen);

        maxBlock = (readLen / blockSize);
        lastBlockSize = readLen % blockSize;

        for (blockId = 0; blockId <= maxBlock; blockId++)
        {
            if (blockId == maxBlock)
            {
                if (lastBlockSize == 0)
                {
                    break;
                }

                blockSize = lastBlockSize;
            }

            reset_buffers();
            u1 high_offset = (u1) (readOffset >> 8) ;
            u1 low_offset = (u1) (readOffset) ;

            m_dataIn = new u1Array(8);
            m_dataOut = new u1Array(0);

            m_dataIn->GetBuffer()[0] = m_channel;
            m_dataIn->GetBuffer()[1] = 0xB0;
            m_dataIn->GetBuffer()[2] = high_offset;
            m_dataIn->GetBuffer()[3] = low_offset;
            m_dataIn->GetBuffer()[4] = 0x03; // Lc = 0x83 0x01 0xFID
            m_dataIn->GetBuffer()[5] = 0x83;
            m_dataIn->GetBuffer()[6] = 0x01;
            m_dataIn->GetBuffer()[7] = (BYTE) EFID;

            CardManager::getInstance ()->exchangeData (*m_dataIn, *m_dataOut, &m_SW1SW2, FALSE);

            // check response
            if (m_SW1SW2 != 0x9000)
            {
                break;
            }

            memcpy(&(data->GetBuffer()[dataOffset]), m_dataOut->GetBuffer(), m_dataOut->GetLength());

            dataOffset += 255;
            readOffset += 255;
        }
    }
    catch(...)
    {
        reset_buffers();

        throw;
    }

    // Result
    switch (m_SW1SW2)
    {
        case 0x9000:
            break;

        case 0x6982:
            throw UnauthorizedAccessException("");

        default:
            throw RemotingException("");
    }

    return data;
}


u1Array* CardModuleApplet::getCertificateDataFromContainer(u1 keyId)
{
    u1Array* data = NULL;
    u1 EFID = keyId;
    u2 EFsize = 0;

     for(int i = 0; i < m_auditStructure.fileCount; i++)
     {
        if(m_auditStructure.fileInfo[i].id_byte == keyId) // A certificate
        {
            EFsize = m_auditStructure.fileInfo[i].totalSize;
            break;
        }
    }

    data = readFile(EFID, 0, EFsize);
    data->Resize(EFsize);
    return data;
}
