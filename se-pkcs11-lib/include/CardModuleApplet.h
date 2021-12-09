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
#ifndef _include_CardModuleApplet_h
#define _include_CardModuleApplet_h

#include <string>
#include <stdexcept>
#include <list>
#include "Array.h"
#include "Except.h"
#include "EccUtils.h"
#include "digest.h"
#include "DataShare.h"
#include "x509cert.h"


#ifdef CardModuleApplet_EXPORTS
#define CardModuleApplet_API __declspec(dllexport)
#else
#define CardModuleApplet_API
#endif

using namespace std;

#define GEN_KEY_PAIR_DATA_LEN		    (3)
#define GEN_KEY_PAIR_DATA_IN		    ("\x84\x01\x04")

#define CARD_APPLET_AID                 ("\xA0\x00\x00\x00\x30\x53\xF1\x24\x01\x77\x01\x01\x49\x53\x41")
#define CARD_APPLET_AID_LEN             (15)

#define COMPUTE_DH_DATAIN_IN             ("\x84\x01\x04\x85\x01\x05")
#define COMPUTE_DH_DATAIN_IN_LEN         (6)

// Containers Properties constants
#define CC_CONTAINER_INFO               (0x00)    // Get only
#define CC_PIN_IDENTIFIER               (0x01)    // Get/Set
#define CC_ASSOCIATED_ECDH_KEY          (0x02)    // Get/Set

#define CC_CONTAINER_TYPE               (0x80)    // Get only
#define CC_TS_CONTAINER                 (0x81)    // Get/Set
#define CC_PIN_IDENTIFIER_EX            (0x91)    // Get/Set

#define C_CARD_PIN_STRENGTH_VERIFY      (0x0A)
#define C_CARD_PIN_INFO                 (0x07)
#define C_CARD_PIN_POLICY               (0x80)    // Get/Set
#define C_CARD_PIN_STRENGTH_CHANGE      (0x0B)
#define C_CARD_PIN_STRENGTH_UNBLOCK     (0x0C)
#define C_CARD_KEYSIZES                 (0x02)

#define PIN_CHANGE_UNBLOCK              (0x01)
#define PIN_CHANGE_CHANGE               (0x02)

#define FILE_DIR_EFID                   (0x0101)
#define DIR_DIR_EFID                    (0x0102)
#define FILE_RECORD_SIZE                (21)
#define DIR_RECORD_SIZE                 (9)

#define FILE_PREFIX_EFID                (0x02)
#define FILE_FIRST_EFID                 (0x05)
#define CARDID_EFID                     (0x0201)
#define CARDCF_EFID                     (0x0202)
#define CARDAPPS_EFID                   (0x0203)
#define CMAPFILE_EFID                   (0x0204)

#define KEY_RSA                         (0x00)
#define KEY_ECC                         (0x01)
#define KEY_EXCHANGE                    (0x01)
#define KEY_SIGNATURE                   (0x02)
#define KEY_NO_REP                      (0x04)
#define ECDSA_256                       (0x03)
#define ECDSA_384                       (0x04)
#define ECDSA_521                       (0x05)
#define ECDHE_256                       (0x06)
#define ECDHE_384                       (0x07)
#define ECDHE_521                       (0x08)
#define EXC_1024_PREFIX                 (0x10)
#define SIG_1024_PREFIX                 (0x20)
#define EXC_2048_PREFIX                 (0x30)
#define SIG_2048_PREFIX                 (0x40)
#define ECDHE_256_PREFIX                (0x50)
#define ECDSA_256_PREFIX                (0x60)
#define ECDHE_384_PREFIX                (0x70)
#define ECDSA_384_PREFIX                (0x80)
#define ECDHE_521_PREFIX                (0x90)
#define ECDSA_521_PREFIX                (0xA0)
#define EXC_3072_PREFIX                 (0xB0)
#define SIG_3072_PREFIX                 (0xC0)
#define EXC_4096_PREFIX                 (0xD0)
#define SIG_4096_PREFIX                 (0xE0)

#define MAX_NAME_LEN                    (50)

#define CONTAINERS_EFID                 (0x0002)
#define CONTAINER_RECORD_SIZE           (11)

class CardModuleApplet_API CardModuleApplet
{
private:
	std::string m_sDeviceName;

	u1Array*    m_dataIn;
    u1Array*    m_dataOut;
    u2          m_SW1SW2;
    BYTE        m_channel;
    u1Array*    m_uri;

    // audit structure
    struct FileInfo
    {
        char* id;
        BYTE id_byte;
        char* label;
        BYTE accessCondition;
        BYTE state;
        BYTE usage;
        BYTE size[2];
        u2 totalSize;
    };

    struct KeyInfo
    {
        BYTE id_byte;
        char* id;
        char* label;
        BYTE accessCondition;
        BYTE state;
        BYTE keyType;
        BYTE usage;
        BYTE cryptoFunc;
        BYTE signatureAlgo;
        BYTE hashAlgo[2];
        BYTE keyAgreementAlgo;
    };

    struct AuditStructure
    {
        int privateKeyCount = 0;
        int publicKeyCount = 0;
        int secretKeyCount = 0;
        int fileCount = 0;
        int certificateCount = 0;
        std::vector<KeyInfo> pubKeyInfo;
        std::vector<KeyInfo> priKeyInfo;
        std::vector<KeyInfo> secretKeyInfo;
        std::vector<FileInfo> fileInfo;
    };

    u1Array*        m_objectlist = NULL;
    AuditStructure  m_auditStructure;
    KeyInfo         m_keyInfoBuffer = {};
    FileInfo        m_fileInfoBuffer = {};

    void        clearAuditStructure();
    void        auditCard(BOOL select);
    u1Array*    getObjectList(BOOL select);
    void        parseObjectList();
    uint8_t     tlvParse(uint8_t tag, BYTE len, int start, BYTE* buffer);
    void        updateKeyBuffer(uint8_t tag, uint8_t len, BYTE* buffer);
    void        updateFileBuffer(uint8_t tag, uint8_t len, BYTE* buffer);

    void        reset_buffers();
    void        init_context(BYTE channel, u1Array* uri);
    void        setup_logical_channel();
    void        close_logical_channel(BYTE channel);
    void        close_all_logical_channel();

    u1Array*    readFile(u1 EFID, u2 offset, u2 length);
    u1Array*    getRsaPublicKey(u1 keyId);
    u1Array*    getEccPublicKey(u1 keyId);
    u1Array*    getPublicKeyFromKeyContainer(u1 keyId);

    u1Array*    getCertificateDataFromContainer(u1 keyId);

    u1Array*    PrivateKeySignCMAC(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter);
    u1Array*    PrivateKeySignECC(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter);
    u1Array*    PrivateKeySignRSA(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter);

    u1Array*    EncodePublicKeyECC(u1Array* pubkey);

    void        PutPublicKey(u1Array* keyID, u1Array* encodedPubKey);

public:

    // ------------------------------------------------------
    // Constructors
    // ------------------------------------------------------
    DWORD GetCardModel();
	bool HasMemoryBug();
	CardModuleApplet(string* readerName, string* uri);
	~CardModuleApplet();

    // ------------------------------------------------------
    // PC/SC Management Methods
    // ------------------------------------------------------
	bool GetPinPadSupported ();
	void SetPinPadSupported (bool bIsPinPad);
	bool HasSSO () const;

    // ------------------------------------------------------
    // Authentication Management Methods
    // ------------------------------------------------------
    u1 get_AdminPersonalized();
    u1 get_UserPersonalized();
    void VerifyPin(u1 role, u1Array* pin);
    void LogOut(u1 role);
    u1Array* GetChallenge();
    void ExternalAuthenticate(u1Array* response);
    void ChangeReferenceData(u1 mode, u1 role, u1Array* oldPin, u1Array* newPin, s4 maxTries);
    s4 GetTriesRemaining(u1 role);
    u1 get_MaxPinRetryCounter();
    u1 IsAuthenticated(u1 role);
    BOOL isPinInValidPeriod(u1 role);
    s8 get_AuthenticationDelay();
    void SetTriesRemaining(u1 role, u1 tryNb);
    void SetAuthenticated(u1 role);
    void SetDeauthenticated(u1 role);
    u1 GetPinId(u1 role);
    u1 GetCardPinId(u1 role);
	bool IsPinPromptAlways(u1 role);
	void getStaticRoles(std::list<u1>& roles);
	void SetPinInitialized(u1 role);
	bool IsPinSMRequiredForVerify(u1 role);
	bool IsPinSMRequiredForUnblock(u1 role);
	bool IsPinSMRequiredForChange(u1 role);

    // ------------------------------------------------------
    // Container Management Methods
    // ------------------------------------------------------
    void CreateCAPIContainer(u1 ctrIndex, u1 keyImport, u1 keySpec, s4 keySize, u1Array* keyValue, u1 role);
    void DeleteCAPIContainer(u1 ctrIndex, u1 keySpec);
    bool IsReadOnly(u1 ctrIndex);
    u1Array* GetCAPIContainer(u1 ctrIndex);
    u1Array* PrivateKeyDecrypt(u1 ctrIndex, u1 keyType, u1Array* encryptedData);
    u1Array* PrivateKeyDecryptEx(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* encryptedData);
	u1Array* PrivateKeySign(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter);
    u1Array* ConstructDHAgreement(u1 ctrIndex, u1Array* dataQx, u1Array* dataQy);

    // ------------------------------------------------------
    // Information Management Methods
    // ------------------------------------------------------
    u1Array* QueryCapabilities();
    s4Array* QueryFreeSpace();
    s4Array* QueryKeySizes();
    s4Array* QueryKeySizesEx(u1 keySpec);
    u1Array* get_SerialNumber();
    string* get_Version();
    void SetHostVersion(u4 hostVersion);
    u1 IsECC();
    u1 hasOAEP_PSS();
	void getRSAMinMax( int &minRsa, int& maxRsa, int &minRsaGen, int &maxRsaGen, u1 role );
	void getECCMinMax( int &minEcc, int& maxEcc, int &minEccGen, int &maxEccGen, u1 role );
    u1 IsLastHashRoundSupported(CDigest::HASH_TYPE hashType);
    u1 IsPlusCard();
    u1 IsSha1Disabled ();

    // ------------------------------------------------------
    // File System Management Methods
    // ------------------------------------------------------
    void CreateDirectory(string* path,u1Array* acls);
    void DeleteDirectory(string* path);
    void CreateFile(string* path, u1Array* acls, s4 initialSize);
    void DeleteFile(string* path);
    void WriteFile(string* path, u1Array* data);
    u1Array* ReadFile(string* path, s4 maxBytesToRead);
    StringArray* GetFiles(string* path);
    u1Array* GetFileProperties(string* path);

    // ------------------------------------------------------
    // Minidriver V6/V7 Methods
    // ------------------------------------------------------
    u1Array* GetChallengeEx(u1 role);
    u1Array* AuthenticateEx(u1 mode,u1 role,u1Array* pin);
    void DeauthenticateEx(u1 roles);
    void ChangeAuthenticatorEx(u1 mode, u1 oldRole, u1Array* oldPin, u1 newRole, u1Array* newPin, s4 maxTries);
    u1Array* GetContainerProperty(u1 ctrIndex, u1 property, u1 flags);
    void SetContainerProperty(u1 ctrIndex, u1 property, u1Array* data, u1 flags);
    u1Array* GetCardProperty(u1 property, u1 flags);
    void SetCardProperty(u1 property, u1Array* data, u1 flags);

    // ------------------------------------------------------
    // GC Control Methods
    // ------------------------------------------------------
    s4 GetMemory();
    void ForceGarbageCollector();

    // ------------------------------------------------------
    //
    // ------------------------------------------------------
	void RestoreContext();
	void VerifyContext();
	void GetRandom(u1* pRnd, u4 rndLength);

    // ------------------------------------------------------
    // SKI Methods
    // ------------------------------------------------------
    u1 ImportSessionKey(u1 bContainerIndex,u1Array* paddingInfo,u1 algId,u1Array* data,u1 flags);
    u1Array* GetKeyProperty(u1 keyId,u1 property,u1 flags);
    void SetKeyProperty(u1 keyId,u1 property,u1Array* data,u1 flags);
    u1Array* ProcessEncData(u1 keyId,u1 dataType,u1Array* data,u1 flags);
    void DestroySessionKey(u1 keyId);
     //---------------------------------------------

    // Util

    //---------------------------------------------

    u1Array* convertDERtoX509(u1Array* cert_in);
 };


#endif
