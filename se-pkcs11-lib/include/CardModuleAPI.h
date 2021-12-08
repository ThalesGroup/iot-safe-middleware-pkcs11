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
#ifndef _include_CardModuleAPI_h
#define _include_CardModuleAPI_h

#include <string>
#include "Array.h"
#include "CardModuleApplet.h"

#ifdef CardModuleAPI_EXPORTS
#define CardModuleAPI_API __declspec(dllexport)
#else
#define CardModuleAPI_API
#endif

using namespace std;

#define NET_STUB    1
#define JAVA_STUB   2

class CardModuleAPI_API CardModuleAPI
{
private:
	CardModuleApplet*  m_pJava;

public:

    // ------------------------------------------------------
    // Constructors
    // ------------------------------------------------------
	CardModuleAPI(string* readerName, string* uri);
	CardModuleAPI(string* readerName, u2 portNumber, string* uri, u1* pbAtr, u4 cbAtr);
    ~CardModuleAPI();
    
    // ------------------------------------------------------
    // Wrapper mode and PC/SC Management Methods
    // ------------------------------------------------------
    DWORD GetCardModel();
	bool HasMemoryBug();
	bool GetPinPadSupported ();
	void SetPinPadSupported (bool bIsPinPad);

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
    u1 IsPinExpired(u1 role);
    s8 get_AuthenticationDelay();
    void SetTriesRemaining(u1 role, u1 tryNb);
    void SetAuthenticated(u1 role);
    void SetDeauthenticated(u1 role);
    u1 GetPinId(u1 role);
    u1 GetCardPinId(u1 role);
	void getStaticRoles(std::list<u1>& roles);
	void SetPinInitialized(u1 role);
	bool IsPinSMRequiredForVerify(u1 role) { return m_pJava->IsPinSMRequiredForVerify(role); }
	bool IsPinSMRequiredForUnblock(u1 role) { return m_pJava->IsPinSMRequiredForUnblock(role); }
	bool IsPinSMRequiredForChange(u1 role) { return m_pJava->IsPinSMRequiredForChange(role); }
	bool HasSSO () const;

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
	bool SupportsDualKeyContainers ();

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
    u1 ImportSessionKey(u1 bContainerIndex,u1Array* paddingInfo,u1 algIg,u1Array* data,u1 flags);
    u1Array* GetKeyProperty(u1 keyId,u1 property,u1 flags);
    void SetKeyProperty(u1 keyId,u1 property,u1Array* data,u1 flags);
    u1Array* ProcessEncData(u1 keyId,u1 dataType,u1Array* data,u1 flags);
    void DestroySessionKey(u1 keyId);
};


#endif
