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
// Machine generated C++ stub file (.h) for remote object CardModuleService
// Created on : 06/05/2008 12:22:51


#ifndef _include_CardModuleService_h
#define _include_CardModuleService_h

#include <string>
#include "MarshallerCfg.h"
#include "Array.h"
#include "Marshaller.h"

#ifdef CardModuleService_EXPORTS
#define CardModuleService_API __declspec(dllexport)
#else
#define CardModuleService_API
#endif

using namespace std;
using namespace Marshaller;

class CardModuleService_API CardModuleService : private SmartCardMarshaller {
protected:
	bool m_bIsPinPad;
public:
    DWORD GetCardModel();
	bool HasMemoryBug() { return true; }

	// Constructors
	CardModuleService(string* uri);
	CardModuleService(string* uri, u4 index);
	CardModuleService(u2 portNumber, string* uri);
	CardModuleService(u2 portNumber, string* uri, u4 index);
	CardModuleService(string* readerName, string* uri);
	CardModuleService(string* readerName, u2 portNumber, string* uri);

	// Pre-defined methods
	string* GetReader(void);
	bool GetPinPadSupported ();
	void SetPinPadSupported (bool bIsPinPad);
    bool HasSSO () const { return true;}

	// Exposed methods
	void ChangeReferenceData(u1 mode,u1 role,u1Array* oldPin,u1Array* newPin,s4 maxTries);
	s4 GetTriesRemaining(u1 role);
	void CreateCAPIContainer(u1 ctrIndex,u1 keyImport,u1 keySpec,s4 keySize,u1Array* keyValue);
	void DeleteCAPIContainer(u1 ctrIndex);
    bool IsReadOnly(u1 ctrIndex);
	u1Array* GetCAPIContainer(u1 ctrIndex);
	u1Array* PrivateKeyDecrypt(u1 ctrIndex,u1 keyType,u1Array* encryptedData);
	void CreateFile(string* path,u1Array* acls,s4 initialSize);
	void CreateDirectory(string* path,u1Array* acls);
	void WriteFile(string* path,u1Array* data);
	u1Array* ReadFile(string* path,s4 maxBytesToRead);
	void DeleteFile(string* path);
	void DeleteDirectory(string* path);
	StringArray* GetFiles(string* path);
	u1Array* GetFileProperties(string* path);
	void ChangeAuthenticatorEx(u1 mode,u1 oldRole,u1Array* oldPin,u1 newRole,u1Array* newPin,s4 maxTries);
	u1Array* GetContainerProperty(u1 ctrIndex,u1 property,u1 flags);
	void SetContainerProperty(u1 ctrIndex,u1 property,u1Array* data,u1 flags);
	void SetCardProperty(u1 property,u1Array* data,u1 flags);
	s4 GetMemory();
	void ForceGarbageCollector();
	void RecursiveDelete(string* path);
	void Select(MemoryStream* AID);
	void Verify(u1 P1,u1 P2,u1Array* pin);
	u1 get_AdminPersonalized();
	u1 get_UserPersonalized();
	u1Array* GetChallenge();
	s8 get_AuthenticationDelay();
	void ExternalAuthenticate(u1Array* response);
	void VerifyPin(u1 role,u1Array* pin);
	u1 IsAuthenticated(u1 role);
	s4Array* QueryFreeSpace();
	s4Array* QueryKeySizes();
	void LogOut(u1 role);
    inline u1 GetPinId(u1 role) { return role; }
    inline u1 GetCardPinId(u1 role) { return role; }
	void SerializeData(string* filename);
	void DeSerializeData(string* filename);
	u1Array* get_SerialNumber();
	string* get_Version();
	void SetHostVersion(u4 hostVersion);
	u1Array* GetChallengeEx(u1 role);
	u1Array* AuthenticateEx(u1 mode,u1 role,u1Array* pin);
	void DeauthenticateEx(u1 roles);
	u1Array* GetCardProperty(u1 property,u1 flags);

	u1 ImportSessionKey(u1 bContainerIndex,u1Array* paddingInfo,u1 algIg,u1Array* data,u1 flags);
	u1Array* GetKeyProperty(u1 keyId,u1 property,u1 flags);
	void SetKeyProperty(u1 keyId,u1 property,u1Array* data,u1 flags);
	u1Array* ProcessEncData(u1 keyId,u1 dataType,u1Array* data,u1 flags);
	void DestroySessionKey(u1 keyId);

	u1Array* BM_GetBioHeader(u1 role);
	u1 BM_BioMatch(u1 role,u1Array* verificationData);
	u1Array* BM_GetRoles();
	u1 get_BM_DefaultRole();
	void set_BM_DefaultRole(u1 value);
	u1 get_BM_AuthPinAllowed();
	string* BM_GetVerifUIName();
	string* BM_GetEnrollUIName();

    // ---------------------------------------------------------
    // ---------------------------------------------------------
    // Not Supported methods !
    // ---------------------------------------------------------
    // ---------------------------------------------------------
    u1Array* PrivateKeyDecryptEx(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* encryptedData);
	u1Array* PrivateKeySign(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter);
    u1Array* ConstructDHAgreement(u1 ctrIndex, u1Array* dataQx, u1Array* dataQy);
    s4Array* QueryKeySizesEx(u1 keySpec);
    void SetTriesRemaining(u1 role, u1 tryNb);
    void SetAuthenticated(u1 role);
    void SetDeauthenticated(u1 role);
    u1 IsECC();
    u1 IsPlusCard();
    u1 IsSha1Disabled ();





};


#endif
