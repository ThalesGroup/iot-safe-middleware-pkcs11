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
#include <windows.h>
#else
#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
#endif

#include "MiniDriverContainer.hpp"
#include "CardModuleAPI.h"
#include "Log.hpp"

#include "cardmod.h"
#include "util.h"
#include <openssl/evp.h>


using namespace std;

CardModuleAPI::CardModuleAPI(string* readerName, string* uri)
{
    m_pJava = NULL;

    try
    {
		m_pJava = new CardModuleApplet(readerName, uri);
    }
    catch(...)
    {
        throw;
    }
}

CardModuleAPI::CardModuleAPI(string* readerName, u2 portNumber, string* uri, u1* rgbAtr, u4 cbAtr)
{
	UNREFERENCED_PARAMETER (portNumber) ;
	UNREFERENCED_PARAMETER (rgbAtr) ;
	UNREFERENCED_PARAMETER (cbAtr) ;

	m_pJava = NULL;

    try
    {
		m_pJava = new CardModuleApplet(readerName, uri);
    }
    catch(...)
    {
        throw;
    }
}


CardModuleAPI::~CardModuleAPI()
{
	if (m_pJava)
    {
        delete m_pJava;
        m_pJava = NULL;
    }
}

DWORD CardModuleAPI::GetCardModel()
{
    return JAVA_STUB;
}

bool CardModuleAPI::HasMemoryBug()
{
	return m_pJava->HasMemoryBug();
}

bool CardModuleAPI::GetPinPadSupported ()
{
	return m_pJava->GetPinPadSupported();
}

void CardModuleAPI::SetPinPadSupported (bool bIsPinPad)
{
    return m_pJava->SetPinPadSupported(bIsPinPad);
}

// Exposed methods

void CardModuleAPI::ChangeReferenceData(u1 mode,u1 role,u1Array* oldPin,u1Array* newPin,s4 maxTries)
{
    m_pJava->ChangeReferenceData(mode, role, oldPin, newPin, maxTries);
}

s4 CardModuleAPI::GetTriesRemaining(u1 role)
{
   return m_pJava->GetTriesRemaining(role);
}

void CardModuleAPI::CreateCAPIContainer(u1 ctrIndex,u1 keyImport,u1 keySpec,s4 keySize,u1Array* keyValue, u1 role)
{
    m_pJava->CreateCAPIContainer(ctrIndex, keyImport, keySpec, keySize, keyValue, role);
}

void CardModuleAPI::DeleteCAPIContainer(u1 ctrIndex, u1 keySpec)
{
    m_pJava->DeleteCAPIContainer(ctrIndex, keySpec);
}

bool CardModuleAPI::IsReadOnly(u1 ctrIndex)
{
    return m_pJava->IsReadOnly(ctrIndex);
}

u1Array* CardModuleAPI::GetCAPIContainer(u1 ctrIndex)
{
    return m_pJava->GetCAPIContainer(ctrIndex);
}

u1Array* CardModuleAPI::PrivateKeyDecrypt(u1 ctrIndex,u1 keyType,u1Array* encryptedData)
{
	return m_pJava->PrivateKeyDecrypt(ctrIndex, keyType, encryptedData);
}

u1Array* CardModuleAPI::PrivateKeyDecryptEx(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* encryptedData)
{
    return m_pJava->PrivateKeyDecryptEx(ctrIndex, keyType, paddingType, algo, encryptedData);
}

u1Array* CardModuleAPI::PrivateKeySign(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter)
{
    return m_pJava->PrivateKeySign(ctrIndex, keyType, paddingType, algo, data, intermediateHash, hashCounter);
}

u1Array* CardModuleAPI::ConstructDHAgreement(u1 ctrIndex, u1Array* dataQx, u1Array* dataQy)
{
    return m_pJava->ConstructDHAgreement(ctrIndex, dataQx, dataQy);
}

bool CardModuleAPI::SupportsDualKeyContainers()
{
    return true;
}

void CardModuleAPI::CreateFile(string* path,u1Array* acls,s4 initialSize)
{
    m_pJava->CreateFile(path, acls, initialSize);
}

void CardModuleAPI::CreateDirectory(string* path,u1Array* acls)
{
    m_pJava->CreateDirectory(path, acls);
}

void CardModuleAPI::WriteFile(string* path,u1Array* data)
{
    m_pJava->WriteFile(path, data);
}

u1Array* CardModuleAPI::ReadFile(string* path,s4 maxBytesToRead)
{
    Log::begin ("CardModuleAPI::ReadFile");
	Log::log ("CardModuleAPI::ReadFile - Read file using CardModuleApplet service ...");
	return m_pJava->ReadFile(path, maxBytesToRead);
    Log::end ("CardModuleAPI::ReadFile");
}

void CardModuleAPI::DeleteFile(string* path)
{
    m_pJava->DeleteFile(path);
}

void CardModuleAPI::DeleteDirectory(string* path)
{
    m_pJava->DeleteDirectory(path);
}

StringArray* CardModuleAPI::GetFiles(string* path)
{
    return m_pJava->GetFiles(path);
}

u1Array* CardModuleAPI::GetFileProperties(string* path)
{
    return m_pJava->GetFileProperties(path);
}

void CardModuleAPI::ChangeAuthenticatorEx(u1 mode,u1 oldRole,u1Array* oldPin,u1 newRole,u1Array* newPin,s4 maxTries)
{
    m_pJava->ChangeAuthenticatorEx(mode, oldRole, oldPin, newRole, newPin, maxTries);
}

u1Array* CardModuleAPI::GetContainerProperty(u1 ctrIndex,u1 property,u1 flags)
{
    return m_pJava->GetContainerProperty(ctrIndex, property, flags);
}

void CardModuleAPI::SetContainerProperty(u1 ctrIndex,u1 property,u1Array* data,u1 flags)
{
    m_pJava->SetContainerProperty(ctrIndex, property, data, flags);
}

void CardModuleAPI::SetCardProperty(u1 property,u1Array* data,u1 flags)
{
    m_pJava->SetCardProperty(property, data, flags);
}

s4 CardModuleAPI::GetMemory()
{
    return m_pJava->GetMemory();
}

void CardModuleAPI::ForceGarbageCollector()
{
    m_pJava->ForceGarbageCollector();
}

void CardModuleAPI::RestoreContext()
{
    m_pJava->RestoreContext();
}

void CardModuleAPI::VerifyContext()
{
    m_pJava->VerifyContext();
}

void CardModuleAPI::GetRandom(u1* pRnd, u4 rndLength)
{
    m_pJava->GetRandom(pRnd, rndLength);
}

u1 CardModuleAPI::get_AdminPersonalized()
{
    return m_pJava->get_AdminPersonalized();
}

u1 CardModuleAPI::get_UserPersonalized()
{
    return m_pJava->get_UserPersonalized();
}

u1Array* CardModuleAPI::GetChallenge()
{
    return m_pJava->GetChallenge();
}

s8 CardModuleAPI::get_AuthenticationDelay()
{
    return m_pJava->get_AuthenticationDelay();
}

void CardModuleAPI::ExternalAuthenticate(u1Array* response)
{
    m_pJava->ExternalAuthenticate(response);
}

void CardModuleAPI::VerifyPin(u1 role,u1Array* pin)
{
    m_pJava->VerifyPin(role, pin);
}

u1 CardModuleAPI::IsAuthenticated(u1 role)
{
    return m_pJava->IsAuthenticated(role);
}

u1 CardModuleAPI::IsPinExpired(u1 role)
{
    return m_pJava->isPinInValidPeriod(role)? 0 : 1;
}

void CardModuleAPI::SetTriesRemaining(u1 role, u1 tryNb)
{
    return m_pJava->SetTriesRemaining(role, tryNb);
}

void CardModuleAPI::SetAuthenticated(u1 role)
{
    return m_pJava->SetAuthenticated(role);
}

void CardModuleAPI::SetDeauthenticated(u1 role)
{
    return m_pJava->SetDeauthenticated(role);
}

u1 CardModuleAPI::GetPinId(u1 role)
{
    return m_pJava->GetPinId(role);
}

u1 CardModuleAPI::GetCardPinId(u1 role)
{
    return m_pJava->GetCardPinId(role);
}

void CardModuleAPI::getStaticRoles(std::list<u1>& roles)
{
    return m_pJava->getStaticRoles(roles);
}

void CardModuleAPI::SetPinInitialized(u1 role)
{
    return m_pJava->SetPinInitialized(role);
}

bool CardModuleAPI::HasSSO () const
{
    return m_pJava->HasSSO();
}

s4Array* CardModuleAPI::QueryFreeSpace()
{
    return m_pJava->QueryFreeSpace();
}

s4Array* CardModuleAPI::QueryKeySizes()
{
    return m_pJava->QueryKeySizes();
}

s4Array* CardModuleAPI::QueryKeySizesEx(u1 keySpec)
{
    return m_pJava->QueryKeySizesEx(keySpec);
}

void CardModuleAPI::LogOut(u1 role)
{
    m_pJava->LogOut(role);
}

u1Array* CardModuleAPI::get_SerialNumber()
{
    return m_pJava->get_SerialNumber();
}

string* CardModuleAPI::get_Version()
{
    return m_pJava->get_Version();
}

void CardModuleAPI::SetHostVersion(u4 hostVersion)
{
    m_pJava->SetHostVersion(hostVersion);
}

u1Array* CardModuleAPI::GetChallengeEx(u1 role)
{
    return m_pJava->GetChallengeEx(role);
}

u1Array* CardModuleAPI::AuthenticateEx(u1 mode,u1 role,u1Array* pin)
{
    return m_pJava->AuthenticateEx(mode, role, pin);
}

void CardModuleAPI::DeauthenticateEx(u1 roles)
{
    m_pJava->DeauthenticateEx(roles);
}

u1Array* CardModuleAPI::GetCardProperty(u1 property,u1 flags)
{
    return m_pJava->GetCardProperty(property, flags);
}


u1 CardModuleAPI::IsECC()
{
    return m_pJava->IsECC();
}

u1 CardModuleAPI::IsSha1Disabled()
{
    return m_pJava->IsSha1Disabled();
}

u1 CardModuleAPI::hasOAEP_PSS()
{
    return m_pJava->hasOAEP_PSS();
}

void CardModuleAPI::getRSAMinMax( int &minRsa, int& maxRsa, int &minRsaGen, int &maxRsaGen, u1 role )
{
    return m_pJava->getRSAMinMax(minRsa, maxRsa, minRsaGen, maxRsaGen, role);
}

void CardModuleAPI::getECCMinMax( int &minEcc, int& maxEcc, int &minEccGen, int &maxEccGen, u1 role )
{
    return m_pJava->getECCMinMax(minEcc, maxEcc, minEccGen, maxEccGen, role);
}

u1 CardModuleAPI::IsLastHashRoundSupported(CDigest::HASH_TYPE hashType)
{
    return m_pJava->IsLastHashRoundSupported(hashType);
}

u1 CardModuleAPI::IsPlusCard()
{
    return m_pJava->IsPlusCard();
}

u1 CardModuleAPI::ImportSessionKey(u1 bContainerIndex,u1Array* paddingInfo,u1 algIg,u1Array* data,u1 flags)
{
    return m_pJava->ImportSessionKey(bContainerIndex, paddingInfo, algIg, data, flags);
}

u1Array* CardModuleAPI::GetKeyProperty(u1 keyId,u1 property,u1 flags)
{
    return m_pJava->GetKeyProperty(keyId, property, flags);
}

void CardModuleAPI::SetKeyProperty(u1 keyId,u1 property,u1Array* data,u1 flags)
{
    return m_pJava->SetKeyProperty(keyId, property, data, flags);
}

u1Array* CardModuleAPI::ProcessEncData(u1 keyId,u1 dataType,u1Array* data,u1 flags)
{
    return m_pJava->ProcessEncData(keyId, dataType, data, flags);
}

void CardModuleAPI::DestroySessionKey(u1 keyId)
{
    return m_pJava->DestroySessionKey(keyId);
}
