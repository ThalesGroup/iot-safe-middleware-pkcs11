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
#ifndef __GEMALTO_CARD_CACHE__
#define __GEMALTO_CARD_CACHE__

#include <boost/ptr_container/serialize_ptr_map.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#ifndef NO_FILESYSTEM
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/archive/archive_exception.hpp>
#endif
#include <map>
#include <string>
#include <set>
#include "MiniDriverModuleService.hpp"
#include "MiniDriverCardCacheFile.hpp"
#include "MiniDriverContainerMapFile.hpp"
#include "MiniDriverAuthentication.hpp"
#include "Except.h"
#include "util.h"


/*
*/
class MiniDriverFiles
{

public:

	typedef std::set<std::string> FILES_NAME;
	typedef boost::ptr_map<std::string, u1ArraySerializable> FILES_BINARY;
	typedef boost::ptr_map<std::string, FILES_NAME> DIRECTORIES;
	typedef enum {CARD_PERMISSION_READ = 0x04, CARD_PERMISSION_WRITE = 0x02, CARD_PERMISSION_EXECUTE = 0x01 } PERMISSIONS;

	MiniDriverFiles(const MiniDriverAuthentication& authentication);

	inline MiniDriverModuleService* getCardModuleService(void) { return m_CardModule; }
	inline void setCardModuleService(MiniDriverModuleService *a_pCardModule) { m_CardModule = a_pCardModule; m_CardCacheFile.setCardModuleService(m_CardModule); }
	inline const MiniDriverAuthentication& getAuthentication() const { return m_Authentication;}

	// Files operations
	void certificateDelete(unsigned char&, unsigned char&);
	void writeFile(const std::string&, const std::string&, u1Array *, const bool& a_bAddToCache = true, const bool& a_bUpdateContainerCounter = false);
	void deleteFile(const std::string&, const std::string&);
	void createFile(const std::string&, const std::string&, u1Array *);
	u1Array* readFile(const std::string&, const std::string&);
	u1Array* readFileWithoutCheck(const std::string&, const std::string&);
	void clearFile(std::string const&);

	FILES_NAME& enumFiles(const std::string&);

	void createDirectory(const std::string&, const std::string&);
	void deleteFileStructure(void);
	void renameFile(const std::string& a_stOldFileDirectory, const std::string& a_stOldFileName, const std::string& a_stNewFileDirectory, const std::string& a_stNewFileName);

	// Container operations
	inline MiniDriverContainer& containerGet(const unsigned char& a_ucContainerIndex) { return m_ContainerMapFile.containerGet(a_ucContainerIndex); }
	inline const MiniDriverContainer* containerGet(void) { return m_ContainerMapFile.containerGet(); }
	inline void containerSearch(MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex) { m_ContainerMapFile.containerSearch(role, a_ucContainerIndex); }
	inline void containerCreate(MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, u1Array *a_pPublicKeyModulus, const int& a_KeySize, u1Array *a_pKeyValue) { m_ContainerMapFile.containerCreate(role, a_ucContainerIndex, a_bKeyImport, a_ucKeySpec, a_pPublicKeyModulus, a_KeySize, a_pKeyValue); }
	void containerDelete(const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec) { m_ContainerMapFile.containerDelete(a_ucContainerIndex, a_ucKeySpec); }
	bool containerReadOnly(const unsigned char& a_ucContainerIndex);
	const MiniDriverContainer& containerRead(const int&);
	inline void containerSetDefault(const unsigned char& a_ucContainerIndex, const bool& a_bIsSmartCardLogon) { m_ContainerMapFile.containerSetDefault(a_ucContainerIndex, a_bIsSmartCardLogon); }
	inline unsigned char containerCount(void) { return m_ContainerMapFile.containerCount(); }
	bool containerGetMatching(MiniDriverAuthentication::ROLES role, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stFileName, const u1Array *a_pPublicKeyModulus);
	inline bool containerIsImportedExchangeKey(const unsigned char& a_ucContainerIndex) { return m_ContainerMapFile.containerIsImportedExchangeKey(a_ucContainerIndex); }
	inline bool containerIsImportedSignatureKey(const unsigned char& a_ucContainerIndex) { return m_ContainerMapFile.containerIsImportedSignatureKey(a_ucContainerIndex); }
	inline unsigned char containerGetFree(void) { return m_ContainerMapFile.containerGetFree(); }
	unsigned char containerGetFreeRoot(void);
	inline void containerUpdatePinInfo(void) { m_ContainerMapFile.containerUpdatePinInfo();}

	// Cache operations
	void clear(const MiniDriverCardCacheFile::ChangeType&);
	inline void clearCardCacheFile() { m_CardCacheFile.clear(); }
	void serialize(void);
	void deserialize(void);

	//inline void hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files ) { m_CardCacheFile.hasChanged( a_Pins, a_Containers, a_Files ); }
	void hasChanged(MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files);
	inline void notifyChange(const MiniDriverCardCacheFile::ChangeType& a_change) { m_CardCacheFile.notifyChange(a_change); }
	inline void cacheDisable(const std::string& a_stFileName) { m_FilesToNotCache.insert(m_FilesToNotCache.begin(), a_stFileName); }
	void cacheDisableWrite(void);

	// void print(void);

	void setStaticProfile(bool bIsStaticProfile) { m_bIsStaticProfile = bIsStaticProfile;}
	inline bool isStaticProfile(void) { return m_bIsStaticProfile;}

	inline bool Validate()
	{
		if (!m_ContainerMapFile.Validate()) return false;
		return true;
	}

private:

	std::string s_stPathSeparator;
	std::string s_stPathMscp;
	std::string m_stPathCertificateRoot;

	const MiniDriverAuthentication& m_Authentication;

	// Service to access the oncard MiniDriver
	MiniDriverModuleService *m_CardModule;

	// Reflect the state of the Container Map File (CMapFile)
	MiniDriverContainerMapFile m_ContainerMapFile;

	bool m_bIsStaticProfile;

	// Reflect the binary content of the files in the smart card
	FILES_BINARY m_BinaryFiles;

	// Reflect the list of files contained by a directory into the smart card
	DIRECTORIES m_Directories;

	// Reflects state of card cache file (CardCF)
	MiniDriverCardCacheFile m_CardCacheFile;

	unsigned long checkException(Exception& x);
	std::vector<std::string> m_FilesToNotCache;
	unsigned char computeIndex(const std::string&);

	///////////////////////////
	// Disk cache management //
	//////////////////////////

#ifndef NO_FILESYSTEM

	// On computer disk serialization and deserialization
	friend class boost::serialization::access;

	template<class Archive> void serialize(Archive& ar, const unsigned int version)
	{
		//Log::begin( "MiniDriverFiles::serialize" );

		if (version < 128) throw boost::archive::archive_exception(boost::archive::archive_exception::unsupported_class_version);

		ar & m_ContainerMapFile;
		ar & m_BinaryFiles;
		ar & m_Directories;
		ar & m_CardCacheFile;
		ar & m_FilesToNotCache;

		//Log::end( "MiniDriverFiles::serialize" );
	}

#endif
};

#ifndef NO_FILESYSTEM
BOOST_CLASS_VERSION(MiniDriverFiles, 128)
#endif

#endif // __GEMALTO_CARD_CACHE__

