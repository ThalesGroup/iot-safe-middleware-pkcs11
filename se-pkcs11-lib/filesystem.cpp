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
#include <sys/stat.h> 	// stat
#include <errno.h>    	// errno, ENOENT, EEXIST

#ifdef WIN32
#include <direct.h>   	// _mkdir
#endif

#include "filesystem.h"


bool isFileExist (const std::string& p_sPath)
{ 
#ifdef WIN32
	struct _stat stFileInfo;
	if (_stat (p_sPath.c_str (), &stFileInfo) != 0)
	{
		return false;
	}
#else
	struct stat stFileInfo;
	if (stat (p_sPath.c_str (), &stFileInfo) != 0)
	{
		return false;
	}
#endif
	return (stFileInfo.st_mode & S_IFDIR) == 0;
}


bool isDirectoryExist (const std::string& p_sPath)
{
#ifdef WIN32
	struct _stat stDirInfo;
	if (_stat (p_sPath.c_str (), &stDirInfo) != 0)
	{
		return false;
	}
#else
	struct stat stDirInfo;
	if (stat (p_sPath.c_str (), &stDirInfo) != 0)
	{
		return false;
	}
#endif
	return (stDirInfo.st_mode & S_IFDIR) != 0;
}


bool makePath (const std::string& p_sPath)
{
#ifdef WIN32
	int nErc = _mkdir (p_sPath.c_str ());
#else
	mode_t mode = ALLPERMS;
	int nErc = mkdir (p_sPath.c_str (), mode);
#endif
	if (nErc == 0) 
		return true;

	switch (errno)
	{
		case ENOENT:
		// The parent directory didn't exist, try to create it
		{
#ifdef WIN32
			size_t nPos = p_sPath.find_last_of ('\\');
#else
			size_t nPos = p_sPath.find_last_of ('/');
#endif
			if (nPos == std::string::npos)
				return false;

			if (!makePath (p_sPath.substr (0, nPos))) 
				return false;
		}

		// Now, try to create it again
#ifdef WIN32
		return (0 == _mkdir (p_sPath.c_str ()));
#else
		return (0 == mkdir (p_sPath.c_str (), mode));
#endif

		case EEXIST:
			// done !
			return isDirectoryExist (p_sPath);

		default:
			return false;
	}
}

