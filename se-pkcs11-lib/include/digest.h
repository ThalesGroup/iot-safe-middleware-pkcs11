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
#ifndef __GEMALTO_DIGEST__
#define __GEMALTO_DIGEST__

#ifdef WIN32
#include <Windows.h>
#endif

#include <string>
#include "Array.h"

class CDigest {

public:
    virtual ~CDigest() {}

    typedef enum { MD5 = 0, SHA1, SHA224, SHA256, SHA384, SHA512} HASH_TYPE;   
 
    virtual void hashUpdate( unsigned char* data, const long& offset, const long& length) = 0;
    virtual void hashFinal( unsigned char* hash) = 0;

	inline long hashLength( void ) { return _hashLength; }
    inline long hashBlock ( void ) { return _hashBlock; }
    inline HASH_TYPE hashType( void ) { return _hashType; }

    virtual void getHashContext(u1Array& intermediateHash, u1Array& hashCounter) = 0;


    static CDigest* getInstance(HASH_TYPE digestType);

protected:    
    HASH_TYPE   _hashType;    
    long      _hashLength;    
    long      _hashBlock;    

    CDigest( HASH_TYPE hashType, long hashLength, long hashBlock) : _hashType(hashType), _hashLength(hashLength), _hashBlock(hashBlock) {}
};

#endif // __GEMALTO_DIGEST__
