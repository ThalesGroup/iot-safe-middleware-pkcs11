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

#ifndef _include_marshaller_h
#define _include_marshaller_h

#ifndef WIN32
#include "wintypes.h"
#endif

MARSHALLER_NS_BEGIN

typedef void (*pCommunicationStream)(u1Array& st,u1Array& stM);

class SMARTCARDMARSHALLER_DLLAPI SmartCardMarshaller
{

private:
    u4            nameSpaceHivecode;
    u2            typeHivecode;    
    u2            portNumber;
    std::string*  uri;
    pCommunicationStream ProcessInputStream;
    pCommunicationStream ProcessOutputStream;
    BOOL          isSensitiveMode;
public:
    // PCSC compatible readers
    SmartCardMarshaller(M_SAL_IN std::string* readerName, u2 portNumber,M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode, u4 index);

    // destructor
    ~SmartCardMarshaller(void);
        
    // Remoting marshalling method
    void Invoke(s4 nParam, ...);
    void SetSensitiveMode(BOOL isSensitive);

    void SetInputStream(pCommunicationStream inStream);
    void SetOutputStream(pCommunicationStream outStream);
};

MARSHALLER_NS_END

#endif


