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
#ifndef __GEMALTO_OBJECT_KEY_GENERIC_SECRET__
#define __GEMALTO_OBJECT_KEY_GENERIC_SECRET__


#include "Pkcs11ObjectKeySecret.hpp"


class GenericSecretKeyObject : public SecretKeyObject {

public:

    boost::shared_ptr< u1Array > m_pValue;

	GenericSecretKeyObject( );

    GenericSecretKeyObject( const GenericSecretKeyObject* );

    virtual ~GenericSecretKeyObject( ) { }

	virtual bool isEqual( StorageObject * that) const;

	virtual bool compare( const CK_ATTRIBUTE& );

	virtual void setAttribute( const CK_ATTRIBUTE&, const bool& );

	virtual void getAttribute( CK_ATTRIBUTE_PTR );

	virtual void serialize( std::vector< u1 >* );

	virtual void deserialize( std::vector< u1 >&, CK_ULONG_PTR );

    virtual void print( void );

    virtual void NULL_drive(u1Array* DHAgreement);
    virtual void ANSI_X9_63_drive(u1Array* DHAgreement, 
        u1Array* SharedInfo);

};

#endif
