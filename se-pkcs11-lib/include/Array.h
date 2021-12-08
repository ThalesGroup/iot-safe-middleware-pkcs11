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

#ifndef _include_marshaller_array_h
#define _include_marshaller_array_h

#include <string>

#ifdef M_SAL_ANNOTATIONS
#include <specstrings.h>
#define M_SAL_IN		__in
#define M_SAL_OUT		__out
#define M_SAL_INOUT		__inout
#else
#define M_SAL_IN
#define M_SAL_OUT		
#define M_SAL_INOUT
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

// data types
typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;
typedef char                s1;
typedef short               s2;
typedef int                 s4;

#ifdef WIN32
typedef unsigned __int64    u8;
typedef __int64             s8;
#else
typedef unsigned long long   u8;
typedef signed   long long   s8;
#endif
typedef char*                lpCharPtr;

extern u4 ToBigEndian(u4 val);
extern u8 ToBigEndian(u8 val);

class u1Array;

class StringArray
{

private:    
	std::string** buffer;	
    s4 _length;

public:    
    StringArray(s4 nelement);
    StringArray(const StringArray &rhs);
    ~StringArray(void);

    u1 IsNull(void);
    u4 GetLength(void);

	std::string* GetStringAt(u4 index);
	void  SetStringAt(u4 index,M_SAL_IN std::string* str);

    u1Array* GetArray ();
};

#define s8Array u8Array
class u8Array
{

private:
    u8* buffer;
    s4 _length;    

public:
    u8Array(s4 nelement);
    u8Array(const u8Array &rhs);
    ~u8Array(void);

    u1 IsNull(void);
    u4 GetLength(void);
    
    void  SetBuffer(u8* buffer);
    u8*   GetBuffer(void);    	

	u8 ReadU8At(u4 pos);    
    void SetU8At(u4 pos, u8 val);

    u8Array& operator +(u8 val);
    u8Array& operator +=(u8 val);
    u8Array& operator +(u8Array &cArray);
    u8Array& operator +=(u8Array &cArray);

};

#define s4Array u4Array
class u4Array
{

private:
    u4* buffer;
    s4 _length;    

public:
    u4Array(s4 nelement);
    u4Array(const u4Array &rhs);
    ~u4Array(void);

    u1 IsNull(void);
    u4 GetLength(void);
    
    void  SetBuffer(u4* buffer);
    u4*   GetBuffer(void);
        
	u4 ReadU4At(u4 pos);
    void SetU4At(u4 pos, u4 val);

    u4Array& operator +(u4 val);
    u4Array& operator +=(u4 val);
    u4Array& operator +(u4Array &cArray);
    u4Array& operator +=(u4Array &cArray);
};

#define s2Array u2Array
#define charArray u2Array
class u2Array
{

private:
    u2* buffer;
    s4 _length;

public:
    u2Array(s4 nelement);
    u2Array(const u2Array &rhs);
    ~u2Array(void);

    u1    IsNull(void);
    u4    GetLength(void);
    
    void  SetBuffer(u2* buffer);
    u2*   GetBuffer(void);
    
	u2    ReadU2At(u4 pos);	
    void  SetU2At(u4 pos, u2 val);

    u2Array& operator +(u2 val);
    u2Array& operator +=(u2 val);
    u2Array& operator +(u2Array &cArray);
    u2Array& operator +=(u2Array &cArray);
};

#define s1Array u1Array
#define MemoryStream u1Array
class u1Array
{

private:
    u1* buffer;
    s4 _length;
	 u4 _maxSize;

public:
    u1Array(s4 nelement, u4 maxSize = 0);
    u1Array(const u1Array &rhs);
	u1Array(const u1Array &array, u4 offset, u4 len);
    u1Array(const u1* buffer, u4 len);
    ~u1Array(void);

    u1  IsNull(void) const;    
    u4  GetLength(void) const;
    
    void  SetBuffer(u1* buffer);
    u1*  GetBuffer(void) const;
    
    u1   ReadU1At(u4 pos) const;		    	
	void SetU1At(u4 pos, u1 val);

	u1Array& Append(std::string* str);	

    u1Array& Append(const u1* buffer, u4 len);	

    u1Array operator +(u1 val);
    u1Array& operator +=(u1 val);
    u1Array operator +(u2 val);
    u1Array& operator +=(u2 val);
    u1Array operator +(u4 val);
    u1Array& operator +=(u4 val);
	u1Array operator +(u8 val);
    u1Array& operator +=(u8 val);
    u1Array operator +(const u1Array &bArray) const;
    u1Array& operator +=(const u1Array &bArray);    

    bool IsEqual(const u1Array& bArray) const;
    bool IsEqual(const u1Array* bArray) const { if (!bArray) return false; return IsEqual(*bArray); }
    bool IsEqual(const u1* buffer, u4 len) const;
    void Clear(); /* set the size of the array to 0 */
    void Resize(u4 length);
};

extern u2 ComputeUTF8Length(lpCharPtr str);
extern void UTF8Encode(lpCharPtr str, u1Array &utf8Data);
extern u2 ComputeLPSTRLength(u1Array &array, u4 offset, u4 len);
extern void UTF8Decode(u1Array &array, u4 offset, u4 len, lpCharPtr &charData);
extern std::string StringToUpper(std::string strToConvert);
extern bool StringStartsWith (const std::string& str, const std::string& part, bool bCaseSensitive);
extern bool MatchAtr (const u1* rgbAtr, const u1* atrValue, const u1* atrMask, u4 length);

#endif

