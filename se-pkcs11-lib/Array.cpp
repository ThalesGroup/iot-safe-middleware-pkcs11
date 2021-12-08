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
#include <Windows.h>
#pragma warning(disable:4201)
#pragma warning(disable:4995)
#endif

#include <stdexcept>
#include <string.h>
#include <algorithm>
#include "Except.h"
#include "Array.h"

// Determine Processor Endianess
#include <limits.h>
#if (UINT_MAX == 0xffffffffUL)
   typedef unsigned int _u4;
#else
#  if (ULONG_MAX == 0xffffffffUL)
     typedef unsigned long _u4;
#  else
#    if (USHRT_MAX == 0xffffffffUL)
       typedef unsigned short _u4;
#    endif
#  endif
#endif

_u4 _endian = 1;

bool isLittleEndian = (*((unsigned char *)(&_endian))) ? true  : false;
bool isBigEndian    = (*((unsigned char *)(&_endian))) ? false : true;

u4 ToBigEndian(u4 val)
{    
    if (isBigEndian)
    {
	    return val;
    }
    else
    {	    
        u4 res;
        res =  val << 24;
        res |= (val << 8) & 0x00FF0000;
        res |= (val >> 8) & 0x0000FF00;
        res |= val >> 24;
        
        return res;
    }
}

u2 ToBigEndian(u2 val)
{    
    if (isBigEndian)
    {
    	return val;
    }
    else
    {
        return (u2)((val << 8) | (val >> 8));
    }
}

u8 ToBigEndian(u8 val)
{
    if (isBigEndian)
    {
    	return val;
    }
    else
    {
	    u4 val1 = (u4)(val >> 32);        
	    u4 val2 = (u4)val;

        val1 = ToBigEndian(val1);
        val2 = ToBigEndian(val2); 
       
	    return (u8)(((u8)val2 << 32) | val1);        
    }
}

u2 ComputeUTF8Length(M_SAL_IN lpCharPtr str)
{    
    u4 nCharProcessed = 0;    
    u4 pair;   
    u4 count;
    u2 leftOver;
    u4 charIndex;
    
    count = 0;
    leftOver = 0;	
    charIndex = 0;
    
    while (nCharProcessed < (u4)strlen(str)) {
        u2 ch = (u2)str[charIndex++];

        if (leftOver == 0) {
			if ((ch >= 0xD800) && (ch <= 0xDBFF)) {
				// This is a low-part of a surrogate pair.
				leftOver = (u2)ch;
                nCharProcessed++;
				continue;
			} else {
				// This is a regular character.
				pair = (u4)ch;
			}
		} else if ((ch >= 0xDC00) && (ch <= 0xDFFF)) {
			// This is a high-part of a surrogate pair. We now have a complete surrogate pair.
			pair = ((leftOver - (u4)0xD800) << 10) + (((u4)ch) - (u4)0xDC00) + (u4)0x10000;
			leftOver = 0;
		} else {
            goto error;            
		}

        // Encode the character pair value.
		if (pair < (u4)0x0080) {            
            count++;
		} else if (pair < (u4)0x0800) {
            count += 2;
		} else if (pair < (u4)0x10000) {
            count += 3;
		} else {
            count += 4;
		}

        nCharProcessed++;
    }    

    if (leftOver != 0) {
        goto error;            
    }    
    
	return (u2)count;

error:;    
    throw new Exception("Error while compute UTF8 encoding length");        
}

void UTF8Encode(M_SAL_IN lpCharPtr str, u1Array &utf8Data)
{
    u4 nCharProcessed = 0;    
    u4 pair;       
    u2 leftOver;        
    u1* bytes = utf8Data.GetBuffer();
    u4 byteCount;
    u4 byteIndex = 0;
    u4 charIndex = 0;

    byteCount = utf8Data.GetLength();	    

    leftOver = 0;	    
    
    while (nCharProcessed < (u4)strlen(str)) {
        u2 ch = str[charIndex++];

        if (leftOver == 0) {
			if ((ch >= 0xD800) && (ch <= 0xDBFF)) {
				// This is a low-part of a surrogate pair.
				leftOver = (u2)ch;
                nCharProcessed++;
				continue;
			} else {
				// This is a regular character.
				pair = (u4)ch;
			}
		} else if ((ch >= 0xDC00) && (ch <= 0xDFFF)) {
			// This is a high-part of a surrogate pair. We now have a complete surrogate pair.
			pair = ((leftOver - (u4)0xD800) << 10) + (((u4)ch) - (u4)0xDC00) + (u4)0x10000;
			leftOver = 0;
		} else {
            goto error;            
		}

        // Encode the character pair value.
		if (pair < (u4)0x0080) {            
            if (byteIndex >= byteCount) {
                goto end;
			}              
            bytes[byteIndex++] = (u1)pair;
		} else if (pair < (u4)0x0800) {
            if ((byteIndex + 2) > byteCount) {
                goto end;                
			}                           
            bytes[byteIndex++] = (u1)(0xC0 | (pair >> 6));
			bytes[byteIndex++] = (u1)(0x80 | (pair & 0x3F));            
		} else if (pair < (u4)0x10000) {
            if ((byteIndex + 3) > byteCount) {
                goto end;				
			}                           
            bytes[byteIndex++] = (u1)(0xE0 | (pair >> 12));
			bytes[byteIndex++] = (u1)(0x80 | ((pair >> 6) & 0x3F));
			bytes[byteIndex++] = (u1)(0x80 | (pair & 0x3F));                                    
		} else {
            if ((byteIndex + 4) > byteCount) {
                goto end;				
			}                           
            bytes[byteIndex++] = (u1)(0xF0 | (pair >> 18));
			bytes[byteIndex++] = (u1)(0x80 | ((pair >> 12) & 0x3F));
			bytes[byteIndex++] = (u1)(0x80 | ((pair >> 6) & 0x3F));
			bytes[byteIndex++] = (u1)(0x80 | (pair & 0x3F));                                    
		}

        nCharProcessed++;
    }                

end:;
    // we do accept byteIndex <= byteCount (dest buffer length > what is really necessary).            
    if (byteIndex > byteCount) {
        goto error;                
    }
    
    if (leftOver != 0) {
        goto error;            
    }        	

    return;

error:;
    throw new Exception("Error while performing UTF8 encoding");    
}

u2 ComputeLPSTRLength(u1Array &array, u4 offset, u4 len)
{
	if ((u8)(offset + len) > (u8)array.GetLength()) {
		throw ArgumentOutOfRangeException("");
	} else {
		u2 charlen = 0;        
		u4 i;
		u1* buff = array.GetBuffer();

		for (i = 0; i < len;) {
			if ((buff[i + offset] & 0x80) == 0) {
				i += 1;
			}
			else if ((buff[i + offset] & 0xE0) == 0xC0) {
				i += 2;
			}
			else if ((buff[i + offset] & 0xF0) == 0xE0) {
				i += 3;
			}
			else {           
				throw Exception("Error parsing UTF-8 bytes");
			}
			charlen++;
		}	    
		return charlen;
	}
}

void UTF8Decode(u1Array &array, u4 offset, u4 len, M_SAL_INOUT lpCharPtr &charData)
{
	if ((u8)(offset + len) > (u8)array.GetLength()) {
		throw ArgumentOutOfRangeException("");
	} else {
		u4 i = 0;    
		u4 pos = 0;
		u1* buff = array.GetBuffer();
	    
		for (i = 0; i < len;) {
			if ((buff[i + offset] & 0x80) == 0) {
				charData[pos] = buff[i + offset];
				i += 1;
			}
			else if ((buff[i + offset] & 0xE0) == 0xC0) {
				charData[pos] = ((buff[i + offset] & 0x1F) << 6) | (buff[i+1 + offset] & 0x3F);
				i += 2;
			}
			else if ((buff[i + offset] & 0xF0) == 0xE0) {
				charData[pos] = ((buff[i + offset] & 0x0F) << 12) | ((buff[i+1 + offset] & 0x3F) << 6) | (buff[i+2 + offset] & 0x3F);
				i += 3;
			}   
			else{            
				throw Exception("Error parsing UTF-8 bytes");
			}
			pos++;        
		}
	}
}

std::string StringToUpper(std::string strToConvert)
{
    std::transform(strToConvert.begin(), strToConvert.end(), strToConvert.begin(), ::toupper);

    return strToConvert;
}

bool StringStartsWith (const std::string& str, const std::string& part, bool bCaseSensitive)
{
	if (bCaseSensitive)
		return str.find(part) == 0;
	else
		return StringToUpper(str).find(StringToUpper(part)) == 0;
}

bool MatchAtr (const u1* rgbAtr, const u1* atrValue, const u1* atrMask, u4 length)
{
    for (u4 i = 0; i < length; i++)
    {
        if ((rgbAtr[i] & atrMask[i]) != atrValue[i])
            return false;
    }
    return true;
}

// *******************
// String Array class
// *******************
StringArray::StringArray(s4 nelement)
{
    this->_length = nelement;

	if (nelement < 0) {
        nelement = 0;
    } 

	this->buffer = new std::string*[nelement];

	// we need to initialize the buffer to zeros
	for(s4 i=0;i<nelement;i++)
		this->buffer[i] = NULL;
	
}

StringArray::StringArray(const StringArray &rhs)
{
	s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;        
    } 
    
	this->buffer = new std::string*[len];

	for(s4 i=0;i<len;i++)
		this->buffer[i] = rhs.buffer[i];

}

StringArray::~StringArray(void)
{	
    // delete the strings in the StringArray
    for(u4 i = 0; i < GetLength(); i++){
        if (buffer[i] != NULL) {
            delete buffer[i];
            buffer[i] = NULL;
        }
    }

	delete[] buffer;
}

u1 StringArray::IsNull(void)
{
    return (this->_length < 0);        
}

u4 StringArray::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

std::string* StringArray::GetStringAt(u4 index)
{
	if (index >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}
    return this->buffer[index];
}

void StringArray::SetStringAt(u4 index, M_SAL_IN std::string* str)
{
	if (index >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}
	this->buffer[index] = str; 
}


u1Array* StringArray::GetArray ()
{
    u4 byteSize = 0;
    for(u4 i = 0; i < GetLength(); i++){
        if (buffer[i] != NULL) {
            byteSize += strlen(buffer[i]->c_str()) + 1;
        }
    }
    byteSize++;

    u1Array* ret = new u1Array (byteSize);
    u1* ptr = ret->GetBuffer();
    for(u4 i = 0; i < GetLength(); i++){
        if (buffer[i] != NULL) {
            const char* s = buffer[i]->c_str();
            size_t len = strlen(s);
            memcpy (ptr, s, len + 1);
            ptr += (len + 1);
        }
    }
    *ptr = 0;

    return ret;
}

// *******************
// Byte Array class
// *******************
u1Array::u1Array(s4 nelement, u4 maxSize)
{    
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
	 if (maxSize < (u4) nelement)
		 maxSize = (u4) nelement;
    this->buffer = new u1[maxSize];        	
	 this->_maxSize = maxSize;
    memset(this->buffer, 0, nelement * sizeof(u1));
}

u1Array::u1Array(const u1Array &rhs)
{
	s4 len = rhs._length;
	u4 maxSize = rhs._maxSize;
    this->_length = len;
    if (len < 0) {
        len = 0;        
    } 
	 if (maxSize < (u4) len)
		 maxSize = (u4) len;
    this->buffer = new u1[maxSize];      
	 this->_maxSize = maxSize;
    memcpy(this->buffer, rhs.buffer, len);
}

u1Array::u1Array(const u1Array &array, u4 offset, u4 len)
{
	if ((u8)(offset + len) > array.GetLength()) {
		throw ArgumentOutOfRangeException("");
	} else {
		this->_length = len;
		this->_maxSize = len;
		this->buffer = new u1[len];
		memcpy(this->buffer, array.buffer + offset, len);
	}
}

u1Array::u1Array(const u1* buf, u4 len)
{
	this->_length = len;
	this->_maxSize = len;
	this->buffer = new u1[len];
	memcpy(this->buffer, buf, len);

}

u1Array::~u1Array(void)
{
    if (this->buffer != NULL) {
        delete [] this->buffer;    
        this->buffer = NULL;
    }
}    

u1 u1Array::IsNull(void) const
{
    return (this->_length < 0);  
}

void u1Array::SetU1At(u4 pos, u1 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException(""); 
	}	
    this->buffer[pos] = val;
}


u1 u1Array::ReadU1At(u4 pos) const
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}	
    return this->buffer[pos];
}

u4 u1Array::GetLength(void) const
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u1Array::SetBuffer(u1* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength());
}

u1* u1Array::GetBuffer(void) const
{
    return this->buffer;
}

// 1 byte add
u1Array u1Array::operator +(u1 val)
{
    u1Array newArray(this->GetLength() + sizeof(u1), _maxSize + sizeof(u1));
    memcpy(newArray.buffer, this->buffer, this->GetLength());
    memcpy(&newArray.buffer[this->GetLength()], &val, sizeof(u1));
    return newArray;
}

u1Array& u1Array::operator +=(u1 val)
{
	 if (this->GetLength() + sizeof(u1) <= _maxSize)
	 {
		 memcpy(&this->buffer[this->GetLength()], &val, sizeof(u1));
		 this->_length = this->GetLength() + sizeof(u1);
	 }
	 else
	 {
		 u1* tempBuffer = new u1[_maxSize + sizeof(u1)];
		 memcpy(tempBuffer, this->buffer, this->GetLength());
		 memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u1));
		 delete[] this->buffer;
		 this->buffer = tempBuffer;
		 this->_length = this->GetLength() + sizeof(u1);    
		 _maxSize += sizeof(u1);
	 }
    return *this;
}

// 2 bytes add
u1Array u1Array::operator +(u2 val)
{
    val = ToBigEndian(val);
    u1Array newArray(this->GetLength() + sizeof(u2), _maxSize + sizeof(u2));        
    memcpy(newArray.buffer, this->buffer, this->GetLength());
    memcpy(&newArray.buffer[this->GetLength()], &val, sizeof(u2));
    return newArray;
}

u1Array& u1Array::operator +=(u2 val)
{
    val = ToBigEndian(val);
	 if (this->GetLength() + sizeof(u2) <= _maxSize)
	 {
		 memcpy(&this->buffer[this->GetLength()], &val, sizeof(u2));
		 this->_length = this->GetLength() + sizeof(u2);
	 }
	 else
	 {
		 u1* tempBuffer = new u1[_maxSize + sizeof(u2)];
		 memcpy(tempBuffer, this->buffer, this->GetLength());
		 memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u2));
		 delete[] this->buffer;
		 this->buffer = tempBuffer;    
		 this->_length = this->GetLength() + sizeof(u2);    
		 _maxSize += sizeof(u2);
	 }
    return *this;
}

// 4 bytes add
u1Array u1Array::operator +(u4 val)
{
    val = ToBigEndian(val);
    u1Array newArray(this->GetLength() + sizeof(u4), _maxSize + sizeof(u4));        
    memcpy(newArray.buffer, this->buffer, this->GetLength());
    memcpy(&newArray.buffer[this->GetLength()], &val, sizeof(u4));
    return newArray;
}

u1Array& u1Array::operator +=(u4 val)
{
    val = ToBigEndian(val);
	 if (this->GetLength() + sizeof(u4) <= _maxSize)
	 {
		 memcpy(&this->buffer[this->GetLength()], &val, sizeof(u4));
		 this->_length = this->GetLength() + sizeof(u4);
	 }
	 else
	 {
		 u1* tempBuffer = new u1[_maxSize + sizeof(u4)];
		 memcpy(tempBuffer, this->buffer, this->GetLength());
		 memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u4));
		 delete[] this->buffer;
		 this->buffer = tempBuffer;    
		 this->_length = this->GetLength() + sizeof(u4);
		 _maxSize += sizeof(u4);
	 }
    return *this;
}

// 8 bytes add
u1Array u1Array::operator +(u8 val)
{
	val = ToBigEndian(val);
    u1Array newArray(this->GetLength() + sizeof(u8), _maxSize + sizeof(u8));        
    memcpy(newArray.buffer, this->buffer, this->GetLength());
    memcpy(&newArray.buffer[this->GetLength()], &val, sizeof(u8));
    return newArray;
}

u1Array& u1Array::operator +=(u8 val)
{
	val = ToBigEndian(val);
	 if (this->GetLength() + sizeof(u8) <= _maxSize)
	 {
		 memcpy(&this->buffer[this->GetLength()], &val, sizeof(u8));
		 this->_length = this->GetLength() + sizeof(u8);
	 }
	 else
	 {
		 u1* tempBuffer = new u1[_maxSize + sizeof(u8)];
		 memcpy(tempBuffer, this->buffer, this->GetLength());
		 memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u8));
		 delete[] this->buffer;
		 this->buffer = tempBuffer;    
		 this->_length = this->GetLength() + sizeof(u8);
		 _maxSize += sizeof(u8);
	 }
    return *this;
}


// bytes array add        
u1Array u1Array::operator +(const u1Array &bArray) const
{   
    s4 len;
    if (IsNull() && bArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + bArray.GetLength();
    }
	 u1Array newArray(len, _maxSize + bArray._maxSize);
    memcpy(newArray.buffer, this->buffer, this->GetLength());
    memcpy(&newArray.buffer[this->GetLength()], bArray.buffer, bArray.GetLength());
    return newArray;    
}

u1Array& u1Array::operator +=(const u1Array &bArray)
{   
	 if (bArray.GetLength() > 0)
	 {
		 if (this->GetLength() + bArray._length <= _maxSize)
		 {
			 memcpy(&this->buffer[this->GetLength()], bArray.buffer, bArray._length);
			 this->_length = this->GetLength() + bArray._length;
		 }
		 else
		 {
			 u1* tempBuffer = new u1[_maxSize + bArray._maxSize];
			 memcpy(tempBuffer, this->buffer, this->GetLength());
			 memcpy(&tempBuffer[this->GetLength()], bArray.buffer, bArray.GetLength());
			 delete[] this->buffer;
			 this->buffer = tempBuffer;
			 this->_length = this->GetLength() + bArray.GetLength();
			 this->_maxSize += bArray._maxSize;
		 }
	 }
    return *this;    
}

u1Array& u1Array::Append(const u1* buf, u4 len)
{
    if (len)
    {
		  if (GetLength () + len <= _maxSize)
		  {
			  memcpy(&buffer[GetLength()], buf, len);
			  _length = GetLength () + len;
		  }
		  else
		  {
			  u1* tempBuffer = new u1[_maxSize + len];
			  memcpy(tempBuffer, this->buffer, GetLength());
			  memcpy(&tempBuffer[GetLength()], buf, len);
			  delete[] buffer;
			  buffer = tempBuffer;
			 _length = GetLength() + len;
			 _maxSize += len;
		  }
    }
    return *this;
}

u1Array& u1Array::Append(std::string* str)
{
	if (str == NULL) {
        *this += (u2)0xFFFF;
    } else {
		u2 strLen = ComputeUTF8Length((lpCharPtr)str->c_str());
        *this += strLen;
        u1Array strArray(strLen);
		UTF8Encode((lpCharPtr)str->c_str(), strArray);
        *this += strArray;
    }
    return *this;
}

bool u1Array::IsEqual(const u1Array& bArray) const
{
    return (_length == bArray._length) && (0 == memcmp(buffer, bArray.buffer, _length));
}

bool u1Array::IsEqual(const u1* buffer, u4 len) const
{
    return (_length == (s4)len) && (0 == memcmp(buffer, buffer, len));
}

void u1Array::Clear()
{
    if (buffer) memset (buffer, 0, _maxSize);
    _length = 0;      
}

void u1Array::Resize(u4 length)
{
    if ((_length > 0 && ((u4)_length) >= length) || (GetLength() == 0 && length == 0))
        _length = length;
	 else if (length <= _maxSize)
	 {
		 memset (buffer + GetLength(), 0, length - GetLength());
		 _length = length;
	 }
    else
    {
        u1* pBackup = buffer;
        buffer = new u1[length];
        memcpy(buffer, pBackup, _length);
        memset(buffer + _length, 0, length - _length);
        _length = length;
		  _maxSize = length;

        delete [] pBackup;
    }
}

// *******************
// UShort Array class
// *******************
u2Array::u2Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0; 
    }
    this->buffer = new u2[nelement];	
    memset(this->buffer, 0, nelement * sizeof(u2));
}

u2Array::u2Array(const u2Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0; 
    } 
    this->buffer = new u2[len];        
    memcpy(this->buffer, rhs.buffer, len * sizeof(u2));
}

u2Array::~u2Array(void)
{
    delete[] this->buffer;    
}    

u1 u2Array::IsNull(void)
{
    return (this->_length < 0);  
}

void u2Array::SetU2At(u4 pos, u2 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}	
    this->buffer[pos] = val;
}

u2 u2Array::ReadU2At(u4 pos)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}		
    return this->buffer[pos];
}

u4 u2Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u2Array::SetBuffer(u2* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength() * sizeof(u2));
}

u2* u2Array::GetBuffer(void)
{
    return this->buffer;
}    

// 2 bytes add
u2Array& u2Array::operator +(u2 val)
{ 
    u2Array* newArray = new u2Array(this->GetLength() + 1);        
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u2));
	newArray->buffer[this->GetLength()] = val;    
    return *newArray;
}

u2Array& u2Array::operator +=(u2 val)
{    
    u2* tempBuffer = new u2[this->GetLength() + 1];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u2));
	tempBuffer[this->GetLength()] = val;    
    delete[] this->buffer;
    this->buffer = tempBuffer;    
    this->_length = this->GetLength() + 1;
    return *this;
}

// Char array add        
u2Array& u2Array::operator +(u2Array &cArray)
{   
    s4 len;
	if (IsNull() && cArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + cArray.GetLength();
    }
    u2Array* newArray = new u2Array(len);    
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u2));
    memcpy(&newArray->buffer[this->GetLength() * sizeof(u2)], cArray.buffer, cArray.GetLength() * sizeof(u2));    
    return *newArray;
}

u2Array& u2Array::operator +=(u2Array &cArray)
{   
    u2* tempBuffer = new u2[this->GetLength() + cArray.GetLength()];        
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u2));	
    memcpy(&tempBuffer[this->GetLength() * sizeof(u2)], cArray.buffer, cArray.GetLength() * sizeof(u2));
    delete[] this->buffer;
    this->buffer = tempBuffer; 
	if (IsNull() && cArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + cArray.GetLength();
    }        
    return *this;    
}

// *******************
// Int Array class
// *******************
u4Array::u4Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    this->buffer = new u4[nelement];    
    memset(this->buffer, 0, nelement * sizeof(u4));
}

u4Array::u4Array(const u4Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;        
    } 
    this->buffer = new u4[len];        
    memcpy(this->buffer, rhs.buffer, len * sizeof(u4));    
}

u4Array::~u4Array(void)
{
    delete[] this->buffer;    
}    

u1 u4Array::IsNull(void)
{
    return (this->_length < 0);  
}

void u4Array::SetU4At(u4 pos, u4 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}	
    this->buffer[pos] = val;
}

u4 u4Array::ReadU4At(u4 pos)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}		
    return this->buffer[pos];
}

u4 u4Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u4Array::SetBuffer(u4* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength() * sizeof(u4));
}

u4* u4Array::GetBuffer(void)
{
    return this->buffer;
}    

// 4 bytes add
u4Array& u4Array::operator +(u4 val)
{
    u4Array* newArray = new u4Array(this->GetLength() + 1);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u4));
	newArray->buffer[this->GetLength()] = val;
    return *newArray;
}

u4Array& u4Array::operator +=(u4 val)
{
    u4* tempBuffer = new u4[this->GetLength() + 1];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u4));
	tempBuffer[this->GetLength()] = val;    
    delete[] this->buffer;
    this->buffer = tempBuffer;    
    this->_length = this->GetLength() + 1;
    return *this;
}

// UInt array add        
u4Array& u4Array::operator +(u4Array &iArray)
{   
    s4 len;
	if (IsNull() && iArray.IsNull()) {    
        len = -1;
    } else {
        len = this->GetLength() + iArray.GetLength();
    }
    u4Array* newArray = new u4Array(len);    
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u4));
    memcpy(&newArray->buffer[this->GetLength() * sizeof(u4)], iArray.buffer, iArray.GetLength() * sizeof(u4));    
    return *newArray;
}

u4Array& u4Array::operator +=(u4Array &iArray)
{    
    u4* tempBuffer = new u4[this->GetLength() + iArray.GetLength()];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u4));
    memcpy(&tempBuffer[this->GetLength() * sizeof(u4)], iArray.buffer, iArray.GetLength() * sizeof(u4));
    delete[] this->buffer;
    this->buffer = tempBuffer;    
	if (IsNull() && iArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + iArray.GetLength();
    }
    return *this;
}


// *******************
// Long Array class
// *******************
u8Array::u8Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    this->buffer = new u8[nelement];    
    memset(this->buffer, 0, nelement * sizeof(u8));
}

u8Array::u8Array(const u8Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;        
    } 
    this->buffer = new u8[len];        
    memcpy(this->buffer, rhs.buffer, len * sizeof(u8));    
}

u8Array::~u8Array(void)
{
    delete[] this->buffer;    
}    

u1 u8Array::IsNull(void)
{
    return (this->_length < 0);  
}

void u8Array::SetU8At(u4 pos, u8 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}	
    this->buffer[pos] = val;
}

u8 u8Array::ReadU8At(u4 pos)
{	
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException("");
	}
    return this->buffer[pos];
}

u4 u8Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u8Array::SetBuffer(u8* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength() * sizeof(u8));
}

u8* u8Array::GetBuffer(void)
{
    return this->buffer;
}    

u8Array& u8Array::operator +(u8 val)
{
    u8Array* newArray = new u8Array(this->GetLength() + 1);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u8));
	newArray->buffer[this->GetLength()] = val;	
    return *newArray;
}

u8Array& u8Array::operator +=(u8 val)
{
    u8* tempBuffer = new u8[this->GetLength() + 1];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u8));    
	tempBuffer[this->GetLength()] = val;
    delete[] this->buffer;
    this->buffer = tempBuffer;    
    this->_length = this->GetLength() + 1;
    return *this;
}

u8Array& u8Array::operator +(u8Array &iArray)
{   
    s4 len;
	if (IsNull() && iArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + iArray.GetLength();
    }
    u8Array* newArray = new u8Array(len);    
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u8));
    memcpy(&newArray->buffer[this->GetLength() * sizeof(u8)], iArray.buffer, iArray.GetLength() * sizeof(u8));    
    return *newArray;
}

u8Array& u8Array::operator +=(u8Array &iArray)
{    
    u8* tempBuffer = new u8[this->GetLength() + iArray.GetLength()];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u8));
    memcpy(&tempBuffer[this->GetLength() * sizeof(u8)], iArray.buffer, iArray.GetLength() * sizeof(u8));
    delete[] this->buffer;
    this->buffer = tempBuffer;    
	if (IsNull() && iArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + iArray.GetLength();
    }
    return *this;
}


