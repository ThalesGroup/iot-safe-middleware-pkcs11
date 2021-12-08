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
#ifndef __GEMALTO_PCSC_MISSING__
#define __GEMALTO_PCSC_MISSING__


#ifndef SCARD_S_SUCCESS
#define SCARD_S_SUCCESS ((LONG)0L)
#endif

#ifndef SCARD_E_NO_SUCH_CERTIFICATE
#define SCARD_E_NO_SUCH_CERTIFICATE ((LONG)0x8010002C)
#endif

#ifndef SCARD_E_FILE_NOT_FOUND
#define SCARD_E_FILE_NOT_FOUND ((LONG)0x80100024)
#endif

#ifndef SCARD_E_COMM_DATA_LOST
#define SCARD_E_COMM_DATA_LOST ((LONG)0x8010002F)
#endif

#ifndef SCARD_W_CHV_BLOCKED
#define SCARD_W_CHV_BLOCKED ((LONG)0x8010006C)
#endif

// An internal consistency check failed.
//
#ifndef SCARD_F_INTERNAL_ERROR
#define SCARD_F_INTERNAL_ERROR ((LONG)0x80100001L)
#endif

// The action was cancelled by an SCardCancel request.
//
#ifndef SCARD_E_CANCELLED
#define SCARD_E_CANCELLED ((LONG)0x80100002L)
#endif

// One or more of the supplied parameters could not be properly interpreted.
//
#ifndef SCARD_E_INVALID_PARAMETER
#define SCARD_E_INVALID_PARAMETER ((LONG)0x80100004L)
#endif

// Not enough memory available to complete this command.
//
#ifndef SCARD_E_NO_MEMORY
#define SCARD_E_NO_MEMORY  ((LONG)0x80100006L)
#endif

// The operation requires a smart card, but no smart card is currently in the device.
//
#ifndef SCARD_E_NO_SMARTCARD
#define SCARD_E_NO_SMARTCARD ((LONG)0x8010000CL)
#endif

// The specified smart card name is not recognized.
//
#ifndef SCARD_E_UNKNOWN_CARD
#define SCARD_E_UNKNOWN_CARD ((LONG)0x8010000DL)
#endif

// One or more of the supplied parameters values could not be properly interpreted.
//
#ifndef SCARD_E_INVALID_VALUE
#define SCARD_E_INVALID_VALUE ((LONG)0x80100011L)
#endif

// An internal error has been detected, but the source is unknown.
//
#ifndef SCARD_F_UNKNOWN_ERROR
#define SCARD_F_UNKNOWN_ERROR ((LONG)0x80100014L)
#endif

// The smart card does not meet minimal requirements for support.
//
#ifndef SCARD_E_CARD_UNSUPPORTED
#define SCARD_E_CARD_UNSUPPORTED ((LONG)0x8010001CL)
#endif

#ifndef SCARD_E_UNEXPECTED
#define SCARD_E_UNEXPECTED ((LONG)0x8010001F)
#endif

// This smart card does not support the requested feature.
//
#ifndef SCARD_E_UNSUPPORTED_FEATURE
#define SCARD_E_UNSUPPORTED_FEATURE ((LONG)0x80100022L)
#endif

#ifndef SCARD_E_WRITE_TOO_MANY
#define SCARD_E_WRITE_TOO_MANY ((LONG)0x80100028)
#endif

// The smart card has been removed, so that further communication is not possible.
//
#ifndef SCARD_W_REMOVED_CARD
#define SCARD_W_REMOVED_CARD ((LONG)0x80100069L)
#endif

#ifndef SCARD_W_CANCELLED_BY_USER
#define SCARD_W_CANCELLED_BY_USER ((LONG)0x8010006E)
#endif

#ifndef SCARD_W_WRONG_CHV
#define SCARD_W_WRONG_CHV ((LONG)0x8010006B)
#endif

#ifndef SCARD_W_CARD_NOT_AUTHENTICATED
#define SCARD_W_CARD_NOT_AUTHENTICATED  ((LONG)0x8010006F)
#endif

#ifndef SCARD_E_DIR_NOT_FOUND
#define SCARD_E_DIR_NOT_FOUND ((LONG)0x80100023)
#endif

// The identified file does not exist in the smart card.
//
#ifndef SCARD_E_FILE_NOT_FOUND
#define SCARD_E_FILE_NOT_FOUND ((LONG)0x80100024L)
#endif

#ifndef SCARD_E_INVALID_CHV
#define SCARD_E_INVALID_CHV ((LONG)0x8010002A)
#endif

#ifndef SCARD_E_CERTIFICATE_UNAVAILABLE
#define SCARD_E_CERTIFICATE_UNAVAILABLE ((LONG)0x8010002D)
#endif

#ifndef SCARD_E_NO_ACCESS
#define SCARD_E_NO_ACCESS ((LONG)0x80100027)
#endif

// The user-specified timeout value has expired.
//
#ifndef SCARD_E_TIMEOUT
#define SCARD_E_TIMEOUT ((LONG)0x8010000AL)
#endif

#endif //__GEMALTO_PCSC_MISSING__

