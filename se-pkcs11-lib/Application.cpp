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
#ifndef WIN32
#include <stdlib.h>
#endif
#include <memory>
#include <string>
#include <vector>

#include "Application.hpp"
#ifndef NO_FILESYSTEM
#include "Configuration.hpp"
#endif
#include "PKCS11Exception.hpp"
#include "Log.hpp"
#include "Token.hpp"
#include "Cache.h"
#include "CardManager.hpp"
#include "filesystem.h"

#ifdef WIN32
#include <shlobj.h> // For SHGetFolderPath
#endif

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

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

_u4 endian = 1;

bool IS_LITTLE_ENDIAN = (*((unsigned char *)(&endian))) ? true  : false;
bool IS_BIG_ENDIAN    = (*((unsigned char *)(&endian))) ? false : true;

// we instantiate these static variables here to be sure they are created before
// the global Application variable is called
std::string MiniDriverAuthentication::g_sPinUserLabel = "PIN";
std::string MiniDriverAuthentication::g_sPinAdminLabel = "SO PIN";
std::string MiniDriverAuthentication::g_sPin3Label = "Digital Signature PIN";
std::string MiniDriverAuthentication::g_sPin4Label = "PIN 4";
std::string MiniDriverAuthentication::g_sPin5Label = "PIN 5";
std::string MiniDriverAuthentication::g_sPin6Label = "PIN 6";
std::string MiniDriverAuthentication::g_sPin7Label = "PIN 7";

bool Application::g_bOpensslInitialized = false;
bool Application::g_bHideStaticSlots = false;
bool Application::g_DisableCertificateValidation = false;
extern bool g_bDllUnloading;

extern CK_BBOOL g_isInitialized;

/*
*/
Application::Application( ) {

	InitCache ();
    Log::start ();

#ifndef NO_FILESYSTEM

	std::string stConfigurationDirectoryPath;
#ifdef WIN32
    // For each user (roaming) data, use the CSIDL_APPDATA value.
    // This defaults to the following path: "\Documents and Settings\All Users\Application Data"
    TCHAR szPath[MAX_PATH];

    SHGetFolderPath( NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, szPath );

    stConfigurationDirectoryPath = std::string( szPath ) + std::string( "/Gemalto/PKCS11/" );
#else
	stConfigurationDirectoryPath = std::string( "/etc/IDGo800/" );
#endif

    std::string stConfigurationFilePath = stConfigurationDirectoryPath + std::string( "Gemalto.PKCS11.ini" );

	if (!isFileExist (stConfigurationFilePath)) {
		Log::s_bEnableLog = false;
		Device::s_bEnableDiskCache = false;
		Token::s_bForcePinUser = true;
    } else {
		CardManager::s_bAPDULogging = false;

        // Initialize the configuration
	    Configuration c;
	    try {

		    c.load( stConfigurationFilePath );

            const std::string stCacheSectionName( "Cache" );
            const std::string stCacheParameterEnable( "Enable" );
            const std::string stLogSectionName( "Log" );
            const std::string stLogParameterEnable( "Enable" );
            const std::string stLogParameterPath( "Path" );
			const std::string stLogParameterApdu( "Apdu" );
            const std::string stEnrollmentSectionName( "Enrollment" );
            const std::string stEnrollmentParameterForcePINUser( "ForcePinUser" );
			const std::string stAtrSectionName( "ATR" );
			const std::string stAtrParameterCount( "Count" );
            const std::string stLabelSectionName( "LABEL" );
            const std::string stLabelParameterPIN_USER( "PIN_USER" );
			const std::string stLabelParameterPIN_ADMIN( "PIN_ADMIN" );
			const std::string stLabelParameterPIN_3( "PIN_3" );
			const std::string stLabelParameterPIN_4( "PIN_4" );
			const std::string stLabelParameterPIN_5( "PIN_5" );
			const std::string stLabelParameterPIN_6( "PIN_6" );
			const std::string stLabelParameterPIN_7( "PIN_7" );
            const std::string stMiscSectionName( "Misc" );
            const std::string stMiscParameterHideStaticSlots( "HideStaticSlots" );
            const std::string stMiscParameterDisableCertificateValidation( "DisableCertificateValidation" );

		    // Read the flag in the configuration to enable/disable the log
		    std::string stResult = "";

		    c.getValue( stLogSectionName, stLogParameterEnable, stResult );

            if( 0 == stResult.compare( "1" ) ) {

			    Log::s_bEnableLog = true;

		        // Read the flag in the configuration for the log filepath
		        stResult = "";

                c.getValue( stLogSectionName, stLogParameterPath, stResult );

                if( stResult.size( ) > 0 ) {

			        Log::setLogPath( stResult );

                } else {
#ifdef WIN32
                    Log::setLogPath( stConfigurationDirectoryPath );
#else
                    Log::setLogPath( "/tmp" );
#endif
                }

		        stResult = "";
                c.getValue( stLogSectionName, stLogParameterApdu, stResult );
				if( 0 == stResult.compare( "1" ) ) {
					CardManager::s_bAPDULogging = true;
				}
		    }

		    // Read the flag in the configuration to enable/disable the cache on disk
		    stResult = "";

            c.getValue( stCacheSectionName, stCacheParameterEnable, stResult );

            if( 0 == stResult.compare( "1" ) ) {
			    Device::s_bEnableDiskCache = true;
		    } else {
			    Device::s_bEnableDiskCache = false;
		    }

        // Read the flag in the configuration to force use of PIN User during enrollment
		    stResult = "";

            c.getValue( stEnrollmentSectionName, stEnrollmentParameterForcePINUser, stResult );

            if( 0 == stResult.compare( "1" ) ) {
			    Token::s_bForcePinUser = true;
		    } else {
			    Token::s_bForcePinUser = false;
		    }

		// Read any additional ATRs that must be supported :
		    stResult = "";

            c.getValue( stAtrSectionName, stAtrParameterCount, stResult );

			int i, atrCount = strtol(stResult.c_str(), NULL, 10);

			if( atrCount > 0 && atrCount != INT_MAX ) {
				char stEntryAtrName[16];
			    for (i = 1; i <= atrCount; i++)
				{
					stResult = "";
					sprintf(stEntryAtrName,"ATR%d", i);
					c.getValue( stAtrSectionName, stEntryAtrName, stResult );

					// remove any spaces
					stResult.erase(std::remove_if(stResult.begin(), stResult.end(), ::isspace), stResult.end());

					size_t valLen = stResult.length();
					if (valLen)
					{
						if ((valLen % 4 == 1) && stResult[(valLen - 1) / 2] == '/')
						{
							// odd characters => ATR + MASK
							CardDesc desc;
							desc.m_atr.Resize((valLen - 1) / 4);
							desc.m_mask.Resize((valLen - 1) / 4);

							Util::fromStringHex(stResult.c_str(), (valLen - 1) / 2, desc.m_atr.GetBuffer());
							Util::fromStringHex(stResult.c_str() + (valLen - 1) / 2 + 1, (valLen - 1) / 2, desc.m_mask.GetBuffer());

							Device::s_vAdditionalAtrs.push_back(desc);
						}
						else if (valLen % 2 == 0)
						{
							// even characters => ATR only
							CardDesc desc;
							desc.m_atr.Resize(valLen / 2);
							desc.m_mask.Resize(valLen / 2);
							Util::fromStringHex(stResult.c_str(), valLen, desc.m_atr.GetBuffer());
							memset(desc.m_mask.GetBuffer(), 0xFF, valLen / 2);

							Device::s_vAdditionalAtrs.push_back(desc);
						}
					}
				}

		    }

		// Read any PIN Labels specified :
		    stResult = "";

            c.getValue( stLabelSectionName, stLabelParameterPIN_USER, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPinUserLabel = stResult;
			}

            c.getValue( stLabelSectionName, stLabelParameterPIN_ADMIN, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPinAdminLabel = stResult;
			}

            c.getValue( stLabelSectionName, stLabelParameterPIN_3, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPin3Label = stResult;
			}

            c.getValue( stLabelSectionName, stLabelParameterPIN_4, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPin4Label = stResult;
			}

            c.getValue( stLabelSectionName, stLabelParameterPIN_5, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPin5Label = stResult;
			}

            c.getValue( stLabelSectionName, stLabelParameterPIN_6, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPin6Label = stResult;
			}

            c.getValue( stLabelSectionName, stLabelParameterPIN_7, stResult );
			if (stResult.length())
			{
				MiniDriverAuthentication::g_sPin7Label = stResult;
			}

        // Read the flag in the configuration to hide virtual slots in static profiles
		    stResult = "";

            c.getValue( stMiscSectionName, stMiscParameterHideStaticSlots, stResult );

            if( 0 == stResult.compare( "1" ) ) {

				Application::g_bHideStaticSlots = true;

		    } else {

			    Application::g_bHideStaticSlots = false;
		    }

        // Read the flag in the configuration to disable certificate attributes validation
		    stResult = "";

            c.getValue( stMiscSectionName, stMiscParameterDisableCertificateValidation, stResult );

            if( 0 == stResult.compare( "1" ) ) {

				Application::g_DisableCertificateValidation = true;

		    } else {

			    Application::g_DisableCertificateValidation = false;
		    }

	    } catch( ... ) {

		    // Unable to find the configuration file
		    // Use default settings instead
            Log::error( "Application::Application", "No configuration file found. Use default settings" );
	    }

    }

#else		// NO_FILESTEM

	// No file system  : Default initialization
	Log::s_bEnableLog = false;
	Device::s_bEnableDiskCache = false;
	Token::s_bForcePinUser = true;

#endif 		// NO_FILESYSTEM

	Log::stop( "Application::Application" );
}


/*
*/
Application::~Application () {
	g_bDllUnloading = true;

    finalize( );
    FinalizeCache();
}


/*
*/
void Application::getSlotList( const CK_BBOOL& a_bTokenPresent, CK_SLOT_ID_PTR a_pSlotList, CK_ULONG_PTR a_pulCount ) {

	CK_ULONG ulCountSlot = 0;
	CK_ULONG ulCountSlotWithToken = 0;
	CK_SLOT_ID iIndex = 0;
    CK_RV rv = CKR_OK;

	// Build the slot list
	size_t l = g_iMaxSlot;

	initializeOpenSSL();

	for( size_t i = 0; i < l ; ++i ) {

        Slot* s = m_Slots[ i ].get( );
        if (s && s->isVirtual() && (!s->isCardPresent() || s->isTokenRemoved()))
        {
            // virtual slot but no card => remove it
            m_Slots[ i ].reset();
            s = NULL;
        }

		if( s && (s->getReaderName() != EMPTY_READER_NAME) ) {
  			if( !a_bTokenPresent ) {
  				// Found a valid slot
  				++ulCountSlot;
  				if( a_pSlotList ) {
                      if ( ulCountSlot > *a_pulCount ) {
                          rv  = CKR_BUFFER_TOO_SMALL;
                      } else {
					                a_pSlotList[ iIndex ] = i;
                          ++iIndex;
                      }
  	              }

  //            } else if( (*m_Slots)[ i ]->getToken( ).get( ) ) { //isCardPresent( ) ) {
          }
          else if ( /*s->isTokenInserted( ) ||*/ s->isCardPresent( ) ) {
      				// Found a slot within a token
      				++ulCountSlotWithToken;
      				if( a_pSlotList ) {
                     if ( ulCountSlotWithToken > *a_pulCount ) {
                          rv = CKR_BUFFER_TOO_SMALL;
                     }
                     else {
                          a_pSlotList[ iIndex ] = i;
                          ++iIndex;
                     }
  				}
			}
		}
	}

	// Return the slot count
	if( a_bTokenPresent ) {
		*a_pulCount = ulCountSlotWithToken;
    } else {
		*a_pulCount = ulCountSlot;
	}

    if ( CKR_OK != rv ) {
        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }
}


/*
*/
const boost::shared_ptr< Slot >& Application::getSlot( const CK_SLOT_ID& a_slotId ) {

    initializeOpenSSL();

    if( a_slotId >= g_iMaxSlot ) {

        throw PKCS11Exception( CKR_SLOT_ID_INVALID );
    }

    boost::shared_ptr< Slot >& s = m_Slots[a_slotId];

    if( !s.get( ) ) {

        throw PKCS11Exception( CKR_SLOT_ID_INVALID );
    }

    return s;
}


/* Initialize the slot list from the device list
*/
void Application::getDevices (void) {

	std::vector <DEVICEINFO> vDevices;

	CardManager::listAvailableDevices (vDevices);
	unsigned char ucDeviceID = 0;

	for (std::vector<DEVICEINFO>::iterator iter = vDevices.begin () ; iter != vDevices.end (); ++iter) {
		DEVICEINFO& stDeviceInfo = (DEVICEINFO&)*iter;

		Log::log( "Application::getDevices - ***** Device   : %s *****", stDeviceInfo.szDeviceName);
		boost::shared_ptr<Device> pDevice;
		pDevice.reset (new Device (stDeviceInfo, ucDeviceID));

		addSlot (pDevice, false);
		ucDeviceID ++;
	}
}


/*
*/
void Application::addSlot( const boost::shared_ptr< Device >& a_pDevice, bool bSetEvent ) {

    if( !a_pDevice ) {
		return;
    }

    Log::begin( "Application::addSlot" );

    unsigned char ucDeviceId = a_pDevice->getDeviceID( );

    CK_SLOT_ID slotID = ucDeviceId;
    m_Slots[ slotID ].reset( new Slot( a_pDevice, slotID, MiniDriverAuthentication::PIN_USER ) );
    if (bSetEvent)
    {
        m_Slots[ slotID ]->setEvent( true, (unsigned char) slotID );
    }

    addVirtualSlots(a_pDevice, slotID, bSetEvent);


    Log::end( "Application::addSlot" );
}

void Application::addVirtualSlots( const boost::shared_ptr< Device >& a_pDevice, CK_SLOT_ID slotID, bool bSetEvent ) {

    if( !a_pDevice ) {

        return;
    }

    Log::begin( "Application::addVirtualSlots" );

    if (a_pDevice->isSmartCardRecognized())
    {
        // Add slots associated with other PINs
        bool bIsStaticProfile = a_pDevice->isStaticProfile();
        bool bNoPinSlotAdded = a_pDevice->isNoPin( MiniDriverAuthentication::PIN_USER );

		if (bIsStaticProfile)
		{
			if (Application::g_bHideStaticSlots)
			{
				Log::log("Application::addVirtualSlots - HideStaticSlots set in configuration. Not displaying virtual slots for this card because it has a static profile.");
			}
			else
			{
				const std::list<MiniDriverAuthentication::ROLES>& rolesPresent = a_pDevice->getStaticRoles();
				for (std::list<MiniDriverAuthentication::ROLES>::const_iterator It = rolesPresent.begin();
						It != rolesPresent.end(); It++)
				{
					MiniDriverAuthentication::ROLES role = *It;
					if ( role != MiniDriverAuthentication::PIN_USER )
					{
						if (!a_pDevice->isNoPin(role))
						{
							slotID++;
							m_Slots[ slotID ].reset( new Slot( a_pDevice, slotID, role, true ) );
							if (bSetEvent)
							{
								m_Slots[ slotID ]->tokenInserted();
								m_Slots[ slotID ]->setEvent( true, (unsigned char) slotID );
							}
						}
						else if (!bNoPinSlotAdded)
						{
							slotID++;
							m_Slots[ slotID ].reset( new Slot( a_pDevice, slotID, MiniDriverAuthentication::PIN_NONE, true ) );
							if (bSetEvent)
							{
								m_Slots[ slotID ]->tokenInserted();
								m_Slots[ slotID ]->setEvent( true, (unsigned char) slotID );
							}
							bNoPinSlotAdded = true;
						}
					}
				}
			}
		}
		else
		{
			std::map<MiniDriverAuthentication::ROLES, bool> rolesUsed;
			unsigned char uContainerCount = a_pDevice->containerCount();
			for (unsigned char i = 0; i < uContainerCount; i++)
			{
				const MiniDriverContainer& container = a_pDevice->containerGet(i);
				if ( MiniDriverContainer::CMAPFILE_FLAG_EMPTY != container.getFlags( ) )
				{
					MiniDriverAuthentication::ROLES role = container.getPinIdentifier();
					if (    (role != MiniDriverAuthentication::PIN_USER)
						&&  (rolesUsed.find(role) == rolesUsed.end())
						)
					{
						rolesUsed[role] = true;
						if (!a_pDevice->isNoPin(role))
						{
							slotID++;
							m_Slots[ slotID ].reset( new Slot( a_pDevice, slotID, role, true ) );
							if (bSetEvent)
							{
								m_Slots[ slotID ]->tokenInserted();
								m_Slots[ slotID ]->setEvent( true, (unsigned char) slotID );
							}
						}
						else if (!bNoPinSlotAdded)
						{
							slotID++;
							m_Slots[ slotID ].reset( new Slot( a_pDevice, slotID, MiniDriverAuthentication::PIN_NONE, true ) );
							if (bSetEvent)
							{
								m_Slots[ slotID ]->tokenInserted();
								m_Slots[ slotID ]->setEvent( true, (unsigned char) slotID );
							}
							bNoPinSlotAdded = true;
						}
					}
				}
			}
        }
    }


    Log::end( "Application::addVirtualSlots" );
}


/*
*/
const boost::shared_ptr< Slot >& Application::getSlotFromSession( const CK_SESSION_HANDLE& a_hSession ) {

	initializeOpenSSL();

	for (int nI = 0 ; nI < g_iMaxSlot; ++nI) {
		boost::shared_ptr<Slot>& s = m_Slots[nI];
		if ( s.get( ) && s->isSessionOwner( a_hSession ) ) {
			return s;
		}
	}

	throw PKCS11Exception( CKR_SESSION_HANDLE_INVALID );
}

/*
*/
void Application::handleResetOnDevice(Device* d)
{
	for (int nI = 0 ; nI < g_iMaxSlot; ++nI) {
		boost::shared_ptr<Slot>& s = m_Slots[nI];
		if( s.get( ) && s->m_Device.get() == d ) {
			s->setAuthenticationLost(true);
		}
	}
}

/*
*/
void Application::handleRemovalOnDevice(Device* d)
{
	unsigned char ucSlotId = 0;

	for (int nI = 0 ; nI < g_iMaxSlot; ++nI) {
		boost::shared_ptr<Slot>& s = m_Slots[nI];
		// If the slot exists and the the names are the same
		if( s.get( ) && !s->getReaderName( ).compare( d->getReaderName() ) )
		{

			s->tokenDelete( );
			s->closeAllSessions();
			s->setEvent( true, ucSlotId );
		}

		++ucSlotId;
	}
}

#ifndef _WIN32
static void GetModuleFileName (char* szPath, size_t pathSize)
{
    char path[1024];
#ifdef __APPLE__
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0)
    {
        char* real = realpath(path, NULL);
        if (real)
        {
            strncpy(szPath, real, pathSize);
            free (real);
        }
        else
            strncpy(szPath, path, pathSize);
    }
    else
        szPath[0] = 0;
#else
    ssize_t count = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (-1 == count)
        szPath[0] = 0;
    else
    {
        path[count] = 0;
        char* real = realpath(path, NULL);
        if (real)
        {
            strncpy(szPath, real, pathSize);
            free (real);
        }
        else
            strncpy(szPath, path, pathSize);
    }
#endif
}
#endif

/*
*/
void Application::initialize( ) {

    if( Log::s_bEnableLog ) {
        Log::log( "" );
        Log::log( "" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        char szDateTimeUTC[260];
        char szProcessPath[1024] = {0};
    #ifdef _WIN32
            DWORD dwSessionID = -1;
            DWORD dwProcessID = GetCurrentProcessId();

            SYSTEMTIME stNow;

            GetModuleFileName(NULL, szProcessPath, sizeof(szProcessPath));
            ProcessIdToSessionId(dwProcessID, &dwSessionID);

            GetSystemTime(&stNow);
            sprintf(szDateTimeUTC,"%04d-%02d-%02d %02d:%02d:%02d.%d(UTC)",
                stNow.wYear,stNow.wMonth,stNow.wDay,stNow.wHour,stNow.wMinute,stNow.wSecond,stNow.wMilliseconds);

            Log::log( " [%s]", szDateTimeUTC);
            Log::log( " PKCS11 STARTS - Session ID = %d - Process ID = %d" , dwSessionID, dwProcessID);
            Log::log( " LOADED BY \"%s\"", szProcessPath);
    #else
        time_t now = time (NULL);
        struct tm tnow = *(gmtime(&now));
        sprintf(szDateTimeUTC,"%04d-%02d-%02d %02d:%02d:%02d(UTC)",
                tnow.tm_year + 1900,tnow.tm_mon + 1,tnow.tm_mday,tnow.tm_hour,tnow.tm_min,tnow.tm_sec);
        GetModuleFileName(szProcessPath, sizeof(szProcessPath));
        Log::log( " [%s]", szDateTimeUTC);
        Log::log( " PKCS11 STARTS - PID=0x%.8X, TID=%p",  getpid(), pthread_self());
        if (strlen(szProcessPath))
            Log::log( " LOADED BY \"%s\"", szProcessPath);
    #endif
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        Log::log( "" );
    }

  	// Get the known PCSC devices
	getDevices( );
}


/*
*/
void Application::finalize (void) {

    if (Log::s_bEnableLog) {
        if (g_bDllUnloading)
        {
            Log::log( "========================" );
#ifdef _WIN32
            char szDateTimeUTC[260];
            SYSTEMTIME stNow;

            GetSystemTime(&stNow);
            sprintf(szDateTimeUTC,"%04d-%02d-%02d %02d:%02d:%02d.%d(UTC)",
                stNow.wYear,stNow.wMonth,stNow.wDay,stNow.wHour,stNow.wMinute,stNow.wSecond,stNow.wMilliseconds);
            Log::log( " [%s]", szDateTimeUTC);
#endif
            Log::log( "PKCS11 Library Unloading" );
            Log::log( "========================" );
            Log::log( "" );
        }
    }

	Log::log("Application::finalize : Stopping thread");
	// Call the finalize method for all managed device
	for (int nI = 0 ; nI < g_iMaxSlot; ++nI) {
		boost::shared_ptr<Slot>& s = m_Slots[nI];
		if( s.get( ) ) {
			s->finalize (true);
		}
	}

    if( Log::s_bEnableLog ) {
        Log::log( "" );
        Log::log( "" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
#ifdef _WIN32
        char szDateTimeUTC[260];
        SYSTEMTIME stNow;

        GetSystemTime(&stNow);
        sprintf(szDateTimeUTC,"%04d-%02d-%02d %02d:%02d:%02d.%d(UTC)",
            stNow.wYear,stNow.wMonth,stNow.wDay,stNow.wHour,stNow.wMinute,stNow.wSecond,stNow.wMilliseconds);
        Log::log( " [%s]", szDateTimeUTC);
#endif
        Log::log( " PKCS11 STOPS" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
        Log::log( "" );
    }

    if (Application::g_bOpensslInitialized)
    {
        // Free OpenSSL memory
	    ERR_free_strings();
	    EVP_cleanup();
	    ENGINE_cleanup();
	    CRYPTO_cleanup_all_ex_data();

       Application::g_bOpensslInitialized = false;
    }

	g_isInitialized = FALSE;
}


void Application::initializeOpenSSL( void ) {
    // Initialize OpenSSL
    if (!g_bOpensslInitialized)
    {
	    ERR_load_crypto_strings();
	    OpenSSL_add_all_algorithms();

#ifndef _WIN32
	    RAND_poll();
#endif
        g_bOpensslInitialized = true;
    }
}
