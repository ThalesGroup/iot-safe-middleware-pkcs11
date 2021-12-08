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
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <Windows.h>
#endif

#include "PCSCMissing.h"

#include "MiniDriverModuleService.hpp"
#include "Log.hpp"
#include <openssl/evp.h>

const char* ERROR_MEMORY = "Persistent";
const unsigned char CARD_PROPERTY_AUTHENTICATED_ROLES = 0x09;
const unsigned int LOW_FREE_MEMORY_ALLOWED = 30000;
#define TIMER_DURATION 2.0

MiniDriverModuleService::MiniDriverModuleService(CardModuleAPI* pCardModService) : m_pCardMod(pCardModService), m_ucSmartCardType(SMART_CARD_TYPE_V2PLUS), m_bMultiPinSupported(true), m_bEnableGC(true)
{
}

MiniDriverModuleService::~MiniDriverModuleService()
{
   if (m_pCardMod) { delete m_pCardMod; m_pCardMod = NULL;}

   for (PROPERTIES::iterator i = m_Properties.begin(); i != m_Properties.end(); i++)
   {
      delete i->second;
   }
   m_Properties.clear();
}

void MiniDriverModuleService::CheckSmartCardType(void)
{
   if (m_pCardMod)
   {
      try {

         std::unique_ptr< u1Array > s( m_pCardMod->GetCardProperty( CARD_VERSION_INFO, 0 ) );

         if( s.get( )  ) { 

            Log::log( "CardModuleService::getVersion - %d.%d.%d.%d", s->ReadU1At( 0 ), s->ReadU1At( 1 ), s->ReadU1At( 2 ), s->ReadU1At( 3 ) );

            if( s->ReadU1At( 0 ) != 0x07) {

               m_ucSmartCardType = SMART_CARD_TYPE_V2; 
			   if (s->ReadU1At( 0 ) < 6)
				  m_bEnableGC = false;
            }
         }
         else if (Log::s_bEnableLog)
             Log::log("m_pCardMod->GetCardProperty( CARD_VERSION_INFO) retuned NULL");

      } catch( ArgumentException& ) {
		  // .NET card case with V6 assembly
		  if (Log::s_bEnableLog) Log::log("m_pCardMod->GetCardProperty(CARD_VERSION_INFO) throw ArgumentException");
         m_ucSmartCardType = SMART_CARD_TYPE_V2;
		 m_bMultiPinSupported = true;
		 m_bEnableGC = true;
      }
      catch( Exception& ex ) {
		  // .NET card case with V5 assembly
		  unsigned long errorCode = SCARD_E_UNEXPECTED;
		  try { 
			  checkException(ex); 
		  } 
		  catch(MiniDriverException& miniEx)
		  {
			errorCode = miniEx.getError();
		  }
		  if (Log::s_bEnableLog) Log::log("m_pCardMod->GetCardProperty(CARD_VERSION_INFO) throw Exception associated with code 0x%.8X", errorCode);
         m_ucSmartCardType = SMART_CARD_TYPE_V2;
		 m_bMultiPinSupported = false;
		 m_bEnableGC = false;
      }
      catch( ... ) { 
		  // .NET card case with V5 assembly
         if (Log::s_bEnableLog) Log::log("m_pCardMod->GetCardProperty(CARD_VERSION_INFO) throw an unknown exception");
         m_ucSmartCardType = SMART_CARD_TYPE_V2;
		 m_bMultiPinSupported = false;
		 m_bEnableGC = false;
      }
   }
}

void MiniDriverModuleService::ForceGarbageCollector()
{
    if( !m_bEnableGC ) { 

        return; 
    } 

    try { 

       m_pCardMod->ForceGarbageCollector(); 

    } catch( ... ) {}
    m_Timer.start( ); 
}

void MiniDriverModuleService::manageGarbageCollector( void )
{
    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        if( m_Timer.getCurrentDuration( ) < TIMER_DURATION ) {

            return;
        }

        try {
            unsigned int uRemainingMemory = GetMemory( );

            //Log::log( "CardModuleService::manageGarbageCollector - memory <%ld>", i );

            if( uRemainingMemory < LOW_FREE_MEMORY_ALLOWED ) {

                ForceGarbageCollector( );
            }

        } catch( ... ) {

        }

        m_Timer.start( );

    }
}

/*
*/
unsigned int MiniDriverModuleService::GetMemory( ) { 

    u4 uiRemainingMemory = 0;

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        try {

            // Try the "getMemory" command
           uiRemainingMemory = m_pCardMod->GetMemory();

        } catch( Exception& ) {

            //m_ucSmartCardType = SMART_CARD_TYPE_V2;

            // Try the "getFreeSpace" command
            try { 

               u4Array* a = m_pCardMod->QueryFreeSpace();

                if( a && ( a->GetLength( ) > 2 ) ) {

                    uiRemainingMemory = a->ReadU4At( 2 );
                }

                if (a) delete a;

            } catch( Exception& x ) { 

                checkException( x ); 
            }
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        try { 

            u4Array* a = m_pCardMod->QueryFreeSpace();

            if( a && ( a->GetLength( ) > 2 ) ) {

                uiRemainingMemory = a->ReadU4At( 2 );
            }
            if (a) delete a;

        } catch( Exception& x ) { 

            checkException( x ); 
        }
    }

    return uiRemainingMemory; 
}

LONG MiniDriverModuleService::AnalyseExceptionString(Exception& ex)
{
    LONG resultCode = SCARD_F_UNKNOWN_ERROR;
    
    if (ex.what() != NULL) 
    {
        if (strcmp(ex.what(), ERROR_MEMORY) == 0)
        {
            ForceGarbageCollector( );
            
            return (SCARD_E_NO_MEMORY);
        }
        
        // card has directly returned a windows error code.
        resultCode = (long) strtoul(ex.what(), NULL, 0);
    
        if (resultCode == 0) 
        {
            // translation failed
            resultCode = SCARD_F_UNKNOWN_ERROR;
        }
    }
    
    return resultCode;
}

/* checkException
*/
void MiniDriverModuleService::checkException( Exception &x ) {

    if( x.what( ) ) {

        if( 0 == strcmp( x.what( ), ERROR_MEMORY ) ) {

            Log::error( "CardModuleService::checkException", "Memory Error" );

            ForceGarbageCollector( );

            // Not enough memory available to complete this command.
            throw MiniDriverException( SCARD_E_NO_MEMORY );
        }
    }

    if( dynamic_cast< UnauthorizedAccessException* >( &x ) ) {

        Log::error( "CardModuleService::checkException", " UnauthorizedAccessException" );

        // No PIN was presented to the smart card.
        throw MiniDriverException( SCARD_W_CARD_NOT_AUTHENTICATED );
    }

    if( dynamic_cast< OutOfMemoryException* >( &x ) ) {

        Log::error( "CardModuleService::checkException", " OutOfMemoryException" );

        // Not enough memory available to complete this command.
        throw MiniDriverException( SCARD_E_NO_MEMORY );
    }

    if( dynamic_cast< DirectoryNotFoundException* >( &x ) ) {

        Log::error( "CardModuleService::checkException", " DirectoryNotFoundException" );

        // The identified directory does not exist in the smart card.
        throw MiniDriverException( SCARD_E_DIR_NOT_FOUND );
    }

    if( dynamic_cast< FileNotFoundException * >( &x ) ) {

        Log::error( "CardModuleService::checkException", " FileNotFoundException" );

        // The identified file does not exist in the smart card.
        throw MiniDriverException( SCARD_E_FILE_NOT_FOUND );
    }

    if( dynamic_cast< IOException * >( &x ) ) {

        Log::error( "CardModuleService::checkException", " IOException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_WRITE_TOO_MANY );
    }

    if( dynamic_cast< TypeLoadException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " TypeLoadException" );

        //m_ucSmartCardType = SMART_CARD_TYPE_V2;

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
    }

    if( dynamic_cast< VerificationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " VerificationException" );

        // The supplied PIN is incorrect.
        throw MiniDriverException( SCARD_E_INVALID_CHV );
    }

    if( dynamic_cast< RemotingException * >( &x ) ) {

        // Can occur after when the computer wakes up after sleep
        Log::error( "CardModuleService::checkException", " RemotingException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_NO_SMARTCARD );
        // Other possibilities: SCARD_F_COMM_ERROR SCARD_E_COMM_DATA_LOST SCARD_W_REMOVED_CARD
    }

    if( dynamic_cast< CryptographicException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " CryptographicException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< SystemException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " SystemException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< ArgumentException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArgumentException" );

        // One or more of the supplied parameters could not be properly interpreted.
        throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
    }

    if( dynamic_cast< ArgumentNullException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArgumentNullException" );

        // One or more of the supplied parameters could not be properly interpreted.
        throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
    }

    if( dynamic_cast< ArgumentOutOfRangeException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArgumentOutOfRangeException" );

        // A communications error with the smart card has been detected. Retry the operation.
        throw MiniDriverException( SCARD_E_COMM_DATA_LOST );
    }

    if( dynamic_cast< IndexOutOfRangeException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " IndexOutOfRangeException" );

        // One or more of the supplied parameters could not be properly interpreted.
        throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
    }

    if( dynamic_cast< InvalidCastException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " InvalidCastException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< InvalidOperationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " InvalidOperationException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< NotImplementedException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " NotImplementedException" );

        // This smart card does not support the requested feature.
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
    }

    if( dynamic_cast< NotSupportedException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " NotSupportedException" );

        // This smart card does not support the requested feature.
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
    }

    if( dynamic_cast< NullReferenceException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " NullReferenceException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< ObjectDisposedException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ObjectDisposedException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< ApplicationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ApplicationException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< ArithmeticException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArithmeticException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< ArrayTypeMismatchException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArrayTypeMismatchException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< BadImageFormatException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " BadImageFormatException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< DivideByZeroException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " DivideByZeroException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< FormatException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " FormatException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< RankException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " RankException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< StackOverflowException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " StackOverflowException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< MemberAccessException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MemberAccessException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< MissingFieldException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MissingFieldException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< MissingMemberException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MissingMemberException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< MissingMethodException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MissingMethodException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< OverflowException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " OverflowException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< SecurityException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " SecurityException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< SerializationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " SerializationException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    // An unexpected card error has occurred.
    throw MiniDriverException( SCARD_E_UNEXPECTED );
}

s4 MiniDriverModuleService::getTriesRemaining(u1 role)
{
   s4 triesLeft = 0;
   try
   {
      triesLeft = m_pCardMod->GetTriesRemaining(role);
   }
   catch( Exception& x ) { checkException( x ); }
   return triesLeft;
}

void MiniDriverModuleService::createContainer(u1 ctrIndex,u1 keyImport,u1 keySpec,s4 keySize,u1Array* keyValue, u1 role)
{
   try
   {
      m_pCardMod->CreateCAPIContainer(ctrIndex, keyImport, keySpec, keySize, keyValue, role);
   }
   catch( Exception& x ) { checkException( x ); }
   ForceGarbageCollector( );
}

void MiniDriverModuleService::deleteContainer(u1 ctrIndex, u1 keySpec)
{
   try
   {
      m_pCardMod->DeleteCAPIContainer(ctrIndex, keySpec);
   }
   catch( Exception& x ) { checkException( x ); }
   ForceGarbageCollector( );
}

u1Array* MiniDriverModuleService::getContainer(u1 ctrIndex)
{
   u1Array* pResult = NULL;
   try
   {
      pResult = m_pCardMod->GetCAPIContainer(ctrIndex);
   }
   catch( Exception& x ) { checkException( x ); }
   return pResult;
}

const int CARD_PROPERTY_PIN_IDENTIFIER = 0x01;
const int CARD_PROPERTY_PIN_IDENTIFIER_EX = 0x91;

u1Array* MiniDriverModuleService::getContainerProperty(u1 ctrIndex,u1 property,u1 flags)
{
    if( (SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) || (IsMultiPinSupported() && ((property == CARD_PROPERTY_PIN_IDENTIFIER_EX) || (property == CARD_PROPERTY_PIN_IDENTIFIER))))
    {
      try
      {
         return m_pCardMod->GetContainerProperty(ctrIndex, property, flags);
      }
      catch( Exception& x ) { checkException( x ); }
    }
    return NULL;
}

void MiniDriverModuleService::setContainerProperty(u1 ctrIndex,u1 property,u1Array* data,u1 flags)
{
   try
   {
      return m_pCardMod->SetContainerProperty(ctrIndex, property, data, flags);
   }
   catch( Exception& x ) { checkException( x ); }
}

u1Array* MiniDriverModuleService::privateKeyDecrypt(u1 ctrIndex,u1 keyType,u1Array* encryptedData)
{
   u1Array* a = NULL;
   try
   {
      a = m_pCardMod->PrivateKeyDecrypt(ctrIndex, keyType, encryptedData);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
   return a;
}

u1Array* MiniDriverModuleService::privateKeyDecryptEx(u1 ctrIndex,u1 keyType,u1 paddingType, u1 algo, u1Array* encryptedData)
{
   u1Array* a = NULL;
   try
   {
      a = m_pCardMod->PrivateKeyDecryptEx(ctrIndex, keyType, paddingType, algo, encryptedData);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
   return a;
}

u1Array* MiniDriverModuleService::privateKeySign(u1 ctrIndex, u1 keyType, u1 paddingType, u1 algo, u1Array* data, u1Array* intermediateHash, u1Array* hashCounter)
{
   u1Array* a = NULL;
   try
   {
      a = m_pCardMod->PrivateKeySign(ctrIndex, keyType, paddingType, algo, data, intermediateHash, hashCounter);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
   return a;
}

u1Array* MiniDriverModuleService::constructDHAgreement(u1 ctrIndex, u1Array* dataQx, u1Array* dataQy)
{
   u1Array* a = NULL;
   try
   {
      a = m_pCardMod->ConstructDHAgreement(ctrIndex, dataQx, dataQy);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
   return a;
}

bool MiniDriverModuleService::supportsDualKeyContainers(void)
{
   try
   {
      return m_pCardMod->SupportsDualKeyContainers();
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
   return false;
}

void MiniDriverModuleService::createFile(string* path,u1Array* acls,s4 initialSize)
{
   try
   {
      m_pCardMod->CreateFile(path, acls, initialSize);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
}

void MiniDriverModuleService::createDirectory(string* path,u1Array* acls)
{
   try
   {
      m_pCardMod->CreateDirectory(path, acls);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
}

void MiniDriverModuleService::writeFile(string* path,u1Array* data)
{
   try
   {
      m_pCardMod->WriteFile(path, data);
   }
   catch( Exception& x ) { checkException( x ); }
   manageGarbageCollector();
}

u1Array* MiniDriverModuleService::readFile(string* path)
{
   u1Array* a = readFileWithoutMemoryCheck( path ); 
   manageGarbageCollector( ); 
   return a;
}

u1Array* MiniDriverModuleService::readFileWithoutMemoryCheck(string* path)
{
   u1Array* pResult = NULL;
   try
   {
      pResult = m_pCardMod->ReadFile(path, 0);
   }
   catch( Exception& x ) { checkException( x ); }
   return pResult;
}

void MiniDriverModuleService::deleteFile(string* path)
{
   try
   {
      m_pCardMod->DeleteFile(path);
   }
   catch( Exception& x ) { checkException( x ); }
   ForceGarbageCollector( );
}

void MiniDriverModuleService::deleteDirectory(string* path)
{
   try
   {
      m_pCardMod->DeleteDirectory(path);
   }
   catch( Exception& x ) { checkException( x ); }
   ForceGarbageCollector( );
}

StringArray* MiniDriverModuleService::getFiles(string* path)
{
   StringArray* pResult = NULL;
   try
   {
      pResult = m_pCardMod->GetFiles(path);
   }
   catch( Exception& x ) { checkException( x ); }
   return pResult;
}

u1Array* MiniDriverModuleService::getFileProperties(string* path)
{
   try
   {
      return m_pCardMod->GetFileProperties(path);
   }
   catch( Exception& x ) { checkException( x ); }
   return NULL;
}

bool MiniDriverModuleService::generateSessionPinEx(u1 role, 
                                      u1Array* pPin,
                                      u1ArraySecure& sbSessionPin,
									  s4* pcAttemptsRemaining
                                       )
{
   long  resultCode = SCARD_S_SUCCESS;
   u1Array* ba = NULL;
   s4       nAttemptsRemaining = -1;

   // case of .NET card with old assembly that doesn't support session PIN and it retourns UnauthorizedAccessException!!
   // So we can't know for sure if the user entered a wrong PIN or if the card doesn't support session PIN
   // So, we use this heuristique test for old cards
   if (IsV2() & !IsMultiPinSupported() && !IsGCEnabled())
   {
      Log::log( "MiniDriverModuleService::generateSessionPinEx - V2 card with old assembly (no multi-pin and no GC) => no support for session PIN.");
      return false;
   }


   try
   {
      u1 bMode = 0x01;// force: CARD_AUTHENTICATE_GENERATE_SESSION_PIN
      u1Array pin(0);
      pin.SetBuffer(NULL);
	  ba = m_pCardMod->AuthenticateEx(bMode, role, &pin); 


      if (ba != NULL)
      {        
         //Sesion PIN Generation -> Compute Card Session PIN     
         //   It is what the Card expects to validate authentication 
        
         {
            SHA_CTX sha;
            DWORD i;
            BYTE  bKey[24] = {0};
            BYTE  bClearRnd[8] = {0};
            BYTE  bSessionPIN[20] = {0};
            BYTE  checkVal = 0;

            // Check Session Random Length
            if (ba->GetLength() != 8)
            {
               throw MiniDriverException(SCARD_E_INVALID_PARAMETER);
            }

            // Compute Key = SHA1(Clear PIN)
            SHA1_Init(&sha);
			SHA1_Update(&sha, pPin->GetBuffer(), pPin->GetLength());
            SHA1_Final(bKey, &sha);

            // Decrypt Session Random = 3DES_ECB(Decrypt, Session Random, SHA1(clear PIN))
             int clearRndLength = 8;
             EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
             EVP_DecryptInit(ctx, EVP_des_ede3(), bKey, NULL);
             EVP_DecryptUpdate(ctx, bClearRnd, &clearRndLength, ba->GetBuffer(), ba->GetLength());
             EVP_CIPHER_CTX_free(ctx);
            
            // Check Random Integrity (Checksum)
            for (i = 0; i < 7; i++) 
            {
               checkVal ^= bClearRnd[i];                
            }
            if (checkVal != bClearRnd[7])
            {
               // call card to deactivate session pin on the given role
               try
               {
                  m_pCardMod->AuthenticateEx(0x03, role, &pin); 
               }
               catch(...)
               {
               }
               throw UnauthorizedAccessException("");                        
            }

            // Compute Card Session PIN = SHA1(Session Random + PIN)
            SHA1_Init(&sha);
            SHA1_Update(&sha, bClearRnd, ba->GetLength());
			SHA1_Update(&sha, pPin->GetBuffer(), pPin->GetLength());
            SHA1_Final(bSessionPIN, &sha);

            // Set Card Session PIN
			sbSessionPin.Clear();
			sbSessionPin.Resize(20);
			sbSessionPin.SetBuffer(bSessionPIN);
         }
      }
   }
   catch(RemotingException& rex)
   {
      resultCode = rex.getResultCode();
      
      if (resultCode == 0)    // zero signifies that it was not PCSC related error
      {
         resultCode = SCARD_E_COMM_DATA_LOST;
      }
   }
   
   catch(UnauthorizedAccessException&)
   {                    
      resultCode = SCARD_W_WRONG_CHV;

      nAttemptsRemaining = getTriesRemaining(role);        

      if(pcAttemptsRemaining != 0)
      {
         *pcAttemptsRemaining = nAttemptsRemaining;        
      }

      if(nAttemptsRemaining == 0)
      {
         resultCode = SCARD_W_CHV_BLOCKED;
      }
   }

   catch(NullReferenceException&)
   {
      resultCode = SCARD_E_INVALID_PARAMETER;
   }
   
   catch(ArgumentNullException&)
   {
      resultCode = SCARD_E_INVALID_PARAMETER;
   }
   
   catch(ArgumentException&)
   {
      resultCode = SCARD_E_INVALID_PARAMETER;
   }
   
   catch(Exception& ex)
   {
      resultCode = AnalyseExceptionString(ex);

      if (resultCode == SCARD_E_UNSUPPORTED_FEATURE)
      {
        return false;
      }
   
      // check if someone is messing with the protocol
      if (resultCode == SCARD_F_UNKNOWN_ERROR) 
      {
         resultCode = SCARD_W_WRONG_CHV;
      }
   }
   
   catch(...)
   {    
      // for all other cases
      resultCode = SCARD_F_UNKNOWN_ERROR;        

	  nAttemptsRemaining = getTriesRemaining(role);        

      if(pcAttemptsRemaining != 0)
      {
         *pcAttemptsRemaining = nAttemptsRemaining;        
      }

      if(nAttemptsRemaining == 0)
      {
         resultCode = SCARD_W_CHV_BLOCKED;
      }
   }
   
   // Cleanup
   
   if(ba != NULL)
   {
      delete ba;
   }

   if (resultCode != SCARD_S_SUCCESS)
   {
      throw MiniDriverException(resultCode);
   }
   
   return true;
}

void MiniDriverModuleService::changeReferenceData(u1 mode,u1 role,u1Array* oldPin,u1Array* newPin,s4 maxTries)
{
   try
   {
      m_pCardMod->ChangeReferenceData(mode, role, oldPin, newPin, maxTries);
   }
   catch( Exception& x ) { checkException( x ); }
}

void MiniDriverModuleService::changeAuthenticatorEx(u1 mode,u1 oldRole,u1Array* oldPin,u1 newRole,u1Array* newPin,s4 maxTries)
{
   try
   {
      m_pCardMod->ChangeAuthenticatorEx(mode, oldRole, oldPin, newRole, newPin, maxTries);
   }
   catch( Exception& x ) { checkException( x ); }
}

void MiniDriverModuleService::SetPinInitialized(u1 role)
{
   try
   {
      m_pCardMod->SetPinInitialized(role);
   }
   catch( Exception& x ) { checkException( x ); }
}

u1Array* MiniDriverModuleService::getCardProperty(u1 a_ucProperty,u1 a_ucFlags)
{
    if( SMART_CARD_TYPE_V2PLUS != m_ucSmartCardType ) { 

        return NULL; 
    } 

    if(		( CARD_FREE_SPACE != a_ucProperty ) 
		&&	( CARD_AUTHENTICATED_ROLES != a_ucProperty ) 
		&&	( CARD_CHANGE_PIN_FIRST != a_ucProperty ) 
		&&	(CARD_PROPERTY_PIN_INFO_EX != a_ucProperty) 
		&&	(C_CARD_PIN_INFO != a_ucProperty) 
		&&	(C_CARD_PIN_POLICY != a_ucProperty) 
		&&	(C_CARD_PIN_STRENGTH_VERIFY != a_ucProperty) 
		&&	(C_CARD_PIN_STRENGTH_CHANGE != a_ucProperty) 
		&&	(C_CARD_PIN_STRENGTH_UNBLOCK != a_ucProperty) 
		&&	(C_CARD_KEYSIZES != a_ucProperty) 
		
	  ) {

        PROPERTIES::iterator i = m_Properties.find( a_ucProperty );

        if( m_Properties.end( ) != i ) {

           return new u1Array(*i->second);
        }
    }


    try {  

        u1Array* p = m_pCardMod->GetCardProperty(a_ucProperty, a_ucFlags);

        if (m_Properties[ a_ucProperty ])
        {
           delete m_Properties[ a_ucProperty ];
        }

        m_Properties[ a_ucProperty ] = p;

        return new u1Array(*m_Properties[ a_ucProperty ]);

    } catch( Exception& x ) {      

        checkException( x );
    } 

    return NULL; 
}

void MiniDriverModuleService::setCardProperty(u1 a_ucProperty,u1Array* a_pData,u1 a_ucFlags)
{
    if( SMART_CARD_TYPE_V2PLUS != m_ucSmartCardType ) { return; }

    try {

       m_pCardMod->SetCardProperty(a_ucProperty, a_pData, a_ucFlags);

        if (m_Properties[ a_ucProperty ])
        {
           delete m_Properties[ a_ucProperty ];
        }

        m_Properties[ a_ucProperty ] = new u1Array(*a_pData);

    } catch( Exception& x ) { 

        checkException( x );
    }
}

bool MiniDriverModuleService::isAuthenticated(u1 a_ucRole, bool bForceRequest)
{
    bool bIsAuthenticated = false;

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        // Try to get the flag using the card properties
        try {

			if (bForceRequest)
				throw Exception("");

           std::unique_ptr< u1Array > p( getCardProperty( CARD_PROPERTY_AUTHENTICATED_ROLES, 0 ) );

            bIsAuthenticated = ( ( (unsigned char)( p->ReadU1At( 0 ) & a_ucRole ) ) == a_ucRole ); 

        } catch( Exception& ) {

            //// The card properties are not supported
            // Try the get the flag from a command
            try {

               bIsAuthenticated = (m_pCardMod->IsAuthenticated(a_ucRole) != 0);

            } catch( Exception& x ) { 

                checkException( x ); 
            }
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        // Try the get the flag from a command
        try {

            bIsAuthenticated = (m_pCardMod->IsAuthenticated(a_ucRole) != 0);

        } catch( Exception& x ) { 

            checkException( x ); 
        }
    }

    return bIsAuthenticated; 
}

bool MiniDriverModuleService::isPinExpired(u1 a_ucRole)
{
   bool bExpiredPin = false;
   try {

      bExpiredPin = (m_pCardMod->IsPinExpired(a_ucRole) != 0);

   } catch( Exception& x ) { 

      checkException( x ); 
   }

   return bExpiredPin;
}

void MiniDriverModuleService::SetAuthenticated(u1 role)
{
   try {

      m_pCardMod->SetAuthenticated(role);

   } catch( Exception& x ) { 

      checkException( x ); 
   }
}

void MiniDriverModuleService::SetDeauthenticated(u1 role)
{
   try {

      m_pCardMod->SetDeauthenticated(role);

   } catch( Exception& x ) { 

      checkException( x ); 
   }
}

u1Array* MiniDriverModuleService::authenticateEx(u1 mode,u1 role,u1Array* pin)
{
   u1Array* pResult = NULL;
   try {

      pResult = m_pCardMod->AuthenticateEx(mode, role, pin);

   } catch( Exception& x ) { 

      checkException( x ); 
   }
   return pResult;
}

void MiniDriverModuleService::verifyPin(u1 a_ucRole,u1Array* a_pPin)
{
    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        // Try to authentication using authenticateEx
        try {

            authenticateEx( 0, a_ucRole, a_pPin ); 

        } catch( Exception& ) {

            //// The authenticaqteEx is not supported

            // Try the authentication using verify PIN
            try {

                m_pCardMod->VerifyPin(a_ucRole, a_pPin);

            } catch( Exception& x ) { 

                checkException( x ); 
            }  
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        // Try the get the flag from a command
        try {

            m_pCardMod->VerifyPin(a_ucRole, a_pPin);

        } catch( ArgumentException& x ) { 

			try {
				Log::log( "MiniDriverModuleService::verifyPin - received ArgumentException, trying to call authenticateEx instead");

				authenticateEx( 0, a_ucRole, a_pPin ); 

			} catch( Exception& )
			{
				checkException( x );
			}

        } catch( Exception& x ) { 

            checkException( x ); 
        }
    }
}

void MiniDriverModuleService::deauthenticateEx(u1 roles)
{
   try {

      m_pCardMod->DeauthenticateEx(roles);

   } catch( Exception& x ) { 

      checkException( x ); 
   }
}

void MiniDriverModuleService::logOut(u1 a_ucRole)
{
    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        // Try to deauthentication using deauthenticateEx
        try {

            deauthenticateEx( a_ucRole );

        } catch( Exception& ) {

            //// The authenticaqteEx is not supported

            // Try the deauthentication using logout
            try {

               m_pCardMod->LogOut(a_ucRole);

            } catch( Exception& x ) { 

                checkException( x ); 
            }  
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        // Try the get the flag from a command
        try {

            m_pCardMod->LogOut(a_ucRole);

        } catch( Exception& x ) { 

            checkException( x ); 
        }
    }
}

u1Array* MiniDriverModuleService::getChallenge()
{
   u1Array* pResult = NULL;
   try {
      pResult = m_pCardMod->GetChallenge();
   } catch( Exception& x ) { 
      checkException( x ); 
   }
   return pResult;
}

void MiniDriverModuleService::externalAuthenticate(u1Array* response)
{
   try {
      m_pCardMod->ExternalAuthenticate(response);
   } catch( Exception& x ) { 
      checkException( x ); 
   }
}

s4Array* MiniDriverModuleService::getKeySizes()
{
   s4Array* pResult = NULL;
   try {
      pResult = m_pCardMod->QueryKeySizes();
   } catch( Exception& x ) { 
      checkException( x ); 
   }
   return pResult;
}

u1Array* MiniDriverModuleService::getSerialNumber()
{
   u1Array* pResult = NULL;
   try {
      pResult = m_pCardMod->get_SerialNumber();
   } catch( Exception& x ) { 
      checkException( x ); 
   }  
   return pResult;
}
