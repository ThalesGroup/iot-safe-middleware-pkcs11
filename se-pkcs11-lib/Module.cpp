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
#include "Cache.h"

HINSTANCE g_hModule = NULL; /**< DLL Instance. */
extern bool g_bDllUnloading;

BOOL APIENTRY DllMain( HINSTANCE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID /*lpReserved*/
                     )
{
    switch(ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH :
        {
            g_hModule = hModule;
        }
        break;
    case DLL_PROCESS_DETACH : 
        {
            g_bDllUnloading = true;
        }
        break;
    }
    return TRUE;
}


#endif

