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

#include <cstring>

#include "Timer.hpp"
#include "Log.hpp"


/*
*/
void Timer::start( void ) {

#ifdef WIN32
	m_clockStart = clock( );
#else	
   gettimeofday( &m_clockStart, NULL ); 
#endif
}


/*
*/
void Timer::stop( const char* a_pMessage ) {

    if( !Log::s_bEnableLog ) {

        return;
    }

    stop( );

	if( 0.400 < m_Duration ) {

        Log::log( "$$$$$$$$$$$$$$$$$$$$$$$ %s - Elapsed time <%f> seconds", a_pMessage, m_Duration );

    } else {
        Log::log( "%s - Elapsed time <%f> seconds", a_pMessage, m_Duration );
    }
}


/*
*/
double Timer::getCurrentDuration( void ) {
 
#ifdef WIN32
      double duration = (double)(clock( ) - m_clockStart) / CLOCKS_PER_SEC;
	  //m_clockStart = 0;
#else	
      timeval now;         
      gettimeofday( &now, NULL );  

		double duration1 = now.tv_sec;         
      duration1 += (double)( (double) now.tv_usec / (double) 1e6 );       
      double duration2 = m_clockStart.tv_sec;         
      duration2 += (double)( (double) m_clockStart.tv_usec / (double) 1e6 );
      double duration = duration1 - duration2;
 
      //memset( &m_clockStart, 0, sizeof( timeval ) );
#endif

    //Log::log( "Timer::getCurrentDuration - Elapsed time <%f> seconds", duration );

	return duration;
}




/*
*/
void Timer::stop( void ) {

      m_Duration = getCurrentDuration( );
}
