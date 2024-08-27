/*******************************************************************************
 C *opyright (c) 2014, Jan Koester jan.koester@gmx.net
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 * Neither the name of the <organization> nor the
 names of its contributors may be used to endorse or promote products
 derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#include <chrono>
#include <thread>
#include <cstring>
#include <atomic>

#include <vector>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>

#include "exception.h"
#include "socket.h"
#include "error.h"

#define HIDDEN __attribute__ ((visibility ("hidden")))

std::atomic<int> netplus::socket::_InitCount=0;

netplus::socket::socket(){
    _Socket=-1;
    _SocketPtr=nullptr;
    _Type=-1;
    ++_InitCount;
}

netplus::socket::~socket(){
    --_InitCount;
}

void netplus::socket::setnonblocking(){
    int sockopts=fcntl(_Socket, F_GETFL, 0);
    if(fcntl( _Socket, F_SETFL,sockopts | O_NONBLOCK)<0){
        NetException exception;
        exception[NetException::Error] << "Could not set ClientSocket nonblocking!";
        throw exception;
    }
}

void netplus::socket::setTimeout(int usec){
    struct timeval timeout;
    timeout.tv_sec =  0;
    timeout.tv_usec = usec;
    if (setsockopt (_Socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
        sizeof timeout) < 0){

        char errstr[512];
        strerror_r_netplus(errno,errstr,512);

        NetException exception;
        exception[NetException::Error] << "Could not set ClientSocket Recv timeout"<< errstr;
        throw exception;
    }


    if (setsockopt (_Socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
        sizeof timeout) < 0){

        char errstr[512];
        strerror_r_netplus(errno,errstr,512);

        NetException exception;
        exception[NetException::Error] << "Could not set ClientSocket Send timeout" << errstr;
        throw exception;

    }
}
