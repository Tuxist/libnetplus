/*******************************************************************************
Copyright (c) 2014, Jan Koester jan.koester@gmx.net
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
#include <atomic>
#include <cstring>

#include <vector>
#include <cstdio>
#include <cstring>
#include <fcntl.h>

#include "exception.h"
#include "socket.h"
#include "error.h"
#include "config.h"

//#define HIDDEN __attribute__ ((visibility ("hidden")))


#define WIN32_LEAN_AND_MEAN

#pragma comment (lib, "Ws2_32.lib")

std::atomic<int> netplus::socket::_InitCount=0;

netplus::socket::socket(){
    _Socket=-1;
    _SocketPtr=nullptr;
    _Type=-1;
    if (_InitCount<1) {
        if (WSAStartup(MAKEWORD(2, 2), _WSAData) != 0) {
            NetException exception;
            exception[NetException::Critical] << "socket: WSAStartup failed: ";
        }
    }
    ++_InitCount;
}

netplus::socket::~socket(){
    --_InitCount;
    int zero = 0;
    if (_InitCount.compare_exchange_strong(zero, std::memory_order_release)) {
        WSACleanup();
        delete _WSAData;
        _WSAData = nullptr;
    }
}

void netplus::socket::setnonblocking(){
    u_long mode = 1; // 1 to enable non-blocking socket
    if(ioctlsocket(_Socket, FIONBIO, &mode) <0){
        NetException exception;
        exception[NetException::Error] << "Could not set ClientSocket nonblocking!";
        throw exception;
    }
}

void netplus::socket::setTimeout(int sec){
    return;
}

