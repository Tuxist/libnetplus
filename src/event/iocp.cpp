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

#include <iostream>
#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <cstring>

#include <signal.h>
#include <stdlib.h>
#include <stdint.h>

#include <winsock2.h>
#include <ws2ipdef.h>
#include <mswsock.h>

#include <errno.h>

#include "socket.h"
#include "exception.h"
#include "eventapi.h"
#include "connection.h"
#include "../windows/error.h"
#include <assert.h>

#define READEVENT 0
#define SENDEVENT 1

#define BLOCKSIZE 16384

namespace netplus {

    void eventapi::RequestEvent(con* curcon, const int tid, void* args) {
        //dummy
    };

    void eventapi::ResponseEvent(con* curcon, const int tid, void* args) {
        //dummy
    };

    void eventapi::ConnectEvent(con* curcon, const int tid, void* args) {
        //dummy
    };

    void eventapi::DisconnectEvent(con* curcon, const int tid, void* args) {
        //dummy
    };

    void eventapi::CreateConnetion(con** curcon) {
        *curcon = new con(this);
    };

    void eventapi::deleteConnetion(con* curcon) {
        delete curcon;
    };

    event::event(socket* serversocket, int timeout) {
        if (!serversocket) {
            NetException exp;
            exp[NetException::Critical] << "server socket empty!";
            throw exp;
        }
        _Timeout = timeout;
        _ServerSocket = serversocket;
        _ServerSocket->bind();
        _ServerSocket->setnonblocking();
        _ServerSocket->listen();

        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        threads = sysinfo.dwNumberOfProcessors;
    }

    event::~event() {
    }

    void event::runEventloop(void* args) {
        NetException exception;

        HANDLE iocp = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE,nullptr,0, threads);

        if (!iocp) {
            NetException exp;
            exp[NetException::Critical] << "event: runEventloop couldn't create iocp !";
            throw exp;
        }

        _ServerSocket->listen();

        ::CreateIoCompletionPort((HANDLE)_ServerSocket->fd(), iocp, (u_long)0, 0);

        LPFN_ACCEPTEX lpfnAcceptEx = NULL;
        GUID GuidAcceptEx = WSAID_ACCEPTEX;
        WSAOVERLAPPED olOverlap;
        DWORD dwBytes;

        int iResult = WSAIoctl(_ServerSocket->fd(), SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidAcceptEx, sizeof(GuidAcceptEx),
            &lpfnAcceptEx, sizeof(lpfnAcceptEx),
            &dwBytes, NULL, NULL);

        if (iResult == SOCKET_ERROR) {
            NetException exp;
            exp[NetException::Critical]<<"WSAIoctl failed with error: " << WSAGetLastError();;
            closesocket(_ServerSocket->fd());
            WSACleanup();
            throw exp;
        }

        memset(&olOverlap, 0, sizeof(olOverlap));

    }
};


