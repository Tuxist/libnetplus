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
#include <thread>
#include <vector>
#include <cstring>
#include <cstdio>

extern "C" {
    #include <winsock2.h>
    #include <WS2tcpip.h>
    #include <fcntl.h>
};

#include "exception.h"
#include "socket.h"
#include "error.h"

#include "config.h"

netplus::udp::udp() : socket() {
    _SocketPtr=::malloc(sizeof(addrinfo));
    _SocketPtrSize=sizeof(addrinfo);
    _Socket = INVALID_SOCKET;
    _Type=sockettype::UDP;
}

netplus::udp::udp(const char* uxsocket,int maxconnections,int sockopts) : socket() {
    NetException exception;
    exception[NetException::Critical] << "udp: Windows doesn't support UnixSockets !";
    throw exception;
}

netplus::udp::udp(const char* addr, int port,int maxconnections,int sockopts) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;

    struct addrinfo hints,*result,*rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    SOCKET tsock;
    char serv[512];
    snprintf(serv,512,"%d",port);

    if ((tsock=getaddrinfo(addr, serv,&hints,&result)) < 0) {
        exception[NetException::Critical] << "Socket Invalid address/ Address not supported";
        throw exception;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        _Socket = ::socket(rp->ai_family, rp->ai_socktype,
                            rp->ai_protocol);
        if (_Socket == -1)
            continue;
        _SocketPtr = malloc(rp->ai_addrlen);
        memset(_SocketPtr, 0, rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;
        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        break;
    }

    freeaddrinfo(result);
}

netplus::udp::~udp(){

    if(_Socket>=0)
        ::closesocket(_Socket);
    ::free(_SocketPtr);
}

netplus::udp::udp(SOCKET sock) : socket() {
    _SocketPtr=::malloc(sizeof(addrinfo));
    _SocketPtrSize=sizeof(addrinfo);
    ((struct addrinfo*)_SocketPtr)->ai_family=AF_UNSPEC;
    _Socket=sock;
    _Type=sockettype::UDP;
}


void netplus::udp::listen(){
    NetException exception;
    if(::listen(_Socket,_Maxconnections) < 0){
        exception[NetException::Critical] << "Can't listen Server Socket";
        throw exception;
    }
}

int netplus::udp::fd(){
    return _Socket;
}

netplus::udp& netplus::udp::operator=(int sock){
     _Socket=sock;
     return *this;
};

int netplus::udp::getMaxconnections(){
    return _Maxconnections;
}

void netplus::udp::accept(socket *csock){
    NetException exception;
    struct sockaddr myaddr;
    socklen_t myaddrlen;
    *csock = ::accept(_Socket, &myaddr, &myaddrlen);
    if(csock->_Socket<0){
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    csock->_SocketPtrSize = myaddrlen;
    csock->_SocketPtr = malloc(myaddrlen);
    memcpy(csock->_SocketPtr,&myaddr,myaddrlen);
}

void netplus::udp::bind(){
    NetException exception;
    if (::bind(_Socket,(const struct sockaddr*)_SocketPtr,_SocketPtrSize) < 0){
        exception[NetException::Error] << "Can't bind Server Socket";
        throw exception;
    }
}


size_t netplus::udp::sendData(socket *csock, void* data, unsigned long size){
    return sendData(csock,data,size,0);
}

size_t netplus::udp::sendData(socket *csock, void* data, unsigned long size,int flags){
    NetException exception;
    int rval=::send(csock->_Socket,
                 (char*)data,
                        size,
                        flags
                     );
    if(rval<0){
        int etype=NetException::Error;
        if(errno==EAGAIN)
            etype=NetException::Note;

        char errstr[512];
        strerror_r_netplus(errno,errstr,512);

        exception[etype] << "Socket senddata failed on Socket: " << (size_t)csock->_Socket
                                       << " ErrorMsg: " <<  errstr;

        throw exception;
    }
    return (size_t)rval;
}


size_t netplus::udp::recvData(socket *csock, void* data, unsigned long size){
    return recvData(csock,data,size,0);
}

size_t netplus::udp::recvData(socket *csock, void* data, unsigned long size,int flags){
    NetException exception;
    int recvsize=::recv(csock->_Socket,
                            (char*)data,
                            size,
                            flags
                         );
    if(recvsize<0){
        int etype=NetException::Error;

        if(errno==EAGAIN)
            etype=NetException::Note;

        char errstr[512];
        strerror_r_netplus(errno,errstr,512);

        exception[etype] << "Socket recvData failed on Socket: " << (size_t) csock->_Socket
                                       << " ErrorMsg: " <<  errstr;
        throw exception;
    }
    return (size_t)recvsize;
}

void netplus::udp::connect(socket *csock){
    NetException exception;

    if ( ::connect(csock->fd(),(struct sockaddr*)csock->_SocketPtr,csock->_SocketPtrSize) < 0) {
        char errstr[512];
        strerror_r_netplus(errno,errstr,512);

        exception[NetException::Error] << "Socket connect: can't connect to server aborting " << " ErrorMsg:" << errstr;
        throw exception;
    }
}

void netplus::udp::getAddress(std::string &addr){
    if(!_SocketPtr)
       return;
    char ipaddr[INET6_ADDRSTRLEN];
    if(((struct sockaddr*)_SocketPtr)->sa_family==AF_INET6)
        inet_ntop(AF_INET6, &(((struct sockaddr_in6*)_SocketPtr)->sin6_addr), ipaddr, INET6_ADDRSTRLEN);
    else
        inet_ntop(AF_INET, &((struct sockaddr_in*)_SocketPtr)->sin_addr, ipaddr, INET_ADDRSTRLEN);
    addr=ipaddr;
}


