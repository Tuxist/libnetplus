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

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#include "exception.h"
#include "socket.h"


netplus::socket::socket(){
    _Socket=-1;
}

netplus::socket::~socket(){
}


void netplus::socket::setnonblocking(){
    int sockopts=fcntl(_Socket, F_GETFL, 0);
    if(fcntl( _Socket, F_SETFL,sockopts | O_NONBLOCK)<0){
        NetException exception;
        exception[NetException::Error] << "Could not set ClientSocket nonblocking!";
        throw exception;
    }
}

int netplus::socket::getSocket(){
    return _Socket;
}

netplus::tcp::tcp(const netplus::tcp& ctcp){
    _Socket=ctcp._Socket;
    if(_UxPath.empty())
        _SocketPtr=new struct sockaddr_in;
    else
        _SocketPtr=new struct sockaddr_un;

    memcpy(_SocketPtr,ctcp._SocketPtr,sizeof(ctcp._SocketPtr));

    _SocketPtrSize=ctcp._SocketPtrSize;
}

netplus::tcp::tcp(const char* uxsocket,int maxconnections,int sockopts) : socket(){
    NetException exception;
    int optval = 1;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    _Maxconnections=maxconnections;
    _SocketPtr = new struct sockaddr_un;
    memset(_SocketPtr,0,sizeof(struct sockaddr_un));
    ((struct sockaddr_un *)_SocketPtr)->sun_family = AF_UNIX;
    if(!uxsocket){
        exception[NetException::Critical] << "Can't copy Server UnixSocket";
        throw exception;
    }
    _UxPath=uxsocket;
    memcpy(((struct sockaddr_un *)_SocketPtr)->sun_path,uxsocket,strlen(uxsocket)+1);
    
    if ((_Socket=::socket(AF_UNIX,SOCK_STREAM, 0)) < 0){
        exception[NetException::Critical] << "Can't create TCP UnixSocket";
        throw exception;
    }
    
    setsockopt(_Socket,SOL_SOCKET,sockopts,&optval, sizeof(optval));
}

netplus::tcp::tcp(const char* addr, int port,int maxconnections,int sockopts) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    
    _SocketPtr = new struct sockaddr_in;
    memset(_SocketPtr, 0, sizeof(struct sockaddr_in));

    _SocketPtrSize=sizeof(struct sockaddr_in);

    struct addrinfo hints,*result,*rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    int tsock;

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

        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;

        break;
    }

    ::freeaddrinfo(result);
    
    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
}
                                        
netplus::tcp::~tcp(){
    if(_Socket>=0)
        ::close(_Socket);
    if(!_UxPath.empty()){
        unlink(_UxPath.c_str());
        delete (struct sockaddr_un*)_SocketPtr;
    }else{
        delete (struct sockaddr_in*)_SocketPtr;
    }

}

netplus::tcp::tcp() : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
}


void netplus::tcp::listen(){
    NetException exception;
    if(::listen(_Socket,_Maxconnections) < 0){
        exception[NetException::Critical] << "Can't listen Server Socket";
        throw exception;
    }
}

int netplus::tcp::getMaxconnections(){
    return _Maxconnections;
}

netplus::socket *netplus::tcp::accept(){
    NetException exception;
    socket *csock=new tcp();
    csock->_Socket = ::accept(_Socket,(struct sockaddr *)csock->_SocketPtr,&csock->_SocketPtrSize);
    if(csock->_Socket<0){
        delete csock;
        csock=nullptr;
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    return csock;
}

void netplus::tcp::bind(){
    NetException exception;
    if (::bind(_Socket,((const struct sockaddr *)_SocketPtr), sizeof(struct sockaddr)) < 0){
        exception[NetException::Error] << "Can't bind Server Socket";
        throw exception;
    }
}


unsigned int netplus::tcp::sendData(socket* socket, void* data, unsigned long size){
    return sendData(socket,data,size,0);
}

unsigned int netplus::tcp::sendData(socket* socket, void* data, unsigned long size,int flags){
    NetException exception;
    if(!socket){                                                                                     
        exception[NetException::Error] << "Socket sendata failed invalid socket !";
        throw exception;                                                                             
    }   
    int rval=::sendto(socket->_Socket,
                        data,
                        size,
                        flags,
                        (struct sockaddr *)&socket->_SocketPtr,
                        socket->_SocketPtrSize
                     );
    if(rval<0){
        if(errno==EAGAIN)
            return 0;

        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket;
        throw exception;
    }
    return rval;
}


unsigned int netplus::tcp::recvData(socket* socket, void* data, unsigned long size){
    return recvData(socket,data,size,0);
}

unsigned int netplus::tcp::recvData(socket* socket, void* data, unsigned long size,int flags){
    NetException exception;
    if(!socket){
        exception[NetException::Error] << "Socket recvdata failed invalid socket!";
        throw exception;        
    }
    int recvsize=::recvfrom(socket->_Socket,
                            data,
                            size,
                            flags,
                            (struct sockaddr *)&socket->_SocketPtr,
                            &socket->_SocketPtrSize
                         );
    if(recvsize<0){
        if(errno==EAGAIN)
            return 0;
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;
}

netplus::tcp* netplus::tcp::connect(){
    NetException exception;
    int sock=0;;
    if ((sock=::connect(_Socket, (struct sockaddr*)_SocketPtr, _SocketPtrSize)) < 0) {
        delete clntsock;
        exception[NetException::Error] << "Socket connect: can't connect to server aborting ";
        throw exception;
    }

    tcp *clntsock=new tcp();
    clntsock->_Socket=sock;
    return clntsock;
}


void netplus::tcp::getAddress(std::string &addr){
    char ipaddr[512];
    struct sockaddr sockaddr;
    socklen_t iplen = sizeof(struct sockaddr);
    memset(&sockaddr,0,iplen);
    getsockname(_Socket, (struct sockaddr *) &sockaddr, &iplen);
    inet_ntop(AF_UNSPEC, &sockaddr, ipaddr, sizeof(ipaddr));
    addr=ipaddr;
}

netplus::udp::udp(const netplus::udp& cudp){
    _Socket=cudp._Socket;
    if(_UxPath.empty()){
        _SocketPtr=new struct sockaddr_in;
        memcpy(_SocketPtr,cudp._SocketPtr,sizeof(struct sockaddr_in));
    }else{
        _SocketPtr=new struct sockaddr_un;
        memcpy(_SocketPtr,cudp._SocketPtr,sizeof(struct sockaddr_un));
    }

    _SocketPtrSize=cudp._SocketPtrSize;
}


netplus::udp::udp(const char* uxsocket,int maxconnections,int sockopts) : socket(){
    NetException exception;
    int optval = 1;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    _Maxconnections=maxconnections;

    _SocketPtr = new struct sockaddr_un;
    memset(_SocketPtr,0,sizeof(struct sockaddr_un));
    ((struct sockaddr_un *)_SocketPtr)->sun_family = AF_UNIX;
    if(!uxsocket){
        exception[NetException::Critical] << "Can't copy Server UnixSocket";
        throw exception;
    }
    _UxPath=uxsocket;
    memcpy(((struct sockaddr_un *)_SocketPtr)->sun_path,uxsocket,strlen(uxsocket)+1);

    if ((_Socket=::socket(AF_UNIX,SOCK_DGRAM, IPPROTO_UDP)) < 0){
        exception[NetException::Critical] << "Can't create UDP UnixSocket";
        throw exception;
    }

    setsockopt(_Socket,SOL_SOCKET,sockopts,&optval, sizeof(optval));

}

netplus::udp::udp(const char* addr, int port,int maxconnections,int sockopts) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;

    _SocketPtr = new struct sockaddr_in;
    memset(_SocketPtr, 0, sizeof(struct sockaddr_in));

    _SocketPtrSize=sizeof(struct sockaddr_in);

    struct addrinfo hints,*result,*rp;


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    int tsock;
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

        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;
        break;
    }

    ::freeaddrinfo(result);

    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
}

netplus::udp::~udp(){
    if(_Socket>=0)
        ::close(_Socket);
    if(!_UxPath.empty()){
        unlink(_UxPath.c_str());
        delete (struct sockaddr_un*)_SocketPtr;
    }else{
        delete (struct sockaddr_in*)_SocketPtr;
    }
}

netplus::udp::udp() : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
}


void netplus::udp::listen(){
    NetException exception;
    if(::listen(_Socket,_Maxconnections) < 0){
        exception[NetException::Critical] << "Can't listen Server Socket";
        throw exception;
    }
}

int netplus::udp::getMaxconnections(){
    return _Maxconnections;
}

netplus::socket *netplus::udp::accept(){
    NetException exception;
    socket *csock=new udp();
    csock->_Socket = ::accept(_Socket,(struct sockaddr *)csock->_SocketPtr,&csock->_SocketPtrSize);
    if(csock->_Socket<0){
        delete csock;
        csock=nullptr;
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    return csock;
}

void netplus::udp::bind(){
    NetException exception;
    if (::bind(_Socket,((const struct sockaddr *)_SocketPtr), sizeof(struct sockaddr)) < 0){
        exception[NetException::Error] << "Can't bind Server Socket";
        throw exception;
    }
}


unsigned int netplus::udp::sendData(socket* socket, void* data, unsigned long size){
    return sendData(socket,data,size,0);
}

unsigned int netplus::udp::sendData(socket* socket, void* data, unsigned long size,int flags){
    NetException exception;
    if(!socket){
        exception[NetException::Error] << "Socket sendata failed invalid socket !";
        throw exception;
    }
    int rval=::send(socket->_Socket,
                        data,
                        size,
                        flags
                     );
    if(rval<0){
        if(errno==EAGAIN)
            return 0;
        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket;
        throw exception;
    }
    return rval;
}


unsigned int netplus::udp::recvData(socket* socket, void* data, unsigned long size){
    return recvData(socket,data,size,0);
}

unsigned int netplus::udp::recvData(socket* socket, void* data, unsigned long size,int flags){
    NetException exception;
    if(!socket){
        exception[NetException::Error] << "Socket recvdata failed invalid socket!";
        throw exception;
    }
    int recvsize=::recv(socket->_Socket,
                            data,
                            size,
                            flags
                         );
    if(recvsize<0){
        if(errno==EAGAIN)
            return 0;
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;
}

netplus::udp* netplus::udp::connect(){
    NetException exception;
    int sock=0;
    if ((sock=::connect(_Socket, (struct sockaddr*)_SocketPtr, sizeof(struct sockaddr))) < 0) {
        exception[NetException::Error] << "Socket connect: can't connect to server aborting ";
        throw exception;
    }
    udp *clntsock=new udp();
    clntsock->_Socket=sock;
    return clntsock;
}

void netplus::udp::getAddress(std::string &addr){
    char ipaddr[512];
    struct sockaddr_in sockaddr;
    socklen_t iplen = sizeof(sockaddr);
    bzero(&sockaddr, sizeof(sockaddr));
    getsockname(_Socket, (struct sockaddr *) &sockaddr, &iplen);
    inet_ntop(AF_INET, &sockaddr.sin_addr, ipaddr, sizeof(ipaddr));
    addr=ipaddr;
}

netplus::ssl::ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *cert,
              size_t certlen,const unsigned char *key, size_t keylen) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    
    _SocketPtr = new struct sockaddr_in;
    memset(_SocketPtr, 0, sizeof(struct sockaddr_in));

    _SocketPtrSize=sizeof(struct sockaddr_in);

    struct addrinfo hints,*result,*rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    int tsock;

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

        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;
        break;
    }

    ::freeaddrinfo(result);
    
    
    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
    
    _Cert = new cryptplus::x509(cert,certlen);
    write(1,key,keylen);
    
}

netplus::ssl::ssl(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
}

netplus::ssl::~ssl(){
    delete _Cert;
    delete (struct sockaddr_in*)_SocketPtr;
    close(_Socket);
}

netplus::socket *netplus::ssl::accept(){
    NetException exception;
    socket *csock=new ssl();
    csock->_Socket = ::accept(_Socket,(struct sockaddr *)csock->_SocketPtr,
                          &csock->_SocketPtrSize);
    if(csock->_Socket<0){
        delete csock;
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    return csock;
}

void netplus::ssl::bind(){
    NetException exception;
    if (::bind(_Socket,((const struct sockaddr *)_SocketPtr), sizeof(struct sockaddr)) < 0){
        exception[NetException::Error] << "Can't bind Server Socket";
        throw exception;
    }
}

void netplus::ssl::listen(){
    NetException httpexception;
    if(::listen(_Socket,_Maxconnections) < 0){
        httpexception[NetException::Critical] << "Can't listen Server Socket";
        throw httpexception;
    }  
}

int netplus::ssl::getMaxconnections(){
    return _Maxconnections;
}
     
unsigned int netplus::ssl::sendData(socket *socket,void *data,unsigned long size){
    return sendData(socket,data,size,0);
}

unsigned int netplus::ssl::sendData(socket *socket,void *data,unsigned long size,int flags){
    NetException exception;
    if(!socket){                                                                                     
        exception[NetException::Error] << "Socket sendata failed invalid socket !";
        throw exception;                                                                             
    }   
    int rval=::sendto(socket->_Socket,
                        data,
                        size,
                        flags,
                        (const struct sockaddr *)&socket->_SocketPtr,
                        socket->_SocketPtrSize
                     );
    if(rval<0){
        if(errno==EAGAIN)
            return 0;
        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket;
        throw exception;
    }
    return rval;
}

unsigned int netplus::ssl::recvData(socket *socket,void *data,unsigned long size){
    return recvData(socket,data,size,0);
}

unsigned int netplus::ssl::recvData(socket *socket,void *data,unsigned long size,int flags){
    NetException exception;
    if(!socket){
        exception[NetException::Error] << "Socket recvdata failed invalid socket!";
        throw exception;        
    }
    int recvsize=::recvfrom(socket->_Socket,
                            data,
                            size,
                            flags,
                            (struct sockaddr *)socket->_SocketPtr,
                            &socket->_SocketPtrSize
                         );
    if(recvsize<0){
        if(errno==EAGAIN)
            return 0;
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;    
}

netplus::ssl* netplus::ssl::connect(){
    NetException exception;
    int sock=0;
    if ((sock=::connect(_Socket, (struct sockaddr*)_SocketPtr, sizeof(struct sockaddr))) < 0) {
        exception[NetException::Error] << "Socket connect: can't connect to server aborting ";
        throw exception;
    }
    ssl *clntsock=new ssl();
    clntsock->_Socket=sock;
    return clntsock;
}

void netplus::ssl::getAddress(std::string &addr){
    char ipaddr[512];
    struct sockaddr_in sockaddr;
    socklen_t iplen = sizeof(sockaddr);
    bzero(&sockaddr, sizeof(sockaddr));
    getsockname(_Socket, (struct sockaddr *) &sockaddr, &iplen);
    inet_ntop(AF_INET, &sockaddr.sin_addr, ipaddr, sizeof(ipaddr));
    addr=ipaddr;
}

//             size_t        version;
//             size_t        serial;
//             size_t        signature_id;
//             array<char>   issuer_name;
//             time          notbefore;
//             time          notafter;
//             array<char>   subject;
//             struct public_key_info {
//                 array<char> algorithm;
//                 array<char> public_key;
//             };
//             array<char>   signature_algorithm;
//             array<char>   signature;


