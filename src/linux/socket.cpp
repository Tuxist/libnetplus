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

#include <vector>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <mutex>

#include "exception.h"
#include "socket.h"

#define HIDDEN __attribute__ ((visibility ("hidden")))

HIDDEN std::mutex        _tcpmutex;
HIDDEN std::vector<int>  _tcplock;

HIDDEN void addlock_tcp(int socket){
    const std::lock_guard<std::mutex> lock(_tcpmutex);
    _tcplock.push_back(socket);
}

HIDDEN bool _rmlock_tcp(int socket){
    const std::lock_guard<std::mutex> lock(_tcpmutex);
    int rm=-1;
    for (auto it = std::begin(_tcplock); it!=std::end(_tcplock); ++it){
        if(*it && *it==socket){
            if(rm==-1){
                _tcplock.erase(it);
                it = std::begin(_tcplock);
            }
            ++rm;
        }
    }
    if(rm == 0)
        return true;
    return false;
}


HIDDEN std::mutex        _udpmutex;
HIDDEN std::vector<int>  _udplock;

HIDDEN void addlock_udp(int socket){
    const std::lock_guard<std::mutex> lock(_udpmutex);
    _udplock.push_back(socket);
}

HIDDEN bool _rmlock_udp(int socket){
    const std::lock_guard<std::mutex> lock(_udpmutex);
    int rm=-1;
    for (auto it = std::begin(_udplock); it!=std::end(_udplock); ++it){
        if(*it && *it==socket){
            if(rm==-1){
                _udplock.erase(it);
                it = std::begin(_udplock);
            }
            ++rm;
        }
    }
    if(rm == 0)
        return true;
    return false;
}


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
    _SocketPtr=ctcp._SocketPtr;
    _SocketPtrSize=ctcp._SocketPtrSize;
    addlock_tcp(_Socket);
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
    _SocketPtrSize=sizeof(sockaddr_un);
    setsockopt(_Socket,SOL_SOCKET,sockopts,&optval, sizeof(optval));
    addlock_tcp(_Socket);
}

netplus::tcp::tcp(const char* addr, int port,int maxconnections,int sockopts) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    


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

    if ((tsock=::getaddrinfo(addr, serv,&hints,&result)) < 0) {
        exception[NetException::Critical] << "Socket Invalid address/ Address not supported";
        throw exception;
    }

    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        _Socket = ::socket(rp->ai_family, rp->ai_socktype,
                           rp->ai_protocol);
        if (_Socket == -1)
            continue;
        _SocketPtr = operator new(rp->ai_addrlen);
        memset(_SocketPtr, 0, rp->ai_addrlen);
        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;

        break;
    }

    ::freeaddrinfo(result);
    
    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
    addlock_tcp(_Socket);
}
                                        
netplus::tcp::~tcp(){
    if(_rmlock_tcp(_Socket)){
        if(_Socket>=0)
            ::close(_Socket);
        operator delete(_SocketPtr,&_SocketPtr);
    }
}

netplus::tcp::tcp(int sock) : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=sock;
    addlock_tcp(_Socket);
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
    struct sockaddr myaddr;
    socklen_t myaddrlen=sizeof(myaddr);
    int sock = ::accept(_Socket,(struct sockaddr *)&myaddr,&myaddrlen);
    if(sock<0){
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    socket *csock=new tcp(sock);
    csock->_SocketPtrSize = myaddrlen;
    csock->_SocketPtr = operator new(myaddrlen);
    memcpy(csock->_SocketPtr,&myaddr,myaddrlen);
    return csock;
}

void netplus::tcp::bind(){
    NetException exception;
    if (::bind(_Socket,((const struct sockaddr *)_SocketPtr), _SocketPtrSize) < 0){
        exception[NetException::Error] << "Can't bind Server Socket";
        throw exception;
    }
}


unsigned int netplus::tcp::sendData(socket* socket, void* data, unsigned long size){
    return sendData(socket,data,size,0);
}

unsigned int netplus::tcp::sendData(socket* socket, void* data, unsigned long size,int flags){
TCPSEND:
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
        if(errno==EAGAIN){
            sleep(1);
            goto TCPSEND;
        }

#ifdef _GNU_SOURCE
        char buf[512];
        char *errstr=strerror_r(errno,buf,512);
#else
        char errstr[512];
        strerror_r(errno,errstr,512);
#endif
        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket
                                       << " ErrorMsg: " <<  errstr;
        throw exception;
    }
    return rval;
}


unsigned int netplus::tcp::recvData(socket* socket, void* data, unsigned long size){
    return recvData(socket,data,size,0);
}

unsigned int netplus::tcp::recvData(socket* socket, void* data, unsigned long size,int flags){
TCPRECV:
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
            goto TCPRECV;


#ifdef _GNU_SOURCE
        char buf[512];
        char *errstr=strerror_r(errno,buf,512);
#else
        char errstr[512];
        strerror_r(errno,errstr,512);
#endif

        exception[NetException::Error] << "Socket recvdata failed on Socket: " << socket->_Socket
                                       << " ErrorMsg: " <<  errstr;
        throw exception;
    }
    return recvsize;
}

netplus::tcp* netplus::tcp::connect(){
    NetException exception;
    int sock=0;
    if ( ::connect(sock,(struct sockaddr*)_SocketPtr,_SocketPtrSize) < 0) {
#ifdef _GNU_SOURCE
        char buf[512];
        char *errstr=strerror_r(errno,buf,512);
#else
        char errstr[512];
        strerror_r(errno,errstr,512);
#endif
        exception[NetException::Error] << "Socket connect: can't connect to server aborting " << " ErrorMsg:" << errstr;
        throw exception;
    }
    tcp *clntsock=new tcp(sock);
    return clntsock;
}


void netplus::tcp::getAddress(std::string &addr){
    if(!_SocketPtr)
        return;
    char ipaddr[INET6_ADDRSTRLEN];
    if(((struct sockaddr*)_SocketPtr)->sa_family==AF_INET6)
        inet_ntop(AF_INET6, &(((struct sockaddr_in6*)_SocketPtr)->sin6_addr), ipaddr, INET6_ADDRSTRLEN);
    else
        inet_ntop(AF_INET, &((struct sockaddr_in*)_SocketPtr)->sin_addr, ipaddr, INET_ADDRSTRLEN);
    addr=ipaddr;
}

netplus::udp::udp(const netplus::udp& cudp){
    _Socket=cudp._Socket;
    _SocketPtr=cudp._SocketPtr;
    _SocketPtrSize=cudp._SocketPtrSize;
    addlock_udp(_Socket);
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
    addlock_udp(_Socket);
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
        _SocketPtr = operator new(rp->ai_addrlen);
        memset(_SocketPtr, 0, rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;
        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        break;
    }

    ::freeaddrinfo(result);

    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
    addlock_udp(_Socket);
}

netplus::udp::~udp(){
    if(_rmlock_udp(_Socket)){
        if(_Socket>=0)
            ::close(_Socket);
        if(!_UxPath.empty()){
            unlink(_UxPath.c_str());
        }
        operator delete(_SocketPtr,&_SocketPtrSize);
    }
}

netplus::udp::udp(int sock) : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=sock;
    addlock_udp(_Socket);
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
    struct sockaddr_storage myaddr;
    socklen_t myaddrlen;
    int sock = ::accept(_Socket,(struct sockaddr *)&myaddr,&myaddrlen);
    if(sock<0){
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    socket *csock=new udp(sock);
    csock->_SocketPtrSize = myaddrlen;
    csock->_SocketPtr = operator new(myaddrlen);
    memcpy(csock->_SocketPtr,&myaddr,myaddrlen);
    return csock;
}

void netplus::udp::bind(){
    NetException exception;
    if (::bind(_Socket,((const struct sockaddr *)_SocketPtr), _SocketPtrSize) < 0){
        exception[NetException::Error] << "Can't bind Server Socket";
        throw exception;
    }
}


unsigned int netplus::udp::sendData(socket* socket, void* data, unsigned long size){
    return sendData(socket,data,size,0);
}

unsigned int netplus::udp::sendData(socket* socket, void* data, unsigned long size,int flags){
UDPSEND:
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
        if(errno==EAGAIN){
            sleep(1);
            goto UDPSEND;
        }
        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket;
        throw exception;
    }
    return rval;
}


unsigned int netplus::udp::recvData(socket* socket, void* data, unsigned long size){
    return recvData(socket,data,size,0);
}

unsigned int netplus::udp::recvData(socket* socket, void* data, unsigned long size,int flags){
UDPRECV:
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
        if(errno==EAGAIN){
            sleep(1);
            goto UDPRECV;
        }
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;
}

netplus::udp* netplus::udp::connect(){
    NetException exception;
    int sock=0;
    if ( ::connect(sock,(struct sockaddr*)_SocketPtr,_SocketPtrSize) < 0) {
        exception[NetException::Error] << "Socket connect: can't connect to server aborting ";
        throw exception;
    }
    udp *clntsock=new udp(sock);
    return clntsock;
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

netplus::ssl::ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *cert,
              size_t certlen,const unsigned char *key, size_t keylen) : socket() {
   NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;



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

    if ((tsock=::getaddrinfo(addr, serv,&hints,&result)) < 0) {
        exception[NetException::Critical] << "Socket Invalid address/ Address not supported";
        throw exception;
    }

    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        _Socket = ::socket(rp->ai_family, rp->ai_socktype,
                           rp->ai_protocol);
        if (_Socket == -1)
            continue;
        _SocketPtr = operator new(rp->ai_addrlen);
        memset(_SocketPtr, 0, rp->ai_addrlen);
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
    close(_Socket);
    operator delete(_SocketPtr,&_SocketPtrSize);
}

netplus::socket *netplus::ssl::accept(){
    NetException exception;
    socket *csock=new ssl();
    struct sockaddr_storage myaddr;
    socklen_t myaddrlen;
    csock->_Socket = ::accept(_Socket,(struct sockaddr *)&myaddr,&myaddrlen);
    if(csock->_Socket<0){
        delete csock;
        csock=nullptr;
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    csock->_SocketPtrSize = myaddrlen;
    csock->_SocketPtr = operator new(myaddrlen);
    memcpy(csock->_SocketPtr,&myaddr,myaddrlen);
    return csock;
}

void netplus::ssl::bind(){
    NetException exception;
    if (::bind(_Socket,((const struct sockaddr *)_SocketPtr), _SocketPtrSize) < 0){
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
SSLSEND:
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
        if(errno==EAGAIN){
            sleep(1);
            goto SSLSEND;
        }
        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket;
        throw exception;
    }
    return rval;
}

unsigned int netplus::ssl::recvData(socket *socket,void *data,unsigned long size){
    return recvData(socket,data,size,0);
}

unsigned int netplus::ssl::recvData(socket *socket,void *data,unsigned long size,int flags){
SSLRECV:
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
        if(errno==EAGAIN){
            sleep(1);
            goto SSLRECV;
        }
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;    
}

netplus::ssl* netplus::ssl::connect(){
    NetException exception;
    int sock=0;
    if ( (sock=::connect(_Socket,(struct sockaddr*)_SocketPtr,_SocketPtrSize)) < 0) {
        exception[NetException::Error] << "Socket connect: can't connect to server aborting ";
        throw exception;
    }
    ssl *clntsock=new ssl();
    clntsock->_Socket=sock;
    return clntsock;
}

void netplus::ssl::getAddress(std::string &addr){
    if(!_SocketPtr)
        return;
    char ipaddr[INET6_ADDRSTRLEN];
    if(((struct sockaddr*)_SocketPtr)->sa_family==AF_INET6)
        inet_ntop(AF_INET6, &(((struct sockaddr_in6*)_SocketPtr)->sin6_addr), ipaddr, INET6_ADDRSTRLEN);
    else
        inet_ntop(AF_INET, &((struct sockaddr_in*)_SocketPtr)->sin_addr, ipaddr, INET_ADDRSTRLEN);
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


