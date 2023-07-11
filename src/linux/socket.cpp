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

#include "exception.h"
#include "socket.h"


netplus::socket::socket(){
    _Socket=-1;
    _SocketPtr = new struct sockaddr;
    _SocketPtrSize=sizeof(sockaddr);
    bzero(_SocketPtr,_SocketPtrSize);
}

netplus::socket::~socket(){
    close(_Socket);
    delete (struct sockaddr*)_SocketPtr;
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


netplus::tcp::tcp(const char* uxsocket,int maxconnections,int sockopts) : socket(){
    NetException exception;
    int optval = 1;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    _Maxconnections=maxconnections;
    struct sockaddr_un usock{0};
    usock.sun_family = AF_UNIX;
    if(!uxsocket){
        exception[NetException::Critical] << "Can't copy Server UnixSocket";
        throw exception;
    }
    _UxPath=uxsocket;
    memcpy(usock.sun_path,uxsocket,strlen(uxsocket)+1);
    
    if ((_Socket=::socket(AF_UNIX,SOCK_STREAM, IPPROTO_TCP)) < 0){
        exception[NetException::Critical] << "Can't create Socket UnixSocket";
        throw exception;
    }
    
    setsockopt(_Socket,SOL_SOCKET,sockopts,&optval, sizeof(optval));
    
    if (::bind(_Socket,((const struct sockaddr *)&usock), sizeof(struct sockaddr_un)) < 0){
        exception[NetException::Error] << "Can't bind Server UnixSocket";
        throw exception;
    }
}

netplus::tcp::tcp(const char* addr, int port,int maxconnections,int sockopts) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    
    _Socket = ::socket(AF_INET,SOCK_STREAM,0);
    
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    
    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
    
    ::bind(_Socket,((const struct sockaddr *)&address),sizeof(address));
    
    if(_Socket <0){
        exception[NetException::Critical] << "Could not bind serversocket";
        throw exception;
    }
}
                                        
netplus::tcp::~tcp(){
    ::close(_Socket);
    if(!_UxPath.empty()){
        unlink(_UxPath.c_str());
    }
}

netplus::tcp::tcp() : socket(){
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
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    return csock;
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
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;
}

netplus::ssl::ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *cert,
              size_t certlen,const unsigned char *key, size_t keylen) : socket() {
    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;
    
    _Socket = ::socket(AF_INET,SOCK_STREAM,0);
    
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    
    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
    
    ::bind(_Socket,((const struct sockaddr *)&address),sizeof(address));
    
    if(_Socket <0){
        exception[NetException::Critical] << "Could not bind serversocket";
        throw exception;
    }
    
    _Cert = new cryptplus::x509(cert,certlen);
    write(1,key,keylen);
    
}

netplus::ssl::ssl(){
    
}

netplus::ssl::~ssl(){
    delete _Cert;
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
                        (const struct sockaddr *)socket->_SocketPtr,
                        socket->_SocketPtrSize
                     );
    if(rval<0){
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
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;    
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


