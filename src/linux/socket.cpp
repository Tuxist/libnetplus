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
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>

#include "exception.h"
#include "socket.h"

#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#define HIDDEN __attribute__ ((visibility ("hidden")))

netplus::socket::socket(){
    _Socket=-1;
    _Locked=0;
    _SocketPtr=nullptr;
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

netplus::tcp::tcp(const netplus::tcp& ctcp){
    _Locked++;
    _Socket=ctcp._Socket;
    _SocketPtr=ctcp._SocketPtr;
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
    _SocketPtrSize=sizeof(sockaddr_un);
    setsockopt(_Socket,SOL_SOCKET,sockopts,&optval, sizeof(optval));
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
        _SocketPtr = std::malloc(rp->ai_addrlen);
        memset(_SocketPtr, 0, rp->ai_addrlen);
        memcpy(_SocketPtr,rp->ai_addr,rp->ai_addrlen);
        _SocketPtrSize=rp->ai_addrlen;

        break;
    }

    ::freeaddrinfo(result);
    
    int optval = 1;
    setsockopt(_Socket, SOL_SOCKET, sockopts,&optval,sizeof(optval));
}
                                        
netplus::tcp::~tcp(){
    if(_Locked==0){
       if(_Socket>=0)
          ::close(_Socket);
       ::free(_SocketPtr);
    }else{
        --_Locked;
    }
}

netplus::tcp::tcp(int sock) : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=sock;
}


void netplus::tcp::listen(){
    NetException exception;
    if(::listen(_Socket,_Maxconnections) < 0){
        exception[NetException::Critical] << "Can't listen Server Socket";
        throw exception;
    }
}

int netplus::tcp::fd(){
    return _Socket;
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
            return 0;
        }

        char errstr[512];
        strerror_r(errno,errstr,512);

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


        char errstr[512];
        strerror_r(errno,errstr,512);

        exception[NetException::Error] << "Socket recvdata failed on Socket: " << socket->_Socket
                                       << " ErrorMsg: " <<  errstr;
        throw exception;
    }
    return recvsize;
}

netplus::tcp* netplus::tcp::connect(){
    NetException exception;
    tcp *clntsock=new tcp(0);

    clntsock->_Socket=::socket(((struct sockaddr*)_SocketPtr)->sa_family,SOCK_STREAM,0);

    if ( ::connect(clntsock->_Socket,(struct sockaddr*)_SocketPtr,_SocketPtrSize) < 0) {
        delete clntsock;

        char errstr[512];
        strerror_r(errno,errstr,512);

        exception[NetException::Error] << "Socket connect: can't connect to server aborting " << " ErrorMsg:" << errstr;
        throw exception;
    }
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
    _Locked++;
    _Socket=cudp._Socket;
    _SocketPtr=cudp._SocketPtr;
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
    _SocketPtrSize=sizeof(sockaddr_un);
    setsockopt(_Socket,SOL_SOCKET,sockopts,&optval, sizeof(optval));
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
}

netplus::udp::~udp(){
    if(_Locked==0){
        if(_Socket>=0)
            ::close(_Socket);
        operator delete(_SocketPtr,&_SocketPtrSize);
    }else{
        --_Locked;
    }
}

netplus::udp::udp(int sock) : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=sock;
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
            return 0;
        }
        char errstr[512];
        strerror_r(errno,errstr,512);

        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket
                                       << " ErrorMsg: " <<  errstr;

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
        if(errno==EAGAIN){
            return 0;
        }
        char errstr[512];
        strerror_r(errno,errstr,512);

        exception[NetException::Error] << "Socket recvData failed on Socket: " << socket->_Socket
                                       << " ErrorMsg: " <<  errstr;
        throw exception;
    }
    return recvsize;
}

netplus::udp* netplus::udp::connect(){
    NetException exception;
    udp *clntsock=new udp(0);

    clntsock->_Socket=::socket(((struct sockaddr*)_SocketPtr)->sa_family,SOCK_DGRAM,0);

    if ( ::connect(clntsock->_Socket,(struct sockaddr*)_SocketPtr,_SocketPtrSize) < 0) {
        delete clntsock;

        char errstr[512];
        strerror_r(errno,errstr,512);

        exception[NetException::Error] << "Socket connect: can't connect to server aborting " << " ErrorMsg:" << errstr;
        throw exception;
    }
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


    mbedtls_net_init( &_Socket );
    mbedtls_ssl_init( &_SSLCtx );
    mbedtls_ssl_config_init( &_SSLConf );
    mbedtls_x509_crt_init( &_Cacert );
    mbedtls_ctr_drbg_init( &_SSLCTR_DRBG );
    mbedtls_entropy_init( &_SSLEntropy );

    int ret;
    char err_str[256];

    if ((ret = mbedtls_ssl_config_defaults(&_SSLConf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "failed: mbedtls_ssl_config_defaults returned: " << err_str;
        throw exception;
    }

    mbedtls_ssl_conf_rng(&_SSLConf, mbedtls_ctr_drbg_random, &_SSLCTR_DRBG);

    const char *pers = "libnet_ssl_server";

    size_t use_len;

    if( ( ret = mbedtls_ctr_drbg_seed( &_SSLCTR_DRBG, mbedtls_entropy_func, &_SSLEntropy,
                                        (const unsigned char *) pers,
                                        strlen( pers ) ) ) != 0 ){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "mbedtls_ctr_drbg_seed returned: " << err_str;
        throw exception;
    }

    mbedtls_pem_context pm;
    mbedtls_pem_init(&pm);

    if( ( ret = mbedtls_pem_read_buffer(&pm,"-----BEGIN CERTIFICATE-----","-----END CERTIFICATE-----",cert,nullptr,0,&use_len) ) != 0 ){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "mbedtls_pem_read_buffer returned: " << err_str ;
        throw exception;
    }

    if( ( ret = mbedtls_x509_crt_parse(&_Cacert,pm.private_buf,pm.private_buflen ) )  != 0 ){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "mbedtls_x509_crt_parse returned: " << err_str ;
        throw exception;
    }

    mbedtls_pem_free(&pm);

    mbedtls_pk_context pkey;
    mbedtls_pk_init(&pkey);
    ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) key,
                                keylen, nullptr, 0,
                                mbedtls_ctr_drbg_random, &_SSLCTR_DRBG);
    if (ret != 0) {
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] <<  " failed\n  !  mbedtls_pk_parse_key returned" << err_str;
        throw exception;
    }

    mbedtls_pk_free(&pkey);

    memset(_Addr,0,255);

    if(strlen(addr)<255){
        memcpy(_Addr,addr,strlen(addr)+1);
    }else{
        exception[NetException::Critical] <<"Addr too long can't copy !";
        throw exception;
    }

    _Port=port;

}

netplus::ssl::ssl(){
    mbedtls_net_init( &_Socket );
    mbedtls_ssl_init( &_SSLCtx );
    mbedtls_ssl_config_init( &_SSLConf );
    mbedtls_x509_crt_init( &_Cacert );
    mbedtls_ctr_drbg_init( &_SSLCTR_DRBG );
}

netplus::ssl::~ssl(){
    mbedtls_net_free(&_Socket);
    mbedtls_ssl_free(&_SSLCtx);
    mbedtls_ssl_config_free(&_SSLConf);
    mbedtls_ctr_drbg_free(&_SSLCTR_DRBG);
    mbedtls_entropy_free(&_SSLEntropy);
}

netplus::socket *netplus::ssl::accept(){
    NetException exception;
    ssl *csock=new ssl();

    int ret;
    char err_str[256];

    mbedtls_ssl_set_bio(&csock->_SSLCtx,&csock->_Socket, mbedtls_net_send, mbedtls_net_recv, NULL);

    if( (ret=mbedtls_ssl_setup(&csock->_SSLCtx,&csock->_SSLConf)) <0){
        delete csock;
        csock=nullptr;
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Error] << "Can't setup on Socket: " << err_str;
        throw exception;
    }


    if( (ret=mbedtls_net_accept(&_Socket,&csock->_Socket,nullptr,0,nullptr)) <0){
        delete csock;
        csock=nullptr;
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Error] << "Can't accept on Socket: " << err_str;
        throw exception;
    }

    while ((ret = mbedtls_ssl_handshake(&csock->_SSLCtx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            delete csock;
            csock=nullptr;
            mbedtls_strerror(ret, err_str, 256);
            exception[NetException::Error] << "Can't accept on Socket: " << err_str;
            throw exception;
        }
    }

    return csock;
}

void netplus::ssl::bind(){
    NetException exception;
    int ret=0;
    char port[255];
    snprintf(port,255,"%d",_Port);
    if ((ret = mbedtls_net_bind(&_Socket,_Addr,port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        exception[NetException::Error] << " failed\n  ! mbedtls_net_bind returned" << ret;
        throw exception;
    }
}

void netplus::ssl::listen(){
    //not needed beause mbedtls_net_bind bind and listen in one funciton
    return;
}

int netplus::ssl::fd(){
    return _Socket.fd;
}

int netplus::ssl::getMaxconnections(){
    return _Maxconnections;
}
     
unsigned int netplus::ssl::sendData(socket *socket,void *data,unsigned long size){
    NetException exception;
    if(!socket){
        exception[NetException::Error] << "Socket sendata failed invalid socket !";
        throw exception;
    }
    int rval=::mbedtls_ssl_write(&_SSLCtx,(unsigned char*)data,size);
    if(rval<0){
        if(errno==EAGAIN){
            return 0;
        }
        exception[NetException::Error] << "Socket senddata failed on Socket: " << socket->_Socket;
        throw exception;
    }
    return rval;}

unsigned int netplus::ssl::recvData(socket *socket,void *data,unsigned long size){
    NetException exception;
    if(!socket){
        exception[NetException::Error] << "Socket recvdata failed invalid socket!";
        throw exception;
    }
    int recvsize=::mbedtls_ssl_read(&_SSLCtx,(unsigned char*)data,size);
    if(recvsize<0){
        if(errno==EAGAIN){
            return 0;
        }
        exception[NetException::Error] << "Socket recvdata failed on Socket: "
                                          << socket->_Socket;
        throw exception;
    }
    return recvsize;
}

netplus::ssl* netplus::ssl::connect(){
    NetException exception;

    char port[255];
    snprintf(port,255,"%d",_Port);

    if ( mbedtls_net_connect(&_Socket,_Addr,port,MBEDTLS_NET_PROTO_TCP) < 0) {
        exception[NetException::Error] << "Socket connect: can't connect to server aborting !";
        throw exception;
    }

    mbedtls_ssl_set_bio(&_SSLCtx,&_Socket, mbedtls_net_send, mbedtls_net_recv, NULL);

    int ret;

    while ((ret = mbedtls_ssl_handshake(&_SSLCtx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            exception[NetException::Error] << "Can't connect on Socket";
            throw exception;
        }
    }

    return this;
}

void netplus::ssl::setnonblocking(){
    if(mbedtls_net_set_nonblock(&_Socket)<0){
        NetException exception;
        exception[NetException::Error] << "Could not set ClientSocket nonblocking!";
        throw exception;
    }
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


