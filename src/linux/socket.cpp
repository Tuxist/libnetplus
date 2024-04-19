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

extern "C" {
    #include "mbedtls/net_sockets.h"
    #include "mbedtls/ssl.h"
    #include "mbedtls/ctr_drbg.h"
    #include "mbedtls/entropy.h"
    #include "mbedtls/pem.h"
    #include <mbedtls/debug.h>
    #include <mbedtls/error.h>
    #include <mbedtls/platform.h>
}

#define HIDDEN __attribute__ ((visibility ("hidden")))

netplus::socket::socket(){
    _Socket=-1;
    _Locked=0;
    _SocketPtr=nullptr;
    _Type=-1;
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
    _Type=sockettype::TCP;
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
    _Type=sockettype::TCP;
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
    _Type=sockettype::TCP;
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

netplus::tcp::tcp() : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=-1;
    _Type=sockettype::TCP;
}

netplus::tcp::tcp(int sock) : socket(){
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=sock;
    _Type=sockettype::TCP;
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

void netplus::tcp::accept(socket *csock){
    NetException exception;
    struct sockaddr myaddr;
    socklen_t myaddrlen=sizeof(myaddr);
    int sock = ::accept(_Socket,(struct sockaddr *)&myaddr,&myaddrlen);
    if(sock<0){
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    socket *ccsock=csock;
    ccsock->_SocketPtrSize = myaddrlen;
    ccsock->_SocketPtr = operator new(myaddrlen);
    memcpy(ccsock->_SocketPtr,&myaddr,myaddrlen);
    csock=ccsock;
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


netplus::udp::udp() : socket() {
    _SocketPtr=nullptr;
    _SocketPtrSize=0;
    _Socket=-1;
    _Type=sockettype::UDP;
}

netplus::udp::udp(const netplus::udp& cudp) : socket(){
    _Locked++;
    _Socket=cudp._Socket;
    _SocketPtr=cudp._SocketPtr;
    _SocketPtrSize=cudp._SocketPtrSize;
    _Type=sockettype::UDP;
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
    _Type=sockettype::UDP;
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
    _Type=sockettype::UDP;
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

int netplus::udp::getMaxconnections(){
    return _Maxconnections;
}

void netplus::udp::accept(socket *csock){
    NetException exception;
    struct sockaddr_storage myaddr;
    socklen_t myaddrlen;
    int sock = ::accept(_Socket,(struct sockaddr *)&myaddr,&myaddrlen);
    if(sock<0){
        exception[NetException::Error] << "Can't accept on Socket";
        throw exception;
    }
    socket *ccsock=(udp*)csock;
    ccsock->_SocketPtrSize = myaddrlen;
    ccsock->_SocketPtr = operator new(myaddrlen);
    memcpy(ccsock->_SocketPtr,&myaddr,myaddrlen);
    csock=ccsock;
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

namespace netplus {
    struct HIDDEN SSLPrivate {
            mbedtls_net_context      _Socket;
            mbedtls_entropy_context  _SSLEntropy;
            mbedtls_ctr_drbg_context _SSLCTR_DRBG;
            mbedtls_ssl_context      _SSLCtx;
            mbedtls_ssl_config       _SSLConf;
            mbedtls_x509_crt         _Cacert;
            mbedtls_pk_context       _SSLPKey;
    };
};

netplus::ssl::ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *cert,
              size_t certlen,const unsigned char *key, size_t keylen) : ssl() {

    NetException exception;
    _Maxconnections=maxconnections;
    if(sockopts == -1)
        sockopts=SO_REUSEADDR;

    int ret;
    char err_str[256];

    if ((ret = mbedtls_ssl_config_defaults(&((SSLPrivate*)_SSLPrivate)->_SSLConf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "failed: mbedtls_ssl_config_defaults returned: " << err_str;
        throw exception;
    }

    const char *pers = "libnet_ssl_server";

    size_t use_len;

    if( ( ret = mbedtls_ctr_drbg_seed( &((SSLPrivate*)_SSLPrivate)->_SSLCTR_DRBG, mbedtls_entropy_func, &((SSLPrivate*)_SSLPrivate)->_SSLEntropy,
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

    if( ( ret = mbedtls_x509_crt_parse(&((SSLPrivate*)_SSLPrivate)->_Cacert,pm.private_buf,pm.private_buflen ) )  != 0 ){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "mbedtls_x509_crt_parse returned: " << err_str ;
        throw exception;
    }

    mbedtls_ssl_conf_ca_chain(&((SSLPrivate*)_SSLPrivate)->_SSLConf,&((SSLPrivate*)_SSLPrivate)->_Cacert,nullptr);

    if (mbedtls_ssl_conf_own_cert(&((SSLPrivate*)_SSLPrivate)->_SSLConf,&((SSLPrivate*)_SSLPrivate)->_Cacert, &((SSLPrivate*)_SSLPrivate)->_SSLPKey) != 0){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "mbedtls_ssl_conf_own_cert returned: " << err_str ;
        throw exception;
    }

    mbedtls_pem_free(&pm);

    ret =  mbedtls_pk_parse_key(&((SSLPrivate*)_SSLPrivate)->_SSLPKey, (const unsigned char *) key,
                                keylen, nullptr, 0,
                                mbedtls_ctr_drbg_random, &((SSLPrivate*)_SSLPrivate)->_SSLCTR_DRBG);
    if (ret != 0) {
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] <<  "mbedtls_pk_parse_key returned: " << err_str;
        throw exception;
    }


    mbedtls_ssl_set_bio(&((SSLPrivate*)_SSLPrivate)->_SSLCtx,&_Socket, mbedtls_net_send, mbedtls_net_recv, nullptr);

    mbedtls_ssl_conf_rng(&((SSLPrivate*)_SSLPrivate)->_SSLConf, mbedtls_ctr_drbg_random, &((SSLPrivate*)_SSLPrivate)->_SSLCTR_DRBG);

    if (mbedtls_ssl_conf_own_cert(&((SSLPrivate*)_SSLPrivate)->_SSLConf, &((SSLPrivate*)_SSLPrivate)->_Cacert, &((SSLPrivate*)_SSLPrivate)->_SSLPKey) != 0){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] <<  "mbedtls_ssl_conf_own_cert returned: " << err_str;
        throw exception;
    }

    memset(_Addr,0,255);

    if(strlen(addr)<255){
        memcpy(_Addr,addr,strlen(addr)+1);
    }else{
        exception[NetException::Critical] <<"Addr too long can't copy !";
        throw exception;
    }

    _Port=port;
    _Type=sockettype::SSL;
}

netplus::ssl::ssl() : socket(){
     _SSLPrivate = new SSLPrivate;
     _Type=sockettype::SSL;
    mbedtls_net_init( &((SSLPrivate*)_SSLPrivate)->_Socket );
    mbedtls_ssl_init( &((SSLPrivate*)_SSLPrivate)->_SSLCtx );
    mbedtls_ssl_config_init( &((SSLPrivate*)_SSLPrivate)->_SSLConf );
    mbedtls_x509_crt_init( &((SSLPrivate*)_SSLPrivate)->_Cacert );
    mbedtls_ctr_drbg_init( &((SSLPrivate*)_SSLPrivate)->_SSLCTR_DRBG );
    mbedtls_entropy_init( &((SSLPrivate*)_SSLPrivate)->_SSLEntropy );
    mbedtls_pk_init(&((SSLPrivate*)_SSLPrivate)->_SSLPKey);
}

netplus::ssl::~ssl(){
    mbedtls_net_free(&((SSLPrivate*)_SSLPrivate)->_Socket);
    mbedtls_ssl_free(&((SSLPrivate*)_SSLPrivate)->_SSLCtx);
    mbedtls_ssl_config_free(&((SSLPrivate*)_SSLPrivate)->_SSLConf);
    mbedtls_x509_crt_free( &((SSLPrivate*)_SSLPrivate)->_Cacert );
    mbedtls_ctr_drbg_free(&((SSLPrivate*)_SSLPrivate)->_SSLCTR_DRBG);
    mbedtls_entropy_free(&((SSLPrivate*)_SSLPrivate)->_SSLEntropy);
    mbedtls_pk_free(&((SSLPrivate*)_SSLPrivate)->_SSLPKey);
    delete (SSLPrivate*)_SSLPrivate;
}

void netplus::ssl::accept(socket *csock){
    NetException exception;

    int ret;
    char err_str[256];
    const char *pers = "libnet_ssl_server";

    ssl *ccsock=(ssl*)csock;

    memcpy(&((SSLPrivate*)ccsock->_SSLPrivate)->_SSLConf ,&((SSLPrivate*)_SSLPrivate)->_SSLConf,sizeof(((SSLPrivate*)_SSLPrivate)->_SSLConf));

    if( ( ret = mbedtls_ctr_drbg_seed( &((SSLPrivate*)ccsock->_SSLPrivate)->_SSLCTR_DRBG, mbedtls_entropy_func, &((SSLPrivate*)ccsock->_SSLPrivate)->_SSLEntropy,
                                        (const unsigned char *) pers,
                                        strlen( pers ) ) ) != 0 ){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Critical] << "mbedtls_ctr_drbg_seed returned: " << err_str;
        throw exception;
    }

    mbedtls_ssl_conf_rng(&((SSLPrivate*)ccsock->_SSLPrivate)->_SSLConf, mbedtls_ctr_drbg_random, &((SSLPrivate*)ccsock->_SSLPrivate)->_SSLCTR_DRBG);

    if( (ret=mbedtls_net_accept(&((SSLPrivate*)_SSLPrivate)->_Socket,&((SSLPrivate*) ccsock->_SSLPrivate)->_Socket,nullptr,0,nullptr)) !=0){
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Error] << "Can't accept on Socket: " << err_str;
        throw exception;
    }

    if ((ret = mbedtls_ssl_setup(&((SSLPrivate*) ccsock->_SSLPrivate)->_SSLCtx,&((SSLPrivate*)ccsock->_SSLPrivate)->_SSLConf )) != 0) {
        mbedtls_strerror(ret, err_str, 256);
        exception[NetException::Error] << "Can't mbedtls_ssl_setup on Socket: " << err_str;
        throw exception;
    }

    mbedtls_ssl_set_bio(&((SSLPrivate*) ccsock->_SSLPrivate)->_SSLCtx,&((SSLPrivate*) ccsock->_SSLPrivate)->_Socket, mbedtls_net_send, mbedtls_net_recv, nullptr);

    while ((ret = mbedtls_ssl_handshake(&((SSLPrivate*) ccsock->_SSLPrivate)->_SSLCtx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, err_str, 256);
            exception[NetException::Error] << "Can't handshake on Socket: " << err_str;
            throw exception;
        }
    }

    csock=ccsock;
}

void netplus::ssl::bind(){
    NetException exception;
    int ret=0;
    char port[255];
    snprintf(port,255,"%d",_Port);
    if ((ret = mbedtls_net_bind(&((SSLPrivate*)_SSLPrivate)->_Socket,_Addr,port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        exception[NetException::Error] << " failed\n  ! mbedtls_net_bind returned" << ret;
        throw exception;
    }
}

void netplus::ssl::listen(){
    //not needed beause mbedtls_net_bind bind and listen in one funciton
    return;
}

int netplus::ssl::fd(){
    return ((SSLPrivate*)_SSLPrivate)->_Socket.fd;
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
    int rval=::mbedtls_ssl_write(&((SSLPrivate*)_SSLPrivate)->_SSLCtx,(unsigned char*)data,size);
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
    int recvsize=::mbedtls_ssl_read(&((SSLPrivate*)_SSLPrivate)->_SSLCtx,(unsigned char*)data,size);
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

    if ( mbedtls_net_connect(&((SSLPrivate*)_SSLPrivate)->_Socket,_Addr,port,MBEDTLS_NET_PROTO_TCP) < 0) {
        exception[NetException::Error] << "Socket connect: can't connect to server aborting !";
        throw exception;
    }

    mbedtls_ssl_set_bio(&((SSLPrivate*)_SSLPrivate)->_SSLCtx,&((SSLPrivate*)_SSLPrivate)->_Socket, mbedtls_net_send, mbedtls_net_recv, NULL);

    int ret;

    while ((ret = mbedtls_ssl_handshake(&((SSLPrivate*)_SSLPrivate)->_SSLCtx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            exception[NetException::Error] << "Can't connect on Socket";
            throw exception;
        }
    }

    return this;
}

void netplus::ssl::setnonblocking(){
    if(mbedtls_net_set_nonblock(&((SSLPrivate*)_SSLPrivate)->_Socket)<0){
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

