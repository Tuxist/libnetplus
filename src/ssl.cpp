#include <cstring>

#include "exception.h"
#include "socket.h"

#define SSL_DEBUG_LEVEL 0

#define HIDDEN __attribute__ ((visibility ("hidden")))

namespace netplus {
};


netplus::ssl::ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *ca,size_t calen) : ssl() {

}

netplus::ssl::ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *cert,
    size_t certlen, const unsigned char* key, size_t keylen) : ssl() {
    _Port=port;
    _Type=sockettype::SSL;
}

netplus::ssl::ssl() : socket(){
     _Type=sockettype::SSL;
}

netplus::ssl::~ssl(){
}

void netplus::ssl::accept(socket *csock){
}

void netplus::ssl::bind(){
}

void netplus::ssl::listen(){
    //not needed beause mbedtls_net_bind bind and listen in one funciton
    return;
}

netplus::ssl& netplus::ssl::operator=(int sock){
     return *this;
};

int netplus::ssl::fd(){
    return -1;
}

int netplus::ssl::getMaxconnections(){
    return _Maxconnections;
}

size_t netplus::ssl::sendData(socket *csock,void *data,unsigned long size){
    NetException exception;
    return 0;
}

size_t netplus::ssl::recvData(socket *csock,void *data,unsigned long size){
    return 0;
}

void netplus::ssl::connect(socket *csock){
}

void netplus::ssl::setnonblocking(){
}

void netplus::ssl::getAddress(std::string &addr){
    // if(!_SocketPtr)
    //     return;
    // char ipaddr[INET6_ADDRSTRLEN];
    // if(((struct sockaddr*)_SocketPtr)->sa_family==AF_INET6)
    //     inet_ntop(AF_INET6, &(((struct sockaddr_in6*)_SocketPtr)->sin6_addr), ipaddr, INET6_ADDRSTRLEN);
    // else
    //     inet_ntop(AF_INET, &((struct sockaddr_in*)_SocketPtr)->sin_addr, ipaddr, INET_ADDRSTRLEN);
    // addr=ipaddr;
}

