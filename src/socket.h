/*******************************************************************************
 * Copyright (c) 2014, Jan Koester jan.koester@gmx.net
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#include <memory>
#include <string>

#include "config.h"

#pragma once

#ifdef Windows
#include <Windows.h>
#endif //Windows

#ifndef SOCKET  
typedef int SOCKET;
#endif

namespace netplus {
        enum sockettype {TCP=0,UDP=1,SSL=2};

        class socket {
        public:
            socket();
            virtual      ~socket();
            virtual void  setnonblocking();
            
            
            virtual void         accept(socket *csock)=0;
            virtual void         bind()=0;
            virtual void         listen()=0;
            
            virtual int          getMaxconnections()=0;
            
            virtual unsigned int sendData(socket *csock,void *data,unsigned long size)=0;
            virtual unsigned int recvData(socket *csock,void *data,unsigned long size)=0;
            
            virtual void         connect(socket *csock)=0;

            virtual void         getAddress(std::string &addr)=0;

            virtual int          fd()=0;

            virtual socket&      operator=(int sock)=0;

            void               *_SocketPtr;
            unsigned int        _SocketPtrSize;
            SOCKET              _Socket;
            int                 _Type;
            void               *_Extension;
#ifdef Windows
            WSADATA             _WSAData;
#endif // Windows

        };
        
        class tcp : public socket{
        public:
            tcp();
            tcp(const netplus::tcp& ctcp) = delete;
            tcp(const char *uxsocket,int maxconnections,
                int sockopts);
            tcp(const char *addr,int port,int maxconnections,
                int sockopts);
            ~tcp();
            
            void          accept(socket *csock);
            void          bind();
            void          listen();
            int           fd();
            tcp&          operator=(int socket);

            int           getMaxconnections();
            
            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);

            virtual void connect(socket *csock);

            void getAddress(std::string &addr);

        private:
            tcp(int sock);
            int             _Maxconnections;
            std::string     _UxPath;
        };
        
        class udp : public socket{
        public:
            udp();
            udp(const udp &cudp) = delete;
            udp(const char *uxsocket,int maxconnections,
                int sockopts);
            udp(const char *addr,int port,int maxconnections,
                int sockopts);
            ~udp();

            void          accept(socket * csock);
            void          bind();
            void          listen();
            int           fd();
            udp&          operator=(int socket);

            int           getMaxconnections();

            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);

            void connect(socket *csock);

            void getAddress(std::string &addr);

        private:
            udp(int sock);
            int             _Maxconnections;
            std::string     _UxPath;
        };

        class ssl : public socket{
        public:
            ssl();
            /*client socket*/
            ssl(const char *addr,int port,int maxconnections,int sockopts,const unsigned char *ca,size_t calen);
            /*server socket*/
            ssl(const char *addr,int port,int maxconnections,
                int sockopts,const unsigned char *cert,size_t certlen,const unsigned char *key, size_t keylen);
            ~ssl();
            
            void          accept(socket *csock);
            void          bind();
            void          listen();
            int           fd();
            ssl&          operator=(int socket);
            int           getMaxconnections();
            
            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            
            void connect(socket *csock);

            void setnonblocking();
            void getAddress(std::string &addr);

        private:
            int                      _Maxconnections;
            int                      _Port;
            char                     _Addr[255];
        };
};
