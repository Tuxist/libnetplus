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

#include <chrono>
#include <string>
#include <cryptplus/cryptplus.h>

#pragma once

namespace netplus {

        class socket {
        public:
            socket();
            virtual      ~socket();
            void         setnonblocking();
            int          getSocket();
            
            
            virtual socket      *accept()=0;
            virtual void         bind()=0;
            virtual void         listen()=0;
            
            virtual int          getMaxconnections()=0;
            
            virtual unsigned int sendData(socket *socket,void *data,unsigned long size)=0;
            virtual unsigned int sendData(socket *socket,void *data,unsigned long size,int flags)=0;
            virtual unsigned int recvData(socket *socket,void *data,unsigned long size)=0;
            virtual unsigned int recvData(socket *socket,void *data,unsigned long size,int flags)=0;
            
            virtual socket* connect()=0;

            virtual void getAddress(std::string &addr)=0;

            int                 _Socket;
            void               *_SocketPtr;
            unsigned int        _SocketPtrSize;
        };
        
        class tcp : public socket{
        public:
            tcp(const netplus::tcp& ctcp);
            tcp(const char *uxsocket,int maxconnections,
                int sockopts);
            tcp(const char *addr,int port,int maxconnections,
                int sockopts);
            ~tcp();
            
            socket       *accept();
            void          bind();
            void          listen();
            
            int           getMaxconnections();
            
            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);

            tcp* connect();

            void getAddress(std::string &addr);

        private:
            bool            _close;
            tcp();
            int             _Maxconnections;
            std::string     _UxPath;
        };
        
        class udp : public socket{
        public:
            udp(const udp &cudp);
            udp(const char *uxsocket,int maxconnections,
                int sockopts);
            udp(const char *addr,int port,int maxconnections,
                int sockopts);
            ~udp();

            socket       *accept();
            void          bind();
            void          listen();

            int           getMaxconnections();

            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);

            udp* connect();

            void getAddress(std::string &addr);

        private:
            bool            _close;
            udp();
            int             _Maxconnections;
            std::string     _UxPath;
        };

        class ssl : public socket{
        public:
            ssl(const char *addr,int port,int maxconnections,
                int sockopts,const unsigned char *cert,size_t certlen,const unsigned char *key, size_t keylen);
            ~ssl();
            
            socket       *accept();
            void          bind();
            void          listen();
            
            int           getMaxconnections();
            
            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);
            
            ssl* connect();

            void getAddress(std::string &addr);

        private:
            ssl();
            int              _Maxconnections;
            std::string      _UxPath;
            size_t           _Cipher;
            cryptplus::x509 *_Cert;
        };

        class quick : public socket{
        };
};
