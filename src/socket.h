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

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

#include <string>

#pragma once

namespace netplus {
        enum sockettype {TCP=0,UDP=1,SSL=2};

        class socket {
        public:
            socket();
            virtual      ~socket();
            virtual void  setnonblocking();
            
            
            virtual void         accept(socket *socket)=0;
            virtual void         bind()=0;
            virtual void         listen()=0;
            
            virtual int          getMaxconnections()=0;
            
            virtual unsigned int sendData(socket *socket,void *data,unsigned long size)=0;
            virtual unsigned int recvData(socket *socket,void *data,unsigned long size)=0;
            
            virtual socket*      connect()=0;

            virtual void         getAddress(std::string &addr)=0;

            virtual int          fd()=0;

            void               *_SocketPtr;
            unsigned int        _SocketPtrSize;
            int                 _Socket;
            int                 _Locked;
            int                 _Type;
        };
        
        class tcp : public socket{
        public:
            tcp();
            tcp(const netplus::tcp& ctcp);
            tcp(const char *uxsocket,int maxconnections,
                int sockopts);
            tcp(const char *addr,int port,int maxconnections,
                int sockopts);
            ~tcp();
            
            void          accept(socket *csock);
            void          bind();
            void          listen();
            int           fd();

            int           getMaxconnections();
            
            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);

            tcp* connect();

            void getAddress(std::string &addr);

        private:
            tcp(int sock);
            int             _Maxconnections;
            std::string     _UxPath;
        };
        
        class udp : public socket{
        public:
            udp();
            udp(const udp &cudp);
            udp(const char *uxsocket,int maxconnections,
                int sockopts);
            udp(const char *addr,int port,int maxconnections,
                int sockopts);
            ~udp();

            void          accept(socket *csock);;
            void          bind();
            void          listen();
            int           fd();

            int           getMaxconnections();

            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int sendData(socket *socket,void *data,unsigned long size,int flags);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size,int flags);

            udp* connect();

            void getAddress(std::string &addr);

        private:
            udp(int sock);
            int             _Maxconnections;
            std::string     _UxPath;
        };

        class ssl : public socket{
        public:
            ssl();
            ssl(const char *addr,int port,int maxconnections,
                int sockopts,const unsigned char *cert,size_t certlen,const unsigned char *key, size_t keylen);
            ~ssl();
            
            void          accept(socket *csock);
            void          bind();
            void          listen();
            int           fd();

            int           getMaxconnections();
            
            unsigned int sendData(socket *socket,void *data,unsigned long size);
            unsigned int recvData(socket *socket,void *data,unsigned long size);
            
            ssl* connect();

            void setnonblocking();
            void getAddress(std::string &addr);

        private:
            int                      _Maxconnections;
            int                      _Port;
            char                     _Addr[255];
            void                    *_SSLPrivate;
        };

        class quick : public socket{
        };
};
