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

#include <map>

#include "socket.h"
#include "connection.h"

#pragma once

struct poll_event;

namespace netplus {
        class eventapi {
        public:
            
            enum EventHandlerStatus{EVIN=0,EVOUT=1,EVUP=2,EVERR=3,EVWAIT=4,EVCON=5};
            
            virtual ~eventapi();
            virtual void initEventHandler()=0;        
            virtual const char *getpolltype()=0;
            
            /*get pollState by thread id*/
            virtual int  pollState(int thid,con *ccon)=0;

            /*EventHandler*/
            virtual unsigned int waitEventHandler()=0;
            virtual void ConnectEventHandler(con** ccon)=0;
            virtual void ReadEventHandler(con*  rcon)=0;
            virtual void WriteEventHandler(con* wcon)=0;
            virtual void CloseEventHandler(con** dcon)=0;
            
            /*HTTP API Events*/
            virtual void RequestEvent(con *curcon)=0;
            virtual void ResponseEvent(con *curcon)=0;
            virtual void ConnectEvent(con *curcon)=0;
            virtual void DisconnectEvent(con *curcon)=0;
            
            /*Connection Ready to send Data 
             * DANGEROUS to burnout your cpu
             *only use this if know what you do!*/
            virtual void sendReady(con *curcon,bool ready)=0;
        public:
            size_t  getThreadsAmount(){
                return thdsamount;
            }
        protected:
            /*store number of threads*/
            size_t  thdsamount;
            /*thread -> connection*/
            std::map<int,con*> thcon;
        };

        class poll : public eventapi{
        public:
            poll(socket* serversocket);
            virtual ~poll();

            void initEventHandler();
            const char *getpolltype();
            int  pollState(int thid,con *ccon);

            unsigned int waitEventHandler();
            void ConnectEventHandler(con** ccon);
            void ReadEventHandler(con* rcon);
            void WriteEventHandler(con *wcon);
            void CloseEventHandler(con **dcon);
            void sendReady(con *curcon,bool ready);
        private:
            void                 _lockCon(int pos);
            void                 _unlockCon(int pos);
            bool                 _trylockCon(int pos);
            void                 _setpollEvents(con *curcon,int events);
            int                  _pollFD;
            struct  poll_event  *_Events;
            socket              *_ServerSocket;

        };
        
        class event : public poll {
        public:
            event(socket *serversocket);
            void runEventloop();
            static void *WorkerThread(void *wrkevent);
            
            /*Events*/                                              
            virtual void RequestEvent(con *curcon);                         
            virtual void ResponseEvent(con *curcon);  
            virtual void ConnectEvent(con *curcon);                         
            virtual void DisconnectEvent(con *curcon);          
            
            virtual ~event();
            static bool _Run;
            static bool _Restart;
            std::mutex  _StateLock;
        };
};
