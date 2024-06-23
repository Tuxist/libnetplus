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

#include <thread>
#include <vector>
#include <memory>

#include "socket.h"
#include "connection.h"

#pragma once

namespace netplus {
        class EventWorker;
        class pollapi;

        class eventapi {
        public:
             /*HTTP API Events*/
            virtual void RequestEvent(con *curcon,const int tid,void *args);
            virtual void ResponseEvent(con *curcon,const int tid,void *args);
            virtual void ConnectEvent(con *curcon,const int tid,void *args);
            virtual void DisconnectEvent(con *curcon,const int tid,void *args);

            /*memory allocation*/
            virtual void CreateConnetion(con **curon)=0;
            virtual void deleteConnetion(con *curon)=0;
        };

        class event : public eventapi{
        public:
            event(socket *serversocket,int timeout = 60);
            void runEventloop(void *args=nullptr);
            static void *WorkerThread(void *wrkevent);

            virtual ~event();
            static bool _Run;
            static bool _Restart;
        private:
            socket                  *_ServerSocket;
            int                      _Timeout;
            int                      _pollFD;
            friend class EventWorker;
        };
};
