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

#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdint.h>
#include <mutex>

#include <cstring>
#include <errno.h>

#include "socket.h"
#include "exception.h"
#include "eventapi.h"
#include "connection.h"

#define READEVENT 0
#define SENDEVENT 1

#define BLOCKSIZE 16384

#ifdef __GNU_SOURCE
#undef __GNU_SOURCE
#endif

struct poll_event {
    uint32_t events;
    epoll_data_t data;
}
#ifdef __x86_64__
__attribute__((__packed__))
#endif
;

namespace netplus {
    class poll : public eventapi{
    public:
        poll(socket* serversocket) {
            _ServerSocket = serversocket;
            _EventNums=0;
        };

        ~poll() {
        };

        /*basic functions*/
        const char* getpolltype() {
            return "EPOLL";
        }

        /*event handler function*/
        void initEventHandler() {
            NetException exception;
            _ServerSocket->bind();
            _ServerSocket->setnonblocking();
            _ServerSocket->listen();

            struct poll_event setevent = (struct poll_event){
                0
            };

            _pollFD = epoll_create1(0);

            if (_pollFD < 0) {
                exception[NetException::Critical] << "initEventHandler:" << "can't create epoll";
                throw exception;
            }

            setevent.events = EPOLLIN;
            setevent.data.ptr = nullptr;

            if (epoll_ctl(_pollFD, EPOLL_CTL_ADD,
                _ServerSocket->fd(),(struct epoll_event*)&setevent) < 0) {
                exception[NetException::Critical] << "initEventHandler: can't create epoll";
            throw exception;
                }

                _Events = new poll_event[_ServerSocket->getMaxconnections()];
                for (int i = 0; i < _ServerSocket->getMaxconnections(); ++i)
                    _Events[i].data.ptr = nullptr;
        };

        int pollState(int pos){

            con *pcon = (con*)_Events[pos].data.ptr;
            NetException exception;

            if(!pcon)
                return EventHandlerStatus::EVCON;

            if(pcon->issending())
                return EventHandlerStatus::EVOUT;

            return EventHandlerStatus::EVIN;
        }

        unsigned int waitEventHandler() {
            for(int i =0; i<_EventNums; ++i){
                NetException except;
                con *delcon = (con*)_Events[i].data.ptr;

                if(!delcon || !delcon->closecon.load())
                    continue;

                int ect = epoll_ctl(_pollFD, EPOLL_CTL_DEL,
                                    delcon->csock->fd(), 0);

                if (ect < 0) {
                    if(errno==ENOENT)
                        continue;
                    except[NetException::Critical] << "CloseEvent can't delete Connection from epoll";
                    throw except;
                }

                DisconnectEvent(delcon);
                deleteConnetion(delcon);
                _Events[i].data.ptr=nullptr;
            }

            _EventNums = epoll_wait(_pollFD, (struct epoll_event*)_Events, _ServerSocket->getMaxconnections(), -1);

            if (_EventNums <0 ) {
                NetException exception;
                exception[NetException::Error] << "waitEventHandler: epoll wait failure";
                throw exception;
            }
            return _EventNums;
        };

        void ConnectEventHandler(int pos)  {
            NetException exception;
            con *ccon;
            CreateConnetion(&ccon);
            try {
                if(_ServerSocket->_Type==sockettype::TCP){
                    ccon->csock=std::make_shared<tcp>();
                    _ServerSocket->accept(ccon->csock);
                    ccon->csock->setnonblocking();
                }else if(_ServerSocket->_Type==sockettype::UDP){
                    ccon->csock=std::make_shared<udp>();
                    _ServerSocket->accept(ccon->csock);
                }else if(_ServerSocket->_Type==sockettype::SSL){
                    ccon->csock=std::make_shared<ssl>();
                    _ServerSocket->accept(ccon->csock);
                }else{
                    exception[NetException::Error] << "ConnectEventHandler: Protocoll are supported";
                    throw exception;

                }
                ccon->closecon=false;
                std::string ip;
                ccon->csock->getAddress(ip);
                std::cout << "Connected: " << ip  << std::endl;

                struct poll_event setevent { 0 };
                setevent.events = EPOLLIN;
                setevent.data.ptr = ccon;

                int estate = epoll_ctl(_pollFD, EPOLL_CTL_ADD, ccon->csock->fd(), (struct epoll_event*)&setevent);

                if ( estate < 0 ) {
                    char errstr[255];
                    strerror_r(errno,errstr,255);
                    exception[NetException::Error] << "ConnectEventHandler: can't add socket to epoll: " << errstr;
                    throw exception;
                }
            } catch (NetException& e) {
                delete ccon;
                throw e;
            }
            ConnectEvent(ccon);
        };

        void ReadEventHandler(int pos) {
            NetException exception;
            con *rcon = (con*)_Events[pos].data.ptr;
            char buf[BLOCKSIZE];
            size_t rcvsize = 0, tries=0;
            for(;;){
                rcvsize=_ServerSocket->recvData(rcon->csock, buf, BLOCKSIZE);

                if(rcvsize!=0 || tries > 5)
                    break;

                ++tries;

                std::this_thread::sleep_for(std::chrono::milliseconds(5*tries));
            }

            if(rcvsize==0){
                NetException exp;
                exp[NetException::Error] << "ReadEvent: no data recived!";
                throw exp;
            }

            rcon->addRecvQueue(buf, rcvsize);
            RequestEvent(rcon);
        };

        void WriteEventHandler(int pos) {

            con *wcon = (con*)_Events[pos].data.ptr;

            if(!wcon->getSendFirst()){
                wcon->sending(false);
                return;
            }

            size_t sended=0,tries=0;

            for(;;){
                sended = _ServerSocket->sendData(wcon->csock,
                                                 (void*)wcon->getSendFirst()->getData(),
                                                 wcon->getSendFirst()->getDataLength());

                if(sended!=0 || tries > 5)
                    break;

                ++tries;

                std::this_thread::sleep_for(std::chrono::milliseconds(5*tries));
            };
            if(sended==0){
                NetException exp;
                exp[NetException::Error] << "WriteEvent: max tries Reached!";
                throw exp;
            }
            ResponseEvent(wcon);
            wcon->resizeSendQueue(sended);
        };


        void CloseEventHandler(int pos) {
            bool expected=false;
            if(_Events[pos].data.ptr){
                ((con*)_Events[pos].data.ptr)->sending(false);
                ((con*)_Events[pos].data.ptr)->closecon.compare_exchange_strong(expected,true);
            }
        };

        /*Connection Ready to send Data*/
        void sendReady(con* curcon, bool ready) {
            if (ready) {
                _setpollEvents(curcon, EPOLLIN | EPOLLOUT);
            }
            else {
                _setpollEvents(curcon, EPOLLIN);
            }
        };


        void _setpollEvents(con* curcon, int events) {
            NetException except;
            struct poll_event setevent { 0 };
            setevent.events = events;
            setevent.data.ptr = curcon;
            if (epoll_ctl(_pollFD, EPOLL_CTL_MOD,
                curcon->csock->fd(), (struct epoll_event*)&setevent) < 0) {
                except[NetException::Error] << "_setEpollEvents: can change socket!";
            throw except;
                }
        };

        void RequestEvent(con *curcon){

        };

        void ResponseEvent(con *curcon){

        };

        void ConnectEvent(con *curcon){
        };

        void DisconnectEvent(con *curcon){

        };

        void CreateConnetion(con **curon){
            *curon=new con();
        }

        void deleteConnetion(con *curon){
            delete curon;
        }

    private:
        int                  _pollFD;
        struct  poll_event  *_Events;
        socket              *_ServerSocket;
        int                  _EventNums;
    };

    bool event::_Run = true;
    bool event::_Restart = false;

    class WorkerArgs {
    public:
        WorkerArgs(std::shared_ptr<event> eventptr ,std::shared_ptr<eventapi> eventapiptr) : eventptr(eventptr) , eventapiptr(eventapiptr){
            eventptr=nullptr;
            pos=nullptr;
            sync=nullptr;
            tid=-1;
        };

        WorkerArgs(const WorkerArgs &args) : eventptr(args.eventptr) , eventapiptr(args.eventapiptr){
            pos=args.pos;
            sync=args.sync;
            tid=args.tid;
        };

        ~WorkerArgs(){
        };


        std::shared_ptr<event>     eventptr;
        std::shared_ptr<eventapi>  eventapiptr;
        std::atomic<int>          *pos;
        std::mutex                *sync;
        int                        tid;
    };

    class EventWorker {
    public:
        EventWorker(void* args) {
            std::shared_ptr<eventapi> eventptr=((WorkerArgs*)args)->eventapiptr;
            while (event::_Run) {
                ((WorkerArgs*)args)->sync->lock();
                int i =((WorkerArgs*)args)->pos[((WorkerArgs*)args)->tid].load();
                try {
                    int state = eventptr->pollState(i);
                    switch (state) {
                        case poll::EventHandlerStatus::EVCON:
                            eventptr->ConnectEventHandler(i);
                            break;
                        default:
                            break;
                    }
                    try{
                        switch (state) {
                            case poll::EventHandlerStatus::EVIN:
                                eventptr->ReadEventHandler(i);
                                break;
                            case poll::EventHandlerStatus::EVOUT:
                                eventptr->WriteEventHandler(i);
                                break;
                            default:
                                NetException excep;
                                excep[NetException::Note] << "Eventworker: nothing todo close connection";
                                throw excep;
                        }
                    }catch(NetException& e){
                        if(e.getErrorType()!=NetException::Note){
                            eventptr->CloseEventHandler(i);
                            throw e;
                        }
                    }
                } catch (NetException& e) {
                    if (e.getErrorType() == NetException::Critical) {
                        throw e;
                    }else if(e.getErrorType() != NetException::Note){
                        std::cerr << e.what() << std::endl;
                    }
                }
                ((WorkerArgs*)args)->pos[((WorkerArgs*)args)->tid].store(-1);
            }
        }

    };

    eventapi::~eventapi() {
    }

    event::event(socket* serversocket) {
        if (!serversocket) {
            NetException exp;
            exp[NetException::Critical] << "server socket empty!";
            throw exp;
        }
        _Poll = std::make_shared<poll>(serversocket);
    }

    event::~event() {
    }


    void event::RequestEvent(con* curcon) {
        return;
    }

    void event::ResponseEvent(con* curcon) {
        return;
    }

    void event::ConnectEvent(con* curcon) {
        return;
    }

    void event::DisconnectEvent(con* curcon) {
        return;
    }

    void event::runEventloop() {
        size_t thrs = sysconf(_SC_NPROCESSORS_ONLN);
        signal(SIGPIPE, SIG_IGN);
        _Poll->initEventHandler();
    MAINWORKERLOOP:
        std::vector<WorkerArgs>  targs;
        std::vector<std::thread> thpool;
        std::atomic<int>        *running;
        running = new std::atomic<int> [thrs];

        for (size_t i = 0; i < thrs; i++) {
           try {
                WorkerArgs args(std::make_shared<event>(*this),_Poll);
                args.tid=i;
                args.pos=running;
                args.pos[i].store(-1);
                args.sync=new std::mutex;
                args.sync->lock();
                targs.push_back(args);
                thpool.push_back(std::thread([targs,i](){
                   new EventWorker((void*)&targs[i]);
                }));
           }
           catch (NetException& e) {
               throw e;
           }
        }

        int wait=-1;
        while (event::_Run) {
            try {

                if(wait<0){
                    for(size_t i = 0; i< thrs; ++i){
                        while(running[i].load()!=-1);
                    }
                    wait=(_Poll->waitEventHandler()-1);
                }

                for(size_t started=0; started<thrs; started++){
                    int expected=-1;
                    if(wait<0)
                        break;
                    if(running[started].compare_exchange_strong(expected,wait)){
                        targs[started].sync->unlock();
                        --wait;
                    }
                }

            }catch(NetException &e){
                switch(e.getErrorType()){
                    case NetException::Note:
                        std::cout << e.what() << std::endl;
                        break;
                    case NetException::Warning:
                        std::cout << e.what() << std::endl;
                        break;
                    case NetException::Error:
                        std::cerr << e.what() << std::endl;
                        break;
                    default:
                        std::cerr << e.what() << std::endl;
                        event::_Run=false;
                        break;
                }
            }
        }

        for(std::vector<std::thread>::iterator thd = thpool.begin(); thd!=thpool.end();  ++thd){
            thd->join();
        }

        for(size_t i = 0; i < thrs; i++){
            delete[] targs[i].sync;
        }

        delete[] running;

        if (event::_Restart) {
            event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};

