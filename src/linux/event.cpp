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
#include <algorithm>
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

    std::atomic<bool> elock(false);

    class pollapi {
    public:
        pollapi(eventapi *eapi,int timeout){
            _evtapi=eapi;
        };

        virtual ~pollapi(){

        };

        enum EventHandlerStatus{EVIN=0,EVOUT=1,EVUP=2,EVERR=3,EVWAIT=4,EVCON=5};

        virtual void initEventHandler()=0;
        virtual const char *getpolltype()=0;
        /*pollstate*/
        virtual int pollState(int pos)=0;

        /*EventHandler*/
        virtual unsigned int waitEventHandler()=0;
        virtual void ConnectEventHandler(int pos)=0;
        virtual void ReadEventHandler(int pos)=0;
        virtual void WriteEventHandler(int pos)=0;
        virtual void CloseEventHandler(int pos)=0;
        virtual void TimeoutEventHandler(int pos)=0;
        virtual void setpollEvents(con* curcon, int events)=0;
    protected:
        eventapi *_evtapi;
    };

    class poll : public pollapi{
    public:
        poll(socket* serversocket,eventapi *eapi,int timeout) : pollapi(eapi,timeout){
            _ServerSocket = serversocket;
            _EventNums=0;
            _evtapi=eapi;
            _Timeout=timeout;
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

            if( _Events[pos].events & EPOLLOUT )
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

                _evtapi->DisconnectEvent(delcon);
                _evtapi->deleteConnetion(delcon);
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
            _evtapi->CreateConnetion(&ccon);
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
                ccon->lasteventime = time(nullptr);
            } catch (NetException& e) {
                _evtapi->deleteConnetion(ccon);
                throw e;
            }
            _evtapi->ConnectEvent(ccon);
        };

        void ReadEventHandler(int pos) {
            NetException exception;
            con *rcon = (con*)_Events[pos].data.ptr;
            char buf[BLOCKSIZE];
            size_t rcvsize = 0;

            rcvsize=_ServerSocket->recvData(rcon->csock, buf, BLOCKSIZE);

            rcon->addRecvData(buf,rcvsize);

            _evtapi->RequestEvent(rcon);
            rcon->lasteventime = time(nullptr);
        };

        void WriteEventHandler(int pos) {

            con *wcon = (con*)_Events[pos].data.ptr;


            std::vector<char> buf;

            wcon->getSendData(buf);

            if(buf.empty()){
                wcon->sending(false);
                return;
            }

            size_t ssize = BLOCKSIZE < buf.size() ? BLOCKSIZE : buf.size();

            size_t sended = _ServerSocket->sendData(wcon->csock,buf.data(),ssize);

            _evtapi->ResponseEvent(wcon);

            if(sended==0)
                wcon->clearSendData();
            else
                wcon->ResizeSendData(sended);

            wcon->lasteventime = time(nullptr);
        };


        void CloseEventHandler(int pos) {
            bool expected=false;
            if(_Events[pos].data.ptr){
                ((con*)_Events[pos].data.ptr)->sending(false);
                ((con*)_Events[pos].data.ptr)->closecon.compare_exchange_strong(expected,true);
            }
        };

        void TimeoutEventHandler(int pos){
             con *tcon = (con*)_Events[pos].data.ptr;

             bool expected=false;

             if(tcon){
                if(time(nullptr) - tcon->lasteventime > _Timeout ){
                    tcon->closecon.compare_exchange_strong(expected,true);
                }
             }

        }

        void setpollEvents(con* curcon, int events) {
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

    private:
        int                  _pollFD;
        struct  poll_event  *_Events;
        socket              *_ServerSocket;
        int                  _EventNums;
        int                  _Timeout;
    };

    bool event::_Run = true;
    bool event::_Restart = false;

    class EventWorkerArgs{
    public:
        EventWorkerArgs(){
        }

        EventWorkerArgs(const EventWorkerArgs &eargs){
            poll=eargs.poll;
            wait.store(eargs.wait);
        }

        pollapi            *poll;
        std::atomic<int>    wait;
    };

    class EventWorker {
    public:
        EventWorker(void* args) {

            EventWorkerArgs *wargs=(EventWorkerArgs*)args;
            pollapi *pollptr=wargs->poll;

            while (event::_Run) {
                int i;

                while ( ( i = wargs->wait.load() ) ==-1 ){
                    usleep(1000);
                }

                try {
CONNECTED:
                    int state = pollptr->pollState(i);
                    try{
                        switch (state) {
                            case pollapi::EventHandlerStatus::EVCON:
                                pollptr->ConnectEventHandler(i);
                                goto CONNECTED;
                            case pollapi::EventHandlerStatus::EVIN:
                                pollptr->ReadEventHandler(i);
                                break;
                            case pollapi::EventHandlerStatus::EVOUT:
                                pollptr->WriteEventHandler(i);
                                break;
                            default:
                                pollptr->TimeoutEventHandler(i);
                                break;
                        }
                    }catch(NetException& e){
                        switch(e.getErrorType()){
                            case NetException::Critical:
                                throw e;
                            case NetException::Note:
                                break;
                            default:
                                pollptr->CloseEventHandler(i);
                        }
                        std::cerr << e.what() << std::endl;
                    }
                } catch (NetException& e) {
                    if (e.getErrorType() == NetException::Critical) {
                        throw e;
                    }else if(e.getErrorType() != NetException::Note){
                        std::cerr << e.what() << std::endl;
                    }
                }

                std::atomic_store_explicit(&wargs->wait, -1, std::memory_order_release);
            }
        }

    };

    void eventapi::RequestEvent(con *curcon){
        //dummy
    };

    void eventapi::ResponseEvent(con *curcon){
        //dummy
    };

    void eventapi::ConnectEvent(con *curcon){
        //dummy
    };

    void eventapi::DisconnectEvent(con *curcon){
        //dummy
    };

    void eventapi::CreateConnetion(con **curcon){
        *curcon=new con(this);
    };

    void eventapi::deleteConnetion(con *curcon){
        delete curcon;
    };

    event::event(socket* serversocket,int timeout) {
        if (!serversocket) {
            NetException exp;
            exp[NetException::Critical] << "server socket empty!";
            throw exp;
        }
        _Poll=new poll(serversocket,this,timeout);
    }

    event::~event() {
    }

    /*Connection Ready to send Data*/
    void event::sendReady(con* curcon, bool ready) {
        if (ready) {
            _Poll->setpollEvents(curcon, EPOLLIN | EPOLLOUT);
        } else {
            _Poll->setpollEvents(curcon, EPOLLIN);
        }
    };

    void event::runEventloop() {
        size_t thrs = sysconf(_SC_NPROCESSORS_ONLN);
        signal(SIGPIPE, SIG_IGN);
        _Poll->initEventHandler();
    MAINWORKERLOOP:
        std::vector<std::thread> thpool;

        EventWorkerArgs** eargs;

        eargs = new EventWorkerArgs* [thrs];

        for (size_t i = 0; i < thrs; i++) {
           try {
                eargs[i]=new EventWorkerArgs;
                eargs[i]->wait.store(-1);
                eargs[i]->poll=_Poll;

                thpool.push_back(std::thread([eargs,i](){
                    std::cout << eargs[i]->wait.load() << std::endl;
                   new EventWorker(eargs[i]);
                }));
           } catch (NetException& e) {
               throw e;
           }
        }

        int wfd=-1;

        while(event::_Run){

            for (size_t i = 0; i < thrs; ++i) {

                if(wfd<0){
                    wfd=(_Poll->waitEventHandler()-1);
                }

                for(size_t started=0; started<thrs; started++){
                    if(wfd<0)
                        break;
                    if( std::atomic_exchange_explicit(&eargs[started]->wait,wfd,  std::memory_order_acquire) ){
                        --wfd;
                    }
                }
            }
        }

        for(std::vector<std::thread>::iterator thd = thpool.begin(); thd!=thpool.end();  ++thd){
            thd->join();
        }

        for (size_t i = 0; i < thrs; i++) {
            delete eargs[i];
        }

        delete[] eargs;

        if (event::_Restart) {
            event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};

