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
#include <memory>

#include <unistd.h>
#include <signal.h>
#include <sys/event.h>
#include <stdlib.h>
#include <stdint.h>
#include <mutex>

#include <cstring>
#include <errno.h>

#include "socket.h"
#include "exception.h"
#include "eventapi.h"
#include "connection.h"
#include "../posix/error.h"
#include <assert.h>

#define READEVENT 0
#define SENDEVENT 1

#define BLOCKSIZE 16384

namespace netplus {
    class pollapi {
    public:
        pollapi(eventapi *eapi,int timeout){
            _evtapi=eapi;
        };

        virtual ~pollapi(){

        };

        enum EventHandlerStatus{EVWAIT=0,EVIN=1,EVOUT=2,EVUP=3,EVERR=4,EVCON=5};

        virtual void initEventHandler()=0;
        virtual const char *getpolltype()=0;
        /*pollstate*/
        virtual int pollState(int pos)=0;

        /*EventHandler*/
        virtual  int waitEventHandler()=0;
        virtual void ConnectEventHandler(int pos,const int tid,void *args)=0;
        virtual void ReadEventHandler(int pos,const int tid,void *args)=0;
        virtual void WriteEventHandler(int pos,const int tid,void *args)=0;
        virtual void CloseEventHandler(int pos,const int tid,void *args)=0;

    protected:
        eventapi *_evtapi;
    };

    class poll : public pollapi{
    public:
        poll(socket* serversocket,eventapi *eapi,int pollfd,int timeout) : pollapi(eapi,timeout){
            NetException exception;

            _evtapi=eapi;
            _Timeout=timeout;
            _pollFD=pollfd;
            _ServerSocket = serversocket;
            _Events = new struct kevent[_ServerSocket->getMaxconnections()];
            int maxcon=_ServerSocket->getMaxconnections();
            for (int i = 0; i <maxcon;  ++i){
                _Events[i].filter=-1;
                _Events[i].flags=-1;
                _Events[i].fflags=-1;
                _Events[i].ident=-1;
                _Events[i].udata=nullptr;
            }
        };

        ~poll() {
            int maxcon=_ServerSocket->getMaxconnections();
            for (int i = 0; i < maxcon; ++i){
                _evtapi->deleteConnetion((con*)_Events[i].udata);
            }
            delete _Events;
        };

        /*basic functions*/
        const char* getpolltype() {
            return "KQUEUE";
        }

        /*event handler function*/
        void initEventHandler() {

        };

        void setpollEvents(con* curcon,int filter,int events){
            NetException except;
            struct kevent setevent = { 0 };

            EV_SET(&setevent,curcon->csock->fd(),filter,events,0,0,curcon);

            if ( kevent(_pollFD, &setevent, 1, nullptr, 0, nullptr) < 0) {
                except[NetException::Error] << "_setPollEvents: can change socket!";
                throw except;
            }
        }

        int pollState(int pos){
            con *pcon = (con*)_Events[pos].udata;
            NetException exception;

            if(!pcon)
                return EventHandlerStatus::EVCON;

            return pcon->state;
        }

        int waitEventHandler() {
            int evn = kevent(_pollFD,nullptr,0,_Events,_ServerSocket->getMaxconnections(),nullptr);
            if (evn < 0 ) {
                NetException exception;

                char str[255];
                strerror_r_netplus(errno,str,255);

                exception[NetException::Error] << "waitEventHandler: kqueue wait failure: " << str;
                throw exception;
            }
            return evn;
        };

        void ConnectEventHandler(int pos,const int tid,void *args)  {
            NetException exception;
            con *ccon;

            _evtapi->CreateConnetion(&ccon);

            if(_ServerSocket->_Type==sockettype::TCP){
                ccon->csock=new tcp();
            }else if(_ServerSocket->_Type==sockettype::UDP){
                ccon->csock=new udp();
            }else if(_ServerSocket->_Type==sockettype::SSL){
                ccon->csock=new ssl();
            }

            _ServerSocket->accept(ccon->csock);
            ccon->csock->setnonblocking();

            std::string ip;
            ccon->csock->getAddress(ip);
            std::cout << "Connected: " << ip  << std::endl;

            ccon->lasteventime = time(nullptr);
            ccon->state=EVIN;

            struct kevent setevent { 0 };

            EV_SET(&setevent, ccon->csock->fd(), EVFILT_READ, EV_ADD | EV_ONESHOT,0,0,ccon);

            int estate = kevent(_pollFD, &setevent, 1, nullptr, 0, nullptr);

            if ( estate < 0 ) {
                char errstr[255];
                strerror_r_netplus(errno,errstr,255);
                exception[NetException::Error] << "ConnectEventHandler: can't add socket to kqueue: " << errstr;
                throw exception;
            }
            _evtapi->ConnectEvent(ccon,tid,args);

        };

        void ReadEventHandler(int pos,const int tid,void *args) {
            con *rcon = (con*)_Events[pos].udata;

            if(!rcon)
                assert(0);
            try{
                std::shared_ptr<char> buf(new char[BLOCKSIZE]);
                size_t rcvsize = _ServerSocket->recvData(rcon->csock, buf.get(), BLOCKSIZE);

                rcon->lasteventime = time(nullptr);

                if(rcvsize>0){
                    rcon->RecvData.append(buf.get(),rcvsize);
                    rcon->state=EVIN;
                }

                _evtapi->RequestEvent(rcon,tid,args);

                if(!rcon->SendData.empty()){
                    rcon->state=EVOUT;
                    setpollEvents(rcon,EVFILT_WRITE,EV_ADD | EV_ONESHOT);
                    return;
                }

                setpollEvents(rcon,EVFILT_READ,EV_ADD | EV_ONESHOT);

            }catch(NetException &e){
                if(e.getErrorType()== NetException::Note){
                     rcon->state=EVIN;
                     setpollEvents(rcon,EVFILT_READ,EV_ADD | EV_ONESHOT);
                     return;
                }
                throw e;
            }
        };

        void WriteEventHandler(int pos,const int tid,void *args) {
            con *wcon = (con*)_Events[pos].udata;
            try{

                _evtapi->ResponseEvent(wcon,tid,args);

                if(wcon->SendData.empty()){
                    wcon->state=EVIN;
                    setpollEvents(wcon,EVFILT_READ,EV_ADD | EV_ONESHOT);
                    return;
                }

                size_t ssize = BLOCKSIZE < wcon->SendData.size() ? BLOCKSIZE : wcon->SendData.size();


                size_t sended;

                wcon->state=EVOUT;

                sended = _ServerSocket->sendData(wcon->csock,wcon->SendData.data(),ssize);
                wcon->SendData.resize(sended);

                wcon->lasteventime = time(nullptr);

                setpollEvents(wcon,EVFILT_WRITE,EV_ADD | EV_ONESHOT);
            }catch(NetException &e){
                if(e.getErrorType()== NetException::Note){
                    wcon->state=EVOUT;
                    setpollEvents(wcon,EVFILT_WRITE,EV_ADD | EV_ONESHOT);
                    return;
                }else{
                    throw e;
                }
            }
        };


        void CloseEventHandler(int pos,const int tid,void *args) {
            con *ccon = (con*)_Events[pos].udata;

            if(!ccon)
                return;

            try{
                struct kevent setevent { 0 };

                EV_SET(&setevent,ccon->csock->fd(),0, EV_DELETE,0,0,nullptr);

                if(kevent(_pollFD,&setevent,1,nullptr,0,nullptr)<0){
                    NetException except;
                    char errstr[255];
                    strerror_r_netplus(errno,errstr,255);
                    except[NetException::Error] << "CloseEventHandler: can't close socket to kqueue: " << errstr;
                    throw except;
                }

                delete  ccon->csock;

                _evtapi->DisconnectEvent(ccon,tid,args);

                _evtapi->deleteConnetion(ccon);

            }catch(NetException &e){
                throw e;
            }

        };

    private:
        int                  _pollFD;
        struct kevent       *_Events;
        socket              *_ServerSocket;
        int                  _Timeout;
    };

    bool event::_Run = true;
    bool event::_Restart = false;

    class EventWorkerArgs{
    public:
        EventWorkerArgs(){
        }

        EventWorkerArgs(const EventWorkerArgs &eargs){
            event=eargs.event;
            pollfd=eargs.pollfd;
            ssocket=eargs.ssocket;
            timeout=eargs.timeout;
            args=eargs.args;
        }

        int                 pollfd;
        int                 timeout;

        eventapi           *event;
        socket             *ssocket;
        void               *args;
    };

    class EventWorker {
    public:
        EventWorker(int tid,EventWorkerArgs* args) {
            poll pollptr(args->ssocket,args->event,args->pollfd,args->timeout);

EVENTLOOP:
            try {
                int wait=pollptr.waitEventHandler();
                for(int i =0; i<wait; ++i){
                    try{
                        switch (pollptr.pollState(i)) {
                            case pollapi::EventHandlerStatus::EVCON:
                                pollptr.ConnectEventHandler(i,tid,args);
                                continue;
                            case pollapi::EventHandlerStatus::EVIN:
                                pollptr.ReadEventHandler(i,tid,args);
                                continue;
                            case pollapi::EventHandlerStatus::EVOUT:
                                pollptr.WriteEventHandler(i,tid,args);
                                continue;
                            default:
                                NetException  e;
                                e[NetException::Error] << "EventWorker: no known event !";
                                throw e;
                        }
                    }catch(NetException& e){
                        switch(e.getErrorType()){
                            case NetException::Critical:
                                throw e;
                            case NetException::Note:
                                continue;
                            default:
                                std::cerr << e.what() << std::endl;
                                pollptr.CloseEventHandler(i,tid,args);
                                continue;
                        }
                    }
                }

            }catch (NetException& e) {
                if (e.getErrorType() == NetException::Critical) {
                    throw e;
                }else if(e.getErrorType() != NetException::Note){
                    std::cerr << e.what() << std::endl;
                }
            }
            goto EVENTLOOP;
        }
    };

    void eventapi::RequestEvent(con *curcon,const int tid,void *args){
        //dummy
    };

    void eventapi::ResponseEvent(con *curcon,const int tid,void *args){
        //dummy
    };

    void eventapi::ConnectEvent(con *curcon,const int tid,void *args){
        //dummy
    };

    void eventapi::DisconnectEvent(con *curcon,const int tid,void *args){
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
        _Timeout=timeout;
        _ServerSocket=serversocket;
        _ServerSocket->bind();
        _ServerSocket->setnonblocking();
        _ServerSocket->listen();
        threads=sysconf(_SC_NPROCESSORS_ONLN);
    }

    event::~event() {
    }

    void event::runEventloop(void *args) {
        NetException exception;

        signal(SIGPIPE, SIG_IGN);

        _pollFD = kqueue();

        if (_pollFD < 0) {
            char errstr[255];
            strerror_r_netplus(errno,errstr,255);
            exception[NetException::Critical] << "initEventHandler:" << "can't create kqueue: " << errstr;
            throw exception;
        }

        struct kevent setevent ={
            0
        };

        EV_SET(&setevent,_ServerSocket->fd(),EVFILT_READ,EV_ADD | EV_CLEAR,0,0,nullptr);

        if (kevent(_pollFD,&setevent,1,nullptr,0,nullptr) < 0) {
            char errstr[255];
            strerror_r_netplus(errno,errstr,255);
            exception[NetException::Critical] << "initEventHandler: can't create kqueue: " << errstr;
            throw exception;
        }

    MAINWORKERLOOP:
        EventWorkerArgs eargs;
        eargs.ssocket=_ServerSocket;
        eargs.event=this;
        eargs.pollfd=_pollFD;
        eargs.timeout=_Timeout;

        std::thread **threadpool = new std::thread*[threads];

        for (size_t i = 0; i < threads; i++) {
            try {
                threadpool[i] = new std::thread([&eargs,i]{
                    EventWorker *evt = new EventWorker(i,&eargs);
                    delete evt;
                });
           } catch (NetException& e) {
               throw e;
           }
        }


        for(size_t i = 0; i < threads; i++){
            threadpool[i]->join();
            delete threadpool[i];
        }

        delete[] threadpool;

        close(_pollFD);

        if (event::_Restart) {
            event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};

