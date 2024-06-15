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
#include "error.h"
#include <assert.h>

#define READEVENT 0
#define SENDEVENT 1

#define BLOCKSIZE 16384

namespace netplus {
    std::mutex clock;
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
        virtual void ConnectEventHandler(int pos)=0;
        virtual void ReadEventHandler(int pos)=0;
        virtual void WriteEventHandler(int pos)=0;
        virtual void CloseEventHandler(int pos)=0;

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
            _Events = new epoll_event[_ServerSocket->getMaxconnections()];
            int maxcon=_ServerSocket->getMaxconnections();
            for (int i = 0; i <maxcon;  ++i){
                _Events[i].data.ptr = nullptr;
            }
        };

        ~poll() {
            int maxcon=_ServerSocket->getMaxconnections();
            for (int i = 0; i < maxcon; ++i){
                _evtapi->deleteConnetion((con*)_Events[i].data.ptr);
            }
            delete _Events;
        };

        /*basic functions*/
        const char* getpolltype() {
            return "EPOLL";
        }

        /*event handler function*/
        void initEventHandler() {

        };

        void setpollEvents(con* curcon,int events){
            NetException except;
            struct epoll_event setevent = { 0 };
            setevent.events = events;
            setevent.data.ptr = curcon;

            if (epoll_ctl(_pollFD, EPOLL_CTL_MOD,curcon->csock->_Socket
                ,&setevent) < 0) {
                except[NetException::Error] << "_setEpollEvents: can change socket!";
                throw except;
            }
        }

        int pollState(int pos){
            con *pcon = (con*)_Events[pos].data.ptr;
            NetException exception;

            if(!pcon)
                return EventHandlerStatus::EVCON;

            return pcon->state;
        }

        int waitEventHandler() {
            int evn = epoll_wait(_pollFD,_Events, _ServerSocket->getMaxconnections(), -1);
            if (evn < 0 ) {
                NetException exception;

                char str[255];
                strerror_r_netplus(errno,str,255);

                exception[NetException::Error] << "waitEventHandler: epoll wait failure: " << str;
                throw exception;
            }
            return evn;
        };

        void ConnectEventHandler(int pos)  {
            std::lock_guard<std::mutex> lock(clock);
            NetException exception;
            con *ccon;
            _evtapi->CreateConnetion(&ccon);

            try {
                if(_ServerSocket->_Type==sockettype::TCP){
                    ccon->csock=new tcp();
                    _ServerSocket->accept(ccon->csock);
                }else if(_ServerSocket->_Type==sockettype::UDP){
                    ccon->csock=new udp();
                    _ServerSocket->accept(ccon->csock);
                }else if(_ServerSocket->_Type==sockettype::SSL){
                    ccon->csock=new ssl();
                    _ServerSocket->accept(ccon->csock);
                }else{
                    exception[NetException::Error] << "ConnectEventHandler: Protocoll are supported";
                    throw exception;

                }

                ccon->csock->setnonblocking();

                std::string ip;
                ccon->csock->getAddress(ip);
                std::cout << "Connected: " << ip  << std::endl;

                ccon->lasteventime = time(nullptr);
                ccon->state=EVIN;

                struct epoll_event setevent { 0 };
                setevent.events =  EPOLLIN | EPOLLET | EPOLLONESHOT;
                setevent.data.ptr = ccon;

                int estate = epoll_ctl(_pollFD, EPOLL_CTL_ADD,ccon->csock->_Socket, &setevent);

                if ( estate < 0 ) {
                    char errstr[255];
                    strerror_r_netplus(errno,errstr,255);
                    exception[NetException::Error] << "ConnectEventHandler: can't add socket to epoll: " << errstr;
                    throw exception;
                }

                _evtapi->ConnectEvent(ccon);

            } catch (NetException& e) {
                _evtapi->deleteConnetion(ccon);
                _Events[pos].data.ptr=NULL;
                throw e;
            }

        };

        void ReadEventHandler(int pos) {
            con *rcon = (con*)_Events[pos].data.ptr;

            try{
                char buf[BLOCKSIZE];
                size_t rcvsize = _ServerSocket->recvData(rcon->csock, buf, BLOCKSIZE);

                if(rcvsize>0){
                     rcon->RecvData.append(buf,rcvsize);
                    _evtapi->RequestEvent(rcon);
                }

                rcon->lasteventime = time(nullptr);

                if(!rcon->SendData.empty()){
                    rcon->state=EVOUT;
                    setpollEvents(rcon,EPOLLOUT | EPOLLET | EPOLLONESHOT);
                    return;
                }

                setpollEvents(rcon,EPOLLIN | EPOLLET | EPOLLONESHOT);


            }catch(NetException &e){
                if(e.getErrorType()== NetException::Note){
                     rcon->state=EVIN;
                     setpollEvents(rcon,EPOLLIN | EPOLLET | EPOLLONESHOT);
                     return;
                }
                throw e;
            }
        };

        void WriteEventHandler(int pos) {
            con *wcon = (con*)_Events[pos].data.ptr;
            try{
                if(wcon->SendData.empty()){
                    wcon->state=EVIN;
                    setpollEvents(wcon,EPOLLIN | EPOLLET | EPOLLONESHOT);
                    return;
                }

                size_t ssize = BLOCKSIZE < wcon->SendData.size() ? BLOCKSIZE : wcon->SendData.size();

                std::cout << ssize << std::endl;

                size_t sended = _ServerSocket->sendData(wcon->csock,wcon->SendData.data(),ssize);

                wcon->SendData.resize(sended);

                wcon->lasteventime = time(nullptr);

                wcon->state=EVOUT;

                _evtapi->ResponseEvent(wcon);

                setpollEvents(wcon,EPOLLOUT | EPOLLET | EPOLLONESHOT);
            }catch(NetException &e){
                if(e.getErrorType()== NetException::Note){
                    wcon->state=EVOUT;
                    setpollEvents(wcon,EPOLLOUT | EPOLLET | EPOLLONESHOT);
                    return;
                }else{
                    throw e;
                }
            }
        };


        void CloseEventHandler(int pos) {
            con *ccon = (con*)_Events[pos].data.ptr;

            if(!ccon)
                return;

            try{

                if(epoll_ctl(_pollFD, EPOLL_CTL_DEL,ccon->csock->fd(), 0)<0){
                    NetException except;
                    char errstr[255];
                    strerror_r_netplus(errno,errstr,255);
                    except[NetException::Error] << "CloseEventHandler: can't close socket to epoll: " << errstr;
                    throw except;
                }
                 delete  ccon->csock;

                _evtapi->DisconnectEvent(ccon);

                _evtapi->deleteConnetion(ccon);

                _Events[pos].data.ptr=nullptr;
            }catch(NetException &e){
                throw e;
            }

        };

    private:
        int                  _pollFD;
        struct epoll_event  *_Events;
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
        }

        int                 pollfd;
        int                 timeout;

        eventapi           *event;
        socket             *ssocket;
    };

    class EventWorker {
    public:
        EventWorker(void* args) {

            EventWorkerArgs *wargs=(EventWorkerArgs*)args;
            poll pollptr(wargs->ssocket,wargs->event,wargs->pollfd,wargs->timeout);

EVENTLOOP:
            try {
                int wait=pollptr.waitEventHandler();
                for(int i =0; i<wait; ++i){
                    try{
                        switch (pollptr.pollState(i)) {
                            case pollapi::EventHandlerStatus::EVCON:
                                pollptr.ConnectEventHandler(i);
                                break;
                            case pollapi::EventHandlerStatus::EVIN:
                                pollptr.ReadEventHandler(i);
                                break;
                            case pollapi::EventHandlerStatus::EVOUT:
                                pollptr.WriteEventHandler(i);
                                break;
                            default:
                                pollptr.CloseEventHandler(i);
                                break;
                        }
                    }catch(NetException& e){
                        switch(e.getErrorType()){
                            case NetException::Critical:
                                throw e;
                            case NetException::Note:
                                break;
                            default:
                                std::cerr << e.what() << std::endl;
                                pollptr.CloseEventHandler(i);
                                break;
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
        _Timeout=timeout;
        _ServerSocket=serversocket;
        _ServerSocket->bind();
        _ServerSocket->setnonblocking();
        _ServerSocket->listen();
    }

    event::~event() {
    }

    void event::runEventloop() {
        NetException exception;

        size_t thrs =  sysconf(_SC_NPROCESSORS_ONLN);
        signal(SIGPIPE, SIG_IGN);

        _pollFD = epoll_create1(0);

        if (_pollFD < 0) {
            exception[NetException::Critical] << "initEventHandler:" << "can't create epoll";
            throw exception;
        }

        struct epoll_event setevent ={
            0
        };

        setevent.events = EPOLLIN | EPOLLET;
        setevent.data.ptr = nullptr;

        if (epoll_ctl(_pollFD, EPOLL_CTL_ADD,_ServerSocket->fd(),&setevent) < 0) {
            exception[NetException::Critical] << "initEventHandler: can't create epoll";
            throw exception;
        }

    MAINWORKERLOOP:
        EventWorkerArgs eargs;
        eargs.ssocket=_ServerSocket;
        eargs.event=this;
        eargs.pollfd=_pollFD;
        eargs.timeout=_Timeout;

        std::thread **threadpool = new std::thread*[thrs];

        for (size_t i = 0; i < thrs; i++) {
            try {
                threadpool[i] = new std::thread([eargs]{
                    new EventWorker((void*)&eargs);
                });
           } catch (NetException& e) {
               throw e;
           }
        }

        for(size_t i = 0; i < thrs; i++){
            threadpool[i]->join();
            delete[] threadpool[i];
        }

        delete[] threadpool;

        close(_pollFD);

        if (event::_Restart) {
            event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};

