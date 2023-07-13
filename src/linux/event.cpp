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
#include <map>
#include <thread>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdint.h> 

#include "socket.h"
#include "exception.h"
#include "eventapi.h"
#include "connection.h"

#define READEVENT 0
#define SENDEVENT 1

#define BLOCKSIZE 16384

struct poll_event {
    uint32_t events;
    epoll_data_t data;
}
#ifdef __x86_64__
__attribute__((__packed__))
#endif
;

namespace netplus {

    poll::poll(socket* serversocket) {
        _ServerSocket = serversocket;
    };

    poll::~poll() {
    };

    /*basic functions*/
    const char* poll::getpolltype() {
        return "EPOLL";
    }

    int poll::pollState(int thid,con *ccon){
        ccon=thcon[thid];
        if(!ccon){
            return poll::EVWAIT;
        }
        if(ccon->getSendLength()!=0)
            return poll::EVOUT;

        return poll::EVIN;
    }

    /*event handler function*/
    void poll::initEventHandler() {
        NetException exception;
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

        setevent.events = EPOLLIN | EPOLLOUT;
        setevent.data.ptr = nullptr;

        if (epoll_ctl(_pollFD, EPOLL_CTL_ADD,
            _ServerSocket->getSocket(),(struct epoll_event*)&setevent) < 0) {
            exception[NetException::Critical] << "initEventHandler: can't create epoll";
            throw exception;
        }

        _Events = new poll_event[_ServerSocket->getMaxconnections()];
        for (int i = 0; i < _ServerSocket->getMaxconnections(); ++i)
            _Events[i].data.ptr = nullptr;
    };

    unsigned int poll::waitEventHandler() {
        int ret = epoll_wait(_pollFD, (struct epoll_event*)_Events, _ServerSocket->getMaxconnections(), -1);
        if (ret == -1) {
            NetException exception;
            exception[NetException::Error] << "waitEventHandler: epoll wait failure";
            throw exception;
        }
        return ret;
    };

    void poll::ConnectEventHandler(con** ccon) {
        NetException exception;
        try {
            if (!ccon) {
                *ccon = new con(this);
                (*ccon)->csock = _ServerSocket->accept();
                (*ccon)->csock->setnonblocking();

                struct poll_event setevent { 0 };
                setevent.events = EPOLLIN;
                setevent.data.ptr = *ccon;

                if (epoll_ctl(_pollFD, EPOLL_CTL_ADD, (*ccon)->csock->getSocket(), (struct epoll_event*)&setevent) < 0) {
                    exception[NetException::Error] << "ConnectEventHandler: can't add socket to epoll";
                    throw exception;
                }
                ConnectEvent(*ccon);
            }
        } catch (NetException& e) {
            delete (*ccon)->csock;
            delete *ccon;
            ccon=nullptr;
            throw e;
        }
    };

    void poll::ReadEventHandler(con* rcon) {
        try {

            char buf[BLOCKSIZE];
            ssize_t rcvsize = _ServerSocket->recvData(rcon->csock, buf, BLOCKSIZE);
            if (rcvsize < 0) {
                NetException exp;
                exp[NetException::Error] << "ReadEvent: recvData failed close connection!";
                throw exp;
            }

            if (rcvsize == 0)
                rcvsize = BLOCKSIZE;

            rcon->addRecvQueue(buf, rcvsize);
            RequestEvent(rcon);
        }
        catch (NetException& e) {
            throw e;
        }
    };

    void poll::WriteEventHandler(con* wcon) {
        try {

            ssize_t sended = _ServerSocket->sendData(wcon->csock,
                (void*)wcon->getSendData()->getData(),
                wcon->getSendData()->getDataLength(), 0);

            if (sended < 0) {
                NetException exp;
                exp[NetException::Error] << "WriteEvent: sendData failed failed close connection!";
                throw exp;
            }

            if (sended == 0)
                sended = wcon->getSendData()->getDataLength();

            wcon->resizeSendQueue(sended);
            ResponseEvent(wcon);
        }
        catch (NetException& e) {
            throw e;
        }
    };

    void poll::CloseEventHandler(con** dcon) {
        NetException except;

        int ect = epoll_ctl(_pollFD, EPOLL_CTL_DEL,(*dcon)->csock->getSocket(), 0);

        if (ect < 0) {
            except[NetException::Error] << "CloseEvent can't delete Connection from epoll";
            throw except;
        }

        DisconnectEvent(*dcon);
        delete (*dcon)->csock;
        delete *dcon;
        dcon=nullptr;
    };

    /*Connection Ready to send Data*/
    void poll::sendReady(con* curcon, bool ready) {
        if (ready) {
            _setpollEvents(curcon, EPOLLIN | EPOLLOUT);
        }
        else {
            _setpollEvents(curcon, EPOLLIN);
        }
    };


    void poll::_setpollEvents(con* curcon, int events) {
        NetException except;
        struct poll_event setevent { 0 };
        setevent.events = events;
        setevent.data.ptr = curcon;
        if (epoll_ctl(_pollFD, EPOLL_CTL_MOD,
            curcon->csock->getSocket(), (struct epoll_event*)&setevent) < 0) {
            except[NetException::Error] << "_setEpollEvents: can change socket!";
            throw except;
        }
    };

    bool event::_Run = true;
    bool event::_Restart = false;

    struct workerArgs{
        eventapi *api;
        int       thid;
    };

    class EventWorker{
    public:

        EventWorker(void* args) {
            eventapi* eventptr = ((workerArgs*)args)->api;
            int id= ((workerArgs*)args)->thid;
            while (event::_Run) {
                try {
                    con *ccon=nullptr;
                    switch (eventptr->pollState(id,ccon)) {
                        case poll::EVIN:
                            eventptr->ReadEventHandler(ccon);
                            break;
                        case poll::EVOUT:
                            eventptr->WriteEventHandler(ccon);
                            break;
                        default:
                            usleep(1000);
                    }
                } catch (NetException& e) {
                    std::cout << e.what() << std::endl;
                    if (e.getErrorType() == NetException::Critical) {
                        throw e;
                    }
                }
            }
        }
    };

    eventapi::~eventapi() {
    }

    event::event(socket* serversocket) : poll(serversocket) {
        if (!serversocket) {
            NetException exp;
            exp[NetException::Critical] << "server socket empty!";
            throw exp;
        }
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
        thdsamount = sysconf(_SC_NPROCESSORS_ONLN);
        signal(SIGPIPE, SIG_IGN);
        initEventHandler();
    MAINWORKERLOOP:

        std::map<int,std::thread> thpool;
        for (size_t i = 0; i < thdsamount; i++) {
           try {
               struct workerArgs args;
               args.api=this;
               args.thid=i;
               thpool[i]=(std::thread([args](){
                   new EventWorker((void*)&args);
               }));
           }
           catch (NetException& e) {
               throw e;
           }
        }



        for (size_t i = 0; i < thdsamount; i++)
            thcon[i]=nullptr;

        while (event::_Run) {
            try {
                int wfd = waitEventHandler();
                for(int i = 0; i < wfd; ++i){
                    con *ccon=nullptr;
                    try{
                        ConnectEventHandler(&ccon);
                        bool free=false;
    SEARCHFREEWORKINGTHREAD:
                        for(size_t ii = 0; ii < thdsamount; ii++){
                            if(!thcon[ii]){
                                thcon[ii]=ccon;
                                free=true;
                            }
                        }
                        if(!free)
                            goto SEARCHFREEWORKINGTHREAD;
                    }catch (NetException& e) {
                        switch (e.getErrorType()) {
                            case NetException::Critical:{
                                throw e;
                            }
                        }
                        std::cout << e.what() << std::endl;
                        if(ccon){
                            for(size_t ii = 0; ii < thdsamount; ii++){
                                if(thcon[ii]==ccon){
                                    CloseEventHandler(&ccon);
                                    thcon[ii]=nullptr;
                                }
                            }
                        }

                    }
                }
            } catch (NetException& e) {
                switch (e.getErrorType()) {
                    case NetException::Critical:{
                        throw e;
                    }
                }
            }
        }

        for(std::map<int,std::thread>::iterator thd = thpool.begin(); thd!=thpool.end();  ++thd){
            thd->second.join();
        }

        if (event::_Restart) {
            event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};
