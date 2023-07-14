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

    int poll::pollState(int pos){
        NetException exception;
        con* ccon = (con*)_Events[pos].data.ptr;
        if (!ccon) {
            return EventHandlerStatus::EVCON;
        }
        if (ccon->getSendData()) {
            return EventHandlerStatus::EVOUT;
        }
        return EventHandlerStatus::EVIN;
    }

    unsigned int poll::waitEventHandler() {
        int ret = epoll_wait(_pollFD, (struct epoll_event*)_Events, _ServerSocket->getMaxconnections(), -1);
        if (ret == -1) {
            NetException exception;
            exception[NetException::Error] << "waitEventHandler: epoll wait failure";
            throw exception;
        }
        return ret;
    };

    void poll::ConnectEventHandler(int pos) {
        NetException exception;
        con *ccon;
        try {
            ccon = new con(this);
            ccon->conlock.lock();
            ccon->csock = _ServerSocket->accept();
            ccon->csock->setnonblocking();

            struct poll_event setevent { 0 };
            setevent.events = EPOLLIN;
            setevent.data.ptr = ccon;

            if (epoll_ctl(_pollFD, EPOLL_CTL_ADD, ccon->csock->getSocket(), (struct epoll_event*)&setevent) < 0) {
                exception[NetException::Error] << "ConnectEventHandler: can't add socket to epoll";
                throw exception;
            }
            std::cout << "I'am connecting" << std::endl;
            ConnectEvent(ccon);
            ccon->conlock.unlock();
        } catch (NetException& e) {
            delete ccon->csock;
            delete ccon;
            throw e;
        }
    };

    void poll::ReadEventHandler(int pos) {
        con* rcon = (con*)_Events[pos].data.ptr;
        if (!rcon) {
                NetException exp;
                exp[NetException::Error] << "ReadEvent: No valied Connection at pos: " << pos;
                throw exp;
        }
        try {
            char buf[BLOCKSIZE];
            ssize_t rcvsize = _ServerSocket->recvData(rcon->csock, buf, BLOCKSIZE);
            if (rcvsize < 0) {
                NetException exp;
                exp[NetException::Error] << "ReadEvent: recvData failed at pos: " << pos;
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

    void poll::WriteEventHandler(int pos) {
        con* wcon = (con*)_Events[pos].data.ptr;
        if (!wcon) {
                NetException exp;
                exp[NetException::Error] << "WriteEvent: No valied Connection at pos: " << pos;
                throw exp;
        }
        try {
            ssize_t sended = _ServerSocket->sendData(wcon->csock,
                (void*)wcon->getSendData()->getData(),
                wcon->getSendData()->getDataLength(), 0);

            if (sended < 0) {
                NetException exp;
                exp[NetException::Error] << "WriteEvent: sendData failed at pos: " << pos;
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

    void poll::CloseEventHandler(int pos) {
        NetException except;
        con* delcon = (con*)_Events[pos].data.ptr;

        if (!delcon) {
            except[NetException::Error] << "CloseEvent connection empty cannot remove!";
            throw except;
        }

        int ect = epoll_ctl(_pollFD, EPOLL_CTL_DEL,
            delcon->csock->getSocket(), 0);

        if (ect < 0) {
            except[NetException::Error] << "CloseEvent can't delete Connection from epoll";
            throw except;
        }

        DisconnectEvent(delcon);
        delete delcon->csock;
        delete delcon;
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

    void poll::unlockCon(int pos){
        const std::lock_guard<std::mutex> lock(_StateLock);
        con *curcon=(con*)_Events[pos].data.ptr;
        if(curcon)
            curcon->conlock.unlock();
    }

    bool poll::trylockCon(int pos){
        const std::lock_guard<std::mutex> lock(_StateLock);
        con *curcon=(con*)_Events[pos].data.ptr;
        if(curcon)
            return curcon->conlock.try_lock();
        return false;
    }

    bool event::_Run = true;
    bool event::_Restart = false;

    class EventWorker{
    public:

        EventWorker(void* args) {
            eventapi* eventptr = ((eventapi*)args);
            while (event::_Run) {
                try {
                    int wfd = eventptr->waitEventHandler();
                    for (int i = 0; i < wfd; ++i) {
                        try {
                            if(!eventptr->trylockCon(i))
                                continue;
                            switch (eventptr->pollState(i)) {
                                case poll::EVCON:
                                    eventptr->ConnectEventHandler(i);
                                    break;
                                case poll::EVIN:
                                    eventptr->ReadEventHandler(i);
                                    break;
                                case poll::EVOUT:
                                    eventptr->WriteEventHandler(i);
                                    break;
                                case poll::EVWAIT:
                                    break;
                                default:
                                    eventptr->CloseEventHandler(i);
                                    break;
                            }
                            eventptr->unlockCon(i);
                        } catch (NetException& e) {
                            std::cerr << e.what() << std::endl;
                            eventptr->CloseEventHandler(i);
                            if (e.getErrorType() == NetException::Critical) {
                                throw e;
                            }
                        }
                    }
                }
                catch (NetException& e) {
                    switch (e.getErrorType()) {
                        case NetException::Critical:
                            throw e;
                        default:
                            std::cerr << e.what() << std::endl;
                            break;
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
        unsigned long thrs = sysconf(_SC_NPROCESSORS_ONLN);
        signal(SIGPIPE, SIG_IGN);
        initEventHandler();
    MAINWORKERLOOP:

        std::vector<std::thread> thpool;
        for (unsigned long i = 0; i < thrs; i++) {
           try {
               thpool.push_back(std::thread([this](){
                   new EventWorker((void*)this);
               }));
           }
           catch (NetException& e) {
               throw e;
           }
        }

        for(std::vector<std::thread>::iterator thd = thpool.begin(); thd!=thpool.end();  ++thd){
            thd->join();
        }

        if (event::_Restart) {
            event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};

