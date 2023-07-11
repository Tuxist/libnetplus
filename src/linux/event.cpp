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

#include <sys/epoll.h>
#include <stdlib.h>
#include <stdint.h> 

#include <socket.h>
#include <exception.h>
#include <eventapi.h>
#include <connection.h>

#define READEVENT 0
#define SENDEVENT 1

#define BLOCKSIZE 16384

namespace netplus {

    socket* serversocket) {
        _ServerSocket = serversocket;
    };

    poll() {
    };

    /*basic functions*/
    const char* getpolltype() {
        return "EPOLL";
    }

    /*event handler function*/
    void initEventHandler() {
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

    unsigned int waitEventHandler() {
        int ret = epoll_wait(_pollFD, (struct epoll_event*)_Events, _ServerSocket->getMaxconnections(), -1);
        if (ret == -1) {
            NetException exception;
            exception[NetException::Error] << "waitEventHandler: epoll wait failure";
            throw exception;
        }
        return ret;
    };

    int ConnectEventHandler(int pos) {
        NetException exception;
        con* ccon = (con*)_Events[pos].data.ptr;
        try {
            if (!ccon) {
                ccon = new con(this);
                ccon->csock = _ServerSocket->accept();
                ccon->csock->setnonblocking();

                struct poll_event setevent { 0 };
                setevent.events = EPOLLIN;
                setevent.data.ptr = ccon;

                if (epoll_ctl(_pollFD, EPOLL_CTL_ADD, ccon->csock->getSocket(), (struct epoll_event*)&setevent) < 0) {
                    delete ccon->csock;
                    delete ccon;
                    exception[NetException::Error] << "ConnectEventHandler: can't add socket to epoll";
                    throw exception;
                }

                ConnectEvent(ccon);

                sys::cout << "I'am connecting" << sys::endl;

                return EventHandlerStatus::EVIN;
            }
            else if (ccon->getSendData()) {
                sys::cout << "I'am sendding" << sys::endl;
                return EventHandlerStatus::EVOUT;
            }
            else {
                sys::cout << "I'am reading" << sys::endl;
                return EventHandlerStatus::EVIN;
            }
        }
        catch (NetException& e) {
            throw e;
        }
    };

    void ReadEventHandler(int pos) {
        try {
            con* rcon = (con*)_Events[pos].data.ptr;
            if (!rcon) {
                NetException exp;
                exp[NetException::Error] << "ReadEvent: No valied Connection at pos: " << pos;
                throw exp;
            }
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

    void WriteEventHandler(int pos) {
        try {
            con* wcon = (con*)_Events[pos].data.ptr;
            if (!wcon) {
                NetException exp;
                exp[NetException::Error] << "WriteEvent: No valied Connection at pos: " << pos;
                throw exp;
            }
            ssize_t sended = _ServerSocket->sendData(wcon->csock,
                (void*)wcon->getSendData()->getData(),
                wcon->getSendData()->getDataSize(), 0);

            if (sended < 0) {
                NetException exp;
                exp[NetException::Error] << "WriteEvent: sendData failed at pos: " << pos;
                throw exp;
            }

            if (sended == 0)
                sended = wcon->getSendData()->getDataSize();

            wcon->resizeSendQueue(sended);
            ResponseEvent(wcon);
        }
        catch (NetException& e) {
            throw e;
        }
    };

    void CloseEventHandler(int pos) {
        SystemException except;
        _ELock.lock();

        con* delcon = (con*)_Events[pos].data.ptr;

        if (!delcon) {
            except[SystemException::Error] << "CloseEvent connection empty cannot remove!";
            _ELock.unlock();
            throw except;
        }

        int ect = epoll_ctl(_pollFD, EPOLL_CTL_DEL,
            delcon->csock->getSocket(), 0);

        if (ect < 0) {
            except[SystemException::Error] << "CloseEvent can't delete Connection from epoll";
            _ELock.unlock();
            throw except;
        }

        DisconnectEvent(delcon);
        delete delcon->csock;
        delete delcon;

        _ELock.unlock();
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
        SystemException except;
        struct poll_event setevent { 0 };
        setevent.events = events;
        setevent.data.ptr = curcon;
        if (epoll_ctl(_pollFD, EPOLL_CTL_MOD,
            curcon->csock->getSocket(), (struct epoll_event*)&setevent) < 0) {
            except[SystemException::Error] << "_setEpollEvents: can change socket!";
            throw except;
        }
    };


    bool Run = true;
    bool _Restart = false;

    class EventWorker /*: public thread*/ {
    public:

        EventWorker(void* args) /*: thread(args) */{

        };


        void* run(void* args) {
            net::eventapi* eventptr = ((net::eventapi*)args);
            while (net::event::_Run) {
                try {
                    unsigned int wfd = eventptr->waitEventHandler();
                    for (int i = 0; i < wfd; ++i) {
                        try {
                            switch (eventptr->ConnectEventHandler(i)) {
                            case net::poll::EVIN:
                                eventptr->ReadEventHandler(i);
                                break;
                            case net::poll::EVOUT:
                                eventptr->WriteEventHandler(i);
                                break;
                            default:
                                SystemException excep;
                                excep[SystemException::Error] << "no action try to close";
                                throw excep;
                            }
                        }
                        catch (SystemException& e) {
                            sys::cout << e.what() << sys::endl;
                            eventptr->CloseEventHandler(i);
                            if (e.getErrorType() == SystemException::Critical) {
                                throw e;
                            }
                        }
                    }
                }
                catch (SystemException& e) {
                    switch (e.getErrorType()) {
                    case SystemException::Critical:
                        sys::cerr << e.what() << sys::endl;
                        break;
                    }
                }
            }
            return nullptr;
        }
    };

    eventapi::~eventapi() {
    }

    event(socket* serversocket) : poll(serversocket) {
        if (!serversocket) {
            SystemException exp;
            exp[SystemException::Critical] << "server socket empty!";
            throw exp;
        }
    }

    event() {
    }


    void RequestEvent(con* curcon) {
        return;
    }

    void ResponseEvent(con* curcon) {
        return;
    }

    void ConnectEvent(con* curcon) {
        return;
    }

    void DisconnectEvent(con* curcon) {
        return;
    }

    void runEventloop() {
        CpuInfo cpuinfo;
        unsigned long thrs = 1; //cpuinfo.getThreads();
        initEventHandler();
    MAINWORKERLOOP:

        //threadpool thpool;
        //for (unsigned long i = 0; i < thrs; i++) {
        //    try {
        //        thread* wth = new EventWorker((void*)this);
        //        thpool.addjob(wth);
        //    }
        //    catch (SystemException& e) {
        //        throw e;
        //    }
        //}

        //thpool.join();

        EventWorker evtwrk((void*)this);
        evtwrk.run((void*)this);
        if (net::event::_Restart) {
            net::event::_Restart = false;
            goto MAINWORKERLOOP;
        }
    }
};
