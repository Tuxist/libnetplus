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

#include <vector>
#include <memory>
#include <atomic>

#pragma once

namespace netplus {
        class eventapi;
        
        class con {
        public:
            class condata {
            public:
                const char*      getData();
                unsigned long    getDataLength();
                condata         *nextcondata();
            protected:
                condata(const char*data, unsigned long datasize);
                ~condata();
            private:
                std::vector<char> _Data;
                condata          *_nextConnectionData;
                friend class    con;
            };
            
            con(eventapi *event);
            ~con();
            
            /*Cache helper functions*/
            
            int             copyValue(condata* startblock, size_t startpos,
                                      condata* endblock, size_t endpos, std::vector<char> &buffer);
            int             searchValue(condata* startblock, condata** findblock,
                                        const char* keyword);
            int             searchValue(condata* startblock, condata** findblock,
                                        const char* keyword,unsigned long keylen);
            
            condata *addSendQueue(const char *data,unsigned long datasize);
            condata *resizeSendQueue(size_t size);
            void     cleanSendData();
            condata *getSendFirst();
            condata *getSendLast();
            size_t   getSendLength();
            
            /*Get Data funtions Recv Queue*/
            condata *addRecvQueue(const char *data,unsigned long datasize);
            condata *resizeRecvQueue(size_t size);
            void     cleanRecvData();
            condata *getRecvFirst();
            condata *getRecvLast();
            size_t   getRecvLength();
            
            /*clientsocket*/
            std::shared_ptr<socket> csock;

            /*set sending state*/
            void    sending(bool state);
            bool    issending();

            std::atomic<bool> closecon;
        protected:
            con();
            /*Incomming Data*/
            size_t   _ReadDataLength;
            /*Outgoing Data*/
            size_t   _SendDataLength;
        private:
            condata *_resizeQueue(condata **firstdata, condata **lastdata,
                                  size_t &qsize,size_t size);
            
            /*Incomming Data*/
            condata *_ReadDataFirst;
            condata *_ReadDataLast;
            
            /*Outgoing Data*/
            condata   *_SendDataFirst;
            condata   *_SendDataLast;
            eventapi  *_eventapi;
            
            /*if pollout*/
            bool      _sending;

            friend class poll;
        };
};
