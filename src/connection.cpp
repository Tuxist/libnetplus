/*******************************************************************************
 * Copyright (c) 2022, Jan Koester jan.koester@gmx.net
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

#include <cstring>

#include "socket.h"
#include "connection.h"
#include "eventapi.h"
#include "exception.h"

const char* netplus::con::condata::getData(){
  return _Data.c_str();
}

unsigned long netplus::con::condata::getDataLength(){
  return _Data.length();
}

netplus::con::condata *netplus::con::condata::nextcondata(){
  return _nextConnectionData;
}

netplus::con::condata::condata(const char*data,unsigned long datasize)  {
    _Data.append(data,datasize);
    _nextConnectionData=nullptr;
}

netplus::con::condata::~condata() {
    delete _nextConnectionData;
}

/** \brief a method to add Data to Sendqueue
  * \param data an const char* to add to sendqueue
  * \param datasize an size_t to set datasize
  * \return the last ConnectionData Block from Sendqueue
  * 
  * This method does unbelievably useful things.  
  * And returns exceptionally the new connection data block.
  * Use it everyday with good health.
  */

netplus::con::condata *netplus::con::addSendQueue(const char*data,unsigned long datasize){
    if(datasize<=0){
        NetException excp;
        excp[NetException::Error] << "addSendQueue wrong datasize";
        throw excp;
    }
    if(!_SendDataFirst){
        _SendDataFirst= new con::condata(data,datasize);
        _SendDataLast=_SendDataFirst;
    }else{
        _SendDataLast->_nextConnectionData=new con::condata(data,datasize);
        _SendDataLast=_SendDataLast->_nextConnectionData;
    }
    _SendDataLength+=datasize;
    _eventapi->sendReady(this,true);
    return _SendDataLast;
}

void netplus::con::cleanSendData(){
   delete _SendDataFirst;
   _SendDataFirst=nullptr;
   _SendDataLast=nullptr;
   _SendDataLength=0;
}

netplus::con::condata *netplus::con::resizeSendQueue(unsigned long size){
    try{
        return _resizeQueue(&_SendDataFirst,&_SendDataLast,_SendDataLength,size);
    }catch(char *e){
        throw e; 
    }
}

netplus::con::condata* netplus::con::getSendData(){
  return _SendDataFirst;
}

size_t netplus::con::getSendLength(){
  return _SendDataLength;
}

netplus::con::condata *netplus::con::addRecvQueue(const char *data,unsigned long datasize){
    if(datasize<=0){
        NetException excp;
        excp[NetException::Error] << "addRecvQueue wrong datasize";
        throw excp;
    }
    if(!_ReadDataFirst){
        _ReadDataFirst= new con::condata(data,datasize);
        _ReadDataLast=_ReadDataFirst;
    }else{
        _ReadDataLast->_nextConnectionData=new con::condata(data,datasize);
        _ReadDataLast=_ReadDataLast->_nextConnectionData;
    }
    _ReadDataLength+=datasize;
    return _ReadDataLast;
}

void netplus::con::cleanRecvData(){
   delete _ReadDataFirst;
  _ReadDataFirst=nullptr;
  _ReadDataLast=nullptr;
  _ReadDataLength=0;
}


netplus::con::condata *netplus::con::resizeRecvQueue(unsigned long size){
    try{
        return _resizeQueue(&_ReadDataFirst,&_ReadDataLast,_ReadDataLength,size);
    }catch(char *e){
        throw e; 
    }
}

netplus::con::condata *netplus::con::getRecvData(){
  return _ReadDataFirst;
}

unsigned long netplus::con::getRecvLength(){
  return _ReadDataLength;
}

void netplus::con::sending(bool state) {
    _sending = state;
    _eventapi->sendReady(this,state);
}

netplus::con::condata *netplus::con::_resizeQueue(condata** firstdata, condata** lastdata,
                                                               unsigned long &qsize,unsigned long size){
    if (size == 0)
        return nullptr;

    NetException exception;
    if(!*firstdata || size > qsize){
        exception[NetException::Error] << "_resizeQueue wrong datasize or ConnectionData";
        throw exception;
    }

#ifdef DEBUG
    int delsize=0,presize=qsize;
#endif

    qsize-=size;

    int temp = 0;

HAVEDATA:
    if((*firstdata)) {
        temp += ((int)(*firstdata)->getDataLength() - size);
DELETEBLOCK:
        if (temp <= 0) {
            size -= (*firstdata)->getDataLength();
#ifdef DEBUG
            delsize += (*firstdata)->getDataLength();
#endif
            condata* newdat = (*firstdata)->_nextConnectionData;
            (*firstdata)->_nextConnectionData = nullptr;
            if (*firstdata == *lastdata)
                (*lastdata) = nullptr;
            delete* firstdata;
            (*firstdata) = newdat;
            if ((*firstdata) && size > 0)
                goto HAVEDATA;
        } else {
            int curlen = ((int)(*firstdata)->getDataLength() - size);

            if ( curlen <= 0) {
                temp -= curlen;
                goto DELETEBLOCK;
            }

            std::string buf = (*firstdata)->_Data.substr(size,curlen);
            (*firstdata)->_Data = buf;
#ifdef DEBUG
            delsize += size;
#endif
            size -= size;
        }
    }

#ifdef DEBUG
    std::cout << " delsize: "    << delsize << ": " << size
                                 << " Calculated Blocksize: " << (presize-delsize)
                                 << " Planned size: " << qsize
                                 << std::endl;
    if((presize-delsize)!=qsize){
        exception[SystemException::Critical] << "_resizeQueue: Calculated wrong size";
        throw exception;
    }
#endif

    return *firstdata;
}

                                                               
int netplus::con::copyValue(con::condata* startblock, size_t startpos,
    con::condata* endblock, size_t endpos, std::string& buffer) {

    con::condata* curdat = startblock;

    do {
        if (curdat == startblock && curdat == endblock) {
            buffer += curdat->_Data.substr(startpos, endpos - startpos);
            break;
        }
        else if (curdat == startblock) {
            size_t len = curdat->_Data.length();
            buffer += curdat->_Data.substr(startpos, len - startpos);
        }
        else if (curdat == endblock) {
            buffer += curdat->_Data.substr(0, endpos);
        }
        else {
            buffer += curdat->_Data;
        }
        curdat = curdat->nextcondata();
    } while (curdat != endblock);

    return buffer.length(); //not include termination
}

int netplus::con::searchValue(con::condata* startblock, con::condata** findblock,
                                       const char* keyword){
    return searchValue(startblock, findblock, keyword,strlen(keyword));
}
                                       
int netplus::con::searchValue(con::condata* startblock, con::condata** findblock,
                                       const char* keyword,unsigned long keylen){
   unsigned long fpos=0,fcurpos=0;
    for(con::condata *curdat=startblock; curdat; curdat=curdat->nextcondata()){
        for(unsigned long pos=0; pos<curdat->getDataLength(); ++pos){
            if(keyword[fcurpos]==curdat->_Data[pos]){
                if(fcurpos==0){
                    fpos=pos;
                    *findblock=curdat;
                }
                fcurpos++;
            }else{
                fcurpos=0;
                fpos=0;
                *findblock=nullptr;
            }
            if(fcurpos==keylen)
                return fpos;
        }
    }
    return -1;
}

netplus::con::con(eventapi *event){
    csock=nullptr;

    _ReadDataFirst=nullptr;
    _ReadDataLast=nullptr;
    _ReadDataLength=0;
    _SendDataFirst=nullptr;
    _SendDataLast=nullptr;
    _SendDataLength=0;
    _eventapi=event;
    _sending=false;
}

netplus::con::con(){
    csock=nullptr;

    _ReadDataFirst=nullptr;
    _ReadDataLast=nullptr;
    _ReadDataLength=0;
    _SendDataFirst=nullptr;
    _SendDataLast=nullptr;
    _SendDataLength=0;
    _eventapi=nullptr;
    _sending=false;
}

netplus::con::~con(){
    delete _ReadDataFirst;
    delete _SendDataFirst;
}

