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

#ifdef DEBUG
#include <iostream>
#endif

/** \brief a method to add Data to Sendqueue
  * \param data an const char* to add to sendqueue
  * \param datasize an size_t to set datasize
  * \return the last ConnectionData Block from Sendqueue
  * 
  * This method does unbelievably useful things.  
  * And returns exceptionally the new connection data block.
  * Use it everyday with good health.
  */

void netplus::con::sending(bool state) {
    _eventapi->sendReady(this,state);
}
netplus::con::con(){
    SendLock.store(false);
    RecvLock.store(false);
}

netplus::con::con(eventapi *eapi) : con(){
    _eventapi=eapi;
}

netplus::con::~con(){
}

void netplus::con::addRecvData(const std::vector<char>& data){
   while (std::atomic_exchange_explicit(&RecvLock, true, std::memory_order_acquire));

   std::copy(data.begin(),data.end(),std::inserter<std::vector<char>>(RecvData,RecvData.end()));

   std::atomic_store_explicit(&RecvLock, false, std::memory_order_release);
}

void netplus::con::addRecvData(const char* data, size_t len){
   while (std::atomic_exchange_explicit(&RecvLock, true, std::memory_order_acquire));

   std::copy(data,data+len,std::inserter<std::vector<char>>(RecvData,RecvData.end()));

   std::atomic_store_explicit(&RecvLock, false, std::memory_order_release);

}

void netplus::con::getRecvData(std::vector<char>& data){
   while (std::atomic_exchange_explicit(&RecvLock, true, std::memory_order_acquire));

   std::copy(RecvData.begin(),RecvData.end(),std::inserter<std::vector<char>>(data,data.begin()));

   std::atomic_store_explicit(&RecvLock, false, std::memory_order_release);
}

void netplus::con::ResizeRecvData(size_t size){
   while (std::atomic_exchange_explicit(&RecvLock, true, std::memory_order_acquire));

   size_t rr = RecvData.size();

   std::move(RecvData.begin()+size,RecvData.end(),RecvData.begin());

   RecvData.resize(rr-size);

   std::atomic_store_explicit(&RecvLock, false, std::memory_order_release);
}

void netplus::con::clearRecvData(){
    while (std::atomic_exchange_explicit(&RecvLock, true, std::memory_order_acquire));

    RecvData.clear();

    std::atomic_store_explicit(&RecvLock, false, std::memory_order_release);

}

size_t netplus::con::RecvSize(){
   while (std::atomic_exchange_explicit(&RecvLock, true, std::memory_order_acquire));

   ssize_t s = RecvData.size();

   std::atomic_store_explicit(&RecvLock, false, std::memory_order_release);

   return s;
}


void netplus::con::addSendData(const std::vector<char>& data){
   while (std::atomic_exchange_explicit(&SendLock, true, std::memory_order_acquire));

   std::copy(data.begin(),data.end(),std::inserter<std::vector<char>>(SendData,SendData.end()));

   std::atomic_store_explicit(&SendLock, false, std::memory_order_release);
}

void netplus::con::addSendData(const char* data, size_t len){
   while (std::atomic_exchange_explicit(&SendLock, true, std::memory_order_acquire));

   std::copy(data,data+len,std::inserter<std::vector<char>>(SendData,SendData.end()));

   std::atomic_store_explicit(&SendLock, false, std::memory_order_release);
}

void netplus::con::getSendData(std::vector<char>& data){
   while (std::atomic_exchange_explicit(&SendLock, true, std::memory_order_acquire));

   std::copy(SendData.begin(),SendData.end(),std::inserter<std::vector<char>>(data,data.begin()));

   std::atomic_store_explicit(&SendLock, false, std::memory_order_release);
}


void netplus::con::ResizeSendData(size_t size){
   while (std::atomic_exchange_explicit(&SendLock, true, std::memory_order_acquire));

   size_t rs = SendData.size();

   std::move(SendData.begin()+size,SendData.end(),SendData.begin());

   SendData.resize(rs-size);

   std::atomic_store_explicit(&SendLock, false, std::memory_order_release);
}

void netplus::con::clearSendData(){
   while (std::atomic_exchange_explicit(&SendLock, true, std::memory_order_acquire));

   SendData.clear();

   std::atomic_store_explicit(&SendLock, false, std::memory_order_release);
}

size_t netplus::con::SendSize(){
   while (std::atomic_exchange_explicit(&SendLock, true, std::memory_order_acquire));

   size_t s =SendData.size();

   std::atomic_store_explicit(&SendLock, false, std::memory_order_release);

   return s;
}
