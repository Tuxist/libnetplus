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

// void netplus::con::addSendQueue(const char*data,unsigned long datasize){
//     std::copy(data,data+datasize,std::inserter<std::vector<char>>(SendData,SendData.end()));
// }
//
// void netplus::con::cleanSendData(){
//    SendData.clear();
// }
//
// void netplus::con::resizeSendQueue(size_t size){
//     std::move(SendData.begin()+size,SendData.end(),std::inserter<std::vector<char>>(SendData,SendData.begin()));
//     SendData.resize(SendData.size()-size);
// }
//
//
// size_t netplus::con::getSendSize(){
//   return SendData.size();
// }
//
// void netplus::con::addRecvQueue(const char *data,unsigned long datasize){
//     std::copy(data,data+datasize,std::inserter<std::vector<char>>(RecvData,RecvData.end()));
// }
//
// void netplus::con::cleanRecvData(){
//     RecvData.clear();
// }
//
//
// void netplus::con::resizeRecvQueue(size_t size){
//     std::move(RecvData.begin()+size,RecvData.end(),std::inserter<std::vector<char>>(RecvData,RecvData.begin()));
//     RecvData.resize(RecvData.size()-size);
// }
//
// size_t netplus::con::getRecvSize(){
//   return RecvData.size();
// }

void netplus::con::sending(bool state) {
    _eventapi->sendReady(this,state);
}
netplus::con::con(){
}

netplus::con::con(eventapi *eapi) : con(){
    _eventapi=eapi;
}

netplus::con::~con(){
}

