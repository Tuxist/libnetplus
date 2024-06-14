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

void netplus::condata<char>::resize(size_t size_c){
   size_t rs = size();

   std::move(begin()+size_c,end(),begin());

   std::vector<char,condataAlloc<char>>::resize(rs-size_c);
}

void netplus::condata<char>::append(const char* data, size_t datalen){

   std::copy(data,data+datalen,std::inserter<std::vector<char,condataAlloc<char>>>(*this,end()));
}

size_t netplus::condata<char>::search(const char* word){
    size_t wsize=strlen(word);
    for(size_t i=0; i<std::vector<char,condataAlloc<char>>::size(); ++i){
      for(size_t ii=0; ii<=wsize; ++ii){
        if(ii==wsize){
          return i-wsize;
        }
        if(at(i)==word[ii]){
          ++i;
          continue;
        }
        break;
      }
    }
    return std::string::npos;
}


netplus::con::con(){
    state=0;
}

netplus::con::con(eventapi *eapi) : con(){
    _eventapi=eapi;
}

netplus::con::~con(){
}

