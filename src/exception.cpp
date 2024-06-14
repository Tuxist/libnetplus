/*******************************************************************************
 * Copyright (c) 2021, Jan Koester jan.koester@gmx.net
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

#include <stdlib.h>
#include <string.h>
#include <mutex>

#include "exception.h"

namespace netplus {
    std::mutex g_exception;
};

netplus::NetException::NetException() {
    curCType=Note;
};

netplus::NetException::NetException(const NetException &exp){
    msg=exp.msg;
    curCType = exp.curCType;
}

netplus::NetException::~NetException(){
}

int netplus::NetException::getErrorType(){
    return curCType; 
}

const char* netplus::NetException::what(){
    return msg.c_str();
}

netplus::NetException& netplus::NetException::append(const char *src){
    const std::lock_guard<std::mutex> lock(g_exception);
    msg.append(src);
    return *this;   
}

netplus::NetException& netplus::NetException::operator[](int errtype){
    curCType=errtype;
    return *this;
}

netplus::NetException& netplus::NetException::operator<<(const char *src){
    return append(src);
};

netplus::NetException& netplus::NetException::operator<<(int src){
    const std::lock_guard<std::mutex> lock(g_exception);
    char buffer[255];
    snprintf(buffer,255,"%d",src);
    msg.append(buffer);
    return *this;
}
