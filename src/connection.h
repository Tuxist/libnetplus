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
#include <limits>
#include <type_traits>

#include <cstddef>

#pragma once

namespace netplus {
        class eventapi;
        class pollapi;

        template <class T>
        class condataAlloc {
        public:
            // type definitions
            typedef T        value_type;
            typedef T*       pointer;
            typedef const T* const_pointer;
            typedef T&       reference;
            typedef const T& const_reference;
            typedef std::size_t    size_type;
            typedef std::ptrdiff_t difference_type;

            // rebind allocator to type U
            template <class U>
            struct rebind {
                typedef condataAlloc<U> other;
            };

            // return address of values
            pointer address (reference value) const {
                return &value;
            }
            const_pointer address (const_reference value) const {
                return &value;
            }

            /* constructors and destructor
             * - nothing to do because the allocator has no state
             */
            condataAlloc() throw() {
            }
            condataAlloc(const condataAlloc&) throw() {
            }
            template <class U>
            condataAlloc (const condataAlloc<U>&) throw() {
            }
            ~condataAlloc() throw() {
            }

            // return maximum number of elements that can be allocated
            size_type max_size () const throw() {
                return (std::numeric_limits<std::size_t>::max)() / sizeof(T);
            }

            // allocate but don't initialize num elements of type T
            pointer allocate (size_type num, const void* = 0) {
                pointer ret = (pointer)(::operator new(num*sizeof(T)));
                return ret;
            }

            // initialize elements of allocated storage p with value value
            void construct (pointer p, const T& value) {
                new((void*)p)T(value);
            }

            // destroy elements of initialized storage p
            void destroy (pointer p) {
                p->~T();
            }

            // deallocate storage p of deleted elements
            void deallocate (pointer p, size_type num) {
                ::operator delete((void*)p);
            }
        };

        // return that all specializations of this allocator are interchangeable
        template <class T1, class T2>
        bool operator== (const condataAlloc<T1>&,
                         const condataAlloc<T2>&) throw() {
                             return true;
        }
        template <class T1, class T2>
        bool operator!= (const condataAlloc<T1>&,
                         const condataAlloc<T2>&) throw() {
                             return false;
        }

        template <typename T>
        class condata;

        template <> class condata<char> : public std::vector<char,condataAlloc<char>>{
        public:
            condata();
            void     resize(size_t size_c);
            void     append(const char *data,size_t datalen);
            size_t   search(const char *word);
            void     push_back(char a);
            size_t   pos;
        };

        class con {
        public:
            
            con(eventapi *event);
            virtual ~con();

            /*clientsocket*/
            socket *csock;

            /*event stauts*/
            int state;

            /*connection Data*/
            condata<char> RecvData;
            condata<char> SendData;

        protected:
            con();
            int lasteventime;
        private:
            eventapi         *_eventapi;
            pollapi          *_pollapi;
            friend class poll;
        };
};
