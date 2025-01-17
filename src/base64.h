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

#include <stdlib.h>
#include <string.h>

#pragma once 

namespace netplus {
    namespace base64 {
        /* aaaack but it's fast and const should make it shared text page. */
        static const unsigned char pr2six[256] = {
            /* ASCII table */
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
            64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
            64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
        };

        static const char basis_64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        inline size_t Decodelen(const char* bufcoded) {
            size_t nbytesdecoded;
            const unsigned char* bufin;
            int nprbytes;

            bufin = (const unsigned char*)bufcoded;
            while (pr2six[*(bufin++)] <= 63);

            nprbytes = (bufin - (const unsigned char*)bufcoded) - 1;
            nbytesdecoded = ((nprbytes + 3) / 4) * 3;

            return nbytesdecoded + 1;
        }

        inline size_t Decode(char* bufplain, const char* bufcoded) {
            size_t nbytesdecoded;
            const unsigned char* bufin;
            unsigned char* bufout;
            int nprbytes;

            bufin = (const unsigned char*)bufcoded;
            while (pr2six[*(bufin++)] <= 63);
            nprbytes = (bufin - (const unsigned char*)bufcoded) - 1;
            nbytesdecoded = ((nprbytes + 3) / 4) * 3;

            bufout = (unsigned char*)bufplain;
            bufin = (const unsigned char*)bufcoded;

            while (nprbytes > 4) {
                *(bufout++) =
                    (unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
                *(bufout++) =
                    (unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
                *(bufout++) =
                    (unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
                bufin += 4;
                nprbytes -= 4;
            }

            /* Note: (nprbytes == 1) would be an error, so just ingore that case */
            if (nprbytes > 1) {
                *(bufout++) =
                    (unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
            }
            if (nprbytes > 2) {
                *(bufout++) =
                    (unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
            }
            if (nprbytes > 3) {
                *(bufout++) =
                    (unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
            }

            *(bufout++) = '\0';
            nbytesdecoded -= (4 - nprbytes) & 3;
            return nbytesdecoded;
        }

        inline size_t Encodelen(size_t len) {
            return ((len + 2) / 3 * 4) + 1;
        }

        size_t inline Encode(char* encoded, const char* string, size_t len) {
            size_t i = 0;
            char* p;

            p = encoded;
            for (i = 0; i < len - 2; i += 3) {
                *p++ = basis_64[(string[i] >> 2) & 0x3F];
                *p++ = basis_64[((string[i] & 0x3) << 4) |
                    ((size_t)(string[i + 1] & 0xF0) >> 4)];
                *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                    ((size_t)(string[i + 2] & 0xC0) >> 6)];
                *p++ = basis_64[string[i + 2] & 0x3F];
            }
            if (i < len) {
                *p++ = basis_64[(string[i] >> 2) & 0x3F];
                if (i == (len - 1)) {
                    *p++ = basis_64[((string[i] & 0x3) << 4)];
                    *p++ = '=';
                }
                else {
                    *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((size_t)(string[i + 1] & 0xF0) >> 4)];
                    *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
                }
                *p++ = '=';
            }

            *p++ = '\0';
            return p - encoded;
        }
    };
};