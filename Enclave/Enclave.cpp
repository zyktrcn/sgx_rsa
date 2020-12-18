/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "ipp/ippcp.h"
#include "ipp/sgx_ippcp.h"
#include <sgx_tcrypto.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

IppsBigNumState* createBigNumState(int len, const Ipp32u* pData)  {
    int size;
    IppStatus status;
    
    status = ippsBigNumGetSize(len, &size);
    if (status != ippStsNoErr) {
        printf("err: ippsBigNumGetSize\n");
    }

    IppsBigNumState* pBN = (IppsBigNumState*)(new Ipp8u [size]);
    
    status = ippsBigNumInit(len, pBN);
    if (status != ippStsNoErr) {
        printf("err: ippsBigNumInit\n");
    }

    if (pData) {
        status = ippsSet_BN(IppsBigNumPOS, len, pData, pBN);
        if (status != ippStsNoErr) {
            printf("err: ippsSet_BN\n");
        }
    }

    return pBN;
}

IppsBigNumState* transformFromIpp8uToIppsBigNumState(Ipp8u* str) {
    int size = (sizeof(str) - 1 + 3)/4;
    IppsBigNumState* pBN = createBigNumState(size, NULL);
    ippsSetOctString_BN(str, sizeof(str) - 1, pBN);
    return pBN;
}

int getBitSize(Ipp8u* str) {
    int size;
    int len = (sizeof(str) - 1 + 3)/4;
    ippsBigNumGetSize(len, &size);
    return size;
}

Ipp32u* rand32(Ipp32u* pX, int size) {
    int rand = 1;
    for (int n = 0; n < size; n++) {
        rand = rand + 1;
        pX[n] = (rand<<16) + rand;
    }
    return pX;
} 

IppsPRNGState*  newPRNG(int bitSize) {
    IppStatus status;
    int seedSize = (bitSize + 31)>>5;
    Ipp32u* seed = new Ipp32u[seedSize];
    Ipp32u* augm = new Ipp32u[seedSize];

    int size;
    IppsBigNumState* pTmp;
    ippsPRNGGetSize(&size);
    IppsPRNGState* pCtx = (IppsPRNGState*)(new Ipp8u[size]);
    status = ippsPRNGInit(bitSize, pCtx);
    if (status != ippStsNoErr) {
        printf("err: ippsPRNGInit\n");

        if (status == ippStsNullPtrErr) {
            printf("null err\n");
        }

        if (status == ippStsLengthErr) {
            printf("length err:%d \n", bitSize);
        }
    }

    pTmp = createBigNumState(seedSize, rand32(seed, seedSize));
    status = ippsPRNGSetSeed(pTmp, pCtx);
    if (status != ippStsNoErr) {
        printf("err: ippsPRNGSetSeed\n");
    }

    delete [] (Ipp8u*)pTmp;

    pTmp = createBigNumState(seedSize, rand32(augm, seedSize));
    status = ippsPRNGSetAugment(pTmp, pCtx);
    if (status != ippStsNoErr) {
        printf("err: ippsPRNGSetAugment\n");
    }

    delete [] (Ipp8u*)pTmp;
    delete [] seed;
    delete [] augm;

    return pCtx;
}

IppsPrimeState* newPrimeGen(int maxBits) {
    IppStatus status;
    int size;

    status = ippsPrimeGetSize(maxBits, &size);
    if (status != ippStsNoErr) {
        printf("err: ippsPrimeGetSize\n");
    }

    IppsPrimeState* pCtx = (IppsPrimeState*)(new Ipp8u[size]);
    status = ippsPrimeInit(maxBits, pCtx);
    if (status != ippStsNoErr) {
        printf("err: ippsPrimeInit\n");
    }

    return pCtx;   
}


Ipp8u pStr[] = "\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65\x99";
Ipp8u qStr[] = "\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15\x03";
Ipp8u dpStr[] = "\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";
Ipp8u dqStr[] = "\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";
Ipp8u invqStr[] = "\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39\xF7";
Ipp8u nStr[] = "\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD\xCB";
Ipp8u dStr[] = "\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3\xC1";
Ipp8u eStr[] = "\x11";

IppsBigNumState* P = transformFromIpp8uToIppsBigNumState(pStr);
IppsBigNumState* Q = transformFromIpp8uToIppsBigNumState(qStr);
IppsBigNumState* dP = transformFromIpp8uToIppsBigNumState(dpStr);
IppsBigNumState* dQ = transformFromIpp8uToIppsBigNumState(dqStr);
IppsBigNumState* invQ = transformFromIpp8uToIppsBigNumState(invqStr);
IppsBigNumState* N = transformFromIpp8uToIppsBigNumState(nStr);
IppsBigNumState* D = transformFromIpp8uToIppsBigNumState(dStr);
IppsBigNumState* E = transformFromIpp8uToIppsBigNumState(eStr);

int bitsN = getBitSize(nStr);
int bitsE = getBitSize(eStr);
int bitsP = getBitSize(pStr);
int bitsQ = getBitSize(qStr);

int ecall_get_pubSize() {
    int keyCtxSize;
    IppStatus status;

    status = ippsRSA_GetSizePublicKey(bitsN, bitsE, &keyCtxSize);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_GetSizePublicKey\n");
    } else {
        printf("success: ippsRSA_GetSizePublicKey\n");
    }

    printf("keyCtxSize: %d\n", keyCtxSize);

    return keyCtxSize;
}

uint8_t* ecall_gen_pubKey(int* keyCtxSize) {
    IppStatus status;

    // define and setup public key
    IppsRSAPublicKeyState* pPub = (IppsRSAPublicKeyState*)( new Ipp8u [*keyCtxSize] );
    status = ippsRSA_InitPublicKey(bitsN, bitsE, pPub, *keyCtxSize);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_InitPublicKey\n");
    } else {
        printf("success: ippsRSA_InitPublicKey\n");
    }
    status = ippsRSA_SetPublicKey(N, E, pPub);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_SetPublicKey\n");
    } else {
        printf("success: ippsRSA_SetPublicKey\n");
    }

    uint8_t* pub = (uint8_t*)malloc(*keyCtxSize);
    memcpy(pub, pPub, *keyCtxSize);
    printf("pPub: %s\n", pPub);
    printf("pub:  %s\n", pub);
    
    return pub;
}

int ecall_get_prvSize() {
    int keyCtxSize;
    IppStatus status;

    // define and setup (type2) private key 
    status = ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &keyCtxSize);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_GetSizePrivateKeyType2\n");
    } else {
        printf("success: ippsRSA_GetSizePrivateKeyType2\n");
    }

    printf("keyCtxSize: %d\n", keyCtxSize);

    return keyCtxSize;
}

uint8_t* ecall_gen_prvKey(int* keyCtxSize) {
    IppStatus status;

    IppsRSAPrivateKeyState* pPrv = (IppsRSAPrivateKeyState*)( new Ipp8u [*keyCtxSize] );
    status = ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, pPrv, *keyCtxSize);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_InitPrivateKeyType2\n");
    } else {
        printf("success: ippsRSA_InitPrivateKeyType2\n");
    }
    status = ippsRSA_SetPrivateKeyType2(P, Q, dP, dQ, invQ, pPrv);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_SetPrivateKeyType2\n");
    } else {
        printf("success: ippsRSA_SetPrivateKeyType2\n");
    }

    uint8_t* prv = (uint8_t*)malloc(*keyCtxSize);
    memcpy(prv, pPrv, *keyCtxSize);
    printf("pPrv: %s\n", pPrv);
    printf("prv:  %s\n", prv);;

    return prv;
}

int ecall_gen_scratchSize(uint8_t** prv, uint8_t** pub, int prvSize, int pubSize) {
    IppsRSAPublicKeyState* pPub = (IppsRSAPublicKeyState*)( new Ipp8u [pubSize] );
    memcpy(pPub, *pub, pubSize);
    printf("generate public key\n");

    IppsRSAPrivateKeyState* pPrv = (IppsRSAPrivateKeyState*)( new Ipp8u [prvSize] );
    memcpy(pPrv, *prv, prvSize);
    printf("generate private key\n");

    int keyCtxSize;
    IppStatus status;

    // allocate scratch buffer
    int buffSizePublic;
    status = ippsRSA_GetBufferSizePublicKey(&buffSizePublic, pPub);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_GetBufferSizePublicKey\n");
    } else {
        printf("success: ippsRSA_GetBufferSizePublicKey\n");
    }

    int buffSizePrivate;
    status = ippsRSA_GetBufferSizePrivateKey(&buffSizePrivate, pPrv);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_GetBufferSizePrivateKey\n");
    } else {
        printf("success: ippsRSA_GetBufferSizePrivateKey\n");
    }

    int buffSize;
    if (buffSizePublic > buffSizePrivate) {
        buffSize = buffSizePublic;
    } else {
        buffSize = buffSizePrivate;
    }

    return buffSize;
}

uint8_t* ecall_encrypt(uint8_t** pub, int pubSize, uint8_t* scratchBuffer, int scratchSize, char** buffer, int bufferSize, int* enSize) {
    IppsRSAPublicKeyState* pPub = (IppsRSAPublicKeyState*)( new Ipp8u [pubSize] );
    memcpy(pPub, *pub, pubSize);
    printf("generate public key\n");

    Ipp8u* scratch = new Ipp8u[scratchSize];

    IppStatus status;

    Ipp8u* enStr = (Ipp8u*)malloc(bufferSize);
    memcpy(enStr, *buffer, bufferSize);
    printf("enStr: %d\n", enStr);

    IppsBigNumState* enBN = transformFromIpp8uToIppsBigNumState(enStr);
    IppsBigNumState* ct = createBigNumState((8+31)>>5, 0);
    status = ippsRSA_Encrypt(enBN, ct, pPub, scratch);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_Encrypt\n");
    } else {
        printf("success: ippsRSA_Encrypt\n");
    }

    ippsGetSize_BN(ct, enSize);
    Ipp8u* bnValue = (Ipp8u*)malloc(*enSize * 4);
    ippsGetOctString_BN(bnValue, *enSize * 4, ct);
    printf("bnValue: %d\n", bnValue);

    uint8_t* encryption = (uint8_t*)malloc(*enSize * 4);
    memcpy(encryption, bnValue, *enSize * 4);

    memcpy(scratchBuffer, scratch, sizeof(scratch));
    
    delete[] pPub;
    delete[] enStr;
    delete[] enBN;
    delete[] ct;
    delete[] bnValue;
    delete[] scratch;

    return encryption;
}

uint8_t* ecall_decryption(uint8_t** prv, int prvSize, uint8_t* scratchBuffer, int scratchSize, uint8_t** encryption, int enSize, int* deSize) {
    IppsRSAPrivateKeyState* pPrv = (IppsRSAPrivateKeyState*)( new Ipp8u [prvSize] );
    memcpy(pPrv, *prv, prvSize);
    printf("generate private key\n");

    Ipp8u* scratch = new Ipp8u[scratchSize];
    memcpy(scratch, scratchBuffer, scratchSize);

    IppStatus status;

    Ipp8u* enStr = (Ipp8u*)malloc(enSize * 4);
    memcpy(enStr, encryption, enSize * 4);

    IppsBigNumState* ct = transformFromIpp8uToIppsBigNumState(enStr);

    IppsBigNumState* deBN = createBigNumState(enSize * 4, NULL);
    status = ippsRSA_Decrypt(ct, deBN, pPrv, scratch);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_Decrypt\n");

        if (status == ippStsNullPtrErr) {
            printf("null err\n");
        }

        if (status == ippStsContextMatchErr) {
            printf("not match\n");
        }

        if (status == ippStsIncompleteContextErr) {
            printf("incomplete err\n");
        }

        if (status == ippStsSizeErr) {
            printf("size err\n");
        }

        if (status == ippStsOutOfRangeErr) {
            printf("out of range\n");
        }

    } else {
        printf("success: ippsRSA_Decrypt\n");
    }

    ippsGetSize_BN(deBN, deSize);
    Ipp8u* bnValue = (Ipp8u*)malloc(*deSize * 4);
    ippsGetOctString_BN(bnValue, *deSize * 4, ct);
    printf("deStr: %d\n", bnValue);

    uint8_t* decryption = (uint8_t*)malloc(*deSize * 4);
    memcpy(decryption, bnValue, *deSize * 4);

    delete[] pPrv;
    delete[] scratch;
    delete[] enStr;
    delete[] ct;
    delete[] deBN;
    
    delete[] bnValue;

    return decryption;
}

void ecall_genKey(uint8_t** prv, uint8_t** pub, int prvSize, int pubSize, char** buffer, int bufferSize) {

    printf("start\n");
    IppsRSAPublicKeyState* pPub = (IppsRSAPublicKeyState*)( new Ipp8u [pubSize] );
    memcpy(pPub, *pub, pubSize);
    printf("generate public key\n");

    IppsRSAPrivateKeyState* pPrv = (IppsRSAPrivateKeyState*)( new Ipp8u [prvSize] );
    memcpy(pPrv, *prv, prvSize);
    printf("generate private key\n");

    int keyCtxSize;
    IppStatus status;

    // allocate scratch buffer
    int buffSizePublic;
    status = ippsRSA_GetBufferSizePublicKey(&buffSizePublic, pPub);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_GetBufferSizePublicKey\n");
    } else {
        printf("success: ippsRSA_GetBufferSizePublicKey\n");
    }

    int buffSizePrivate;
    status = ippsRSA_GetBufferSizePrivateKey(&buffSizePrivate, pPrv);
    if (status != ippStsNoErr) {
        printf("err: ippsRSA_GetBufferSizePrivateKey\n");
    } else {
        printf("success: ippsRSA_GetBufferSizePrivateKey\n");
    }

    int buffSize;
    if (buffSizePublic > buffSizePrivate) {
        buffSize = buffSizePublic;
    } else {
        buffSize = buffSizePrivate;
    }
    Ipp8u* scratchBuffer = NULL;
    scratchBuffer = new Ipp8u [buffSize];

    int error = 0;
    do {

        // // random generator
        // IppsPRNGState* pRand = newPRNG(160);
        // // prime generator
        // IppsPrimeState* pPrimeG = newPrimeGen(bitsP);

        // int validateRes = IPP_IS_INVALID;
        // status = ippsRSA_ValidateKeys(&validateRes,
        //                     pPub, pPrv, NULL, scratchBuffer,
        //                     10, pPrimeG, ippsPRNGen, pRand);

        // if (status != ippStsNoErr) {
        //     printf("err: ippsRSA_ValidateKeys\n");
        // } else {
        //     printf("success: ippsRSA_ValidateKeys\n");
        // }

        // if (validateRes == IPP_IS_INVALID) {
        //     printf("not valid\n");
        // } else {
        //     printf("valid\n");
        // }

        Ipp8u* enStr = (Ipp8u*)malloc(bufferSize);
        memcpy(enStr, *buffer, bufferSize);

        // Ipp8u enStr[] = "\x12\x34\x56\x78\x9a\xbc\xde\xf0\xfe\xdc\xba\x98\x76\x54\x32\x10";
        IppsBigNumState* enBN = transformFromIpp8uToIppsBigNumState(enStr);
        IppsBigNumState* ct = createBigNumState((8+31)>>5, 0);
        status = ippsRSA_Encrypt(enBN, ct, pPub, scratchBuffer);
        if (status != ippStsNoErr) {
            printf("err: ippsRSA_Encrypt\n");
        } else {
            printf("success: ippsRSA_Encrypt\n");
        }

        IppsBigNumState* deBN = createBigNumState(512, NULL);
        status = ippsRSA_Decrypt(ct, deBN, pPrv, scratchBuffer);
        if (status != ippStsNoErr) {
            printf("err: ippsRSA_Decrypt\n");

            if (status == ippStsNullPtrErr) {
                printf("null err\n");
            }

            if (status == ippStsContextMatchErr) {
                printf("not match\n");
            }

            if (status == ippStsIncompleteContextErr) {
                printf("incomplete err\n");
            }

            if (status == ippStsSizeErr) {
                printf("size err\n");
            }

            if (status == ippStsOutOfRangeErr) {
                printf("out of range\n");
            }

        } else {
            printf("success: ippsRSA_Decrypt\n");
        }

        // int enStrSize = (sizeof(enBN) - 1 + 3)/4;
        // char enChar[enStrSize];
        // memcpy(enChar, enBN, enStrSize);
        // printf("%s\n", enChar);

        // int deStrSize = (sizeof(deBN) - 1 + 3)/4;
        // char deChar[deStrSize];
        // memcpy(deChar, deBN, deStrSize);
        // printf("%s\n", deChar);

    } while(0);
    
}
