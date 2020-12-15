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


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <time.h>

#include <fstream>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

int get_file_size(char* filename) {
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    ifs.seekg(0, std::ios::end);
    int size = ifs.tellg();

    return size;
}

char* read_file_to_buff(char* filename, int bsize) {
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    char* buff = new char[bsize];
    ifs.read(buff, bsize);
    ifs.close();

    return buff;
}

void write_buff_to_file(char* filename, char* buff, int bsize, long offset) {
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    ofs.seekp(offset, std::ios::beg);
    ofs.write(buff, bsize);
}

char* char_concat(char* str1, char* str2) {
    int len = strlen(str1) + strlen(str2);
    char* str = (char*)malloc(len);
    strcpy(str, str1);
    strcat(str, str2);

    return str;
}

char* char_plus_int(char* str1, int i) {
    int len = strlen(str1) + 10;
    char* str = (char*)malloc(len);
    sprintf(str, "%s%d\n", str1, i);

    return str;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    // /* Utilize edger8r attributes */
    // edger8r_array_attributes();
    // edger8r_pointer_attributes();
    // edger8r_type_attributes();
    // edger8r_function_attributes();
    
    // /* Utilize trusted libraries */
    // ecall_libc_functions();
    // ecall_libcxx_functions();
    // ecall_thread_functions();

    char* file = "/home/zyktrcn/sgx/sgx_rsa/App/test.png";
    int fileSize = get_file_size(file);
    char* fileBuffer = read_file_to_buff(file, fileSize);
    printf("size: %d\n", fileSize);
    printf("buffer: %s\n", fileBuffer);
    write_buff_to_file("/home/zyktrcn/sgx/sgx_rsa/App/result.png", fileBuffer, fileSize, 0);

    int pubSize;
    ecall_get_pubSize(global_eid, &pubSize);
    printf("pubSize: %d\n", pubSize);

    uint8_t* pub;
    ecall_gen_pubKey(global_eid, &pub, &pubSize);
    printf("pub:  %s\n", pub);

    int prvSize;
    ecall_get_prvSize(global_eid, &prvSize);
    printf("prvSize: %d\n", prvSize);

    uint8_t* prv;
    ecall_gen_prvKey(global_eid, &prv, &prvSize);
    printf("prv:  %s\n", prv);

    int scratchSize;
    ecall_gen_scratchSize(global_eid, &scratchSize, &prv, &pub, prvSize, pubSize);
    printf("scratchSize: %d\n", scratchSize);

    uint8_t* scratchBuffer = (uint8_t*)malloc(scratchSize);;

    clock_t start = clock();

    uint8_t* encryption;
    int enSize;

    sgx_status_t ret = ecall_encrypt(global_eid, &encryption, &pub, pubSize, scratchBuffer, scratchSize, &fileBuffer, fileSize, &enSize);
    if (ret != SGX_SUCCESS) {
        printf("fail\n");

        if (ret == SGX_ERROR_INVALID_PARAMETER) {
            printf("SGX_ERROR_INVALID_PARAMETER\n");
        }

        if (ret == SGX_ERROR_OUT_OF_MEMORY) {
            printf("SGX_ERROR_OUT_OF_MEMORY\n");
        }

        if (ret == SGX_ERROR_UNEXPECTED) {
            printf("SGX_ERROR_UNEXPECTED\n");
        }
    }
    printf("scratchBuffer: %s\n", scratchBuffer);
    printf("enSize: %d\n", enSize);
    printf("encryption: %s\n", encryption);

    clock_t end = clock();

    char* enResult = char_concat(char_plus_int("encryption start:", start), char_plus_int("encryption end:", end));
    printf("%s", enResult);

    start = clock();

    uint8_t* decryption;
    int deSize;

    ret = ecall_decryption(global_eid, &decryption, &prv, prvSize, scratchBuffer, scratchSize, &encryption, enSize, &deSize);
    if (ret != SGX_SUCCESS) {
        printf("fail\n");

        if (ret == SGX_ERROR_INVALID_PARAMETER) {
            printf("SGX_ERROR_INVALID_PARAMETER\n");
        }

        if (ret == SGX_ERROR_OUT_OF_MEMORY) {
            printf("SGX_ERROR_OUT_OF_MEMORY\n");
        }

        if (ret == SGX_ERROR_UNEXPECTED) {
            printf("SGX_ERROR_UNEXPECTED\n");
        }
    }
    printf("deSize: %d\n", deSize);
    printf("decryption: %s\n", decryption);

    end = clock();

    char* deResult = char_concat(char_plus_int("decryption start:", start), char_plus_int("decryption end:", end));
    printf("%s", deResult);

    char* result = char_concat(enResult, deResult);
    printf("bsize: %d\n", strlen(result));
    write_buff_to_file("/home/zyktrcn/sgx/sgx_rsa/App/result.txt", result, strlen(result), 0);


    // sgx_status_t ret = ecall_genKey(global_eid, &prv, &pub, prvSize, pubSize, &fileBuffer, fileSize);
    // if (ret != SGX_SUCCESS) {
    //     printf("fail\n");

    //     if (ret == SGX_ERROR_INVALID_PARAMETER) {
    //         printf("SGX_ERROR_INVALID_PARAMETER\n");
    //     }

    //     if (ret == SGX_ERROR_OUT_OF_MEMORY) {
    //         printf("SGX_ERROR_OUT_OF_MEMORY\n");
    //     }

    //     if (ret == SGX_ERROR_UNEXPECTED) {
    //         printf("SGX_ERROR_UNEXPECTED\n");
    //     }
    // }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

