/*
--------------------AES.c--------------------
Author :        Elerias
Date :          13.12.2020
Version :       1.0.1
Description :   Implementation of AES in C
---------------------------------------------
*/



// Initialisation


    // Include

#include <stdio.h>
#include <stdlib.h>
#include "AES.h"


    // Global variables

const unsigned char SBox[256] =
{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

const unsigned char invSBox[256] =
{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

unsigned char gfmul_2[256];
unsigned char gfmul_3[256];
unsigned char gfmul_9[256];
unsigned char gfmul_11[256];
unsigned char gfmul_13[256];
unsigned char gfmul_14[256];


    // Macros

#define DECLAREVARIABLES() unsigned char a0, a1, a2, a3;
// Declare the variables used for the macros SHIFTROWS (a0), INVSHIFTROWS (a0), MIXCOLUMNS (a0, a1, a2, a3) et INVMIXCOLUMNS (a0, a1, a2, a3).

#define SUBBYTES(state) for (int i=0 ; i<16 ; i++) state[i] = SBox[state[i]];
// Substitute every bytes in the state with the SBox.

#define INVSUBBYTES(state) for (int i=0 ; i<16 ; i++) state[i] = invSBox[state[i]];
// Inverse of SUBBYTES : Substitute every bytes in the state with invSBox.

#define SHIFTROWS(state) \
    a0 = state[1]; \
    state[1] = state[5]; \
    state[5] = state[9]; \
    state[9] = state[13]; \
    state[13] = a0; \
    a0 = state[2]; \
    state[2] = state[10]; \
    state[10] = a0; \
    a0 = state[6]; \
    state[6] = state[14]; \
    state[14] = a0; \
    a0 = state[3]; \
    state[3] = state[15]; \
    state[15] = state[11]; \
    state[11] = state[7]; \
    state[7] = a0;
/* Transpose the state :
 00 04 08 12         00 04 08 12
 01 05 09 13   ==>   05 09 13 01
 02 06 10 14   ==>   10 14 02 06
 03 07 11 15   ==>   15 03 07 11
*/

#define INVSHIFTROWS(state) \
    a0 = state[1]; \
    state[1] = state[13]; \
    state[13] = state[9]; \
    state[9] = state[5]; \
    state[5] = a0; \
    a0 = state[2]; \
    state[2] = state[10]; \
    state[10] = a0; \
    a0 = state[6]; \
    state[6] = state[14]; \
    state[14] = a0; \
    a0 = state[3]; \
    state[3] = state[7]; \
    state[7] = state[11]; \
    state[11] = state[15]; \
    state[15] = a0;
/* Inverse of SHIFTROWS :
 00 04 08 12         00 04 08 12
 01 05 09 13   ==>   13 01 05 09
 02 06 10 14   ==>   10 14 02 06
 03 07 11 15   ==>   07 11 15 03
*/

#define ADDROUNDKEY(state, n) \
    for (int i=0 ; i<16 ; i++) \
    { \
        state[i] = state[i] ^ expKey[i%4][n*4+i/4]; \
    }
// XOR the key n to the state.
// N.B. : This function is itself its inverse because (a xor b) xor b = a.

#define MIXCOLUMNS(state) \
    for (int i=0 ; i<16 ; i+=4) \
    { \
        a0 = state[i]; \
        a1 = state[i+1]; \
        a2 = state[i+2]; \
        a3 = state[i+3]; \
        state[i] = gfmul_2[a0] ^ gfmul_3[a1] ^ a2 ^ a3; \
        state[i+1] = a0 ^ gfmul_2[a1] ^ gfmul_3[a2] ^ a3; \
        state[i+2] = a0 ^ a1 ^ gfmul_2[a2] ^ gfmul_3[a3]; \
        state[i+3] = gfmul_3[a0] ^ a1 ^ a2 ^ gfmul_2[a3]; \
    }
/* Mix the four columns of the state.
Every column is a vector and is transformed by multiplication with the matrix :
 2 3 1 1
 1 2 3 1
 1 1 2 3
 3 1 1 2
The multiplications are products in Galois Field (2 ** 8).
*/

#define INVMIXCOLUMNS(state) \
    for (int i=0 ; i<16 ; i+=4) \
    { \
        a0 = state[i]; \
        a1 = state[i+1]; \
        a2 = state[i+2]; \
        a3 = state[i+3]; \
        state[i] = gfmul_14[a0] ^ gfmul_11[a1] ^ gfmul_13[a2] ^ gfmul_9[a3]; \
        state[i+1] = gfmul_9[a0] ^ gfmul_14[a1] ^ gfmul_11[a2] ^ gfmul_13[a3];  \
        state[i+2] = gfmul_13[a0] ^ gfmul_9[a1] ^ gfmul_14[a2] ^ gfmul_11[a3];  \
        state[i+3] = gfmul_11[a0] ^ gfmul_13[a1] ^ gfmul_9[a2] ^ gfmul_14[a3];  \
    }
/* Inverse of MIXCOLUMNS
The inverse matrix is :
 14 11 13 09
 09 14 11 13
 13 09 14 11
 11 13 09 14
*/

#define XOR(A, B, n) \
    for (int i=0 ; i<n ; i++) \
    { \
        A[i] ^= B[i]; \
    }

#define COPY(A, B, n) \
    for (int i=0 ; i<n ; i++) A[i] = B[i];



// Functions


void printGrid(unsigned char* state)
// Print the current state.
{
    printf("%x %x %x %x\n", state[0], state[4], state[8], state[12]);
    printf("%x %x %x %x\n", state[1], state[5], state[9], state[13]);
    printf("%x %x %x %x\n", state[2], state[6], state[10], state[14]);
    printf("%x %x %x %x\n", state[3], state[7], state[11], state[15]);
}

unsigned char gfmul_function(unsigned char a, unsigned char b)
// Return the product of a and b in Galois Field (2 ** 8).
{
    // Inspired of wikipedia english AES MixColumns C# example.
    unsigned char c=0;

    for (int i=0 ; i<8 ; i++)
    {
        if ((b & 1) != 0)
        {
            c = c ^ a;
        }
        int h = ((a & 0x80) != 0);
        a = a << 1;
        if (h)
        {
            a = a ^ 0x1b;
        }
        b = b >> 1;
    }

    return c;
}

void expandKey(const unsigned char* k)
// Expand the key k and put the result in expKey.
{
    int Nk = Nr-6;
    unsigned char rc[11] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
    for (int i=0 ; i<4 ; i++)
    {
        for (int j=0 ; j<Nk ; j++)
        {
            expKey[i][j] = k[j*4+i];
        }
    }
    for (int j=Nk ; j<4*(Nr+1) ; j++)
    {
        if (j % Nk == 0)
        {
            for (int i=0 ; i<4 ; i++)
            {
                expKey[i][j] = expKey[i][j-Nk] ^ SBox[expKey[(i+1)%4][j-1]] ^ ((i==0) ? rc[j/Nk] : 0);
            }
        }
        else if ((Nk > 6) && (j % Nk == 4))
        {
            for (int i=0 ; i<4 ; i++)
            {
                expKey[i][j] = expKey[i][j-Nk] ^ SBox[expKey[i][j-1]];
            }
        }
        else
        {
            for (int i=0 ; i<4 ; i++)
            {
                expKey[i][j] = expKey[i][j-Nk] ^ expKey[i][j-1];
            }
        }
    }
}

void initGfmul()
// Init the arrays to have fast the result of usefull products in Galois Field (2 ** 8).
{
    for (int j=0 ; j<256 ; j++)
    {
        gfmul_2[j] = gfmul_function(2, j);
        gfmul_3[j] = gfmul_function(3, j);
        gfmul_9[j] = gfmul_function(9, j);
        gfmul_11[j] = gfmul_function(11, j);
        gfmul_13[j] = gfmul_function(13, j);
        gfmul_14[j] = gfmul_function(14, j);
    }
}

void initAES(int m, unsigned char* k)
// Init the AES environnement with the mode m (128, 192 or 256 bits of key) and the not expanded key k.
{
    if (m != 128 && m != 192 && m != 256)
    {
        mode = 128;
    }
    else
    {
        mode = m;
    }
    if (mode == 128)
    {
        Nr = 10;
    }
    else if (mode == 192)
    {
        Nr = 12;
    }
    else
    {
        Nr = 14;
    }
    initGfmul();
    expandKey(k);
}

void encryptBlock(unsigned char* state)
// Encrypt a block of 128 bits (16 bytes).
{

    DECLAREVARIABLES()

    // Initial round key addition
    ADDROUNDKEY(state, 0)

    // Nr - 1 rounds
    for (int n=1 ; n<Nr ; n++)
    {
        SUBBYTES(state)
        SHIFTROWS(state)
        MIXCOLUMNS(state)
        ADDROUNDKEY(state, n)
    }

    // Final round
    SUBBYTES(state)
    SHIFTROWS(state)
    ADDROUNDKEY(state, Nr)
}

void decryptBlock(unsigned char* state)
// Decrypt a block of 128 bits (16 bytes).
{

    DECLAREVARIABLES()

    // Final round;
    ADDROUNDKEY(state, Nr)
    INVSHIFTROWS(state)
    INVSUBBYTES(state)

    // Nr - 1 rounds
    for (int n=Nr-1 ; n>0 ; n--)
    {
        ADDROUNDKEY(state, n)
        INVMIXCOLUMNS(state)
        INVSHIFTROWS(state)
        INVSUBBYTES(state)
    }

    // Initial round key addition
    ADDROUNDKEY(state, 0)
}

unsigned int bitPadding(unsigned char* text, unsigned int length, const unsigned int blockLength)
// Pad a text in order to its length is equals to a multiple of blockLength. Use the bit padding : an 1 is added then the good number of 0.
{
    text[length] = 0x01;
    length++;
    while (length%blockLength != 0)
    {
        text[length] = 0x00;
        length++;
    }
    return length;
}

unsigned int invBitPadding(unsigned char* text, unsigned int length)
{
    while (text[length-1] == 0x00)
    {
        length--;
    }
    length--;
    return length;
}

unsigned int encryptTextECB(unsigned char* text, const unsigned int length)
// Encrypt a text of length length.
{
    int length_c = bitPadding(text, length, 16);

    unsigned char state[16];
    for (int j=0 ; j<length_c ; j+=16)
    {
        for (int k=0 ; k<16 ; k++)
        {
            state[k] = text[j+k];
        }
        encryptBlock(state);
        for (int k=0 ; k<16 ; k++)
        {
            text[j+k] = state[k];
        }
    }

    return length_c;
}

unsigned int decryptTextECB(unsigned char* text_c, const unsigned int length_c)
// Decrypt a text of length length_c and return the length of the text.
{
    unsigned char state[16];
    for (int i=0 ; i<length_c ; i+=16)
    {
        for (int j=0 ; j<16 ; j++)
        {
            state[j] = text_c[i+j];
        }
        decryptBlock(state);
        for (int j=0 ; j<16 ; j++)
        {
            text_c[i+j] = state[j];
        }
    }
    return invBitPadding(text_c, length_c);
}

unsigned int encryptTextCBC(unsigned char* text, const unsigned int length)
// Encrypt a text of length length.
{
    int length_c = bitPadding(text, length, 16);

    unsigned char state[16]={0}; // Initialization Vector
    for (int j=0 ; j<length_c ; j+=16)
    {
        for (int k=0 ; k<16 ; k++)
        {
            state[k] = state[k] ^ text[j+k]; // Difference with ECB : the last cipherblock is added to the new plainblock.
        }
        encryptBlock(state);
        for (int k=0 ; k<16 ; k++)
        {
            text[j+k] = state[k];
        }
    }

    return length_c;
}

unsigned int decryptTextCBC(unsigned char* text_c, const unsigned int length_c)
// Decrypt a text of length length_c and return the length of the text.
{
    unsigned char lastVector[16] = {0}; // Initialization vector
    unsigned char vector[16] = {0};
    unsigned char state[16];
    for (int i=0 ; i<length_c ; i+=16)
    {
        for (int j=0 ; j<16 ; j++)
        {
            state[j] = text_c[i+j];
            vector[j] = state[j];
        }
        decryptBlock(state);
        for (int j=0 ; j<16 ; j++)
        {
            text_c[i+j] = state[j] ^ lastVector[j];
            lastVector[j] = vector[j];

        }
    }
    return invBitPadding(text_c, length_c);

}

void encryptFileECB(const char* sourcefilename, const char* destfilename)
// Encrypt a file.
{
    FILE* source_f = fopen(sourcefilename, "rb");
    FILE* dest_f = fopen(destfilename, "wb");
    if (source_f == NULL)
    {
        printf("%s cannot be opened", sourcefilename);
    }
    if (dest_f == NULL)
    {
        printf("Can't write in %s", destfilename);
    }
    unsigned char temp[16];
    unsigned int n;
    n = fread(temp, sizeof(unsigned char), 16, source_f);
    while (n == 16)
    {
        encryptBlock(temp);
        fwrite(temp, sizeof(unsigned char), 16, dest_f);
        n = fread(temp, sizeof(unsigned char), 16, source_f);
    }
    bitPadding(temp, n, 16);
    encryptBlock(temp);
    fwrite(temp, sizeof(unsigned char), 16, dest_f);
    fclose(source_f);
    fclose(dest_f);
}

void decryptFileECB(const char* sourcefilename, const char* destfilename)
// Decrypt a file.
{
    FILE* source_f = fopen(sourcefilename, "rb");
    FILE* dest_f = fopen(destfilename, "wb");
    unsigned char temp[16];
    fseek(source_f, 0, SEEK_END);
    int i = ftell(source_f) / 16 - 1;
    fseek(source_f, 0, SEEK_SET);
    while (i)
    {
        fread(temp, sizeof(unsigned char), 16, source_f);
        decryptBlock(temp);
        fwrite(temp, sizeof(unsigned char), 16, dest_f);
        i--;
    }
    fread(temp, sizeof(unsigned char), 16, source_f);
    decryptBlock(temp);
    fwrite(temp, sizeof(unsigned char), invBitPadding(temp, 16), dest_f);
    fclose(source_f);
    fclose(dest_f);
}

void encryptFileCBC(const char* sourcefilename, const char* destfilename)
// Encrypt a file.
{
    FILE* source_f = fopen(sourcefilename, "rb");
    FILE* dest_f = fopen(destfilename, "wb");
    if (source_f == NULL)
    {
        printf("%s cannot be opened", sourcefilename);
    }
    if (dest_f == NULL)
    {
        printf("Can't write in %s", destfilename);
    }
    unsigned char vector[16] = {0};
    unsigned char temp[16];
    unsigned int n;
    n = fread(temp, sizeof(unsigned char), 16, source_f);
    while (n == 16)
    {
        XOR(temp, vector, 16);
        encryptBlock(temp);
        COPY(vector, temp, 16);
        fwrite(temp, sizeof(unsigned char), 16, dest_f);
        n = fread(temp, sizeof(unsigned char), 16, source_f);
    }
    bitPadding(temp, n, 16);
    XOR(temp, vector, 16);
    encryptBlock(temp);
    fwrite(temp, sizeof(unsigned char), 16, dest_f);
    fclose(source_f);
    fclose(dest_f);
}

void decryptFileCBC(const char* sourcefilename, const char* destfilename)
// Decrypt a file.
{
    FILE* source_f = fopen(sourcefilename, "rb");
    FILE* dest_f = fopen(destfilename, "wb");
    unsigned char temp[16];
    fseek(source_f, 0, SEEK_END);
    int i = ftell(source_f) / 16 - 1;
    fseek(source_f, 0, SEEK_SET);
    unsigned char lastVector[16] = {0}; // Initialization vector
    unsigned char vector[16] = {0};
    while (i)
    {
        fread(temp, sizeof(unsigned char), 16, source_f);
        COPY(vector, temp, 16);
        decryptBlock(temp);
        XOR(temp, lastVector, 16);
        COPY(lastVector, vector, 16);
        fwrite(temp, sizeof(unsigned char), 16, dest_f);
        i--;
    }
    fread(temp, sizeof(unsigned char), 16, source_f);
    decryptBlock(temp);
    XOR(temp, lastVector, 16);
    fwrite(temp, sizeof(unsigned char), invBitPadding(temp, 16), dest_f);
    fclose(source_f);
    fclose(dest_f);
}
