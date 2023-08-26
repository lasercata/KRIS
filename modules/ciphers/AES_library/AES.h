/*
--------------------AES.h--------------------
Author :        Elerias
Date :          13.12.2020
Version :       1.0.1
Description :   Header of AES.c
---------------------------------------------
*/



#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

void printGrid(unsigned char*);
unsigned char gfmul_function(unsigned char, unsigned char);
void initGfmul();
void expandKey(const unsigned char*);
void initAES(int, unsigned char*);
void encryptBlock(unsigned char*);
void decryptBlock(unsigned char*);
unsigned int bitPadding(unsigned char*, unsigned int, const unsigned int);
unsigned int invBitPadding(unsigned char*, unsigned int);
unsigned int encryptTextECB(unsigned char*, const unsigned int);
unsigned int decryptTextECB(unsigned char*, const unsigned int);
unsigned int encryptTextCBC(unsigned char*, const unsigned int);
unsigned int decryptTextCBC(unsigned char*, const unsigned int);
void encryptFileECB(const char* sourcefilename, const char* destfilename);
void decryptFileECB(const char* sourcefilename, const char* destfilename);
void encryptFileCBC(const char* sourcefilename, const char* destfilename);
void decryptFileCBC(const char* sourcefilename, const char* destfilename);
int mode;
int Nr;
unsigned char expKey[4][60];

#endif // AES_H_INCLUDED
