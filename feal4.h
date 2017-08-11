/*
Version of 20 September 1989.
*/

typedef unsigned char ByteType ;

void SetKey( ByteType * ) ;
void Encrypt( ByteType *Plain, ByteType *Cipher ) ;
void Decrypt( ByteType *Cipher, ByteType *Plain ) ;

#ifndef FEAL4_SOURCE
extern ByteType K[12][2];
extern unsigned long K89, K1011, K1213, K1415;
#endif
