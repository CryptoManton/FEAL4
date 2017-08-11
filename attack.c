#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "praktikum.h"
#include "fealclient.h"

#define MAXENCRYPT 25 /* Maximale Anzahl von Verschluesselungen */

ByteType Rot2Results[256];

void initRot2(void)
{
  int i;
  for (i = 0; i < 256; i++) {
    Rot2Results[i] = (ByteType) (i<<2 | ((i>>6)&3));
  }
}
  
#define Rot2(x) Rot2Results[(x)]
#define S0(a,b) Rot2((a+b)&255)
#define S1(a,b) Rot2((a+b+1)&255)

/* Rundenfunktion des FEAL. x ist die Eingabe, k ist der Rundenschluessel,
 * y ist die Ausgabe. (y und x darf dasselbe Array sein)
 */
void F (ByteType x[4], ByteType k[2], ByteType y[4])
{
  ByteType a, b, c, d;
  a = x[0];
  b = x[0] ^ x[1];
  c = x[2] ^ x[3];
  d = x[3];
  b ^= k[0];
  c ^= k[1];
  b = S1(b,c);
  c = S0(b,c);
  a = S0(a,b);
  d = S1(c,d);
  y[0] = a; y[1] = b; y[2] = c; y[3] = d;
}

#define BIT(a,b) (((a)>>(b))&1)
#define TXT 25
#define debug 0

/* in key[i][2] soll der i-te Rundenschluessel stehen.
 * in der Aufgabe sind key[4] bis key[11] immer 0!!!
 * Dies wird im Rahmenprogramm automatisch gesetzt.
 */
ByteType key [12][2];
ByteType key_real [12][2];
ByteType key_ges [4];

int characteristic1(ByteType m_l[TXT][4], ByteType m_r[TXT][4], ByteType xor[TXT][4], ByteType c_1_xor_f_3[4], int j) {
  int m_l_0 = m_l[j][0] & 0b00000001;
  int m_l_2 = (m_l[j][0] & 0b00000100) >> 2;
  int m_l_8 = m_l[j][1] & 0b00000001;

  int m_r_0 = m_r[j][0] & 0b00000001;

  int r_2_0 = c_1_xor_f_3[0] & 0b00000001;

  int r_3_2 = (xor[j][0] & 0b00000100) >> 2;
  int r_3_8 = xor[j][1] & 0b00000001;
  // 1.Char: m_l[0,2,8] XOR m_r[0] XOR R_2[0] XOR R_3[2,8]
  return m_l_0 ^ m_l_2 ^ m_l_8 
       ^ m_r_0 
       ^ r_2_0 
       ^ r_3_2 ^ r_3_8;
}

int characteristic2(ByteType m_l[TXT][4], ByteType m_r[TXT][4], ByteType xor[TXT][4], ByteType c_1_xor_f_3[4], int j) {
  int m_l_0 = m_l[j][0] & 0b00000001;
  int m_l_8 = m_l[j][1] & 0b00000001;
  int m_l_10 = (m_l[j][1] & 0b00000100) >> 2;
  int m_l_16 = m_l[j][2] & 0b00000001;
  int m_l_24 = m_l[j][3] & 0b00000001;

  int m_r_0 = m_r[j][0] & 0b00000001;
  int m_r_8 = m_r[j][1] & 0b00000001;
  int m_r_16 = m_r[j][2] & 0b00000001;
  int m_r_24 = m_r[j][3] & 0b00000001;

  int r_2_0 = c_1_xor_f_3[0] & 0b00000001;
  int r_2_8 = c_1_xor_f_3[1] & 0b00000001;
  int r_2_16 = c_1_xor_f_3[2] & 0b00000001;
  int r_2_24 = c_1_xor_f_3[3] & 0b00000001;

  int r_3_10 = (xor[j][1] & 0b00000100) >> 2;
  // 2.Char: m_l[0,8,10,16,24] XOR m_r[0,8,16,24] XOR R_2[0,8,16,24] XOR R_3[10]
  return m_l_0 ^ m_l_8 ^ m_l_10 ^ m_l_16 ^ m_l_24 
       ^ m_r_0 ^ m_r_8 ^ m_r_16 ^ m_r_24
       ^ r_2_0 ^ r_2_8 ^ r_2_16 ^ r_2_24
       ^ r_3_10;
}

int characteristic3(ByteType m_l[TXT][4], ByteType m_r[TXT][4], ByteType xor[TXT][4], ByteType c_1_xor_f_3[4], int j) {
  int m_l_8 = m_l[j][1] & 0b00000001;
  int m_l_16 = m_l[j][2] & 0b00000001;
  int m_l_18 = (m_l[j][2] & 0b00000100) >> 2;
  int m_l_24 = m_l[j][3] & 0b00000001;

  int m_r_16 = m_r[j][2] & 0b00000001;
  int m_r_24 = m_r[j][3] & 0b00000001;

  int r_2_16 = c_1_xor_f_3[2] & 0b00000001;
  int r_2_24 = c_1_xor_f_3[3] & 0b00000001;

  int r_3_8 = xor[j][1] & 0b00000001;
  int r_3_18 = (xor[j][2] & 0b00000100) >> 2;
  // 3.Char: m_l[8,16,18,24] XOR m_r[16,24] XOR R_2[16,24] XOR R_3[8,18]
  return m_l_8 ^ m_l_16 ^ m_l_18 ^ m_l_24 
       ^ m_r_16 ^ m_r_24
       ^ r_2_16 ^ r_2_24 
       ^ r_3_8 ^ r_3_18;
}

int characteristic4(ByteType m_l[TXT][4], ByteType m_r[TXT][4], ByteType xor[TXT][4], ByteType c_1_xor_f_3[4], int j) {
  int m_l_16 = m_l[j][2] & 0b00000001;
  int m_l_24 = m_l[j][3] & 0b00000001;
  int m_l_26 = (m_l[j][3] & 0b00000100) >> 2;

  int m_r_24 = m_r[j][3] & 0b00000001;

  int r_2_24 = c_1_xor_f_3[3] & 0b00000001;

  int r_3_16 = xor[j][2] & 0b00000001;
  int r_3_26 = (xor[j][3] & 0b00000100) >> 2;
  // 4.Char: m_l[16,24,26] XOR m_r[24] XOR R_2[24] XOR R_3[16,26]
  return m_l_16 ^ m_l_24 ^ m_l_26
       ^ m_r_24
       ^ r_2_24
       ^ r_3_16 ^ r_3_26;
}

/* Die Funktion attacke soll sich gewaehlte plaintext/ciphertext-Paare
 * vom Daemonen holen (mit der Funktion feal_encrypt()).
 * Dann soll sie die 4 Rundenschluessel berechnen und in
 * key[i] (i von 0 bis 3) speichern.
 */
void attacke (void)
{
  /* XXX Aufgabe */
  ByteType plaintext[TXT][8] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
                                {0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
                                {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
                                {0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
                                {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
                                {0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
                                {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
                                {0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f},
                                {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47},
                                {0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
                                {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
                                {0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f},
                                {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67},
                                {0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
                                {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77},
                                {0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f},
                                {0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f},
                                {0x78, 0x33, 0x32, 0x61, 0x5d, 0x7d, 0x5f, 0x2e},
                                {0x7d, 0x71, 0x3d, 0x7b, 0x43, 0x4b, 0x23, 0x1e},
                                {0x09, 0x14, 0x00, 0x24, 0x13, 0x3c, 0x7e, 0x05},
                                {0x78, 0x79, 0x1a, 0x21, 0x7c, 0x51, 0x49, 0x7f},
                                {0x6c, 0x1b, 0x51, 0x16, 0x2a, 0x71, 0x7e, 0x23},
                                {0x7f, 0x79, 0x3e, 0x21, 0x4a, 0x03, 0x06, 0x2c},
                                {0x21, 0x40, 0x67, 0x7b, 0x7c, 0x7d, 0x7e, 0x19}
                                };
  ByteType cipher[TXT][8];
  ByteType c_l[TXT][4];
  ByteType c_r[TXT][4];
  ByteType c_xor[TXT][4];
  ByteType m_l[TXT][4];
  ByteType m_r[TXT][4];
  ByteType m_xor[TXT][4];
  for (int i = 0; i < TXT; i++) {
    // encrypt the plaintext
    feal_encrypt(plaintext[i], cipher[i]);
    // and half plaintext and cipher and XOR them
    for (int j = 0; j < 4; j++) {
      c_l[i][j] = cipher[i][j];
      c_r[i][j] = cipher[i][j+4];
      c_xor[i][j] = cipher[i][j] ^ cipher[i][j+4];
      m_l[i][j] = plaintext[i][j];
      m_r[i][j] = plaintext[i][j+4];
      m_xor[i][j] = plaintext[i][j] ^ plaintext[i][j+4];
    }
  }
  if (debug) {
    for (int i = 0; i < TXT; i++) {
      printf("\n%d. text:\n", i+1);
      for (int j = 0; j < 8; j++) {
        printf("Pair: (%02x, %02x).\n", plaintext[i][j], cipher[i][j]);
      }
      for (int j = 0; j < 4; j++) {
        printf("In(l, r):(%02x, %02x). XOR: %02x\n", m_l[i][j], m_r[i][j], m_xor[i][j]);
        printf("Out(l, r):(%02x, %02x). XOR: %02x\n", c_l[i][j], c_r[i][j], c_xor[i][j]);
      }
    }
  }

  int k4_count = 0;
  ByteType k4[20][2];
  // brute force k4
  printf("Computing k4...\n");
  for (int i = 0; i < 65536; i++) {
    int still_val = 1;
    int parity[4] = {0,0,0,0};
    k4[k4_count][0] = i & 0xff;
    k4[k4_count][1] = i >> 8;
    for (int j = 0; j < TXT; j++) {
      // bottom up
      ByteType F3_out[4] = {0, 0, 0, 0};
      F(c_xor[j], k4[k4_count], F3_out);
      ByteType c_l_xor_f_3[4] = {c_l[j][0] ^ F3_out[0], c_l[j][1] ^ F3_out[1], c_l[j][2] ^ F3_out[2], c_l[j][3] ^ F3_out[3]};
      
      int parity_char1 = characteristic1(m_l, m_r, c_xor, c_l_xor_f_3, j);
      int parity_char2 = characteristic2(m_l, m_r, c_xor, c_l_xor_f_3, j);
      int parity_char3 = characteristic3(m_l, m_r, c_xor, c_l_xor_f_3, j);
      int parity_char4 = characteristic4(m_l, m_r, c_xor, c_l_xor_f_3, j);
                
      if (j==0) {
        parity[0] = parity_char1;
        parity[1] = parity_char2;
        parity[2] = parity_char3;
        parity[3] = parity_char4;
      }
      if (parity[0] == parity_char1 && parity[1] == parity_char2 && parity[2] == parity_char3 && parity[3] == parity_char4) {  
        still_val = 1;
      } else {
        still_val = 0;
        break;
      }
    }
    if (still_val) {
      printf("Key: (%02x, %02x).\n", k4[k4_count][0], k4[k4_count][1]);
      k4_count++;
    }
  }
  printf("%d possible keys.\n", k4_count);

  int k1_count = 0;
  ByteType k1[20][2];
  printf("Computing k1...\n");
  // brute force k1
  for (int i = 0; i < 65536; i++) {
    int still_val = 1;
    int parity[4] = {0,0,0,0};
    k1[k1_count][0] = i & 0xff;
    k1[k1_count][1] = i >> 8;
    for (int j = 0; j < TXT; j++) {
      // bottom up
      ByteType F0_out[4] = {0, 0, 0, 0};
      F(m_xor[j], k1[k1_count], F0_out);
      ByteType m_l_xor_f_0[4] = {m_l[j][0] ^ F0_out[0], m_l[j][1] ^ F0_out[1], m_l[j][2] ^ F0_out[2], m_l[j][3] ^ F0_out[3]};
      
      int parity_char1 = characteristic1(c_l, c_r, m_xor, m_l_xor_f_0, j);
      int parity_char2 = characteristic2(c_l, c_r, m_xor, m_l_xor_f_0, j);
      int parity_char3 = characteristic3(c_l, c_r, m_xor, m_l_xor_f_0, j);
      int parity_char4 = characteristic4(c_l, c_r, m_xor, m_l_xor_f_0, j);
                
      if (j==0) {
        parity[0] = parity_char1;
        parity[1] = parity_char2;
        parity[2] = parity_char3;
        parity[3] = parity_char4;
      }
      if (parity[0] == parity_char1 && parity[1] == parity_char2 && parity[2] == parity_char3 && parity[3] == parity_char4) {  
        still_val = 1;
      } else {
        still_val = 0;
        break;
      }
    }
    if (still_val) {
      printf("Key: (%02x, %02x).\n", k1[k1_count][0], k1[k1_count][1]);
      k1_count++;
    }
  }
  printf("%d possible keys.\n", k1_count);

  // only one key?! why not save it?
  if (k1_count == 1) {
  }
  if (k4_count == 1) {
  }

  ByteType L1[TXT][4], R2[TXT][4], R1[TXT][4], R3[TXT][4];
  ByteType F3[4], F0[4];
  printf("Brute-Forcing k2 and k3...\n");
  // brute-force k2 and k3
  int k2_val = 1;
  int k3_val = 1;
  for (int i = 0; i < 65536; i++) {
    k2_val = 1;
    k3_val = 1;
    ByteType k[2] = {i & 0xff, i >> 8};
    // there might be more than 1 key for k1 and k4?? what a shame!
    for (int k1s = 0; k1s < k1_count; k1s++) {
      for (int k4s = 0; k4s < k4_count; k4s++) {
      // computing L1, R1 and R2, R3
        for (int i = 0; i < TXT; i++) {
          //F_3 output
          F(m_xor[i], k1[k1s], F0);
          F(c_xor[i], k4[k4s], F3);
          for (int j = 0; j < 4; j++) {
            L1[i][j] = m_xor[i][j];
            R1[i][j] = m_l[i][j] ^ F0[j];
            R2[i][j] = c_l[i][j] ^ F3[j];
            R3[i][j] = c_xor[i][j];
          }
        }
        for (int j = 0; j < TXT; j++) {
          // check the key for all (R1, R2)-pairs and (R2, R1)-pairs
          ByteType F1[4];
          ByteType F2[4];
          F(R1[j], k, F1);
          F(R2[j], k, F2);
          ByteType R2_tmp[4] = {L1[j][0] ^ F1[0], L1[j][1] ^ F1[1], L1[j][2] ^ F1[2], L1[j][3] ^ F1[3]};
          ByteType R1_tmp[4] = {R3[j][0] ^ F2[0], R3[j][1] ^ F2[1], R3[j][2] ^ F2[2], R3[j][3] ^ F2[3]};
          if (R2[j][0] == R2_tmp[0] && R2[j][1] == R2_tmp[1] && R2[j][2] == R2_tmp[2] && R2[j][3] == R2_tmp[3]) {  
            k2_val = 1;
          } else {
            k2_val = 0;
          }
          if (R1[j][0] == R1_tmp[0] && R1[j][1] == R1_tmp[1] && R1[j][2] == R1_tmp[2] && R1[j][3] == R1_tmp[3]) { 
            k3_val = 1;
          } else {
            k3_val = 0;
          }
        }
        // so we found a valid k2, so k1 and k4 are valid too, why not safe them?!
        if (k2_val) {
          printf("Key2 found...%02x%02x.\n", k[0], k[1]);
          key[1][0] = k[0];
          key[1][1] = k[1];
          key[0][0] = k1[k1s][0];
          key[0][1] = k1[k1s][1];
          key[3][0] = k4[k4s][0];
          key[3][1] = k4[k4s][1];
        }
        if(k3_val) {
          printf("Key3 found...%02x%02x.\n", k[0], k[1]);
          key[2][0] = k[0];
          key[2][1] = k[1];
          key[0][0] = k1[k1s][0];
          key[0][1] = k1[k1s][1];
          key[3][0] = k4[k4s][0];
          key[3][1] = k4[k4s][1];
        }
      }
    }
  }
}

void main (void)
{
  int t; /* temporaere Variable */

  initRot2 ();
  if ((t=feal_new_key ()) < 0) {
    fprintf (stderr, "Fehler in feal_new_key: %d\n", t);
    exit (1);
  }
  attacke ();
  memset (key[4], 0, 8*2);
  memset (key_real, 0, 12*2);
  t = feal_check_sub (key, key_real, key_ges);
  if (t > 0) {
    printf ("Der Schluessel war richtig: %02x%02x %02x%02x %02x%02x %02x%02x\n",
      key[0][0], key[0][1], key[1][0], key[1][1], key[2][0], key[2][1],
      key[3][0], key[3][1]);
    printf ("Der Gesamtschluessel, aus dem diese Rundenschluessel entstanden,\n");
    printf ("war: %02x%02x%02x%02x%02x%02x%02x%02x\n", key_ges[0], key_ges[1],
      key_ges[2], key_ges[3], key_ges[4], key_ges[5], key_ges[6], key_ges[7]);
  } else if (t < 0) {
    fprintf (stderr, "Fehler in feal_check_sub: %d\n", t);
    exit (1);
  } else {
    printf ("Der Schluessel war falsch.\n\n");
    printf ("Berechneter Schluessel:    %02x%02x %02x%02x %02x%02x %02x%02x\n",
      key[0][0], key[0][1], key[1][0], key[1][1], key[2][0], key[2][1],
      key[3][0], key[3][1]);
    printf ("Tatsaechlicher Schluessel: %02x%02x %02x%02x %02x%02x %02x%02x\n",
#define key key_real
      key[0][0], key[0][1], key[1][0], key[1][1], key[2][0], key[2][1],
      key[3][0], key[3][1]);
#undef key
    printf ("Der Gesamtschluessel, aus dem diese Rundenschluessel entstanden,\n");
    printf ("war: %02x%02x%02x%02x%02x%02x%02x%02x\n", key_ges[0], key_ges[1],
      key_ges[2], key_ges[3], key_ges[4], key_ges[5], key_ges[6], key_ges[7]);
  }

  exit (0);
}
