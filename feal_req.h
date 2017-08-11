#define DAEMON_NETNAME "FEAL4_Daemon"

#define E_EXCEED -1
#define E_NOKEY -2
  /* CS_Encrypt or CS_CheckKey: no valid key, CS_NewKey: no space */

struct message {
  enum { CS_NewKey, SC_NewKey,
         CS_Encrypt, SC_Encrypt,
         CS_CheckKey, SC_CheckKey,
         CS_CheckSub, SC_CheckSub
  } type;
  union {
    struct cs_new_key {
      char x;
    } cs_new_key;
    struct sc_new_key {
      int ok; /* 0 = ok, <0 = error */
    } sc_new_key;
    struct cs_encrypt {
      ByteType plaintext[8];
    } cs_encrypt;
    struct sc_encrypt {
      ByteType ciphertext[8];
      int remain; /* remaining encryptions - -1 means already exceeded */
    } sc_encrypt;
    struct cs_check_key {
      ByteType key_trial[8];
    } cs_check_key;
    struct sc_check_key {
      ByteType key[8];
      int ok; /* 1 = key was ok, 0 = key was not ok, <0 = error */
    } sc_check_key;
    struct cs_check_sub {
      ByteType key_trial [12][2];
    } cs_check_sub;
    struct sc_check_sub {
      ByteType orig_key[8];
      ByteType key[12][2];
      int ok;
    } sc_check_sub;
  } b; /* body */
};
