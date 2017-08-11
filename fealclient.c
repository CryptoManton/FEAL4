#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network.h"
#include "feal4.h"
#include "feal_req.h"

#define MY_NETNAME "Feal"

static Connection con;
static const char *netname;
static struct message out, in;

int feal_new_key (void)
{
  netname = MakeNetName (MY_NETNAME);
  con = ConnectTo (netname, DAEMON_NETNAME);
  if (! con) {
    fprintf (stderr, "Connection to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  out.type = CS_NewKey;
  if (Transmit (con, &out, sizeof (out)) != sizeof (out)) {
    fprintf (stderr, "Transmit to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  if (Receive (con, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Short receive\n");
    exit (1);
  }
  DisConnect (con);
  if (in.type != SC_NewKey) {
    fprintf (stderr, "feal_new_key: wrong reply type\n");
    exit (1);
  }
  return in.b.sc_new_key.ok;
}

int feal_encrypt (ByteType *plaintext, ByteType *ciphertext)
{
  netname = MakeNetName (MY_NETNAME);
  con = ConnectTo (netname, DAEMON_NETNAME);
  if (! con) {
    fprintf (stderr, "Connection to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  out.type = CS_Encrypt;
  if (plaintext)
    memcpy (out.b.cs_encrypt.plaintext, plaintext, 8);
  else
    memset (out.b.cs_encrypt.plaintext, 0, 8);

  if (Transmit (con, &out, sizeof (out)) != sizeof (out)) {
    fprintf (stderr, "Transmit to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  if (Receive (con, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Short receive\n");
    exit (1);
  }
  DisConnect (con);
  if (in.type != SC_Encrypt) {
    fprintf (stderr, "feal_encrypt: wrong reply type\n");
    exit (1);
  }
  if (ciphertext)
    memcpy (ciphertext, in.b.sc_encrypt.ciphertext, 8);
  return in.b.sc_encrypt.remain;
}

int feal_check_key (ByteType *key_trial, ByteType *key)
{
  netname = MakeNetName (MY_NETNAME);
  con = ConnectTo (netname, DAEMON_NETNAME);
  if (! con) {
    fprintf (stderr, "Connection to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  out.type = CS_CheckKey;
  if (key_trial)
    memcpy (out.b.cs_check_key.key_trial, key_trial, 8);
  else
    memset (out.b.cs_check_key.key_trial, 0, 8);
  if (Transmit (con, &out, sizeof (out)) != sizeof (out)) {
    fprintf (stderr, "Transmit to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  if (Receive (con, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Short receive\n");
    exit (1);
  }
  DisConnect (con);
  if (in.type != SC_CheckKey) {
    fprintf (stderr, "feal_check_key: wrong reply type\n");
    exit (1);
  }
  if (key)
    memcpy (key, in.b.sc_check_key.key, 8);
  return in.b.sc_check_key.ok;
}

int feal_check_sub (ByteType key_trial[12][2], ByteType key[12][2],
                    ByteType *key_orig)
{
  netname = MakeNetName (MY_NETNAME);
  con = ConnectTo (netname, DAEMON_NETNAME);
  if (! con) {
    fprintf (stderr, "Connection to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  out.type = CS_CheckSub;
  memcpy (out.b.cs_check_sub.key_trial, key_trial, 12*2);
  if (Transmit (con, &out, sizeof (out)) != sizeof (out)) {
    fprintf (stderr, "Transmit to daemon failed: %s\n", NET_ErrorText());
    exit (1);
  }
  if (Receive (con, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Short receive\n");
    exit (1);
  }
  DisConnect (con);
  if (in.type != SC_CheckSub) {
    fprintf (stderr, "feal_check_sub: wrong reply type\n");
    exit (1);
  }
  memcpy (key, in.b.sc_check_sub.key, 12*2);
  if (key_orig)
    memcpy (key_orig, in.b.sc_check_sub.orig_key, 8);
  return in.b.sc_check_sub.ok;
}
