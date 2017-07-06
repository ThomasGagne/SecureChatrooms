#include <sodium.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <b64/cencode.h>
#include <b64/cdecode.h>

#include "crypto_helper.h"
#include "chat_client.h"
#include "chat_server.h"
#include "utilities.h"
#include "protocol_constants.h"

int handshake_server(int connfd, unsigned char client_server_symm_key[], unsigned char *server_public_key, unsigned char *server_secret_key) {
  int rlen;
  unsigned char buff_in[BUFFER_SIZE];
  unsigned char *b64encoded, *b64decoded;

  // First, the server send the client their public key
  b64encoded = b64encode_length(server_public_key, crypto_box_PUBLICKEYBYTES);
  write(connfd, b64encoded, strlen(b64encoded));

  // Server now waits for client to generate symm key and wrap it in box
  rlen =read(connfd, buff_in, sizeof(buff_in)-1);
  b64decoded = b64decode(buff_in);
  buff_in[rlen] = '\0';
  unsigned char stored_symm_ciphertext[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES];
  int i;
  for(i = 0; i < crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES; i++) {
    stored_symm_ciphertext[i] = b64decoded[i];
  }

  // Server now attempts to decrypt symm
  unsigned char stored_symm[crypto_secretbox_KEYBYTES];
  if(crypto_box_seal_open(stored_symm, stored_symm_ciphertext, crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES,
                          server_public_key, server_secret_key) != 0) {
    printf("Decryption failed :(\n");
  } else {
    printf("Decryption was completed!\n");
  }

  // To confirm the server got symm, the server computes e_k and sends it to the client
  unsigned char e_k[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES];
  unsigned char e_k_nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(e_k_nonce, crypto_secretbox_NONCEBYTES);
  crypto_secretbox_easy(e_k, stored_symm, crypto_secretbox_KEYBYTES, e_k_nonce, stored_symm);

  // Full message is the nonce, then the encrypted message appended to that
  unsigned char e_k_message[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES];
  for(i = 0; i < crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES; i++) {
    if(i < crypto_secretbox_NONCEBYTES) {
      e_k_message[i] = e_k_nonce[i];
    } else {
      e_k_message[i] = e_k[i - crypto_secretbox_NONCEBYTES];
    }
  }
  b64encoded = b64encode_length(e_k_message, crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES);
  write(connfd, b64encoded, strlen(b64encoded));

  // Server now waits for client to acknowledge that they decrypted successfully
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  buff_in[rlen] = '\0';
  if(!strcmp(buff_in, HANDSHAKE_SUCCESSFUL)) {
    for(i = 0; i < crypto_secretbox_KEYBYTES; i++) {
      client_server_symm_key[i] = stored_symm[i];
    }

    free(b64encoded);
    free(b64decoded);
    return 1;
  } else {
    free(b64encoded);
    free(b64decoded);
    return 0;
  }
}

int handshake_client(unsigned char client_server_symm_key[], int connfd) {
  int rlen;
  unsigned char buff_in[BUFFER_SIZE];
  unsigned char *b64encoded, *b64decoded;

  // Client starts by waiting for server's public key
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  b64decoded = b64decode(buff_in);
  buff_in[rlen] = '\0';
  unsigned char stored_server_public_key[crypto_box_PUBLICKEYBYTES];
  int i;
  for(i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
    stored_server_public_key[i] = b64decoded[i];
  }

  // The client now generates a secret key for client-server comms and sends it--encrypted--to the server
  unsigned char symm[crypto_secretbox_KEYBYTES];
  randombytes_buf(symm, crypto_secretbox_KEYBYTES);

  unsigned char symm_ciphertext[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES];
  crypto_box_seal(symm_ciphertext, symm, crypto_secretbox_KEYBYTES, stored_server_public_key);

  b64encoded = b64encode_length(symm_ciphertext, crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES);
  write(connfd, b64encoded, strlen(b64encoded));

  // The client now waits for the server to respond with the symm key encrypted with itself
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  b64decoded = b64decode(buff_in);
  buff_in[rlen] = '\0';
  unsigned char full_message[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES];
  unsigned char stored_e_k[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES];
  unsigned char stored_e_k_nonce[crypto_secretbox_NONCEBYTES];
  for(i = 0; i < crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES; i++) {
    if(i < crypto_secretbox_NONCEBYTES) {
      stored_e_k_nonce[i] = b64decoded[i];
    } else {
      stored_e_k[i - crypto_secretbox_NONCEBYTES] = b64decoded[i];
    }
    full_message[i] = b64decoded[i];
  }

  // Client now decrypts e_k and verifies that the result is symm
  unsigned char decrypted_e_k[crypto_secretbox_KEYBYTES];
  if(crypto_secretbox_open_easy(decrypted_e_k, stored_e_k, crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES,
                                stored_e_k_nonce, symm) != 0) {
    write(connfd, HANDSHAKE_FAILED, strlen(HANDSHAKE_FAILED));
    return 0;
  }

  int correct_decryption = 1;
  for(i = 0; i < crypto_secretbox_KEYBYTES; i++) {
    if(symm[i] != decrypted_e_k[i]) {
      correct_decryption = 0;
    }
  }

  if(correct_decryption) {

    // Save the symm key
    for(i = 0; i < crypto_secretbox_KEYBYTES; i++) {
      client_server_symm_key[i] = decrypted_e_k[i];
    }

    write(connfd, HANDSHAKE_SUCCESSFUL, strlen(HANDSHAKE_SUCCESSFUL));
  } else {
    write(connfd, HANDSHAKE_FAILED, strlen(HANDSHAKE_FAILED));
  }

  free(b64encoded);
  free(b64decoded);

  return correct_decryption;
}

// Encrypts message to a form in b64encoding which includes the nonce and the message length
int symm_encrypt(char *result, char *message, int message_length, unsigned char symm_key[]) {
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
  unsigned char ciphertext[crypto_secretbox_MACBYTES + message_length];

  crypto_secretbox_easy(ciphertext, message, message_length, nonce, symm_key);

  // The +8 is for the indicator of the message_length
  unsigned char full_message[crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + message_length + MSG_LEN_SIZE];
  char message_length_str[MSG_LEN_SIZE + 1];
  sprintf(message_length_str, "%08d", message_length);

  int i;
  for(i = 0; i < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + message_length + MSG_LEN_SIZE; i++) {
    if(i < MSG_LEN_SIZE) {
      full_message[i] = message_length_str[i];
    } else if(i < crypto_secretbox_NONCEBYTES + MSG_LEN_SIZE) {
      full_message[i] = nonce[i - MSG_LEN_SIZE];
    } else {
      full_message[i] = ciphertext[i - (crypto_secretbox_NONCEBYTES + MSG_LEN_SIZE)];
    }
  }

  char *b64encoded;
  b64encoded = b64encode_length(full_message, crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + message_length + MSG_LEN_SIZE);
  strcpy(result, b64encoded);
  free(b64encoded);

  return 1;
}

// Converts from b64encoding, retrieves the nonce, and decrypts the message
int symm_decrypt(char *result, char *message, unsigned char symm_key[]) {
  unsigned char *b64decoded;
  b64decoded = b64decode(message);

  char message_length_str[MSG_LEN_SIZE + 1];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  // Extract the message length
  int i;
  for(i = 0; i < MSG_LEN_SIZE; i++) {
    message_length_str[i] = b64decoded[i];
  }
  message_length_str[MSG_LEN_SIZE] = '\0';
  int message_length = strtol(message_length_str, NULL, 10);

  unsigned char *ciphertext[BUFFER_SIZE];

  memcpy(ciphertext, &b64decoded[MSG_LEN_SIZE + crypto_secretbox_NONCEBYTES], crypto_secretbox_MACBYTES + message_length);
  memcpy(nonce, &b64decoded[MSG_LEN_SIZE], crypto_secretbox_NONCEBYTES);

  unsigned char decrypted[message_length];
  if(crypto_secretbox_open_easy(decrypted, ciphertext, message_length + crypto_secretbox_MACBYTES, nonce, symm_key) != 0) {
    return 0;
  }

  memcpy(result, decrypted, message_length);
  result[message_length] = '\0';

  free(b64decoded);

  return 1;
}

// Converts a username and password to a symmetric encryption key
void username_password_to_symm_key(unsigned char result[], char *username, char *password) {
  // Compute a password salt from the username
  // libsodium's generic hash isn't secure for short inputs, but since this is just salt it's fine
  unsigned char username_hash[crypto_generichash_BYTES];
  crypto_generichash(username_hash, crypto_generichash_BYTES, username, strlen(username), NULL, 0);
  unsigned char username_salt[crypto_pwhash_SALTBYTES];
  memcpy(username_salt, username_hash, crypto_pwhash_SALTBYTES);

  unsigned char key[crypto_secretbox_KEYBYTES];
  crypto_pwhash(key, crypto_secretbox_KEYBYTES, password, strlen(password), username_salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_DEFAULT);
  memcpy(result, key, crypto_secretbox_KEYBYTES);
}


// Base-64 encoding/decoding from libb64

#define SIZE 2048

char* b64encode_length(const char* input, int length)
{
  /* set up a destination buffer large enough to hold the encoded data */
  char* output = (char*)malloc(SIZE);
  /* keep track of our encoded position */
  char* c = output;
  /* store the number of bytes encoded by a single call */
  int cnt = 0;
  /* we need an encoder state */
  base64_encodestate s;

  /*---------- START ENCODING ----------*/
  /* initialise the encoder state */
  base64_init_encodestate(&s);
  /* gather data from the input and send it to the output */
  cnt = base64_encode_block(input, length, c, &s);
  c += cnt;
  /* since we have encoded the entire input string, we know that
     there is no more input data; finalise the encoding */
  cnt = base64_encode_blockend(c, &s);
  c += cnt;
  /*---------- STOP ENCODING  ----------*/

  /* we want to print the encoded data, so null-terminate it: */
  *c = 0;

  strip_newline(output);
  return output;
}

char* b64encode(const char* input) {
  return b64encode_length(input, strlen(input));
}

char* b64decode_length(const char* input, int length)
{
  /* set up a destination buffer large enough to hold the encoded data */
  char* output = (char*)malloc(SIZE);
  /* keep track of our decoded position */
  char* c = output;
  /* store the number of bytes decoded by a single call */
  int cnt = 0;
  /* we need a decoder state */
  base64_decodestate s;

  /*---------- START DECODING ----------*/
  /* initialise the decoder state */
  base64_init_decodestate(&s);
  /* decode the input data */
  cnt = base64_decode_block(input, length, c, &s);
  c += cnt;
  /* note: there is no base64_decode_blockend! */
  /*---------- STOP DECODING  ----------*/

  /* we want to print the decoded data, so null-terminate it: */
  *c = 0;

  return output;
}

char* b64decode(const char* input) {
  return b64decode_length(input, strlen(input));
}
