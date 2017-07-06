#include <sodium.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <b64/cencode.h>
#include <b64/cdecode.h>

#include "crypto_helper.h"
#include "chat_client.h"
#include "chat_server.h"

void handshake_server(client_t *client, unsigned char *server_public_key, unsigned char *server_secret_key) {
  unsigned char buff_in[BUFFER_SIZE];
  int rlen;
  char *b64encoded, *b64decoded;

  // First, the server sends the client their public key
  // IRL this wouldn't work and the key would need to have a certificate
  // For the purposes of the project though, we ignore this detail and assume the client can and will
  // verify the authenticity of this key
  int connfd = client->connfd;
  b64encoded = b64encode(server_public_key);
  write(connfd, b64encoded, strlen(b64encoded));

  // Server now waits for client's chosen symmetric key and decrypts it
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  buff_in[rlen] = '\0';
  b64decoded = b64decode(buff_in);
  printf("Received b64 symm sealed: %s\n", buff_in);
  unsigned char symm[crypto_secretbox_KEYBYTES];
  if(crypto_box_seal_open(&client->client_server_symm_key[0], b64decoded, crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES, server_public_key, server_secret_key) != 0) {
    printf("Symm message corrupted\n");
  } else {
    symm[crypto_secretbox_KEYBYTES] = '\0';
  }
  client->client_server_symm_key[crypto_secretbox_KEYBYTES] = '\0';

  printf("Done with seal_open\n");
  b64encoded = b64encode(symm);
  printf("My symm key: %s\n", b64encoded);

  /*
  int i;
  for(i = 0; i < crypto_secretbox_KEYBYTES; i++) {
    client->client_server_symm_key[i] = symm[i];
  }
  client->client_server_symm_key[crypto_secretbox_KEYBYTES] = 0;
  */

  // Server computes E_K(K) and sends to client
  unsigned char e_k_nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(e_k_nonce, crypto_secretbox_NONCEBYTES);
  unsigned char e_k[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES];
  crypto_secretbox_easy(e_k, client->client_server_symm_key, crypto_secretbox_KEYBYTES, e_k_nonce, client->client_server_symm_key);
  e_k[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES] = '\0';

  //printf("E_k has length %s\n", crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES);
  //printf("Sending e_k %s to client\n", e_k);

  b64encoded = b64encode(e_k);
  printf("Sending e_k %s\n", b64encoded);
  //write(connfd, b64encoded, crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES);
  write(connfd, b64encoded, strlen(b64encoded));

  printf("Gonna check decoding it for myself...\n");
  printf("I'm using symm key %s\n", client->client_server_symm_key);

  unsigned char d_e_k[crypto_secretbox_KEYBYTES];
  if(crypto_secretbox_open_easy(d_e_k, e_k, crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES, e_k_nonce, client->client_server_symm_key) != 0) {
    printf("Bad decryption on e_k\n");
  } else {
    printf("Good decryption of e_k\n");
  }
  printf("Gonna decode b64 now...\n");
  b64decoded = b64decode(b64encoded);
  if(crypto_secretbox_open_easy(d_e_k, b64decoded, crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES, e_k_nonce, client->client_server_symm_key) != 0) {
    printf("Bad decryption of b64\n");
  } else {
    printf("Good decryption of b64\n");
  }

  b64encoded = b64encode(client->client_server_symm_key);
  printf("My symm key: %s\n", b64encoded);
  printf("My symm key's length is: %d\n", strlen(client->client_server_symm_key));
  printf("My nonce's length is: %d\n", strlen(e_k_nonce));

  FILE *fp = fopen("server_e_k.txt", "ab");
  fputs(e_k, fp);
  fclose(fp);

  sleep(2);

  // Server also sends the nonce used to the client
  b64encoded = b64encode(e_k_nonce);
  printf("Sending nonce %s\n", b64encoded);
  //write(connfd, b64encoded, crypto_secretbox_NONCEBYTES);
  write(connfd, b64encoded, strlen(b64encoded));

  // Wait for SUCCESSFUL_KEY_EXCHANGE from client
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  buff_in[rlen] = '\0';
  printf("Client sent me: %s\n", buff_in);
}

// TODO: Add timestamp/nonce into symm key exchange

void handshake_client(keys_t *keys, int connfd) {
  unsigned char buff_in[BUFFER_SIZE];
  int rlen;
  char *b64encoded, *b64decoded;

  // Client starts by waiting for server's public key
  printf("Waiting for server's public key to come in...\n");
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  buff_in[rlen] = '\0';
  b64decoded = b64decode(buff_in);

  printf("Server's public key: %s\n", buff_in);

  int i;
  for(i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
    keys->server_public_key[i] = b64decoded[i];
  }

  // Client generates a secret key K
  randombytes_buf(keys->client_server_symm_key, crypto_secretbox_KEYBYTES);
  keys->client_server_symm_key[crypto_secretbox_KEYBYTES] = '\0';
  //keys->client_server_symm_key[crypto_secretbox_KEYBYTES] = '\0';
  b64encoded = b64encode_length(keys->client_server_symm_key, crypto_secretbox_KEYBYTES);
  printf("b64 symm: %s\n", b64encoded);

  // Client sends K to server using server's public key using a sealed box
  // TODO: Update this ciphertext length to reflect the final message length with timestamp
  unsigned char sealed_k[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES];
  crypto_box_seal(sealed_k, keys->client_server_symm_key, crypto_secretbox_KEYBYTES, keys->server_public_key);
  b64encoded = b64encode(sealed_k);
  printf("b64 sealed_k is: %s\n", b64encoded);
  write(connfd, b64encoded, strlen(b64encoded));

  // Client now waits for server to respond with E_K(K)
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  buff_in[rlen] = '\0';
  printf("rlen: %d\n", rlen);
  printf("Got e_k %s\n", buff_in);
  b64decoded = b64decode(buff_in);
  unsigned char e_k[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES];
  for(i = 0; i < crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES; i++) {
    e_k[i] = b64decoded[i];
  }
  e_k[crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES] = '\0';

  // Client now waits for the nonce used
  rlen = read(connfd, buff_in, sizeof(buff_in)-1);
  buff_in[rlen] = '\0';
  printf("Got nonce %s\n", buff_in);
  b64decoded = b64decode(buff_in);
  unsigned char e_k_nonce[crypto_secretbox_NONCEBYTES];
  for(i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
    e_k_nonce[i] = b64decoded[i];
  }
  e_k_nonce[crypto_secretbox_NONCEBYTES] = '\0';

  // Client checks that they can decrypt e_k to k
  int successful_decryption = 1;

  printf("Gonna try to decrpyt e_k\n", buff_in);

  b64encoded = b64encode(keys->client_server_symm_key);
  printf("I'm using symm key: %s\n", b64encoded);
  printf("My symm key's length is: %d\n", strlen(keys->client_server_symm_key));
  printf("My nonce's length is: %d\n", strlen(e_k_nonce));

  FILE *fp = fopen("client_e_k.txt", "ab");
  fputs(e_k, fp);
  fclose(fp);

  unsigned char d_e_k[crypto_secretbox_KEYBYTES];
  if(crypto_secretbox_open_easy(d_e_k, e_k, crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES, e_k_nonce, keys->client_server_symm_key) != 0) {
    successful_decryption = 0;
    printf("Message forged, abort!\n");
  } else {
    printf("Decrypted successfully\n");

    for(i = 0; i < crypto_secretbox_KEYBYTES; i++) {
      if(d_e_k[i] != keys->client_server_symm_key[i]) {
        successful_decryption = 0;
        break;
      }
    }
  }

  if(successful_decryption) {
    printf("Decryption successful\n");
    // Send notification to server that we decrypted successfully
    write(connfd, SUCCESSFUL_KEY_EXCHANGE, strlen(SUCCESSFUL_KEY_EXCHANGE));
  } else {
    printf("Bad decryption\n");
    write(connfd, BAD_KEY_EXCHANGE, strlen(BAD_KEY_EXCHANGE));
  }

}

// Base-64 encoding/decoding from libb64

#define SIZE 100

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
