#ifndef CHAT_CLIENT_H_
#define CHAT_CLIENT_H_

// GLOBALS DEFINITIONS

// IO Buffer size
#define BUFFER_SIZE 2048

typedef struct {
  unsigned char client_secret_key[crypto_box_SECRETKEYBYTES];
  unsigned char client_public_key[crypto_box_PUBLICKEYBYTES];
  unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
  unsigned char client_server_symm_key[crypto_secretbox_KEYBYTES];

  unsigned char client_chatroom_secret_key[crypto_box_SECRETKEYBYTES];
  unsigned char client_chatroom_public_key[crypto_box_PUBLICKEYBYTES];

  unsigned char chatroom_secret_key[crypto_secretbox_KEYBYTES];
} keys_t;

#endif
