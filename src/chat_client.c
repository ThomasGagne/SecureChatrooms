#include <sodium.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <semaphore.h>
#include <assert.h>

#include "chat_client.h"
#include "crypto_helper.h"
#include "protocol_constants.h"
#include "utilities.h"

int connfd = 0;
struct sockaddr_in serv_addr;
keys_t *keys;
char *current_state;
sem_t *current_state_lock;
char login_name[80];
char password[80];
int new_account;
int chatroom_message_number = 1;

void *receive_server_data(void *arg) {
  char buff_in[BUFFER_SIZE];
  char crypto_buff[BUFFER_SIZE];
  int rlen;

  while((rlen = read(connfd, crypto_buff, sizeof(crypto_buff)-1)) > 0){

    if(!strlen(crypto_buff)) {
      continue;
    }

    // Decrypt message into buff_in
    symm_decrypt(buff_in, crypto_buff, keys->client_server_symm_key);

    // Split string by state delimiters
    char** tokens;
    tokens = str_split(buff_in, STATE_DELIMITER);

    if(tokens) {
      sem_wait(current_state_lock);
      int i;
      for(i = 0; *(tokens + i); i++) {

        if(!strcmp(current_state, STATE_IN_CHATROOM)) {
          if(!strcmp(*(tokens + i), STATE_IDLE)) {
            current_state = STATE_IDLE;
          } else if(*(tokens + i)[0] == '>') {
            // Just a server message
            // b64 encoding doesn't have the '>' character, so we know it's cleartext
            printf("%s", buff_in);

          } else {
            // An encrypted chat message
            char msg_crypto_buff[BUFFER_SIZE];
            int result = symm_decrypt(msg_crypto_buff, buff_in, keys->chatroom_secret_key);
            if(!result) {
              printf("Error: Unable to decrypt chat message!\n");
            } else {
              printf("%s", msg_crypto_buff);
            }
          }

        } else {

          if(!strcmp(*(tokens + i), STATE_IDLE)) {

            if(!strcmp(current_state, STATE_PRE_AUTHENTICATION)) {
              if(new_account) {
                // Successful login, save chatroom keys to file

                char filename[80];

                // Generate a key from the username and password to encrypt the keyfiles with
                unsigned char file_key[crypto_secretbox_KEYBYTES];
                username_password_to_symm_key(file_key, login_name, password);

                char encrypted_secret_key[BUFFER_SIZE];
                symm_encrypt(encrypted_secret_key, keys->client_chatroom_secret_key, crypto_box_SECRETKEYBYTES, file_key);
                sprintf(filename, "client_keys/%s.secret", login_name);
                write_file(filename, encrypted_secret_key);
                printf("<[Saved secret chatroom key in client_keys/%s.secret]>\n", login_name);

                char encrypted_public_key[BUFFER_SIZE];
                symm_encrypt(encrypted_public_key, keys->client_chatroom_public_key, crypto_box_PUBLICKEYBYTES, file_key);
                sprintf(filename, "client_keys/%s.public", login_name);
                write_file(filename, encrypted_public_key);
                printf("<[Saved public chatroom key in client_keys/%s.public]>\n", login_name);

              } else {

                // Load in chatroom public/private keys from saved files

                char filename[80];
                char *keybuf = (char *)malloc(sizeof(char) * BUFFER_SIZE);

                // Compute the symm key used to encrypt the files from username and password
                unsigned char file_key[crypto_secretbox_KEYBYTES];
                username_password_to_symm_key(file_key, login_name, password);

                sprintf(filename, "client_keys/%s.secret", login_name);
                read_file(filename, keybuf);
                symm_decrypt(keys->client_chatroom_secret_key, keybuf, file_key);

                sprintf(filename, "client_keys/%s.public", login_name);
                read_file(filename, keybuf);
                symm_decrypt(keys->client_chatroom_public_key, keybuf, file_key);

                printf("<[Successfully loaded public/secret keys from client_keys/%s.public and client_keys/%s.secret]>", login_name, login_name);

                free(keybuf);
              }

              // Zero out password
              memset(password, 0, 80);
            }

            current_state = STATE_IDLE;
          } else if(!strcmp(*(tokens + i), STATE_PRE_AUTHENTICATION)) {
            current_state = STATE_PRE_AUTHENTICATION;
          } else if(!strcmp(*(tokens + i), STATE_IN_CHATROOM)) {
            current_state = STATE_IN_CHATROOM;

            if(*(tokens + i + 1)) {
              // Next token will be the encrypted chatroom's secret key

              unsigned char *b64decoded;
              b64decoded = b64decode(*(tokens + i + 1));
              unsigned char chatroom_key_ciphertext[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES];
              memcpy(chatroom_key_ciphertext, b64decoded, crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES);

              if(crypto_box_seal_open(keys->chatroom_secret_key, chatroom_key_ciphertext, crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES,
                                      keys->client_chatroom_public_key, keys->client_chatroom_secret_key) != 0) {
                printf("Error: unable to decrypt chatroom key from server\n");
              }

              free(b64decoded);
            }

            i++;

            current_state = STATE_IN_CHATROOM;

          } else if(!strcmp(*(tokens + i), STATE_ROOM_KEY_REQUEST)) {
            // Generate the key we'll be using first
            randombytes_buf(keys->chatroom_secret_key, crypto_secretbox_KEYBYTES);

            char encrypted_key_list_message[BUFFER_SIZE];
            strcat(encrypted_key_list_message, STATE_ROOM_KEY_GEN_RESPONSE);

            // The remainder of the message will be public keys
            i++;
            for(; *(tokens + i); i++) {

              // Encrypt the chatroom symmetric key with the client's public keys
              unsigned char *b64decoded;
              char *b64encoded;
              b64decoded = b64decode(*(tokens + i));
              unsigned char encrypted_key[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES];
              crypto_box_seal(encrypted_key, keys->client_server_symm_key, crypto_secretbox_KEYBYTES, b64decoded);
              b64encoded = b64encode_length(encrypted_key, crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES);

              strcat(encrypted_key_list_message, STATE_DELIMITER_STRING);
              strcat(encrypted_key_list_message, b64encoded);

              free(b64decoded);
              free(b64encoded);
              free(*(tokens + i));
            }

            char crypto_out_buff[BUFFER_SIZE];
            symm_encrypt(crypto_out_buff, encrypted_key_list_message, strlen(encrypted_key_list_message), keys->client_server_symm_key);
            write(connfd, crypto_out_buff, strlen(crypto_out_buff));

            break;

          } else {
            printf("%s", *(tokens + i));
          }
        }

        free(*(tokens + i));
      }
      sem_post(current_state_lock);
    }

    free(tokens);

    // NOTE: If a message is sent that does end in a newline, it will not print until a message with
    // a newline is sent.
    // This is because stdout is buffered so that it will not output content until it reaches a newline.
    // Hence, this problem is resolved by simply ensuring that everything printed ends in a newline
    // (which should occur through normal usage anyways)
    // Alternatively, use setbuf(stdout, NULL); to turn this behavior off.

    // Ease up on the CPU a bit and yield to higher priority processes
    sleep(0);
  }

  return NULL;
}

int main(int argc, char *argv[]) {

  connfd = socket(AF_INET, SOCK_STREAM, 0);
  if(connfd == -1) {
    printf("Error: Could not create socket.\n");
    exit(1);
  }

  if(argc < 2) {
    printf("Error: you must supply a host to connect to.\n");
    exit(1);
  }

  // Set address from client/map localhost to 127.0.0.1
  char *server_address = argv[1];
  if(!strcmp("localhost", server_address)) {
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  } else {
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  if(connect(connfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("Error: Connection failed.\n");
    exit(1);
  }

  // Perform crypto handshake with server
  keys = (keys_t *) malloc(sizeof(keys_t));

  int successful_handshake = 0;
  while(!successful_handshake) {
    successful_handshake = handshake_client(keys->client_server_symm_key, connfd);

    if(!successful_handshake) {
      printf("<[Handshake with \"%s\" failed, trying again...]>\n", argv[1]);
      sleep(2);
    } else {
      printf("<[Successfully connected to \"%s\"]>\n", argv[1]);
    }
  }

  // Create thread for waiting for and printing info from the server
  pthread_t tid;
  pthread_create(&tid, NULL, &receive_server_data, (void*)NULL);

  ////////////////////////////////////////////////////////////
  // Process input from user
  ////////////////////////////////////////////////////////////

  char buf[BUFFER_SIZE];
  char crypto_buf[BUFFER_SIZE];
  char token_buf[BUFFER_SIZE];

  current_state_lock = sem_open("/SecureChatroomClientCurrentStateLock", O_CREAT);
  current_state = STATE_PRE_AUTHENTICATION;

  while(1) {
    fgets(buf, BUFFER_SIZE, stdin);
    strip_newline(buf);

    // Pre-process input so we can do any crypto/additional stuff

    // Split string by state delimiters
    char** tokens;
    strcpy(token_buf, buf);
    tokens = str_split(token_buf, ' ');

    if(tokens) {
      sem_wait(current_state_lock);

      // Set login name and generate keys
      if(!strcmp(current_state, STATE_PRE_AUTHENTICATION) && !strcmp(*(tokens + 0), "\\NEW") &&
         *(tokens + 1) && *(tokens + 2)) {

        strcpy(login_name, *(tokens + 1));
        strcpy(password, *(tokens + 2));

        // Generate chatroom keys
        crypto_box_keypair(keys->client_chatroom_public_key, keys->client_chatroom_secret_key);

        // Append public key to \NEW message in b64
        char *b64encoded;
        b64encoded = b64encode_length(keys->client_chatroom_public_key, crypto_box_PUBLICKEYBYTES);
        buf[strlen(buf)] = ' ';
        strcat(buf, b64encoded);
        strcat(buf, "\n");
        free(b64encoded);

        new_account = 1;

      } else if(!strcmp(current_state, STATE_PRE_AUTHENTICATION) && !strcmp(*(tokens + 0), "\\LOGIN") &&
                *(tokens + 1) && *(tokens + 2)) {

        strcpy(login_name, *(tokens + 1));
        strcpy(password, *(tokens + 2));
        new_account = 0;

      } else if(!strcmp(current_state, STATE_IN_CHATROOM) && *(tokens + 0)[0] != '\\') {
        // Send an encrypted chatroom message
        char msg_buff[BUFFER_SIZE];
        sprintf(msg_buff, "[%s, %d] %s\n", login_name, chatroom_message_number++, buf);
        symm_encrypt(buf, msg_buff, strlen(msg_buff), keys->chatroom_secret_key);
      }
      sem_post(current_state_lock);
    }

    // Token cleanup
    int i;
    for(i = 0; *(tokens + i); i++) {
      free(*(tokens + i));
    }
    free(tokens);

    // Send to server with crypto wrapper
    crypto_buf[0] = '\0';
    symm_encrypt(crypto_buf, buf, strlen(buf), keys->client_server_symm_key);
    write(connfd, crypto_buf, strlen(crypto_buf));

    if(!strcmp(buf, "\\QUIT")) {
      goto DONE;
    }
  }

 DONE:
  pthread_cancel(tid);
  sem_close(current_state_lock);
  close(connfd);
  free(keys);

}
