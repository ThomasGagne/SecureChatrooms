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

#include "chat_server.h"
#include "protocol_constants.h"
#include "crypto_helper.h"
#include "database_helper.h"
#include "utilities.h"

// Connected clients
client_t *clients[MAX_CLIENTS];
// Open chatrooms
chatroom_t *chatrooms[MAX_CHATROOMS];

// CRYPTO ////////////////////////////////
unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
unsigned char server_secret_key[crypto_box_SECRETKEYBYTES];


// Adds the chatroom to the next free location
int add_chatroom(chatroom_t *chatroom) {
  int i;
  for(i = 0; i < MAX_CHATROOMS; i++) {
    if(!chatrooms[i]->chatroom_uid) {
      chatrooms[i] = chatroom;
      return 1;
    }
  }

  return 0;
}

// Send message to specified client
void send_client_message_no_wait(client_t *client, char *message) {
  char buff_out[BUFFER_SIZE];
  symm_encrypt(buff_out, message, strlen(message), client->client_server_symm_key);
  write(client->connfd, buff_out, strlen(buff_out));
}

void send_client_message(client_t *client, char *message) {
  send_client_message_no_wait(client, message);
  // Client seems to have a bug with dropping messages when sent too quickly, so this puts a bit of time in between them
  // It's a user application after all, this shouldn't be that noticeable.
  // The only time it'll be noticed is when sending multiple messages one after another,
  // and arguably we should have a bit of cooldown
  sleep(1);
}

// Send message to everybody in chatroom
void send_chatroom_message(chatroom_t *chatroom, char *message) {
  int i;
  for(i = 0; i < MAX_CHATROOM_USERS; i++) {
    if(chatroom->present_clients[i]) {
      send_client_message_no_wait(chatroom->present_clients[i], message);
    }
  }
}

// Disconnects the specified client from the specified chatroom
void remove_client_from_chatroom(client_t *client, chatroom_t *chatroom) {
  char buff_out[BUFFER_SIZE];
  sprintf(buff_out, ">> [%s] has left the room.\n", client->name);
  send_chatroom_message(chatroom, buff_out);

  // Mark client as non-present in room
  int i;
  for(i = 0; i < MAX_CHATROOM_USERS; i++) {
    if(chatroom->present_clients[i] == client) {
      chatroom->present_clients[i] = 0;
    }
  }
}

void *handle_client(void *arg){
  char buff_out[BUFFER_SIZE];
  char buff_in[BUFFER_SIZE];
  char crypto_in_buff[BUFFER_SIZE];
  int rlen;

  client_t *client = (client_t *)arg;

  // Perform crypto handshake
  int successful_handshake = 0;
  while(!successful_handshake) {
    successful_handshake = handshake_server(client->connfd, client->client_server_symm_key, server_public_key, server_secret_key);

    if(!successful_handshake) {
      printf("<[Handshake failed, trying again...]>\n");
      sleep(1);
    } else {
      printf("<[Successful handshake]>\n");
    }
  }

  ////////////////////////////////////////////////////////////
  // Ask the user for authentication/create a new account
  ////////////////////////////////////////////////////////////

  send_client_message(client, ">> Hello user! Please enter \\LOGIN [username] [password] if you have an account, or enter \\NEW [username] [password] for a new account\n");

  int authenticated = 0;

  while(!authenticated) {
    rlen = read(client->connfd, crypto_in_buff, sizeof(crypto_in_buff)-1);
    crypto_in_buff[rlen] = '\0';

    // Perform message decryption
    symm_decrypt(buff_in, crypto_in_buff, client->client_server_symm_key);
    strip_newline(buff_in);

    char *command;
    command = strtok(buff_in, " ");

    if(!strcmp(command, "\\LOGIN")) {
      char *username = strtok(NULL, " ");
      char *password = strtok(NULL, " ");

      if(username == NULL || password == NULL) {
        send_client_message(client, ">> Please only enter \\LOGIN [username] [password] or \\NEW [username] [password]\n");
      } else {

        // Handle login
        send_client_message(client, ">> Please wait a moment while we check your password\n");

        if(strlen(username) > MAX_USERNAME_LENGTH) {
          username[MAX_USERNAME_LENGTH + 1] = '\0';
        }
        if(strlen(password) > MAX_USERNAME_LENGTH) {
          password[MAX_USERNAME_LENGTH + 1] = '\0';
        }

        // Test credentials against DB
        if(test_login(username, password)) {
          strcpy(client->name, username);
          client->user_uid = client->uid;
          authenticated = 1;

          // Get public chatroom key from db
          if(!get_user_chatroom_public_key(username, client->b64_chatroom_public_key)) {
            printf("Error: Couldn't retrieve key from db\n");
          }

        } else {
          send_client_message(client, ">> Sorry, wrong username or password. Please try again.\n");
        }
      }

      // Clear password from RAM
      memset(password, 0, strlen(password));

    } else if(!strcmp(command, "\\NEW")) {
      char *username = strtok(NULL, " ");
      char *password = strtok(NULL, " ");
      char *public_key = strtok(NULL, " ");


      if(username == NULL || password == NULL) {
        send_client_message(client, ">> Please only enter \\LOGIN [username] [password] or \\NEW [username] [password]\n");
      } else if(public_key == NULL){
        send_client_message(client, ">> Something went wrong with creating your account, please try again.\n");
      } else {

        send_client_message(client, ">> Please wait a moment while we attempt to create your account\n");

        if(strlen(username) > MAX_USERNAME_LENGTH) {
          username[MAX_USERNAME_LENGTH + 1] = '\0';
        }
        if(strlen(password) > MAX_USERNAME_LENGTH) {
          password[MAX_USERNAME_LENGTH + 1] = '\0';
        }

        if(username_exists(username)) {
          send_client_message(client, ">> Sorry, but that username is already taken.\n");
        } else {

          // Create new account
          new_account(username, password, public_key);

          // Clear password from RAM
          memset(password, 0, strlen(password));

          strcpy(client->name, username);
          client->user_uid = client->uid;
          authenticated = 1;

          strcpy(client->b64_chatroom_public_key, public_key);

          send_client_message(client, ">> Account successfully created!\n");
        }
      }

    } else {
      send_client_message(client, ">> Please only enter \\LOGIN [username] [password] or \\NEW [username] [password]\n");
    }
  }

  printf("<[Client \"%s\" has logged in.]>\n", client->name);

  strcat(buff_out, STATE_IDLE);
  strcat(buff_out, STATE_DELIMITER_STRING);
  strcat(buff_out, "\n");
  send_client_message(client, buff_out);

  sprintf(buff_out, ">> You are now successfully logged in as \"%s\".\n>> Type \\HELP for a list of commands.\n", client->name);
  send_client_message(client, buff_out);

  ////////////////////////////////////////////////////////////
  // Loop receiving input from client
  ////////////////////////////////////////////////////////////

  // Current index in chatrooms of the current chatroom the client is in
  // -1 for if the client is not in a chatroom at the time
  client->current_chatroom = -1;

  // Receive input from client
 next_input: while((rlen = read(client->connfd, crypto_in_buff, sizeof(crypto_in_buff)-1)) > 0){
    crypto_in_buff[rlen] = '\0';
    buff_out[0] = '\0';

    // Perform decryption
    symm_decrypt(buff_in, crypto_in_buff, client->client_server_symm_key);
    strip_newline(buff_in);

    // Ignore empty buffer
    if(!strlen(buff_in)){
      continue;
    }

    // Special options
    if(buff_in[0] == '\\'){
      char *command, *param;
      command = strtok(buff_in," ");

      if(!strcmp(command, "\\QUIT")){
        // Have user quit and exit
        // User probably won't get to read this, but that's ok
        //send_client_message(client, ">> Thank you for using our service!\n");
        if(client->current_chatroom != -1) {
          remove_client_from_chatroom(client, chatrooms[client->current_chatroom]);
        }

        printf("<[Client \"%s\" has disconnected]>\n", client->name);

        goto DONE;

      } else if(!strcmp(command, "\\LEAVE")) {

        // Have user leave the current room
        if(client->current_chatroom != -1) {
          printf("<[Client \"%s\" has left chatroom \"%s\"]>\n", client->name, chatrooms[client->current_chatroom]->name);

          remove_client_from_chatroom(client, chatrooms[client->current_chatroom]);
          client->current_chatroom = -1;

          strcat(buff_out, STATE_IDLE);
          strcat(buff_out, STATE_DELIMITER_STRING);
          strcat(buff_out, "\n");
          send_client_message(client, buff_out);

        } else {
          sprintf(buff_out, ">> You're not currently in a chatroom.\n");
          send_client_message(client, buff_out);
        }

      } else if(!strcmp(command, "\\JOIN")) {
        // Have user join an open chatroom
        param = strtok(NULL, " ");

        if(param){

          int found_room = 0;

          int i;
          for(i = 0; i < MAX_CHATROOMS; i++) {

            // Find the chatroom the user is looking for by name
            if(chatrooms[i] && !strcmp(chatrooms[i]->name, param)) {
              found_room = 1;

              // Check that user is authorized to enter this chatroom
              int j, authorized = 0;
              for(j = 0; j < MAX_CHATROOM_USERS; j++) {
                if(!strcmp(chatrooms[i]->allowed_usernames[j], client->name)) {
                  authorized = 1;
                  break;
                }
              }

              // Add user to chatroom if authorized
              if(authorized) {

                client->current_chatroom = i;
                chatrooms[i]->present_clients[j] = client;

                // Send the client their encrypted chatroom key
                sprintf(buff_out, STATE_IN_CHATROOM);
                strcat(buff_out, STATE_DELIMITER_STRING);
                strcat(buff_out, chatrooms[i]->encrypted_room_keys[j]);
                send_client_message(client, buff_out);

                send_client_message(client, ">> You've successfully joined the chatroom.\n");

                sprintf(buff_out, ">> [%s] has joined the room.\n", client->name);
                send_chatroom_message(chatrooms[i], buff_out);

                printf("<[Client \"%s\" has joined chatroom \"%s\"]>\n", client->name, chatrooms[client->current_chatroom]->name);

              } else {
                send_client_message(client, ">> Sorry, you aren't authorized to enter that chatroom.\n");
              }

              // Leave find-the-chatroom loop
              break;
            }
          }

          if(!found_room) {
            send_client_message(client, ">> Sorry, but that room doesn't exist!\n");
          }

        } else {
          send_client_message(client, ">> Error: You must specify the name of a chatroom to join!\n");
        }

      } else if(!strcmp(command, "\\CREATE")) {
        // Have user create a new chatroom

        if(chatroom_count++ < MAX_CHATROOMS) {

          // Only allow one chatroom to be created at a time
          sem_wait(chatroom_array_lock);

          param = strtok(NULL, " ");

          if(param) {
            // Check that the name doesn't already exist
            int name_taken = 0;
            int i;
            for(i = 0; i < MAX_CHATROOMS; i++) {
              if(chatrooms[i] && !strcmp(chatrooms[i]->name, param)) {
                name_taken = 1;
                break;
              }
            }

            if(!name_taken) {
              chatroom_t *new_room = (chatroom_t *)malloc(sizeof(chatroom_t));
              new_room->chatroom_uid = cr_uid++;
              param[MAX_USERNAME_LENGTH + 1] = '\0';
              strcpy(new_room->name, param);

              // Assume the user includes themselves in the room
              strcpy(new_room->allowed_usernames[0], client->name);

              // We'll be needing to get a list of the encrypted room keys from the client,
              // so start collecting the public keys of the members to send to the creator
              char public_key_list[BUFFER_SIZE];
              strcat(public_key_list, STATE_ROOM_KEY_REQUEST);
              strcat(public_key_list, STATE_DELIMITER_STRING);
              strcat(public_key_list, client->b64_chatroom_public_key);

              // Read in all the listed usernames
              int allowed_name_count = 0;
              char *next_name;
              while(next_name = strtok(NULL, " "), next_name != NULL) {
                if(allowed_name_count++ < MAX_CHATROOM_USERS) {

                  // Don't allow a room to be created if it has an invalid name
                  if(!username_exists(next_name)) {
                    sprintf(buff_out, ">> ERROR: username \"%s\" does not exist.\n", next_name);
                    send_client_message(client, buff_out);
                    goto next_input;

                  } else {
                    strcpy(new_room->allowed_usernames[allowed_name_count], next_name);

                    char public_key[64];
                    get_user_chatroom_public_key(next_name, public_key);
                    strcat(public_key_list, STATE_DELIMITER_STRING);
                    strcat(public_key_list, public_key);
                  }

                } else {
                  send_client_message(client, ">> Error: You've tried to add more than 256 authorized users.\n");
                  goto next_input;
                }
              }

              // Get the list of encrypted room keys from the client
              strcat(public_key_list, "\n");
              send_client_message(client, public_key_list);

            GET_ROOM_KEYS:
              rlen = read(client->connfd, crypto_in_buff, sizeof(crypto_in_buff)-1);
              crypto_in_buff[rlen] = '\0';

              // Perform message decryption
              symm_decrypt(buff_in, crypto_in_buff, client->client_server_symm_key);

              // Ignore empty buffer
              if(!strlen(buff_in)){
                goto GET_ROOM_KEYS;
              }

              // Split list of encrypted room keys by state delimiters
              char** tokens;
              tokens = str_split(buff_in, STATE_DELIMITER);

              if(tokens) {
                int k;
                // First is assumed to be STATE_RESPONSE
                for(k = 1; *(tokens + k); k++) {
                  strcpy(new_room->encrypted_room_keys[k-1], *(tokens + k));

                  free(*(tokens + k));
                }
              }

              free(tokens);


              // Done getting list of encrypted room keys from the client

              new_room->num_allowed_usernames = allowed_name_count;

              // Add chatroom to array
              for(i = 0; i < MAX_CHATROOMS; i++) {
                if(!chatrooms[i] || chatrooms[i]->name[0] == '\0') {
                  chatrooms[i] = new_room;
                  break;
                }
              }

              printf("<[Client \"%s\" has created chatroom \"%s\"]>\n", client->name, new_room->name);

            } else {
              send_client_message(client, ">> Sorry, but that chatroom name is already taken.\n");
              continue;
            }

          } else {
            send_client_message(client, ">> Error: You have not supplied a room name!\n");
          }

          send_client_message(client, ">> Your chatroom has been successfully created!\n");
          send_client_message(client, ">> Type \\JOIN [room-name] to join the chatroom.\n");

          sem_post(chatroom_array_lock);

        } else {
          send_client_message(client, ">> Error: Maximum number of chatrooms has already been reached.\n");
        }

      } else if(!strcmp(command, "\\CLOSE")) {

        // Close the chatroom the user is currently in
        // Any user authorized to join a room can close the room

        if(client->current_chatroom != -1) {
          int current_chatroom_copy = client->current_chatroom;

          // For all clients in present_clients, set their current_chatroom to -1
          client_t *temp_client;
          int i;
          for(i = 0; i < MAX_CHATROOM_USERS; i++) {
            temp_client = chatrooms[current_chatroom_copy]->present_clients[i];

            if(temp_client) {
              sprintf(buff_out, STATE_IDLE);
              strcat(buff_out, STATE_DELIMITER_STRING);
              char temp_buff[80];
              sprintf(temp_buff, ">> [%s] has closed the chatroom.\n", client->name);
              strcat(buff_out, temp_buff);

              send_client_message(temp_client, buff_out);

              temp_client->current_chatroom = -1;
            }
          }

          // "Delete" the room
          // We need to zero out the chatroom_t since we can technically still access it
          // and it'll still have the same name, so it's as if it still existed
          memset(chatrooms[current_chatroom_copy], 0, sizeof(chatroom_t));
          free(chatrooms[current_chatroom_copy]);

        } else {
          send_client_message(client, ">> You are not currently in a chatroom to close.\n");
        }

      } else if(!strcmp(command, "\\AVAILABLE")) {

        // List any rooms the user is authorized to join

        int at_least_one_available = 0;

        // Enumerate all rooms and test if user is authorized to join
        int i, j;
        for(i = 0; i < MAX_CHATROOMS; i++) {
          if(chatrooms[i] && strlen(chatrooms[i]->name) > 0) {
            for(j = 0; j < MAX_CHATROOM_USERS; j++) {
              if(!strcmp(chatrooms[i]->allowed_usernames[j], client->name)) {
                at_least_one_available = 1;

                char temp_buff[256];
                sprintf(temp_buff, ">> Room \"%s\" is currently available for you to join\n", chatrooms[i]->name);
                strcat(buff_out, temp_buff);
                break;
              }
            }
          }
        }

        send_client_message(client, buff_out);

        if(!at_least_one_available) {
          send_client_message(client, ">> No rooms are currently available for you to join\n");
        }

      } else if(!strcmp(command, "\\HELP")) {
        // Print help info to user
        sprintf(buff_out, ">> You can type:\n");
        strcat(buff_out, ">> \\HELP for help and options\n");
        strcat(buff_out, ">> \\CREATE [name] [ID1] [ID2] ... to create a chatroom with the given name which the given user IDs can join the room. It is not necessary to include your own ID\n");
        strcat(buff_out, ">> \\AVAILABLE to list any open chatrooms you can join\n");
        strcat(buff_out, ">> \\JOIN [name] to join the chatroom with the given name\n");
        strcat(buff_out, ">> \\LEAVE to leave the current chatroom you are in\n");
        strcat(buff_out, ">> \\CLOSE to close the current chatroom you are in\n");
        strcat(buff_out, ">> \\QUIT to terminate the program\n");
        send_client_message(client, buff_out);

      } else {
        sprintf(buff_out, "Sorry, but \"%s\" is not a valid command. Perhaps you should try \\HELP\n", command);
        send_client_message(client, buff_out);
      }

    } else {
      // If client is in a chatroom, send the message to everybody in the chatroom
      if(client->current_chatroom != -1) {

        // Check if another user has closed the room
        if(chatrooms[client->current_chatroom]) {

          strcpy(buff_out, buff_in);

          int i;
          for(i = 0; i < MAX_CHATROOM_USERS; i++) {
            if(chatrooms[client->current_chatroom]->present_clients[i] && chatrooms[client->current_chatroom]->present_clients[i]->user_uid != client->user_uid) {
              send_client_message(chatrooms[client->current_chatroom]->present_clients[i], buff_out);
            }
          }
        }
      } else {
        send_client_message(client, "Sorry, but that isn't a valid command. Perhaps you should try \\HELP\n");
      }
    }

    // Ease up on the CPU a bit and yield to higher priority processes
    sleep(0);
  }

 DONE:

  close(client->connfd);
  free(client);
  client_count--;
  pthread_detach(pthread_self());

  return NULL;
}

int main(int argc, char *argv[]) {

  // Generate public/secret keys
  crypto_box_keypair(server_public_key, server_secret_key);

  // listenfd is socket to listen on,
  // connfd is for connecting to new clients
  int listenfd = 0, connfd = 0;
  struct sockaddr_in serv_addr;
  struct sockaddr_in cli_addr;

  // threads for handling new client connections
  pthread_t tid;

  // Mutex lock for access to chatroom array
  chatroom_array_lock = sem_open("/SecureChatroomServerChatroomArrayLock", O_CREAT);

  // Socket settings
  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(PORT);

  // Bind socket
  if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
    perror("<[Socket binding failed]>");
    return 1;
  }

  // Open listening socket
  if(listen(listenfd, 10) < 0){
    perror("<[Socket listening failed]>");
    return 1;
  }

  printf("<[SERVER STARTED]>\n");

  // Loop for accepting clients and passing off clients to handler thread
  while(1){
    socklen_t clilen = sizeof(cli_addr);
    connfd = accept(listenfd, (struct sockaddr*)&cli_addr, &clilen);

    // Check if max clients is reached
    if((client_count + 1) == MAX_CLIENTS){
      printf("<[MAX CLIENTS REACHED]>\n");
      printf("<[REJECT ");

      printf("%d.%d.%d.%d",
             cli_addr.sin_addr.s_addr & 0xFF,
             (cli_addr.sin_addr.s_addr & 0xFF00)>>8,
             (cli_addr.sin_addr.s_addr & 0xFF0000)>>16,
             (cli_addr.sin_addr.s_addr & 0xFF000000)>>24);

      printf("]>\n");
      close(connfd);
      continue;
    }

    // Client settings
    client_t *cli = (client_t *)malloc(sizeof(client_t));
    cli->addr = cli_addr;
    cli->connfd = connfd;
    cli->uid = uid++;

    client_count++;

    // Create new thread to handle client
    pthread_create(&tid, NULL, &handle_client, (void*)cli);

    // Reduce CPU usage
    sleep(1);
  }
}
