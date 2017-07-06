#ifndef CHAT_SERVER_H_
#define CHAT_SERVER_H_

#include <semaphore.h>

// GLOBALS DEFINITIONS

// Max connections possible
#define MAX_CLIENTS 256
// Max number chatrooms which can be open at any time
#define MAX_CHATROOMS 256
// Max number users who can be allowed to join a chatroom
#define MAX_CHATROOM_USERS 32
// IO Buffer size
#define BUFFER_SIZE 2048
// Max length of a username
#define MAX_USERNAME_LENGTH 64

// GLOBAL VARIABLES

// Current number clients connected
static unsigned int client_count = 0;
// Current number chatrooms opened
static unsigned int chatroom_count = 0;
// Client id counter, for giving a session id to each client
static int uid = 10;
// Chatroom counter, for giving a session id to each chatroom
static int cr_uid = 10;

// GLOBAL SEMAPHORES

// A mutex lock for the array of open chatrooms
sem_t *chatroom_array_lock;

// STRUCTS

// TODO: Add public keys to client struct so that we don't have to do a DB call whenever they're queried

// Client struct
typedef struct {
  // Client remote address
  struct sockaddr_in addr;
  // Connection file descriptor
  int connfd;
  // Client unique id for this connection
  int uid;
  // User unique id, corresponding to their user ID in the database
  int user_uid;
  // Client's screen name
  char name[MAX_USERNAME_LENGTH];
  // Index in chatrooms of the chatroom the user is in
  // -1 for if the user is not in a chatroom
  int current_chatroom;
  // Symmetric key used for communicating with client
  unsigned char client_server_symm_key[crypto_secretbox_KEYBYTES];
  // Client's chatroom public key
  char b64_chatroom_public_key[64];
} client_t;

// Chatroom struct
typedef struct {
  // Unique id for this session
  int chatroom_uid;
  // List of usernames of allowed clients
  char allowed_usernames[MAX_CHATROOM_USERS][MAX_USERNAME_LENGTH];
  // Number of allowed clients
  int num_allowed_usernames;

  // List of connected clients
  // present_clients[i] being non-null indicates that allowed_user_uids[i] is in this room
  client_t *present_clients[MAX_CHATROOM_USERS];

  // A list of the chatroom key encrypted for each client
  char encrypted_room_keys[MAX_CHATROOM_USERS][256];

  // Unique name of the chatroom for users to search and connect to
  char name[MAX_USERNAME_LENGTH];
} chatroom_t;

#endif
