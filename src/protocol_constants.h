#ifndef PROTOCOL_CONSTANTS_
#define PROTOCOL_CONSTANTS_

#define PORT 5000

// Application client states

// Client has not logged in yet; set to this upon app startup
#define STATE_PRE_AUTHENTICATION "STATE_PRE_AUTHENTICATION"
// Client has logged in but is not in a room
#define STATE_IDLE "STATE_IDLE"
// Client is currently part of a chatroom
#define STATE_IN_CHATROOM "STATE_IN_CHATROOM"

// Client is being asked to compute the encrypted room keys for the members upon room creation
#define STATE_ROOM_KEY_REQUEST "STATE_ROOM_KEY_REQUEST"
// Client's response with the computed encrypted room keys
#define STATE_ROOM_KEY_GEN_RESPONSE "STATE_ROOM_KEY_GEN_RESPONSE"

#define STATE_DELIMITER '|'
#define STATE_DELIMITER_STRING "|"

// Whether or not the client-server handshake was successful
#define HANDSHAKE_SUCCESSFUL "HANDSHAKE_SUCCESSFUL"
#define HANDSHAKE_FAILED "HANDSHAKE_FAILED"

#endif
