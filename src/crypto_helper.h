#ifndef CRYPTO_HELPER_H_
#define CRYPTO_HELPER_H_

#define SUCCESSFUL_KEY_EXCHANGE "SUCCESS_KEY_EXCHANGE"
#define BAD_KEY_EXCHANGE "FAILURE_KEY_EXCHANGE"

// The number of bytes used to indicate the length of an encrypted message
#define MSG_LEN_SIZE 8

int handshake_server(int connfd, unsigned char client_server_symm_key[], unsigned char *server_public_key, unsigned char *server_secret_key);
int handshake_client(unsigned char server_public_key[], int connfd);

int symm_encrypt(char *result, char *message, int message_length, unsigned char symm_key[]);
int symm_decrypt(char *result, char *message, unsigned char symm_key[]);

void username_password_to_symm_key(unsigned char result[], char *username, char *password);

char* b64encode_length(const char* input, int length);
char* b64decode_length(const char* input, int length);
char* b64encode(const char* input);
char* b64decode(const char* input);

#endif
