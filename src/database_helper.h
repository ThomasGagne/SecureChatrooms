#ifndef DB_HELPER_H_
#define DB_HELPER_H_

#define DBFILE "db/accounts.db"

int test_login(char *username, char *password);
int username_exists(char *username);
int get_user_chatroom_public_key(char *username, char key[]);
int new_account(char *account, char *password, char *public_chatroom_key);

#endif
