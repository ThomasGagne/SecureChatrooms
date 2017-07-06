#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

#include "database_helper.h"

sqlite3 *db;

// Returns 0 if name doesn't exist or bad password, 1 if name and password match
int test_login(char *username, char *password) {
  sqlite3 *db;
  sqlite3_open(DBFILE, &db);

  char *zSql = "select passwordHash from Account where username = ?;";
  sqlite3_stmt *ppStmt;
  sqlite3_prepare_v2(db, zSql, strlen(zSql), &ppStmt, NULL);
  // This binding sanitizes inputs
  sqlite3_bind_text(ppStmt, 1, username, strlen(username), SQLITE_STATIC);

  int step_result = sqlite3_step(ppStmt);
  int result = 0;

  if(step_result == SQLITE_ROW) {
    if(crypto_pwhash_str_verify((char *) sqlite3_column_text(ppStmt, 0), password, strlen(password)) != 0) {
      result = 0;
    } else {
      result = 1;
    }
  } else if(step_result != SQLITE_DONE){
    printf("Something's probably gone wrong.\n");
  }

  sqlite3_finalize(ppStmt);
  sqlite3_close(db);

  return result;
}

// Returns 1 if the given username exists, 0 otherwise
int username_exists(char *username) {
  sqlite3 *db;
  sqlite3_open(DBFILE, &db);

  char *zSql = "select username from Account where username = ?;";
  sqlite3_stmt *ppStmt;
  sqlite3_prepare_v2(db, zSql, strlen(zSql), &ppStmt, NULL);
  sqlite3_bind_text(ppStmt, 1, username, strlen(username), SQLITE_STATIC);

  int step_result = sqlite3_step(ppStmt);
  int result = 0;

  if(step_result == SQLITE_ROW) {
    result = 1;
  } else if(step_result != SQLITE_DONE){
    printf("Something's probably gone wrong.\n");
  }

  sqlite3_finalize(ppStmt);
  sqlite3_close(db);

  return result;
}

// Places the given username's chatroom key into key
// Returns 0 if username does not exist
int get_user_chatroom_public_key(char *username, char key[]) {
  sqlite3 *db;
  sqlite3_open(DBFILE, &db);

  char *zSql = "select publicChatroomKey from Account where username = ?;";
  sqlite3_stmt *ppStmt;
  sqlite3_prepare_v2(db, zSql, strlen(zSql), &ppStmt, NULL);
  sqlite3_bind_text(ppStmt, 1, username, strlen(username), SQLITE_STATIC);

  int step_result = sqlite3_step(ppStmt);
  int result = 0;

  if(step_result == SQLITE_ROW) {
    strcpy(key, (char *)sqlite3_column_text(ppStmt, 0));
    result = 1;
  }

  sqlite3_finalize(ppStmt);
  sqlite3_close(db);

  return result;
}

// Creates a new account in the database
// Returns 1 if the creation was successfull, 0 if unsuccessfull
// Does not check if the given username already exists
int new_account(char *username, char *password, char *public_chatroom_key) {
  sqlite3 *db;
  sqlite3_open(DBFILE, &db);

  char *zSql = "insert into Account values (?, ?, ?);";
  sqlite3_stmt *ppStmt;
  sqlite3_prepare_v2(db, zSql, strlen(zSql), &ppStmt, NULL);
  sqlite3_bind_text(ppStmt, 1, username, strlen(username), SQLITE_STATIC);

  // Perform password hashing
  char hashed_password[crypto_pwhash_STRBYTES];
  if(crypto_pwhash_str(hashed_password, password, strlen(password),
                       crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    printf("ERROR: out of memory hashing password!\n");
  }

  sqlite3_bind_text(ppStmt, 2, hashed_password, crypto_pwhash_STRBYTES, SQLITE_STATIC);
  sqlite3_bind_text(ppStmt, 3, public_chatroom_key, strlen(public_chatroom_key), SQLITE_STATIC);

  int step_result = sqlite3_step(ppStmt);
  int result = 0;

  if(step_result == SQLITE_DONE) {
    result = 1;
  } else {
    printf("Something's probably gone wrong.\n");
  }

  sqlite3_finalize(ppStmt);
  sqlite3_close(db);

  return result;
}
