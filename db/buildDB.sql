.mode columns
.headers on
.nullvalue NULL
PRAGMA foreign_keys = ON;

drop table if exists Account;

create table Account (
  username TEXT PRIMARY KEY,
  passwordHash TEXT NOT NULL,
  publicChatroomKey TEXT NOT NULL
);
