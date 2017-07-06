CC=gcc
DEPS=crypto_helper.h chat_server.h chat_client.h database_helper.h protocol_constants.h utilities.h
CFLAGS=-Wall -w -I include
COMPSERVER=chat_server
COMPCLIENT=chat_client
SERVEROBJ=src/chat_server.o
CLIENTOBJ=src/chat_client.o
DBHOBJ=src/database_helper.o
CHOBJ=src/crypto_helper.o
UTILOBJ=src/utilities.o


%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o src/$@ $< -lpthread -lsodium

all: $(UTILOBJ) $(CHOBJ) $(SERVEROBJ) $(CLIENTOBJ) $(DBHOBJ)
	$(CC) $(CFLAGS) -o $(COMPSERVER) $(SERVEROBJ) $(DBHOBJ) $(CHOBJ) $(UTILOBJ) -lpthread -lsodium -lsqlite3 -I include -Llib/ -lb64
	$(CC) $(CFLAGS) -o $(COMPCLIENT) $(CLIENTOBJ) $(CHOBJ) $(UTILOBJ) -lpthread -lsodium -I include -Llib/ -lb64
	sh db/initializeDB.sh
	rm -f handshake_temp/*.txt
	rm -rf client_keys
	mkdir -p client_keys

.PHONY: clean

clean:
	rm -f src/*.o $(COMPSERVER) $(COMPCLIENT)
	rm -rf client_keys
	rm db/accounts.db
