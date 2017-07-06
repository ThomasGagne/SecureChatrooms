Thomas Gagne
Group 8
AIT, Applied Cryptography, Levente Buttyan & Istvan Lam
November 27, 2016

------------------------------------------------------------

BUILD INSTRUCTIONS:
This code can be built using the standard make and gcc tools (i.e. just run `make`).
This code does include a compiled libb64 library for base64 encoding, so if errors arise during
compilation due to this please build the library found at http://libb64.sourceforge.net/
and copy the compiled src/libb64.a library file and move it to the lib/ folder in this project.

This project requires a dependency on libsodium and sqlite3 being installed.

This project was developed on OSX 10.10.4 Yosemite.
I am uncertain of the portability of this code to other operating systems/architectures.
I was able to compile it on Debian after replacing the lib/libb64.a library.
However, I was unable to get the program to run correctly due to either messages not being
passed along the network properly, problems with conversion between signed/unsigned chars, or an
issue with the compiled libb64.a library.
Bottom line is that you might be able to get it to work on different operating systems with
enough tinkering, but it should work reliably on at least OSX 10.10.4.

------------------------------------------------------------

USAGE INSTRUCTIONS:
To start a chat server users can connect to, simply run `./chat_server`
To use the client to connect to a server, run `./chat_client [Server-IP-address]`
The various help messages should be enough to indicate the usage of the program from there.

------------------------------------------------------------

OVERVIEW OF PROTOCOL:
In this project I originally planned on using OpenSSL for encrypting the communications between
client and server.
However, in implementation I quickly learned of the difficulties involved with creating and
managing SSL certificates for the server.
Consequently, I took a different approach for encrypting client-server communications:

First, it is assumed that the client has knowledge of the server's public key, which in real life
would be provided through a separate certificate authority signing the server's public key.
The client begins by computing a secret key K, encrypting it with the server's public key, and
sending it to the server.
The server decrypts the key, then encrypts K with itself to arrive at E_K(K), which it sends to
the client.
The client then decrypts E_K(K) and verifies that the decrypted result equals the original key they
computed.
Once verified, the client indicates to the server that they both have the correct key, and the
client and server then use K as a symmetric key for communications.

This exchange works because attacks focused on modifying messages or posing as a different party
would require knowledge of either the server's private key, or knowledge of the key the client
computed.

As for the protocol used for managing chatroom keys between clients, despite how I described my
planned protocol in the project proposal, I unfortunately was forced to go in a different
direction in the final project.
This was because in my original protocol, I planned to have chatroom key exchanges between clients
done by using the elliptic curve Diffie-Hellman protocol extended to support multiple parties.
This required having access to a multiplication operation over the elliptic curve finite field used
in order to appropriately extend the protocol to multiple parties.
However, despite libsodium providing three separate implementations of this operation, I was unable
to get any implementation to respect commutativity, which was necessary and integral to this
protocol extension.
As a result, I was forced to abandon this protocol and choose a different means for exchanging keys
between chatroom participants:

The protocol for creating a chatroom involves the client first sending a list of every user they
want to include in the chatroom to the server.
The server then sends back a list of the public keys of each user the client requested.
The client computes a secret chatroom key for symmetric communications, and uses each public key
to encrypt this key, then sends the result back to the server.
The server stores these encrypted keys and when a client attempts to join the chatroom, they will
be sent the chatroom key encrypted with their own public key, and can hence decrypt the key and use
it as a symmetric key for chatroom communications.

Note that the encrypted communications between the client and server ensure that the messages
in the chatroom creation protocol cannot be tampered with by an attacker.
While the server could undermine this exchange in various ways (for example, compute its own
secret key, use the public keys to encrypt it, and then send these to connecting clients instead of
using the secret key the chatroom creator computed), it is impossible to prevent these
possibilities since the server must act as a certificate authority for client's public keys and
hence at any point could simply replace a client's requested public key with its own.
Hence, the effectiveness of this protocol is dependent upon being able to trust that the server
will not attempt to intentionally compromise communications.
While this problem could be solved by having a separate certificate authority signing each user's
public keys, the original problem of the server replacing the secret key still persists.
I do want to point out, however, that in my original protocol this attack was not possible since
it was a key agreement protocol and that this vulnerability only arose due to me being forced to
settle for a less effective protocol since libsodium did not provide the functionality I required.

Additionally, please note that the above protocol descriptions are high-level and do not touch
upon the addition of integrity and replay protection mechanisms.
Despite not covering them in this text file though, these have been implemented in the project as
necessary and as I originally described in my project proposal.

------------------------------------------------------------

ADDITIONAL NOTES:
Obviously, I didn't use the chatroom server/client programs provided and instead opted to write
my own in C.
I've never done network programming in C though and of the network programming that I have done,
I've never written a server or client as complex as this.
When combined with the addition of crypto to the project, I unfortunately did not have much time
to make the server or client as robust or bug-free as I would have liked.
Consequently, there are times when the server or client might crash without warning or when
strange behavior might arise due to the client and server becoming desynced in an exchange.
While the program will typically work perfectly when the program is used in the intended way and
is not abused, if problems do arise during usage please be mindful of this.
In short, if errors do arise, it is likely not the fault of the implementation of the crypto but
instead is the fault of my inability to program a robust client and server in the time given.
