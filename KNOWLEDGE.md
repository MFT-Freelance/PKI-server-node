# BASIC NOTIONS
On internet every communication go through a number of servers and routers. At any point during the transport of the message (an HTTP request, an email or anything) between you and your target, anyone can intercept, listen or modify your communication.
The only way to ensure privacy in the wild is through encryption. You encrypt your message, with "Keys", so that your target is the only one able to decrypt and read it.
Once you know that your message is not interceptable, the other problem is to identify who you are talking to. That is achieved through the "Signature" of your keys by an authority.

## Encryption
There are 2 types of keys used for encrytion, symmetric and asymmetric.

### Symmetric key
With symmetric keys encryption, the same key is used to encrypt and decrypt the message. Think of it as a shared password between you and your target. The encryption/decryption is an order of magnitude faster with symmetric keys than with asymmetric keys but it implies that more than one entity (you and every one you want to talk to in our case) are responsible for keeping the key actually secret, which is obviously a big security flaw.

### Asymmetric key
Asymmetric keys are composed of 2 parts, a secret key (SK) and a public key (PK). As the name implies a SK is secret and is never shared with anyone, that responsibility is only on the owner of the SK, while a PK is public and shared with everyone.
The PK is used to encrypt the message and then it can only be decrypted by the SK. The method to talk to someone is easy, get its PK, encrypt your message and send it to them. The owner of the SK is the only one able to decrypt it. When they want to reply to you they get your PK, encrypt their message and send it to you and you are, then, the only one able to decrypt their message with your SK.
As noted above the encryption by asymmetric keys is an order of magnitude slower than with symmetric key but is a fundamental piece of internet privacy and security.

### Message integrity
In both cases (symmetric or asymmetric keys) if it is tampered with, the message is unreadable. It ensures, quite crudely, the integrity of your communications.

## Identification
Once you know that your message can't be read or tampered with by others, you need to be sure that the person you are talking to is really who you think they are. This is achieved through the signature of the public key by a certificate authority.

### Certificate authority and signature
On a technical level a certificate authority (CA) is just a hierarchy of SK used to sign others PK.
When you request the signature of your PK by an authority you add identity information like your address and name, or web domain for websites, it then creates a signed certificate with an expiration date. The signature can then be verified by the CA PK to ensure the integrity of the PK you receive from someone, hence its identity and for websites, it ensures that the certificate for a domain comes from that domain.
Basic security mandates that the authority PK used to verify the PK coming from the wild not come from the wild, it should be a Trusted Third Party.

### Real life application
In real life, CAs are companies that check the veracity of the informations you put in your certificates. 
If you request the signature of a PK for a domain name, they check that you own that domain. If you claim to be a company or that you live in a particular country, they verify that you do. And if it's true they sign your PK.
Those are well known companies like VeriSign, GeoTrust or StartSSL and their PKs are included in browsers or OS during installation because of the trust they built with manufacturers over time (they are the Trusted Third Party).
The downside of that scheme is that their service is not free, since the verification takes time and money.

## TLS/SSL
Transport Security Layer is the child of Socket Security Layer and is the standard for internet security. Its most well known application is Secured HTTP (HTTPS). It implements all the principles we discussed before.

### Server and Mutual auth
We talk about server auth if the server is the only one offering its certificate and mutual auth if the server request the client to present their certificate as well.
For public servers, like public websites, server auth is enough most of the time since the only party in the relationship which has to be identified is the website and client identification/authorization can be achieved by other (and more user friendly) means. Mutual auth is used mostly for Machine to Machine relationships.

### TLS handshake and communication
This is a pretty high level summarization of a TLS handshake (server auth):
- The client request the server PK
- The server sends its PK to the client
- The client verify the identity of the PK against its list of trusted CAs
- The client sends a "Hello client" and a computed secret (pre-master key) to the server encrypted with its PK
- The server decrypt this first message with its SK, keep the pre-master key and sends back an acknowledgment
- Both client and server compute the same secret from the pre-master key: the shared secret
- From now on, and for the duration of the connection, both server and client use the shared secret, a symmetric key, to encrypt and decrypt their communications

In the case of mutual auth, the client sends its PK too and the server verify it against its list of trusted CAs