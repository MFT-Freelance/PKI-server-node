# PKI-server-node
A Public Key Infrastructure management server in Node JS

Note: Basic notions of security are available [here](/KNOWLEDGE.md).

## Features
- Add certificate authorities, root and intermediate
- Create / remove users
- Create private key / certificate pair signed by your CA
- Get certificates list signed by the CAs
- Revoke a certificate or all certificates related to a domain

## Coming next
- Import an existing CA hierarchy

## Getting started
Note: You can make this project work on a Windows environment by using Cygwin to start the project. You will still have to have openssl installed though.
### Execute npm install
### Modify config/creation.yml and config/server.yaml to fit your requirements
Note: The pkidir path should be set with UNIX style separators ("/") whatever your environment.
### Start server with "node server.js"
Note: You can have debug logs by setting environment variable "DEBUG=pki:*".
Note: You can log openssl output by setting environment variable "VERBOSE_SSL=true".
### Once your servers are started, the structure is created. Get the key and certificate for your admin user in [PKIDIR]/users/[username in config]
Note: The first user is your admin user, necessary to connect to the secured server with mutual authentication and create additional users among other things.
### Start creating users, additional Certificat Authorities or Self Signed Certificates using the API.
Note: The description of the API is in [API.md](/API.md).




## Acknowledgement:
This project is based on the work by [Adito Software](https://github.com/aditosoftware) there: [NodePKI](https://github.com/aditosoftware/nodepki) which gave me a very good starting point for my specific requirements.
