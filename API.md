# API

API response bodies:

    {
        success: <bool>,
        <more attributes>
    }

    Set VERBOSE_SSL=true as environment variable to log openssl output
    Set DEBUG=pki:* to see debug logs

## Public HTTPS server

### Get authorities list (Public)

    GET /authorities/

### Download CA public key (Public)

    GET /:cafilepath

### Request CA public key (Public)

    GET /ca/:caroot/:caname/

    Request params:
    * :caroot <String> | Name of the root CA to fetch ("base")
    * :caname <String> | Name of the certificate to fetch ("root", "intermediate", "intermediate-server", etc)

    Response:
    * cert: <String> | certificate


### Request CA chain public key (Public)

    GET /ca/:caroot/:caname/chain/

    Request params:
    * :caroot <String> | Name of the root CA to fetch ("base")
    * :caname <String> | Name of the certificate to fetch ("root", "intermediate", "intermediate-server", etc)

    Response:
    * cert: <String> | chained certificate

### Get infos from a certificate (Public)

    PUT /certificate/info/

    Request params:
    * cert <String> | required | certificate to validate

    Response:
    * certificateText: <String> | infos from open ssl for this certificate


## Secured HTTPS server (mutual authentication)

## Authority

### Create a new Root certificate authority (Authenticated Admin)

    POST /api/v1/ca/root/

    Request params:
    * name <String> | required | Name of the CA to create
    * passphrase <String> | optional | Password to use to create new CA, if not present the passphrase will be randomly generated
    * days <Number> | optional (default = 3650) | CA lifetime in days
    * info: <Object>
        * C <String> | required | Country
        * ST <String> | required | State
        * L <String> | required | Locality
        * O <String> | required | Organisation
        * OU <String> | required | Organisation Unit
        * CN <String> | required | Common name

    Response:
    * cert: <String> | root CA certificate


### Create a new intermediate certificate authority (Authenticated Admin)

    POST /api/v1/ca/intermediate/

    Request params:
    * name <String> | required | Name of the intermediate CA to create
    * passphrase <String> | optional | Password to use to create new CA, if not present the passphrase will be randomly generated
    * days <Number> | optional (default = 3650) | CA lifetime in days
    * info: <Object>
        * C <String> | required | Country
        * ST <String> | required | State
        * L <String> | required | Locality
        * O <String> | required | Organisation (if the issuer is root, Organisation must be the same as issuer)
        * OU <String> | required | Organisation Unit
        * CN <String> | required | Common name
    * issuer: <Object>
        * root <String> | required | Issuer CA root
        * name <String> | required | Issuer certificate name

    Response:
    * certChain: <String> | chained certificate


## Users

### Create a new API user (Authenticated Admin)

    POST /api/v1/user/

    Request params:
    * name <String> | required | username
    * passphrase <String> | required | password

    Response:
    * created: <Boolean> | Has the user been created

### Get user key pair (Authenticated Admin)

    GET /api/v1/user/:name/

    Request params:
    * :name <String> | required | username

    Response:
    * key: <String> | User private key
    * cert: <String> | User public certificate

### Delete an API user (Authenticated Admin)

    DELETE /api/v1/user/:name

    Request params:
    * :name <String> | required | username

    Response:
    * deleted: <Boolean> | Has the user been created


## Certificates

### Verify a certificate with its issuer (Authenticated User)

    PUT /api/v1/certificate/verify/

    Request params:
    * cert <String> | required | certificate to validate
    * issuer: <Object>
        * root <String> | required | Issuer CA root
        * name <String> | required | Issuer certificate name

    Response:
    * verified: <Boolean> | is the certificate valid for this issuer

### Request a new private key and csr (Authenticated User)

    POST /api/v1/certificate/private/

    Request params:
    * password <String> | optional | Password to use to create new private key, if not present the certificate won't be protected by a password
    * numBits <Number> | optional (default = 4096) | The size of the private key to generate in bits
    * info: <Object>
        * C <String> | required | Country
        * ST <String> | required | State
        * L <String> | required | Locality
        * O <String> | required | Organisation
        * CN <String> | required | Common name (main domain)
        * OU <String> | required | Organisation Unit
        * email <String> | optional | Email address
        * ipAddress <String array> | optional | Array of IP addresses
        * altNames <String array> | optional | Array of alternate domains

    Response:
    * key: <String> | private key file content
    * csr: <String> | Certificate Signing Request file content


### Get public key signed by an issuer (Authenticated User)

    POST /api/v1/certificate/sign/

    Request params:
    * csr: <String> | required | Certificate Signing Request file content
    * type <String/Enum> | optional (default is server) | ["client"/"server"]
    * lifetime <Number> | optional (default is defined in config) | Public key lifetime in days
    * issuer: <Object>
        * root <String> | required | Issuer CA root
        * name <String> | required | Issuer certificate name

    Response:
    * cert: <String> | certificate (public key) file content


### Get Public/Private key pair (Authenticated User)

    POST /api/v1/certificate/pair/

    Request params:
    * password <String> | optional | Password to use to create new private key, if not present the certificate won't be protected by a password
    * numBits <Number> | optional (default = 4096) | The size of the private key to generate in bits
    * info: <Object>
        * C <String> | required | Country
        * ST <String> | required | State
        * L <String> | required | Locality
        * O <String> | required | Organisation
        * OU <String> | required | Organisation Unit
        * CN <String> | required | Common name (main domain)
        * email <String> | optional | Email address
        * ipAddress <String array> | optional | Array of IP addresses
        * altNames <String array> | optional | Array of alternate domains
    * issuer: <Object>
        * root <String> | required | Issuer CA root
        * name <String> | required | Issuer certificate name
    * type <String/Enum> | optional (default is server) | ["client"/"server"]
    * lifetime <Number> | optional (default is defined in config) | Public key lifetime in days

    Response:
    * key: <String> | private key file content
    * cert: <String> | certificate (public key) file content


### Get list of certificates by authority (Authenticated Admin)

    GET /api/v1/certificates/

    Request params:

    Response:
    * [rootname]: <Object> | entry for one ca root
        * [issuername]: <Object> | entry for one ca
            * certificate <Array> | Array of certificates
                * certificate <Object>
                    * state <String> | State of the certificate (V/R/E)
                    * expirationtime <String> | Certificate expiration time
                    * revocationtime <String> | Certificate revocation time (if revoked)
                    * serial <String> | Certificate serial number
                    * subject <Object>
                        * C <String> | Country
                        * ST <String> | State
                        * L <String> | Locality
                        * O <String> | Organisation (if the issuer is root, Organisation must be the same as issuer)
                        * CN <String> | Common name


### Revoke all certificates related to a domain (Authenticated Admin)

    POST /api/v1/certificate/revoke/

    Request params:
    * name <String> | required | Common name (main domain) of the certificate
    * issuer: <Object>
        * root <String> | required | Issuer CA root
        * name <String> | required | Issuer certificate name

    Response:
    * revoked: <Boolean> | result of the revokation


### Revoke a certificate by serial number (Authenticated Admin)

    DELETE /api/v1/certificate/:caroot/:caname/:serial

    Request params:
    * :caroot <String> | Name of the root CA to fetch ("base")
    * :caname <String> | Name of the certificate to fetch ("root", "intermediate", "intermediate-server", etc)
    * :serial <String> | serial number of the certificate

    Response:
    * revoked: <Boolean> | result of the revokation
