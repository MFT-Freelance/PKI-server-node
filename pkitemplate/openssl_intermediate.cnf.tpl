[ca]

default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = {basedir}
CAName            = {CAName}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $certs
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/.rand
copy_extensions   = copy

# The root key and root certificate.
private_key       = $dir/$CAName.key.pem
certificate       = $dir/$CAName.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/$CAName.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 7

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = {days}
preserve          = no
policy            = policy_loose
unique_subject    = no


[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional


[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

prompt = no

[ req_distinguished_name ]
C={country}
ST={state}
L={locality}
O={organization}
OU={unit}
CN={commonname}



###
### Extensions
###

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

### For Intermediate CA
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign


### For User (Client) certificates
[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection


### For server certificates
[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
crlDistributionPoints = URI:{crlurl}
authorityInfoAccess = OCSP;URI:{ocspurl}


### For CRLs
[ crl_ext ]
authorityKeyIdentifier=keyid:always


### For OCSP certificates
[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
