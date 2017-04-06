[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
req_extensions      = v3_req

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

prompt = no


[ req_distinguished_name ]
C={country}
ST={state}
L={locality}
O={organization}
OU={unit}
CN={commonname}


[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alternate_names

[alternate_names]
{alt_names}