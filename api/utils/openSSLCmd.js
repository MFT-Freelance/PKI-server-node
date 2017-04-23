'use strict';
const log = require('debug')('pki:api:utils:openSSLCmd');
const path = require('path');
const fs = require('fs');
const exec = require('child_process').exec;
const spawn = require('child_process').spawn;

const verbose = (process.env.VERBOSE_SSL === 'true');

function createCA(configFile, name, lifetime, passphrase, folder, cb) {
    folder = folder.replace(/\\/g, '/');
    exec('openssl req -config ' + configFile + '.cnf -key ' + name + '.key.pem -new -x509 -days ' + lifetime + ' -sha256 -extensions v3_ca -out ' + name + '.cert.pem -passin pass:' + passphrase, {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function createKey(name, passphrase, numbits, folder, cb) {
    folder = folder.replace(/\\/g, '/');
    if (passphrase) {
        createCipheredKey(name, passphrase, numbits, folder, cb);
    } else {
        createClearKey(name, numbits, folder, cb);
    }
}

function createCipheredKey(name, passphrase, numbits, folder, cb) {
    log('create cyphered key');
    exec('openssl genrsa -aes256 -out ' + name + '.key.pem -passout pass:' + passphrase + ' ' + numbits.toString(), {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function createClearKey(name, numbits, folder, cb) {
    log('create clear key');
    exec('openssl genrsa -out ' + name + '.key.pem ' + numbits.toString(), {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function createCSR(info, name, passphrase, folder, cb) {
    folder = folder.replace(/\\/g, '/');
    const subj = '-subj "/C=' + info.C + '/ST=' + info.ST + '/L=' + info.L + '/O=' + info.O + '/OU=' + info.OU + '/CN=' + info.CN + '"';
    exec('openssl req ' + subj + ' -new -sha256 -key ' + name + '.key.pem -out ' + name + '.csr.pem -passin pass:' + passphrase, {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function createCSR2(info, name, passphrase, folder, cb) {
    copySSLCnf(name, info, folder, function(e) {
        if (e) {
            cb(e);
        } else {
            folder = folder.replace(/\\/g, '/');
            if (passphrase) {
                log('create cyphered CSR');
                exec('openssl req -config openssl' + name + '.cnf -new -sha256 -key ' + name + '.key.pem -out ' + name + '.csr.pem -passin pass:' + passphrase, {
                    cwd: folder
                }, function(err, stdout, stderr) {
                    callback(cb, err, stdout, stderr);
                });
            } else {
                log('create clear CSR');
                exec('openssl req -config openssl' + name + '.cnf -new -nodes -key ' + name + '.key.pem -out ' + name + '.csr.pem', {
                    cwd: folder
                }, function(err, stdout, stderr) {
                    callback(cb, err, stdout, stderr);
                });
            }

        }
    });

}

function copySSLCnf(name, info, folder, cb) {

    fs.readFile('pkitemplate/openssl_apicert.cnf.tpl', 'utf8', function(err, openssl_cert) {
        if (err) {
            cb(err);
        } else {
            openssl_cert = openssl_cert.replace(/{state}/g, info.ST);
            openssl_cert = openssl_cert.replace(/{country}/g, info.C);
            openssl_cert = openssl_cert.replace(/{locality}/g, info.L);
            openssl_cert = openssl_cert.replace(/{organization}/g, info.O);
            openssl_cert = openssl_cert.replace(/{unit}/g, info.OU);
            openssl_cert = openssl_cert.replace(/{commonname}/g, info.CN);
            let alternates = '';
            if (info.email) {
                alternates += 'email = ' + info.email + '\n';
            }
            if (info.ipAddress && info.ipAddress.length > 0) {
                for (let i = 0; i < info.ipAddress.length; i++) {
                    alternates += 'IP.' + (i + 1).toString() + ' = ' + info.ipAddress[i] + '\n';
                }
            }
            if (info.altNames && info.altNames.length > 0) {
                for (let i = 0; i < info.altNames.length; i++) {
                    alternates += 'DNS.' + (i + 1).toString() + ' = ' + info.altNames[i] + '\n';
                }
            } else {
                alternates += 'DNS.1 = ' + info.CN + '\n';
            }
            openssl_cert = openssl_cert.replace(/{alt_names}/g, alternates);
            fs.writeFile(path.join(folder, 'openssl' + name + '.cnf'), openssl_cert, function(err) {
                if (err) {
                    cb(err);
                } else {
                    cb(null, true);
                }
            });
        }
    });

}

function createCertificate(caConfigFile, caExtensionType, caPassword, csrFileName, certFileName, lifetime, folder, cb) {
    folder = folder.replace(/\\/g, '/');
    caConfigFile = caConfigFile.replace(/\\/g, '/');
    exec('openssl ca -config ' + caConfigFile + '.cnf -extensions ' + caExtensionType + ' -days ' + lifetime + ' -notext -md sha256 -in ' + csrFileName + '.csr.pem -out ' + certFileName + '.cert.pem -passin pass:' + caPassword + ' -batch', {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function convertToPKCS(outName, caFile, publicFile, privateFile, folder, cb) {
    caFile = caFile.replace(/\\/g, '/');
    publicFile = publicFile.replace(/\\/g, '/');
    privateFile = privateFile.replace(/\\/g, '/');
    folder = folder.replace(/\\/g, '/');
    exec('openssl pkcs12 -export -out ' + outName + '.pfx -inkey ' + privateFile + '.key.pem -in ' + publicFile + '.cert.pem -certfile ' + caFile + '.crt', {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function verifyWithCA(issuerFile, caCert, folder, cb) {
    issuerFile = issuerFile.replace(/\\/g, '/');
    caCert = caCert.replace(/\\/g, '/');
    folder = folder.replace(/\\/g, '/');
    exec('openssl verify -CAfile ' + issuerFile + '.cert.pem ' + caCert, {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function readInfo(caCert, folder, cb) {
    caCert = caCert.replace(/\\/g, '/');
    folder = folder.replace(/\\/g, '/');
    exec('openssl x509 -text -noout -in ' + caCert, {
        cwd: folder
    }, function(err, stdout, stderr) {
        if (verbose && stderr) {
            console.info(stderr);
        }
        if (err && err !== '') {
            cb(err);
        } else {
            cb(undefined, stdout);
        }
    });
}

function generateCRL(passphrase, cnfPath, folder, cb) {
    cnfPath = cnfPath.replace(/\\/g, '/');
    const crlFile = cnfPath.replace(/openssl.cnf/g, 'crl/crl.pem');
    const crl = spawn('openssl', [
        'ca',
        '-config', cnfPath,
        '-gencrl',
        '-out', crlFile
    ], {
        cwd: folder,
        shell: false,
        detached: true
    });

    crl.on('error', function(err) {
        log("Error during crl generation:", err);
        cb(err);
    });

    crl.on('exit', function(code) {
        if (code === 0) {
            log("CRL successfully created");
            cb(null, true);
        } else {
            log("Error during CRL creation");
            cb(null, false);
        }
    });

    // Enter CA private key password
    crl.stdin.write(passphrase + '\n');
}

function revokeCertificate(serialNumber, passphrase, folder, cb) {
    folder = folder.replace(/\\/g, '/');
    exec('openssl ca -config openssl.cnf -revoke ./certs/' + serialNumber.toString() + '.pem -passin pass:' + passphrase, {
        cwd: folder
    }, function(err, stdout, stderr) {
        callback(cb, err, stdout, stderr);
    });
}

function callback(cb, err, stdout, stderr) {
    if (verbose && stderr) {
        console.info(stderr);
    }
    if (err && err !== '') {
        cb(err);
    } else {
        cb(undefined, 1);
    }
}

module.exports = {
    key: createKey,
    ca: createCA,
    caCsr: createCSR,
    csr: createCSR2,
    cert: createCertificate,
    pkcs: convertToPKCS,
    verify: verifyWithCA,
    read: readInfo,
    crl: generateCRL,
    revoke: revokeCertificate
};