'use strict';
const log = require('debug')('pki:api:component:ocsp');
const fs = require('fs-extra');
const cont = require('suspend').resume;
const ssl = require('../utils/openSSLCmd');

function* createOCSPKeys(ocspPath, passphrase, info) {
    log(">>> Creating OCSP Keys in", ocspPath);

    /*
     * Prepare intermediate/ocsp dir
     */
    fs.ensureDirSync(ocspPath);
    let openssl_intermediate_ocsp = fs.readFileSync('pkitemplate/openssl_ocsp.cnf.tpl', 'utf8');
    openssl_intermediate_ocsp = openssl_intermediate_ocsp.replace(/{state}/g, info.ST);
    openssl_intermediate_ocsp = openssl_intermediate_ocsp.replace(/{country}/g, info.C);
    openssl_intermediate_ocsp = openssl_intermediate_ocsp.replace(/{locality}/g, info.L);
    openssl_intermediate_ocsp = openssl_intermediate_ocsp.replace(/{organization}/g, info.O);
    openssl_intermediate_ocsp = openssl_intermediate_ocsp.replace(/{commonname}/g, info.CN);
    fs.writeFileSync(ocspPath + '/openssl.cnf', openssl_intermediate_ocsp);

    yield ssl.key('ocsp', passphrase, 4096, ocspPath, cont());

    yield ssl.caCsr(info, 'ocsp', passphrase, ocspPath, cont());

    yield ssl.cert('../openssl', 'ocsp', passphrase, 'ocsp', 'ocsp', 3650, ocspPath, cont());

    fs.removeSync(ocspPath + '/ocsp.csr.pem');
}

module.exports = {
    createOCSPKeys
};