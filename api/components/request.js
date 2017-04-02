'use strict';
const log = require('debug')('pki:api:component:request');
const _ = require('lodash');
const fs = require('fs-extra');
const uuidV4 = require('uuid/v4');
const path = require('path');
const suspend = require('suspend');
const cont = suspend.resume;
const ssl = require('../utils/openSSLCmd');
const fileTree = require('../utils/fileTree');
const authority = require('./authority');
const cadb = require('./cadb');

function* signRequest(csr, issuer, type, lifetime) {

    log('>>>>>>>>>> Signing request certificate by', issuer);

    const issuerCWD = yield* fileTree.path(path.join(global.config.pkidir, issuer.root, path.sep), issuer.name);
    const caConfigPath = path.join(issuerCWD, 'openssl');
    const issuerInfo = yield cadb.getCAInfo(issuer.root, issuer.name, cont());
    if (issuerCWD === false || !issuerInfo) {
        throw new Error('Unknown issuer :' + issuer.root + ' >>>> ' + issuer.name);
    }

    log('issuerCWD ', issuerCWD);

    // Create temporary directory ...
    const tempdir = path.join(global.config.pkidir, 'tmp', uuidV4(), path.sep);
    yield fs.ensureDir(tempdir, cont());

    // Write .csr file to tempdir
    yield fs.writeFile(tempdir + 'request.csr.pem', csr, cont());

    yield ssl.cert(caConfigPath, type, issuerInfo.passphrase, 'request', 'temp', lifetime, tempdir, cont());

    const certdata = yield fs.readFile(path.join(tempdir, 'temp.cert.pem'), 'utf8', cont());

    try {
        yield fs.access(tempdir, cont());
        yield fs.remove(tempdir, cont());
    } catch (exc) {
        log('>>>>>>>>>> error on directory remove', exc);
    }

    log('>>>>>>>>>> Signed and cleaned!');

    return certdata;
}

function* readCrt(cert) {
    // create temp cert file
    const tempdir = path.join(global.config.pkidir, 'tmp', uuidV4(), path.sep);
    const tempFile = path.join(tempdir, 'read.cert.pem');
    yield fs.ensureDir(tempdir, cont());
    yield fs.writeFile(tempFile, cert, cont());

    let txt;
    try {
        txt = yield ssl.read('read.cert.pem', tempdir, cont());
        yield fs.remove(tempdir, cont());
    } catch (exc) {
        yield fs.remove(tempdir, cont());
        throw exc;
    }

    return txt;
}

function* revokeByNameAndUpdate(certif, issuer) {

    log('>>>>>>>>>> Revoke certificate ', certif);

    const issuerCWD = yield* fileTree.path(path.join(global.config.pkidir, issuer.root, path.sep), issuer.name);
    const issuerInfo = yield cadb.getCAInfo(issuer.root, issuer.name, cont());
    if (issuerCWD === false || !issuerInfo) {
        throw new Error('Unknown issuer :' + issuer.root + ' >>>> ' + issuer.name);
    }

    log('issuerCWD ', issuerCWD);

    const allCerts = yield* authority.certificates();
    const serials = [];
    if (allCerts[issuer.root] && allCerts[issuer.root][issuer.name]) {
        allCerts[issuer.root][issuer.name].certificates.forEach(function(cert) {
            log('cert ', cert);
            if (cert.subject.CN === certif && cert.state !== 'R') {
                serials.push(cert.serial);
            }
        });
    }

    const l = serials.length;
    if (l <= 0) {
        throw new Error('No valid certificate has been found in our database for domain:' + certif);
    }
    for (let i = 0; i < l; i++) {
        yield ssl.revoke(serials[i], issuerInfo.passphrase, issuerCWD, cont());
        log('>>>>>>>>>> Revoked ', serials[i]);
    }

    yield* authority.crl();

    return l;
}

function* revokeBySerialAndUpdate(serial, issuer) {

    log('>>>>>>>>>> Revoke serial ', serial);

    const issuerCWD = yield* fileTree.path(path.join(global.config.pkidir, issuer.root, path.sep), issuer.name);
    const issuerInfo = yield cadb.getCAInfo(issuer.root, issuer.name, cont());
    if (issuerCWD === false || !issuerInfo) {
        throw new Error('Unknown issuer :' + issuer.root + ' >>>> ' + issuer.name);
    }

    log('issuerCWD ', issuerCWD);
    const revokation = yield ssl.revoke(serial, issuerInfo.passphrase, issuerCWD, cont());

    yield* authority.crl();

    return revokation;
}

module.exports = {
    sign: signRequest,
    read: readCrt,
    nameRevoke: revokeByNameAndUpdate,
    serialRevoke: revokeBySerialAndUpdate
};