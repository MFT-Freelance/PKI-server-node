'use strict';

const log = require('debug')('pki:api:component:authority');
const fs = require('fs-extra');
const cont = require('suspend').resume;
const path = require('path');
const uuidV4 = require('uuid/v4');
const cadb = require('./cadb');
const ocsp = require('./ocsp');
const ssl = require('../utils/openSSLCmd');
const fileTree = require('../utils/fileTree');

// Sample: V	270129084423Z	270129084423Z	100E	unknown	/C=DE/ST=Germany/O=ADITO Software GmbH/OU=IT/CN=ADITO General Intermediate CA/emailAddress=it@adito.de
const indexRegex = /([R,E,V])(\t)(.*)(\t)(.*)(\t)([\dA-F]*)(\t)(unknown)(\t)(.*)/;

function* createRootCA(name, config) {
    log(">>> Creating Root CA", name);

    const pkidir = global.config.pkidir;
    const rootDir = path.join(pkidir, name, path.sep);

    fileTree.rootStructure(name, config.days, config.info);

    yield ssl.key(name, config.passphrase, 4096, rootDir, cont());

    yield ssl.ca('openssl', name, config.days, config.passphrase, rootDir, cont());

    yield fs.copy(path.join(rootDir, name + '.cert.pem'), path.join(pkidir, 'public', name, name + '.cert.pem'), cont());

    yield cadb.saveCaInfo(name, name, name, config.passphrase, 0, cont());

    return yield fs.readFile(path.join(rootDir, name + '.cert.pem'), 'utf8', cont());
}

function* createIntermediateCA(config, issuer) {
    log(">>> Creating " + config.name + " CA with issuer: " + issuer.name);

    const pkidir = global.config.pkidir;
    const rootdir = path.join(global.config.pkidir, issuer.root, path.sep);

    let issuerCWD;
    let myCWD;
    let publicDir;
    if (issuer.isRoot) {
        issuerCWD = rootdir;
        myCWD = path.join(issuerCWD, config.name);
        publicDir = path.join(pkidir, 'public', issuer.root, config.name);
    } else {
        issuerCWD = yield* fileTree.path(rootdir, issuer.name);
        issuerCWD = path.join(issuerCWD, path.sep);
        myCWD = path.join(issuerCWD, config.name);
        publicDir = path.join(pkidir, 'public', fileTree.route(myCWD, issuer.root, path.sep));
    }

    log('issuerCWD', issuerCWD);
    log('myCWD', myCWD);
    log('publicDir', publicDir);

    const ocspPort = yield cadb.getNextOcspPort(cont());

    fileTree.structure(issuerCWD, fileTree.route(myCWD, issuer.root, path.sep), config.name, config.days, config.info, ocspPort);

    yield ssl.key(config.name, config.passphrase, 4096, myCWD, cont());

    yield ssl.caCsr(config.info, config.name, config.passphrase, myCWD, cont());

    const interFile = path.join(issuerCWD, 'openssl');
    const issuerInfo = yield cadb.getCAInfo(issuer.root, issuer.name, cont());
    yield ssl.cert(interFile, 'v3_intermediate_ca', issuerInfo.passphrase, config.name, config.name, config.days, myCWD, cont());

    yield fs.remove(path.join(myCWD, config.name + '.csr.pem'), cont());

    // Make intermediate cert public
    yield fs.copy(path.join(myCWD, config.name + '.cert.pem'), path.join(publicDir, config.name + '.cert.pem'), cont());

    yield cadb.saveCaInfo(issuer.root, issuer.name, config.name, config.passphrase, ocspPort, cont());

    const cachain = yield* getChain(issuer.root, path.join(myCWD, config.name + '.cert.pem'));
    yield fs.writeFile(path.join(myCWD, 'ca-chain-' + config.name + '.cert.pem'), cachain, cont());

    // Make CA chain cert public
    yield fs.copy(path.join(myCWD, 'ca-chain-' + config.name + '.cert.pem'), path.join(publicDir, 'ca-chain-' + config.name + '.cert.pem'), cont());

    const ocspPath = path.join(myCWD, 'ocsp');
    const ocspInfo = {
        C: config.info.C,
        ST: config.info.ST,
        L: config.info.L,
        O: config.info.O,
        CN: global.config.server.ocsp.domain
    };
    yield* ocsp.createOCSPKeys(ocspPath, config.passphrase, ocspInfo);

    return cachain;
}

function* getChain(rootname, childPath) {
    let fullChain = yield fs.readFile(childPath, 'utf8', cont());
    const dirPath = path.dirname(childPath);
    const directories = dirPath.split(path.sep);
    const l = directories.length - 2;
    for (let i = l; i >= 0; i--) {
        try {
            const parentPath = directories.slice(0, i + 1).join(path.sep);
            const chainFile = path.join(parentPath, path.sep, directories[i] + '.cert.pem');
            const chain = yield fs.readFile(chainFile, 'utf8', cont());
            fullChain += '\n\n' + chain;
            log('add to ca chain:', chainFile);
            if (directories[i] === rootname) {
                return fullChain;
            }
        } catch (err) {
            if (err.code !== 'ENOENT') {
                throw err;
            }
        }
    }
    return fullChain;
}

function* verifyCert(issuer, cert) {
    // find ca chain path to check
    const chainName = 'ca-chain-' + issuer.name;
    const cwd = yield* fileTree.path(path.join(global.config.pkidir, issuer.root), issuer.name);
    // create temp cert file
    const tempdir = path.join(global.config.pkidir, 'tmp', uuidV4(), path.sep);
    const tempFile = path.join(tempdir, 'check.cert.pem');
    yield fs.ensureDir(tempdir, cont());
    yield fs.writeFile(tempFile, cert, cont());

    let result = true;
    try {
        yield ssl.verify(chainName, tempFile, cwd, cont());
    } catch (exc) {
        result = false;
    }

    yield fs.remove(tempdir, cont());

    return result;
}

function* updateCACrl(root, caName) {
    log(">>> Updating CRL for: " + caName);

    const issuerInfo = yield cadb.getCAInfo(root, caName, cont());

    const issuerCWD = yield* fileTree.path(path.join(global.config.pkidir, root, path.sep), caName);
    const confFile = path.join(issuerCWD, 'openssl.cnf');
    const publicDir = path.join(global.config.pkidir, 'public', fileTree.route(issuerCWD, root, path.sep));

    log(">>> Try creating CRL");
    const updated = yield ssl.crl(issuerInfo.passphrase, confFile, '/', cont());
    log(">>> CRL created", updated);
    if (updated) {
        yield fs.copy(path.join(issuerCWD, 'crl', 'crl.pem'), path.join(publicDir, caName + '.crl.pem'), cont());
    }

    return updated;
}

function* updateCRL() {
    const allCas = yield cadb.getAllCAInfos(cont());
    for (let i = 0; i < allCas.length; i++) {
        const ca = allCas[i];
        if (ca.root !== ca.name) {
            yield* updateCACrl(ca.root, ca.name);
        }
    }
    return true;
}

function* certificateList() {
    const indexList = yield* fileTree.indexes([], global.config.pkidir);
    const certificates = {};
    const l = indexList.length;

    const treatSubject = function() {
        const self = this;
        const sj = self.txtSubject.split('/');
        sj.forEach(function(prop) {
            const parts = prop.split('=');
            self.subject[parts[0]] = parts[1];
        });
        delete self.txtSubject;
    };
    for (let i = 0; i < l; i++) {
        const ca = indexList[i];
        const certs = yield fs.readFile(ca.path, 'utf8', cont());
        const lines = certs.split('\n');
        const l2 = lines.length;
        for (let j = 0; j < l2; j++) {
            const issuer = lines[j];
            const columns = indexRegex.exec(issuer);

            if (columns !== null) {
                const certificate = {
                    state: columns[1],
                    expirationtime: columns[3],
                    revocationtime: columns[5],
                    serial: columns[7],
                    txtSubject: columns[11],
                    subject: {}
                };

                treatSubject.apply(certificate);

                if (!certificates[ca.root]) {
                    certificates[ca.root] = {};
                }

                if (!certificates[ca.root][ca.issuer]) {
                    certificates[ca.root][ca.issuer] = {
                        certificates: []
                    };
                }
                certificates[ca.root][ca.issuer].certificates.push(certificate);
            } else {
                log("Error while parsing index.txt line :(");
            }
        }
    }

    return certificates;
}

module.exports = {
    root: createRootCA,
    intermediate: createIntermediateCA,
    verify: verifyCert,
    crl: updateCRL,
    certificates: certificateList
};