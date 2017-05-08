'use strict';

const log = require('debug')('pki:api:component:import');
const fs = require('fs-extra');
const moment = require('moment');
const uuidV4 = require('uuid/v4');
const path = require('path');
const suspend = require('suspend');
const cont = suspend.resume;
const authority = require('./authority');
const ssl = require('../utils/openSSLCmd');
const fileTree = require('../utils/fileTree');

function* importRootCA(name, key, certificate, passphrase) {
    const files = yield* saveTempFiles(key, certificate);
    log("Files saved", files);

    // Get infos from PK
    const fullInfo = yield ssl.read('ca.cert.pem', files.folder, cont());
    const caInfo = extractInfo(fullInfo);
    log("Info extracted", caInfo);

    // Create root/intermediate ca files
    const days = moment.duration(caInfo.validity.diff(moment())).asDays();
    const cfg = {
        passphrase,
        days: Math.floor(days),
        info: caInfo.subject
    };
    yield* authority.root(name, cfg);
    log("Root CA created");

    // Replace files with imported one
    const pkidir = global.config.pkidir;
    const rootDir = path.join(pkidir, name, path.sep);
    yield fs.copy(files.key, path.join(rootDir, name + '.key.pem'), {
        replace: true
    }, cont());
    log("Key file copied");
    yield fs.copy(files.cert, path.join(rootDir, name + '.cert.pem'), {
        replace: true
    }, cont());
    log("Certificate file copied");

    yield fs.copy(path.join(rootDir, name + '.cert.pem'), path.join(pkidir, 'public', name, name + '.cert.pem'), {
        replace: true
    }, cont());
    log("Public file copied");

    yield fs.remove(files.folder, cont());

    return {
        root: name,
        name
    };
}

function* importIntermediateCA(issuer, name, key, certificate, passphrase) {
    const files = yield* saveTempFiles(key, certificate);
    log("Files saved", files);

    // Verify the CA chain
    issuer.isRoot = (issuer.name === issuer.root);
    if (issuer.isRoot) {
        yield ssl.verify(issuer.name, files.cert, path.join(global.config.pkidir, issuer.root), cont());
    } else {
        const chainName = 'ca-chain-' + issuer.name;
        const cwd = yield* fileTree.path(path.join(global.config.pkidir, issuer.root), issuer.name);
        yield ssl.verify(chainName, files.cert, cwd, cont());
    }
    log("CA chain verified");

    // Get infos from PK
    const fullInfo = yield ssl.read('ca.cert.pem', files.folder, cont());
    const caInfo = extractInfo(fullInfo);
    log("Info extracted", caInfo);

    // Create intermediate ca files
    const days = moment.duration(caInfo.validity.diff(moment())).asDays();
    const cfg = {
        passphrase,
        name,
        days: Math.floor(days),
        info: caInfo.subject
    };
    yield* authority.intermediate(cfg, issuer);
    log("Intermediate CA created");

    const pkidir = global.config.pkidir;
    const rootdir = path.join(global.config.pkidir, issuer.root, path.sep);

    let myCWD;
    let publicDir;
    if (issuer.isRoot) {
        myCWD = path.join(rootdir, name);
        publicDir = path.join(pkidir, 'public', issuer.root, name);
    } else {
        let issuerCWD = yield* fileTree.path(rootdir, issuer.name);
        issuerCWD = path.join(issuerCWD, path.sep);
        myCWD = path.join(issuerCWD, name);
        publicDir = path.join(pkidir, 'public', fileTree.route(myCWD, issuer.root, path.sep));
    }

    yield fs.copy(files.key, path.join(myCWD, name + '.key.pem'), {
        replace: true
    }, cont());
    log("Key file copied");
    yield fs.copy(files.cert, path.join(myCWD, name + '.cert.pem'), {
        replace: true
    }, cont());
    log("Certificate file copied");

    // Make intermediate cert public
    yield fs.copy(path.join(myCWD, name + '.cert.pem'), path.join(publicDir, name + '.cert.pem'), {
        replace: true
    }, cont());
    log("Public file copied");

    yield fs.remove(files.folder, cont());

    const cachain = yield* fileTree.chain(issuer.root, path.join(myCWD, name + '.cert.pem'));
    yield fs.writeFile(path.join(myCWD, 'ca-chain-' + name + '.cert.pem'), cachain, cont());

    // Make CA chain cert public
    yield fs.copy(path.join(myCWD, 'ca-chain-' + name + '.cert.pem'), path.join(publicDir, 'ca-chain-' + name + '.cert.pem'), {
        replace: true
    }, cont());

    return {
        root: issuer.root,
        name
    };
}

function* saveTempFiles(key, certificate) {
    // Create temporary directory ...
    const tempdir = path.join(global.config.pkidir, 'tmp', uuidV4(), path.sep);
    yield fs.ensureDir(tempdir, cont());

    const files = {
        folder: tempdir,
        key: tempdir + 'ca.key.pem',
        cert: tempdir + 'ca.cert.pem'
    };
    // Write key file to tempdir
    yield fs.writeFile(files.key, key, cont());
    // Write cert file to tempdir
    yield fs.writeFile(files.cert, certificate, cont());

    return files;
}

function extractInfo(str) {
    const rxSubject = /Subject: (.+)/g;
    const rxValidity = /Not After : (.+)/g;
    const rxBits = /Public-Key: \((.+) bit\)/g;

    const info = {};
    const subj = rxSubject.exec(str);
    if (subj.length > 1) {
        info.subject = {};
        const arSubjects = subj[1].split(',');
        if (arSubjects.length > 6) {
            throw new Error('"subject" in certificate does not have the right format.');
        }
        for (let i = 0; i < arSubjects.length; i++) {
            const pair = arSubjects[i].split('=');
            info.subject[pair[0].trim()] = pair[1].trim();
        }
    } else {
        throw new Error('No good match for "subject" in the certificate.');
    }
    const val = rxValidity.exec(str);
    if (val.length > 1) {
        info.validity = moment(val[1], 'MMM D HH:mm:ss YYYY ZZ');
    } else {
        throw new Error('No good match for "validity" in the certificate.');
    }
    const bits = rxBits.exec(str);
    if (bits.length > 1) {
        info.numBits = Number(bits[1]);
    } else {
        throw new Error('No good match for "number of bits" in the certificate.');
    }

    return info;
}

module.exports = {
    root: importRootCA,
    intermediate: importIntermediateCA
};