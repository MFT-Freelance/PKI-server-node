'use strict';

const log = require('debug')('pki:api:component:privateKeys');
const fs = require('fs-extra');
const suspend = require('suspend');
const cont = suspend.resume;
const path = require('path');
const ssl = require('../utils/openSSLCmd');

function* createPrivateKey(keyName, passphrase, numbits, info) {

    log('>>>>>>>>>> Creating private key', keyName);

    const pkidir = path.join(global.config.pkidir, 'tmp', path.sep);
    yield fs.ensureDir(pkidir, cont());

    yield ssl.key(keyName, passphrase, numbits, pkidir, cont());

    yield ssl.csr(info, keyName, passphrase, pkidir, cont());

    fs.readFile(path.join(pkidir, keyName + '.key.pem'), 'utf8', suspend.fork());
    fs.readFile(path.join(pkidir, keyName + '.csr.pem'), 'utf8', suspend.fork());
    const files = yield suspend.join();

    fs.remove(path.join(pkidir, keyName + '.key.pem'), suspend.fork());
    fs.remove(path.join(pkidir, keyName + '.csr.pem'), suspend.fork());
    yield suspend.join();

    log('>>>>>>>>>> Created!');

    return {
        key: files[0],
        csr: files[1]
    };
}

module.exports = {
    create: createPrivateKey
};