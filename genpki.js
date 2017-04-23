'use strict';

const log = require('debug')('pki:generate');
const path = require('path');
const fs = require('fs-extra');
const yaml = require('js-yaml');
const cont = require('suspend').resume;

const authority = require('./api/components/authority');
const auth = require('./api/components/auth');
const privateKeys = require('./api/components/privateKeys');
const request = require('./api/components/request');

let config;

/*
 * Make sure there is a config file config.yml
 */
if (fs.existsSync('config/creation.yml')) {
    log("Reading config file config/creation.yml ...");
    config = yaml.safeLoad(fs.readFileSync('config/creation.yml', 'utf8'));
} else {
    log("Script will now quit.");
    process.exit();
}

const pkidir = config.pkidir;

function PKIExists() {

    fs.ensureDir(pkidir);

    if (fs.existsSync(pkidir + 'created')) {
        log(">>> PKI Exists in", pkidir);
        return true;
    } else {
        log(">>> PKI do not exists in", pkidir);
        log(">>> Creating PKI");
        return false;
    }
}

function* createCA() {
    const rootNames = Object.keys(config.ca.roots);
    for (let i = 0; i < rootNames.length; i++) {
        yield* createRootCa(rootNames[i], config.ca.roots[rootNames[i]]);
    }
}

function* createRootCa(name, ca) {
    log(">>> Creating Root CA > ", name);

    const cfg = {
        passphrase: ca.passphrase,
        days: ca.days,
        info: {
            C: ca.country,
            ST: ca.state,
            L: ca.locality,
            O: ca.organization,
            OU: ca.unit,
            CN: ca.commonname
        }
    };
    yield* authority.root(name, cfg);

    for (let i = 0; i < ca.issued.length; i++) {
        yield* createIntermediateCA(name, name, ca, ca.issued[i]);
    }
}

function* createIntermediateCA(root, name, ca, inter) {
    log(">>> Creating Intermediate CA > ", inter.name);

    const issuer = {
        root,
        name,
        isRoot: (root === name)
    };
    const cfg = {
        passphrase: inter.passphrase,
        name: inter.name,
        days: ca.days,
        info: {
            C: ca.country,
            ST: ca.state,
            L: ca.locality,
            O: ca.organization,
            OU: ca.unit,
            CN: inter.commonname
        }
    };
    yield* authority.intermediate(cfg, issuer);

    if (inter.issued && inter.issued.length > 0) {
        for (let i = 0; i < inter.issued.length; i++) {
            yield* createIntermediateCA(root, inter.name, ca, inter.issued[i]);
        }
    }
}

function* createAPIKeys() {
    log(">>> Creating HTTPS API certificates");

    const ca = config.ca.roots[config.server.issuer.root];
    const data = {
        name: config.server.certificate.name,
        password: config.server.certificate.passphrase,
        lifetime: config.server.certificate.lifetime,
        type: "server_cert",
        info: {
            C: ca.country,
            ST: ca.state,
            L: ca.locality,
            O: ca.organization,
            OU: ca.unit,
            CN: config.server.commonname,
            email: config.server.email,
            ipAddress: config.server.altIps,
            altNames: config.server.altNames
        },
        issuer: config.server.issuer
    };

    const privates = yield* privateKeys.create(data.name, data.password, 4096, data.info);

    const certdata = yield* request.sign(privates.csr, data.issuer, data.type, data.lifetime);

    yield fs.writeFile(path.join(pkidir, config.server.certificate.directory, data.name + '.key.pem'), privates.key, 'utf8', cont());
    yield fs.writeFile(path.join(pkidir, config.server.certificate.directory, data.name + '.cert.pem'), certdata, 'utf8', cont());
}

function* createUsers() {
    const username = config.users.admin.username;
    const pass = config.users.admin.passphrase;

    log(">>> Creating Admin user", username);
    yield* auth.addUser(username, pass, 0);

    for (let i = 0; i < config.users.others.length; i++) {
        const usr = config.users.others[i];
        yield* auth.addUser(usr.username, usr.passphrase, 1);
    }
}

module.exports.start = function*() {
    if (PKIExists() === false) {

        log(">>> Creating CA file structure", pkidir);

        yield fs.ensureDir(pkidir, cont());
        yield fs.ensureDir(path.join(pkidir, config.server.certificate.directory), cont());
        yield fs.ensureDir(path.join(pkidir, 'public'), cont());

        yield* createCA();
        yield* createAPIKeys();
        yield* createUsers();

        yield fs.writeFile(pkidir + 'created', '', 'utf8', cont());

        return true;
    } else {
        return false;
    }
};