const log = require('debug')('pki:generate');
const fs = require('fs-extra');
const yaml = require('js-yaml');

const authority = require('./api/components/authority');
const auth = require('./api/components/auth');
const ocsp = require('./api/components/ocsp');
const privateKeys = require('./api/components/privateKeys');
const request = require('./api/components/request');

/*
 * Make sure there is a config file config.yml
 */
if (fs.existsSync('data/config/config.yml')) {
    log("Reading config file data/config/config.yml ...");
    global.config = yaml.safeLoad(fs.readFileSync('data/config/config.yml', 'utf8'));
} else {
    // There is no config file yet. Create one from config.yml.default and quit server.
    log("No custom config file 'data/config/config.yml' found.");
    fs.ensureDirSync('data/config');
    fs.copySync('config.default.yml', 'data/config/config.yml');
    log("Default config file was copied to data/config/config.yml.");

    log("**********************************************************************");
    log("***   Please customize data/config/config.yml according to your    ***");
    log("***                 environment and restart script.                ***");
    log("**********************************************************************");

    log("Script will now quit.");
    process.exit();
}

const pkidir = global.config.pkidir;
/**
 * Start all the things!
 */



function PKIExists() {

    fs.ensureDir(pkidir);

    if (fs.existsSync(pkidir + 'created')) {
        log(">>> PKIExists in", pkidir);
        return true;
    } else {
        return false;
    }
}

function createFileStructure() {
    log(">>> Creating CA file structure", pkidir);

    fs.ensureDirSync(pkidir);

    fs.ensureDirSync(pkidir + 'apicert');

    fs.ensureDirSync(pkidir + 'public');
}

function* createRootCA() {
    log(">>> Creating Root CA");

    const cfg = {
        passphrase: global.config.ca.root.passphrase,
        days: global.config.ca.root.days,
        info: {
            C: global.config.ca.root.country,
            ST: global.config.ca.root.state,
            L: global.config.ca.root.locality,
            O: global.config.ca.root.organization,
            CN: global.config.ca.root.commonname
        }
    };
    yield* authority.root(global.config.ca.root.name, cfg);
}

function* createIntermediateCA() {
    log(">>> Creating Intermediate CA");

    const cfg = {
        passphrase: global.config.ca.intermediate.passphrase,
        name: 'intermediate',
        days: global.config.ca.intermediate.days,
        info: {
            C: global.config.ca.intermediate.country,
            ST: global.config.ca.intermediate.state,
            L: global.config.ca.intermediate.locality,
            O: global.config.ca.intermediate.organization,
            CN: global.config.ca.intermediate.commonname
        }
    };
    const issuer = {
        name: global.config.ca.root.name,
        root: global.config.ca.root.name,
        isRoot: true
    };

    yield* authority.intermediate(cfg, issuer);
}

function* createIntermediateCAclient() {
    log(">>> Creating Client Intermediate CA");

    const cfg = {
        passphrase: global.config.ca.intermediate.passphrase,
        name: 'intermediate-client',
        days: global.config.ca.intermediate.days,
        info: {
            C: global.config.ca.intermediate.country,
            ST: global.config.ca.intermediate.state,
            L: global.config.ca.intermediate.locality,
            O: global.config.ca.intermediate.organization,
            CN: 'Client Intermediate CA'
        }
    };
    const issuer = {
        name: 'intermediate',
        root: global.config.ca.root.name,
        isRoot: false
    };

    yield* authority.intermediate(cfg, issuer);
}

function* createIntermediateCAServer() {
    log(">>> Creating Server Intermediate CA");

    const cfg = {
        passphrase: global.config.ca.intermediate.passphrase,
        name: 'intermediate-server',
        days: global.config.ca.intermediate.days,
        info: {
            C: global.config.ca.intermediate.country,
            ST: global.config.ca.intermediate.state,
            L: global.config.ca.intermediate.locality,
            O: global.config.ca.intermediate.organization,
            CN: 'Server Intermediate CA'
        }
    };
    const issuer = {
        name: 'intermediate',
        root: global.config.ca.root.name,
        isRoot: false
    };

    yield* authority.intermediate(cfg, issuer);
}

/*
 * Creates server certificate pair for HTTP API
 * Directly form Root CA
 */
function* createAPICert() {
    log(">>> Creating HTTPS API certificates");

    const data = {
        password: global.config.api.password,
        name: global.config.api.name,
        info: {
            C: "FR",
            ST: "PACA",
            L: "Antibes",
            O: "MFT",
            CN: global.config.server.secure.domain,
            ipAddress: global.config.server.altIps,
            altNames: global.config.server.altNames
        },
        lifetime: 365,
        type: "server_cert",
        issuer: {
            root: global.config.ca.root.name,
            name: "intermediate-server"
        }
    };

    const privates = yield* privateKeys.create(data.name, data.password, 4096, data.info);

    const certdata = yield* request.sign(privates.csr, data.issuer, data.type, data.lifetime);

    fs.writeFileSync(pkidir + 'apicert/' + data.name + '.key.pem', privates.key, 'utf8');
    fs.writeFileSync(pkidir + 'apicert/' + data.name + '.cert.pem', certdata, 'utf8');
}

/*
 * Sets correct file permissions for CA files
 */
function setFilePerms() {
    log(">>> Setting file permissions");
    /* jshint ignore:start */
    // Root CA
    fs.chmodSync(pkidir + global.config.ca.root.name + '/' + global.config.ca.root.name + '.key.pem', 0400);
    fs.chmodSync(pkidir + global.config.ca.root.name + '/' + global.config.ca.root.name + '.cert.pem', 0444);
    fs.chmodSync(pkidir + global.config.ca.root.name + '/openssl.cnf', 0400);

    // Intermediate CA
    fs.chmodSync(pkidir + global.config.ca.root.name + '/intermediate/intermediate.key.pem', 0400);
    fs.chmodSync(pkidir + global.config.ca.root.name + '/intermediate/intermediate.cert.pem', 0444);
    fs.chmodSync(pkidir + global.config.ca.root.name + '/intermediate/openssl.cnf', 0400);
    /* jshint ignore:end */
}

function* createAdminUser() {
    const username = global.config.user.name;
    const pass = global.config.user.password;

    log(">>> Creating Admin user", username);
    yield* auth.addUser(username, pass, 0);
}

module.exports.start = function*() {
    if (PKIExists() === false) {

        createFileStructure();

        yield* createRootCA();
        yield* createIntermediateCA();
        yield* createIntermediateCAServer();
        yield* createIntermediateCAclient();
        // yield* createIntermediateCATest();
        // yield* createOCSPKeys();
        yield* createAPICert();

        setFilePerms();
        yield* createAdminUser();

        fs.writeFileSync(pkidir + 'created', '', 'utf8');

        return true;
    } else {
        return false;
    }
};