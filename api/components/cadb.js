'use strict';

const log = require('debug')('pki:api:components:cadb');
const fs = require('fs-extra');
const path = require('path');

const DB_FILE_PATH = path.join(global.config.pkidir, 'db', 'ca.db');
const SEP = '_-_';

function saveCaInfo(root, parent, name, passphrase, port, cb) {
    // Make sure DB file exists ...
    fs.ensureFile(DB_FILE_PATH, function(err) {
        if (err) {
            cb(err);
        } else {
            // Read existing file
            fs.readFile(DB_FILE_PATH, 'utf8', function(err, passfile) {
                if (err) {
                    cb(err);
                } else {
                    // Update file
                    passfile = passfile + root + SEP + parent + SEP + name + SEP + passphrase + SEP + port + '\n';
                    fs.writeFile(DB_FILE_PATH, passfile, 'utf8', function(err) {
                        if (err) {
                            cb(err);
                        } else {
                            cb(null, true);
                        }
                    });
                }
            });

        }
    });
}

function getCAInfo(root, name, cb) {
    // Read existing file
    fs.readFile(DB_FILE_PATH, 'utf8', function(err, issuers) {
        if (err) {
            cb(err);
        } else {
            const lines = issuers.split('\n');

            const l = lines.length;
            for (let i = 0; i < l; i++) {
                const issuer = lines[i].split(SEP);
                if (issuer[0] === root && issuer[2] === name) {
                    cb(null, {
                        root: issuer[0],
                        parent: issuer[1],
                        name: issuer[2],
                        passphrase: issuer[3],
                        ocspPort: issuer[4]
                    });
                    return;
                }
            }

            cb();
        }
    });
}

function getAllCAInfos(cb) {
    // Read existing file
    fs.readFile(DB_FILE_PATH, 'utf8', function(err, issuers) {
        if (err) {
            cb(err);
        } else {
            const lines = issuers.split('\n');

            try {
                const l = lines.length;
                const cas = [];
                for (let i = 0; i < l; i++) {
                    const issuer = lines[i].split(SEP);
                    if (issuer[0] !== '') {
                        cas.push({
                            root: issuer[0],
                            parent: issuer[1],
                            name: issuer[2],
                            ocspPort: issuer[4]
                        });
                    }
                }

                cb(null, cas);
            } catch (exc) {
                cb(exc);
            }
        }
    });
}

function getNextOcspPort(cb) {
    let base = Number(global.config.server.ocsp.port);

    // Read existing file
    fs.readFile(DB_FILE_PATH, 'utf8', function(err, issuers) {
        if (err) {
            cb(err);
        } else {
            const lines = issuers.split('\n');
            lines.forEach(function(l) {
                const issuer = l.split(SEP);
                if (Number(issuer[4]) > base) {
                    base = Number(issuer[4]);
                }
            });

            cb(null, base + 1);
        }
    });
}

module.exports = {
    saveCaInfo,
    getCAInfo,
    getAllCAInfos,
    getNextOcspPort,
    DB_FILE_PATH
};