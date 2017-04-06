'use strict';

const crypto = require('crypto');
const fs = require('fs-extra');
const log = require('debug')('pki:api:component:auth');
const suspend = require('suspend');
const yaml = require('js-yaml');
const cont = suspend.resume;
const path = require('path');
const privateKeys = require('./privateKeys.js');
const request = require('./request.js');

const DB_FILE_PATH = path.join(global.config.pkidir, 'db', 'user.db');

let config;
if (fs.existsSync('config/creation.yml')) {
    log("Reading config file config/creation.yml ...");
    config = yaml.safeLoad(fs.readFileSync('config/creation.yml', 'utf8'));
}

/*
 * Add a new user to DB
 */
const addUser = function*(username, password, lvl) {
    // Make sure DB file exists ...
    yield fs.ensureFile(DB_FILE_PATH, cont());

    // Calc passhash
    const passhash = crypto.createHash('sha256').update(username + ':' + password).digest('hex');

    // Read existing file
    let passfile = yield fs.readFile(DB_FILE_PATH, 'utf8', cont());

    // Check if user alreadys exists
    const found = yield* userExists(username);

    if (found === false) {
        // Update file
        passfile = passfile + username + ':' + passhash + ':' + lvl + '\n';
        yield fs.writeFile(DB_FILE_PATH, passfile, 'utf8', cont());

        const keys = yield* createUserKey(username, password);
        const userDirPath = path.join(global.config.pkidir, 'users', username);
        yield fs.ensureDir(userDirPath, cont());
        yield fs.writeFile(path.join(userDirPath, 'key.pem'), keys.key, 'utf8', cont());
        yield fs.writeFile(path.join(userDirPath, 'cert.pem'), keys.cert, 'utf8', cont());
        return true;
    } else {
        return false;
    }
};

const userExists = function*(username) {
    // Read existing file
    const passfile = yield fs.readFile(DB_FILE_PATH, 'utf8', cont());

    // Check if user alreadys exists
    const lines = passfile.split('\n');
    let found = false;
    lines.forEach(function(line) {
        const line_username = line.split(':')[0];
        if (line_username === username) {
            found = true;
        }
    });
    return found;
};

/*
 * Delete user from DB
 */
const delUser = function*(username) {
    yield fs.ensureFile(DB_FILE_PATH, cont());

    const passfile = yield fs.readFile(DB_FILE_PATH, 'utf8', cont());
    const lines = passfile.split('\n');
    let changed = false;

    let passfile_out = '';

    // Re-write file without user

    lines.forEach(function(line) {
        if (line !== '') {
            const usrVal = line.split(':');
            const line_username = usrVal[0];

            if (line_username !== username) {
                passfile_out += line + '\n';
            } else {
                changed = usrVal[1];
            }
        }
    });

    yield fs.writeFile(DB_FILE_PATH, passfile_out, cont());

    return changed;

};

const checkUser = function(hash, callback) {

    // Read password file
    fs.readFile(DB_FILE_PATH, 'utf8', function(err, passFile) {

        if (err) {
            callback(err);
        } else {
            const lines = passFile.split('\n');

            const found = {
                name: 'anon',
                lvl: -1
            };
            lines.forEach(function(line) {
                if (line.split(':')[1] === hash) {
                    found.name = line.split(':')[0];
                    found.lvl = line.split(':')[2];
                }
            });

            callback(null, found);
        }

    });
};

const authMiddleWare = function(lvl, acceptBasic) {
    return function myAuth(req, res, next) {
        const subject = req.socket.getPeerCertificate().subject;
        if (!subject) {
            if (!acceptBasic) {
                res.status(401).send('you need a verified client certificate to access this service');
            } else {
                log('basic http authorization');
                basicAuth(req, function(err, user) {

                    if (err) {
                        res.status(500).send('An error occured ' + err.message);
                    } else {
                        if (user.lvl >= 0 && user.lvl <= lvl) {
                            req.user = user;
                            next();
                        } else {
                            res.status(401).send('You\'re not authorized to access this service');
                        }
                    }
                });
            }
        } else {
            log('certificate authorization');
            const common = subject.CN;
            checkUser(common, function(err, user) {
                if (err) {
                    res.status(500).send('An error occured ' + err.message);
                } else {
                    if (user.lvl >= 0 && user.lvl <= lvl) {
                        req.user = user;
                        next();
                    } else {
                        res.status(401).send('You\'re not authorized to access this service');
                    }
                }
            });
        }
    };
};

function basicAuth(req, cb) {
    const header = req.headers.authorization || ''; // get the header
    const token = header.split(/\s+/).pop() || ''; // and the encoded auth token
    const b64Translated = new Buffer(token, 'base64').toString(); // convert from base64
    const hash = crypto.createHash('sha256').update(b64Translated).digest('hex');
    checkUser(hash, cb);
}

function* createUserKey(username, passWord) {
    const ca = config.ca.roots[config.users.issuer.root];
    const info = {
        C: ca.country,
        ST: ca.state,
        L: ca.locality,
        O: ca.organization,
        OU: ca.unit,
        CN: crypto.createHash('sha256').update(username + ':' + passWord).digest('hex')
    };

    const privates = yield* privateKeys.create(username, passWord, 4096, info);

    const certdata = yield* request.sign(privates.csr, config.users.issuer, 'usr_cert', 365);

    return {
        key: privates.key,
        cert: certdata
    };
}

module.exports = {
    addUser,
    userExists,
    checkUser,
    delUser,
    authenticate: authMiddleWare,
    DB_FILE_PATH
};