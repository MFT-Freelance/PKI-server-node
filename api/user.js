'use strict';

const log = require('debug')('pki:api:users');
const path = require('path');
const fs = require('fs-extra');
const suspend = require('suspend');
const validator = require('./utils/validator.js');
const response = require('./utils/baseResponse.js');
const auth = require('./components/auth.js');
const request = require('./components/request.js');

const user = {};

user.create = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "name": {
                "type": "string"
            },
            "passphrase": {
                "type": "string"
            }
        },
        "required": ["name", "passphrase"]
    };

    log("Admin is requesting to create a new user", req.body.name);

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }

    suspend.run(function*() {
        const data = req.body;

        const created = yield* auth.addUser(data.name, data.passphrase, 1);
        if (!created) {
            throw new Error('User already exists!');
        }

        return created;
    }, function(err, created) {
        response.callback(err, 101, created, res);
    });
};

user.getPair = function(req, res) {
    if (!req.params.name) {
        response.callback(new Error('Missing parameter "name"'), 400, null, res);
        return;
    }

    log("Admin is requesting key pairs of client " + req.params.name);

    suspend.run(function*() {
            const username = req.params.name;

            const exists = yield* auth.userExists(username);
            if (!exists) {
                throw new Error('Unknown user');
            }
            const userDirPath = path.join(global.config.pkidir, 'users', username);
            fs.readFile(path.join(userDirPath, 'key.pem'), 'utf8', suspend.fork());
            fs.readFile(path.join(userDirPath, 'cert.pem'), 'utf8', suspend.fork());

            const resultArr = yield suspend.join();

            return {
                key: resultArr[0],
                cert: resultArr[1]
            };
        },
        function(err, pair) {

            response.callback(err, 101, pair, res);

        });
};

user.remove = function(req, res) {

    if (!req.params.name) {
        response.callback(new Error('Missing parameter "name"'), 400, null, res);
        return;
    }

    log("Admin is requesting to remove a  user", req.params.name);

    suspend.run(function*() {
        const username = req.params.name;

        const exists = yield* auth.userExists(username);
        if (!exists) {
            throw new Error('Unknown user');
        }
        const removed = yield* auth.delUser(username);

        if (removed !== false) {
            const userIssuer = {
                root: global.config.ca.root.name,
                name: 'intermediate-client'
            };

            const nb = yield* request.nameRevoke(removed, userIssuer);

            return nb > 0;
        } else {
            return false;
        }

    }, function(err, created) {
        response.callback(err, 101, created, res);
    });
};

module.exports = user;