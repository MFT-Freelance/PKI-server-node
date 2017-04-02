'use strict';

const log = require('debug')('pki:api:ca');
const path = require('path');
const suspend = require('suspend');
const uuidV4 = require('uuid/v4');
const authority = require('./components/authority');
const fileTree = require('./utils/fileTree.js');
const validator = require('./utils/validator.js');
const response = require('./utils/baseResponse.js');

const ca = {};

/**
 * Get CA Cert
 */
ca.get = function(req, res) {

    if (!req.params.caroot || !req.params.caname) {
        res.json({
            success: false,
            errors: [{
                code: 101,
                message: 'Missing parameter "caroot" or "caname"'
            }]
        });
        return;
    }

    log("Client is requesting certificate of CA " + req.params.caroot + " >>>> " + req.params.caname);

    if (req.params.chain) {
        log("Client is requesting chain version");
    }

    suspend.run(function*() {
            let fileName = req.params.caname + '.cert.pem';
            if (req.params.chain) {
                fileName = 'ca-chain-' + fileName;
            }
            const root = path.join(global.config.pkidir, req.params.caroot);
            return yield* fileTree.file(root, fileName);
        },
        function(err, cert) {
            response.callback(err, 101, cert, res);
        });
};

/**
 * Create root CA Public/Private key pair
 */
ca.root = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "name": {
                "type": "string"
            },
            "passphrase": {
                "type": "string"
            },
            "days": {
                "type": "number"
            },
            "info": {
                "type": "object",
                "properties": {
                    "C": {
                        "type": "string"
                    },
                    "ST": {
                        "type": "string"
                    },
                    "L": {
                        "type": "string"
                    },
                    "O": {
                        "type": "string"
                    },
                    "CN": {
                        "type": "string"
                    }
                },
                "required": ["C", "ST", "L", "O", "CN"]
            }
        },
        "required": ["name", "info"]
    };

    log("Client is requesting to create a new root CA certificate ", req.body);

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }

    suspend.run(function*() {

        const data = req.body;

        const lifetime = data.days ? data.days : global.config.ca.root.days;
        const password = data.passphrase ? data.passphrase : uuidV4().toString();

        const caExists = yield* fileTree.path(global.config.pkidir, data.name);
        if (caExists) {
            throw new Error('A CA already exists with the name: ' + data.name);
        }

        const cfg = {
            passphrase: password,
            days: lifetime,
            info: data.info
        };

        return yield* authority.root(data.name, cfg);
    }, function(err, cert) {
        response.callback(err, 101, cert, res);
    });

};

/**
 * Create intermediate CA Public/Private key pair
 */
ca.intermediate = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "issuer": {
                "type": "object",
                "properties": {
                    "root": {
                        "type": "string"
                    },
                    "name": {
                        "type": "string"
                    }
                },
                "required": ["root", "name"]
            },
            "passphrase": {
                "type": "string"
            },
            "name": {
                "type": "string"
            },
            "days": {
                "type": "number"
            },
            "info": {
                "type": "object",
                "properties": {
                    "C": {
                        "type": "string"
                    },
                    "ST": {
                        "type": "string"
                    },
                    "L": {
                        "type": "string"
                    },
                    "O": {
                        "type": "string"
                    },
                    "CN": {
                        "type": "string"
                    }
                },
                "required": ["C", "ST", "L", "O", "CN"]
            }
        },
        "required": ["issuer", "name", "info"]
    };

    log("Client is requesting to create a new intermediate CA certificate ", req.body);

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }

    suspend.run(function*() {

        const data = req.body;

        const lifetime = data.days ? data.days : global.config.ca.intermediate.days;
        const password = data.passphrase ? data.passphrase : uuidV4().toString();

        const caExists = yield* fileTree.path(global.config.pkidir, data.name);
        if (caExists) {
            throw new Error('A CA key already exists with the name: ' + data.name);
        }

        const cfg = {
            passphrase: password,
            name: data.name,
            days: lifetime,
            info: data.info
        };
        const issuer = data.issuer;
        issuer.isRoot = (issuer.name === issuer.root);
        return yield* authority.intermediate(cfg, issuer);
    }, function(err, certChain) {
        response.callback(err, 101, certChain, res);
    });

};

module.exports = ca;