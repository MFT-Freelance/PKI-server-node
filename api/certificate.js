'use strict';

const log = require('debug')('pki:api:certificate');
const suspend = require('suspend');
const _ = require('lodash');

const validator = require('./utils/validator.js');
const response = require('./utils/baseResponse.js');
const privateKeys = require('./components/privateKeys.js');
const request = require('./components/request.js');
const authority = require('./components/authority');

const certificate = {};
const certificates = {};

/**
 * Creates private key and certificate signing request
 */
certificate.privates = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "password": {
                "type": "string"
            },
            "numBits": {
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
                    },
                    "ipAddress": {
                        "type": "array"
                    },
                    "altNames": {
                        "type": "array"
                    }
                },
                "required": ["C", "ST", "L", "O", "CN"]
            }
        },
        "required": ["info"]
    };

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }
    log('>>>>>>>>>> privates');

    suspend.run(function*() {
        const data = req.body;
        const keyName = _.snakeCase(data.info.CN);
        const numbits = data.numBits && validator.numberIsBits(data.numBits) ? data.numBits : 4096;
        return yield* privateKeys.create(keyName, data.password, numbits, data.info);
    }, function(err, keys) {
        response.callback(err, 101, keys, res);
    });
};

/**
 * Request method creates certificate from .csr file
 */
certificate.signing = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "csr": {
                "type": "string"
            },
            "lifetime": {
                "type": "number"
            },
            "type": {
                "type": "string"
            },
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
            }
        },
        "required": ["csr", "issuer"]
    };

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }
    log('>>>>>>>>>> signing');

    const data = req.body;

    let lifetime = data.lifetime ? data.lifetime : global.config.cert.lifetime_default;
    lifetime = global.config.cert.lifetime_max >= lifetime ? lifetime : global.config.cert.lifetime_max;

    const type = (data.type && data.type === 'client') ? 'usr_cert' : 'server_cert';

    suspend.run(function*() {

        const certdata = yield* request.sign(data.csr, data.issuer, type, lifetime);

        return {
            cert: certdata
        };

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

/**
 * Request method creates certificate from .csr file
 */
certificate.pairCreation = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "password": {
                "type": "string"
            },
            "lifetime": {
                "type": "number"
            },
            "type": {
                "type": "string"
            },
            "numBits": {
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
                    },
                    "ipAddress": {
                        "type": "array"
                    },
                    "altNames": {
                        "type": "array"
                    }
                },
                "required": ["C", "ST", "L", "O", "CN"]
            },
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
            }
        },
        "required": ["issuer", "info"]
    };

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }
    log('>>>>>>>>>> pairCreation');

    const data = req.body;

    let lifetime = data.lifetime ? data.lifetime : global.config.cert.lifetime_default;
    lifetime = global.config.cert.lifetime_max >= lifetime ? lifetime : global.config.cert.lifetime_max;

    const numbits = data.numBits && validator.numberIsBits(data.numBits) ? data.numBits : 4096;

    const type = (data.type && data.type === 'client') ? 'usr_cert' : 'server_cert';

    suspend.run(function*() {

        const keyName = _.snakeCase(data.info.CN);
        const privates = yield* privateKeys.create(keyName, data.password, numbits, data.info);

        const certdata = yield* request.sign(privates.csr, data.issuer, type, lifetime);

        return {
            key: privates.key,
            cert: certdata
        };

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

certificate.verify = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "cert": {
                "type": "string"
            },
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
            }
        },
        "required": ["cert", "issuer"]
    };

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }
    log('>>>>>>>>>> verify');

    const data = req.body;

    suspend.run(function*() {

        const verified = yield* authority.verify(data.issuer, data.cert);

        return {
            verified
        };

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

certificate.info = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "cert": {
                "type": "string"
            }
        },
        "required": ["cert"]
    };

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }
    log('>>>>>>>>>> info');

    const data = req.body;

    suspend.run(function*() {

        const certificateText = yield* request.read(data.cert);

        return {
            certificateText
        };

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

certificate.revokeDomain = function(req, res) {
    // Validate user input
    const schema = {
        "properties": {
            "name": {
                "type": "string"
            },
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
            }
        },
        "required": ["name", "issuer"]
    };

    // Check API conformity
    const check = validator.checkAPI(schema, req.body);
    if (check.success === false) {
        response.apiError(check.errors, res);
        return;
    }
    log('>>>>>>>>>> revoke');

    const data = req.body;

    suspend.run(function*() {

        return yield* request.nameRevoke(data.name, data.issuer);

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

certificate.revoke = function(req, res) {
    if (!req.params.caroot) {
        response.callback(new Error('Missing parameter "caroot"'), 400, null, res);
        return;
    }
    if (!req.params.caname) {
        response.callback(new Error('Missing parameter "caname"'), 400, null, res);
        return;
    }
    if (!req.params.serial) {
        response.callback(new Error('Missing parameter "serial"'), 400, null, res);
        return;
    }

    log("Admin is requesting revokation of serial " + req.params.serial);

    suspend.run(function*() {
        const issuer = {
            root: req.params.caroot,
            name: req.params.caname
        };
        return yield* request.serialRevoke(req.params.serial, issuer);

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

certificates.list = function(req, res) {

    suspend.run(function*() {

        return yield* authority.certificates();

    }, function(err, result) {
        if (err) {
            log('err', err);
        }
        response.callback(err, 101, result, res);
    });
};

// Export all certificate methods
module.exports = {
    certificate,
    certificates
};