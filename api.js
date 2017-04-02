'use strict';

// Custom modules
const auth = require('./api/components/auth.js');
const certapi = require('./api/certificate.js');
const caapi = require('./api/ca.js');
const usrapi = require('./api/user.js');

const apipath = '/api/v1';
const USER_AUTH = 1;
const ADMIN_AUTH = 0;

let acceptBasic = false;
if (global.config.server.secure.userAuth === false) {
    acceptBasic = true;
}

/**
 * Initializes Public API paths.
 */
const initPublicAPI = function(app) {

    app.get('/ca/:caroot/:caname/', function(req, res) {
        req.params.chain = false;
        caapi.get(req, res);
    });

    app.get('/ca/:caroot/:caname/chain/', function(req, res) {
        req.params.chain = true;
        caapi.get(req, res);
    });

    app.put('/certificate/info/', function(req, res) {
        certapi.certificate.info(req, res);
    });

};

/**
 * Initializes Private API paths.
 */
const initAPI = function(app) {

    // Users
    app.post(apipath + '/user/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        usrapi.create(req, res);
    });

    app.get(apipath + '/user/:name/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        usrapi.getPair(req, res);
    });

    app.delete(apipath + '/user/:name', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        usrapi.remove(req, res);
    });

    // Certificates
    app.put(apipath + '/certificate/verify/', auth.authenticate(USER_AUTH, acceptBasic), function(req, res) {
        certapi.certificate.verify(req, res);
    });

    app.post(apipath + '/certificate/private/', auth.authenticate(USER_AUTH, acceptBasic), function(req, res) {
        certapi.certificate.privates(req, res);
    });

    app.post(apipath + '/certificate/sign/', auth.authenticate(USER_AUTH, acceptBasic), function(req, res) {
        certapi.certificate.signing(req, res);
    });

    app.post(apipath + '/certificate/pair/', auth.authenticate(USER_AUTH, acceptBasic), function(req, res) {
        certapi.certificate.pairCreation(req, res);
    });

    app.post(apipath + '/certificate/revoke/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        certapi.certificate.revokeDomain(req, res);
    });

    app.delete(apipath + '/certificate/:caroot/:caname/:serial/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        certapi.certificate.revoke(req, res);
    });

    app.get(apipath + '/certificates/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        certapi.certificates.list(req, res);
    });

    // Authority
    app.post(apipath + '/ca/root/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        caapi.root(req, res);
    });

    app.post(apipath + '/ca/intermediate/', auth.authenticate(ADMIN_AUTH, false), function(req, res) {
        caapi.intermediate(req, res);
    });
};

module.exports = {
    initAPI,
    initPublicAPI
};