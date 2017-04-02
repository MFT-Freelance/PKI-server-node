'use strict';

/*
 * NodePKI
 * ... a NodeJS-based OpenSSL PKI management server.
 * Originally developed by Thomas Leister for ADITO GmbH.
 * NodePKI is published under MIT License.
 *
 * NodePKI startup file
 * Loads config, prepares CertDB database, starts OCSP server, initializes and starts HTTP server and API.
 */

const fs = require('fs-extra');
const yaml = require('js-yaml');
global.config = yaml.safeLoad(fs.readFileSync('data/config/config.yml', 'utf8'));

const log = require('debug')('pki:server');
const https = require('https');
const express = require('express');
const commandExists = require('command-exists').sync;
const bodyparser = require('body-parser');
const suspend = require('suspend');
const path = require('path');

const api = require('./api.js');
const auth = require('./api/components/auth.js');
const authority = require('./api/components/authority.js');

const publicApp = express();
const app = express();

/***************
 * Start server *
 ***************/
log("NodePKI is starting up ...");

log('\n' + require('figlet').textSync('MFT PKI', {}));

/*
 * Check if the openssl command is available
 */

if (commandExists('openssl') === false) {
    log("openssl command is not available. Please install openssl.");
    process.exit();
}

/*
 * Check if there is a PKI directory with all the OpenSSL contents.
 */
fs.ensureDir(global.config.pkidir);

let mandatoryMutual = true;
if (global.config.server.secure.userAuth === false) {
    mandatoryMutual = false;
}

suspend.run(function*() {

    log('Generate PKI');
    return yield* require('./genpki').start();

}, function(err, hasCreated) {
    if (err) {
        log("PKI creation failed with error", err);
        process.exit();
    } else {
        log("PKI created", hasCreated);

        // Make sure DB file exists ...
        fs.ensureFileSync(auth.DB_FILE_PATH);

        /*
         * Start HTTP and HTTPS server
         */
        const PATH_TO_CHAIN_CLIENT = path.join(global.config.pkidir, 'public', global.config.ca.root.name, 'intermediate', 'intermediate-client', 'ca-chain-intermediate-client.cert.pem');

        const PATH_TO_CERT = path.join(global.config.pkidir, 'apicert', global.config.api.name + '.cert.pem');
        const PATH_TO_KEY = path.join(global.config.pkidir, 'apicert', global.config.api.name + '.key.pem');

        const options = {
            ca: [fs.readFileSync(PATH_TO_CHAIN_CLIENT)],
            cert: fs.readFileSync(PATH_TO_CERT),
            key: fs.readFileSync(PATH_TO_KEY),
            passphrase: global.config.api.password,
            requestCert: true,
            rejectUnauthorized: mandatoryMutual
        };
        const publicOpts = {
            cert: fs.readFileSync(PATH_TO_CERT),
            key: fs.readFileSync(PATH_TO_KEY),
            passphrase: global.config.api.password,
            requestCert: false
        };
        log(">>>>>> API CERT " + PATH_TO_CERT);
        log(">>>>>> API KEY " + PATH_TO_KEY);

        app.use(bodyparser.json()); // JSON body parser for /api/ paths

        const server = https.createServer(options, app);
        server.listen(global.config.server.secure.port, global.config.server.listen.ip, function() {
            const host = server.address().address;
            const port = server.address().port;

            log(">>>>>> HTTPS API server is listening on " + host + ":" + port + " <<<<<<");

            log("Registering API endpoints");
            app.get('/ping', function(req, res) {

                const certif = req.socket.getPeerCertificate().subject;
                res.send('hello ' + JSON.stringify(certif));
            });
            api.initAPI(app);

            publicApp.use(express.static(global.config.pkidir + 'public')); // Static dir.
            publicApp.use(bodyparser.json()); // JSON body parser for /api/ paths
            publicApp.get('/ping', function(req, res) {
                res.send('hello public API');
            });
            const publicS = https.createServer(publicOpts, publicApp);
            publicS.listen(global.config.server.public.port, global.config.server.public.domain, function() {
                const host = publicS.address().address;
                const port = publicS.address().port;

                log(">>>>>> HTTPS Public server is listening on " + host + ":" + port + " <<<<<<");
                log("Public directory is " + global.config.pkidir + " avalaible at https://" + global.config.server.public.domain + ":" + port + "/");

                api.initPublicAPI(publicApp);
            });

            updateCrl();

            const crlInter = setInterval(updateCrl, 24 * 60 * 60 * 1000);

            /*********************************
             * Server stop routine and events *
             *********************************/
            const stopServer = function() {
                log("Received termination signal.");
                log("Bye!");
                clearInterval(crlInter);
                process.exit();
            };

            process.on('SIGINT', stopServer);
            process.on('SIGHUP', stopServer);
            process.on('SIGQUIT', stopServer);
        });
    }
});

function updateCrl() {
    suspend.run(function*() {
        return yield* authority.crl();
    }, function(err, result) {
        log("updateCrl", err, result);
    });
}

// Export app constiable
module.exports = {
    app
};