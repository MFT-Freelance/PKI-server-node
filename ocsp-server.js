/*
 * OCSP-Server via OpenSSL
 */

const spawn = require('child_process').spawn;
const log = require('debug')('pki:ocsp-server');

let ocsp;

/**
 * Function starts OpenSSL server
 */
const startServer = function() {
    return new Promise(function(resolve, reject) {
        log("Starting OCSP server ...");

        ocsp = spawn('openssl', [
            'ocsp',
            '-port', global.config.server.ip + ':' + global.config.server.ocsp.port,
            '-text',
            '-sha256',
            '-index', 'index.txt',
            '-CA', 'ca-chain.cert.pem',
            '-rkey', 'ocsp/ocsp.key.pem',
            '-rsigner', 'ocsp/ocsp.cert.pem'
        ], {
            cwd: global.config.pkidir + 'intermediate',
            detached: true,
            shell: true
        });

        // Enter ocsp private key password
        ocsp.stdin.write(global.config.ca.intermediate.ocsp.passphrase + '\n');

        log(">>>>>> OCSP server is listening on " + global.config.server.ip + ':' + global.config.server.ocsp.port + " <<<<<<");

        resolve();

        ocsp.on('error', function(error) {
            log("OCSP server startup error: " + error);
        });

        ocsp.on('close', function(code) {
            if (code === null) {
                log("OCSP server exited successfully.");
            } else {
                log("Error: OCSP exited with code " + code);
            }
        });
    });
};


const stopServer = function() {
    ocsp.kill('SIGHUP');
    log("OCSP server stopped.");
};


module.exports = {
    startServer,
    stopServer
};