'use strict';

const log = require('debug')('pki:api:utils:fileTree');
const fs = require('fs-extra');
const cont = require('suspend').resume;
const path = require('path');

function* walkAndSearch(baseDir, fileName) {
    try {
        return yield fs.readFile(path.join(baseDir, fileName), 'utf8', cont());
    } catch (err) {
        if (err && err.code === 'ENOENT') {
            log('not exists', path.join(baseDir, fileName));
            // const directories = fs.readdirSync(baseDir).filter(file => fs.statSync(path.join(baseDir, file)).isDirectory());
            const d = yield fs.readdir(baseDir, cont());
            const directories = d.filter(file => fs.statSync(path.join(baseDir, file)).isDirectory());
            for (let i = 0; i < directories.length; i++) {
                const result = yield* walkAndSearch(path.join(baseDir, directories[i]), fileName);
                if (result) {
                    log('exists', path.join(path.join(baseDir, directories[i]), fileName));
                    return result;
                }
            }
            return null;
        } else {
            log('error', err);
            throw err;
        }
    }
}

function* findFilePath(baseDir, fileName) {
    try {
        yield fs.access(path.join(baseDir, fileName), cont());
        return path.join(baseDir, fileName);
    } catch (err) {
        if (err && err.code === 'ENOENT') {
            const d = yield fs.readdir(baseDir, cont());
            const directories = d.filter(file => fs.statSync(path.join(baseDir, file)).isDirectory());
            for (let i = 0; i < directories.length; i++) {
                const result = yield* findFilePath(path.join(baseDir, directories[i]), fileName);
                if (result) {
                    log('exists', result);
                    return result;
                }
            }
            return false;
        } else {
            log('error', err);
            throw err;
        }
    }
}

function createRootFileStructure(rootName, days, info) {
    log(">>> Creating CA file structure", rootName, info);
    const pkidir = global.config.pkidir;

    fs.ensureDirSync(pkidir);

    /*
     * Prepare root/ dir
     */

    fs.ensureDirSync(pkidir + rootName);

    fs.ensureDirSync(pkidir + rootName + '/certs');
    fs.ensureDirSync(pkidir + rootName + '/crl');

    fs.writeFileSync(pkidir + rootName + '/index.txt', '', 'utf8');
    fs.writeFileSync(pkidir + rootName + '/serial', '1000', 'utf8');

    // Customize openssl.cnf and copy to root/

    let openssl_root = fs.readFileSync('pkitemplate/openssl_root.cnf.tpl', 'utf8');
    openssl_root = openssl_root.replace(/{basedir}/g, pkidir + rootName);
    openssl_root = openssl_root.replace(/{rootname}/g, rootName);
    openssl_root = openssl_root.replace(/{days}/g, days);
    openssl_root = openssl_root.replace(/{country}/g, info.C);
    openssl_root = openssl_root.replace(/{state}/g, info.ST);
    openssl_root = openssl_root.replace(/{locality}/g, info.L);
    openssl_root = openssl_root.replace(/{organization}/g, info.O);
    openssl_root = openssl_root.replace(/{unit}/g, info.OU);
    openssl_root = openssl_root.replace(/{commonname}/g, info.CN);

    fs.writeFileSync(pkidir + rootName + '/openssl.cnf', openssl_root);

    /*
     * Creater public dir
     */
    fs.ensureDirSync(pkidir + 'public/' + rootName);
}

function createIntermediateFileStructure(parentDir, publicDir, newPath, days, info, ocspPort) {
    /*
     * Prepare intermediate/ dir
     */
    parentDir = parentDir.replace(/\\/g, '/');
    publicDir = publicDir.replace(/\\/g, '/');
    fs.ensureDirSync(parentDir + newPath);

    fs.ensureDirSync(parentDir + newPath + '/certs');
    fs.ensureDirSync(parentDir + newPath + '/crl');

    fs.writeFileSync(parentDir + newPath + '/index.txt', '', 'utf8');
    fs.writeFileSync(parentDir + newPath + '/serial', '1000', 'utf8');
    fs.writeFileSync(parentDir + newPath + '/crlnumber', '1000', 'utf8');

    // Customize openssl.cnf and copy to parentDir + newPath + '/openssl.cnf'

    let openssl_intermediate = fs.readFileSync('pkitemplate/openssl_intermediate.cnf.tpl', 'utf8');
    openssl_intermediate = openssl_intermediate.replace(/{CAName}/g, newPath);
    openssl_intermediate = openssl_intermediate.replace(/{basedir}/g, parentDir + newPath);
    openssl_intermediate = openssl_intermediate.replace(/{days}/g, days);
    openssl_intermediate = openssl_intermediate.replace(/{country}/g, info.C);
    openssl_intermediate = openssl_intermediate.replace(/{state}/g, info.ST);
    openssl_intermediate = openssl_intermediate.replace(/{locality}/g, info.L);
    openssl_intermediate = openssl_intermediate.replace(/{organization}/g, info.O);
    openssl_intermediate = openssl_intermediate.replace(/{unit}/g, info.OU);
    openssl_intermediate = openssl_intermediate.replace(/{commonname}/g, info.CN);
    openssl_intermediate = openssl_intermediate.replace(/{ocspurl}/g, 'http://' + global.config.server.ocsp.domain + ':' + ocspPort.toString());
    openssl_intermediate = openssl_intermediate.replace(/{crlurl}/g, 'https://' + global.config.server.crl.domain + ':' + global.config.server.crl.port + '/' + publicDir + '/' + newPath + '.crl.pem');
    fs.writeFileSync(parentDir + newPath + '/openssl.cnf', openssl_intermediate);
}

function getPublicTreeFromRoot(myPath, rootName, sep) {
    const p = myPath.split(sep);
    for (let i = 0; i < p.length; i++) {
        if (p[i] === rootName) {
            return p.slice(i).join(sep);
        }
    }
    throw new Error('root name not found');
}

function* findAllIndexText(fileList, baseDir, rootName) {
    log('findAllIndexText', fileList.length, baseDir);
    try {
        yield fs.access(path.join(baseDir, 'index.txt'), cont());
        const p = baseDir.split(path.sep);
        if (!rootName) {
            rootName = p[p.length - 1];
        }
        fileList.push({
            root: rootName,
            issuer: p[p.length - 1],
            path: path.join(baseDir, 'index.txt')
        });
    } catch (err) {
        if (err.code !== 'ENOENT') {
            log('error', err);
            throw err;
        }
    }
    const d = yield fs.readdir(baseDir, cont());
    const directories = d.filter(file => fs.statSync(path.join(baseDir, file)).isDirectory());
    for (let i = 0; i < directories.length; i++) {
        yield* findAllIndexText(fileList, path.join(baseDir, directories[i]), rootName);
    }
    return fileList;
}

module.exports = {
    file: walkAndSearch,
    path: findFilePath,
    route: getPublicTreeFromRoot,
    rootStructure: createRootFileStructure,
    structure: createIntermediateFileStructure,
    indexes: findAllIndexText
};