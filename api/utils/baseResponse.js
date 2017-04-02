'use strict';
const log = require('debug')('pki:api:utils:baseResponse');

function wrongAPISchema(apierrors, res) {
    const errors = [];

    apierrors.forEach(function(apierror) {
        errors.push({
            code: apierror.code,
            message: apierror.message
        });
    });

    const resobj = {
        success: false,
        errors
    };

    res.json(resobj);
}

function managedResponse(err, code, result, response) {
    if (err) {
        log('error', err);
        response.json({
            success: false,
            errors: [{
                code,
                message: err.message
            }]
        });
    } else {
        response.json({
            success: true,
            result
        });
    }
}

module.exports = {
    apiError: wrongAPISchema,
    callback: managedResponse
};