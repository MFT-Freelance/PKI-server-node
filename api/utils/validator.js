'use strict';

/**
 * Validator for API inputs
 * Utilizes AJV
 */
const _ = require('lodash');
const Ajv = require('ajv');
const ajv = Ajv({
    allErrors: true
});


const validator = {};

validator.checkAPI = function(schema, data) {
    const valid = ajv.validate(schema, data);

    if (valid) {
        return {
            success: true
        };
    } else {
        const errors = [];

        ajv.errors.forEach(function(error) {
            let message = '',
                code = 0;

            switch (error.keyword) {
                case 'required':
                    code = 400;
                    message = 'Property \'' + error.params.missingProperty + '\' is missing.';
                    break;
                case 'type':
                    code = 400;
                    message = 'Wrong type: ' + error.dataPath + ' ' + error.message;
                    break;
                default:
                    code = 500;
                    message = 'Unknown input error. :(';
            }

            const pusherror = {
                message,
                code
            };

            errors.push(pusherror);
        });

        return {
            success: false,
            errors: errors
        };
    }
};

validator.numberIsBits = function(myNum) {
    return _.includes([512, 1024, 2048, 4096], myNum);
};


module.exports = validator;