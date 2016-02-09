'use strict';

var crypto = require('crypto');
var utils = require('util');

function InvalidVerifier(){
    Error.call(this, arguments);
    Error.captureStackTrace(this);
    this.name = 'InvalidVerifier';
}

utils.inherits(InvalidVerifier, Error);

function CannotPerformOperation(){
    Error.apply(this, arguments);
    Error.captureStackTrace(this);
    this.name = 'CannotPerformOperation';
}

utils.inherits(CannotPerformOperation, Error);

var options = {
    PBKDF2_HASH_ALGORITHM: 'sha1',
    PBKDF2_ITERATIONS: 32000,
    PBKDF2_SALT_BYTES: 24,
    PBKDF2_OUTPUT_BYTES: 18
};

var internal = {
    VERIFIER_SECTIONS: 5,
    VERIFIER_ALGORITHM_INDEX: 0,
    VERIFIER_ITERATION_INDEX: 1,
    VERIFIER_SIZE_INDEX: 2,
    VERIFIER_SALT_INDEX: 3,
    VERIFIER_PBKDF2_INDEX: 4
};

function defaults(opts) {
    var result = {};
    for(var k in options) {
        if (!opts || !Object.hasOwnProperty.call(opts, k)) {
            result[k] = options[k];
        }
    }
    return result;
}

function PasswordStorage(opts) {
    this.options = defaults(opts);
}

function toBase64(buffer) {
    return new Buffer(buffer, 'binary').toString('base64');
}

PasswordStorage.prototype.createVerifier = function(password, callback){
    // format: algorithm:iterations:outputSize:salt:pbkdf2output
    var self = this;

    crypto.randomBytes(this.options.PBKDF2_SALT_BYTES, function(err, saltRaw) {
        if (err) {
            return callback(new CannotPerformOperation(
                'Random number generator failed. Not safe to proceed.'
            ));
        }

        self.pbkdf2(
            self.options.PBKDF2_HASH_ALGORITHM,
            password,
            saltRaw,
            self.options.PBKDF2_ITERATIONS,
            self.options.PBKDF2_OUTPUT_BYTES,
            function(err, output){
                if (err) {
                    return callback(err);
                }
                callback(null,
                    self.options.PBKDF2_HASH_ALGORITHM +
                    ':' +
                    self.options.PBKDF2_ITERATIONS +
                    ':' +
                    self.options.PBKDF2_OUTPUT_BYTES +
                    ':' +
                    toBase64(saltRaw) +
                    ':' +
                    toBase64(output)
                );
            },
            true
        );
    });
};

PasswordStorage.prototype.slowEquals = function(a, b){
    if (!Buffer.isBuffer(a)){
        a = new Buffer(a, 'binary');
    }
    if (!Buffer.isBuffer(b)) {
        b = new Buffer(b, 'binary');
    }
    var diff = a.length ^ b.length;

    for(var i = 0; i < a.length && i < b.length; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
};

PasswordStorage.prototype.pbkdf2 = function(algorithm, password, salt, count, keyLength, callback, rawOutput){
    algorithm = algorithm.toLowerCase();

    if (crypto.getHashes().indexOf(algorithm) === -1) {
        return callback(new CannotPerformOperation(
            'Invalid or unsupported hash algorithm.'
        ));
    }

    // Whitelist, or we could end up with people using CRC32.
    var ok_algorithms = [
        'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'ripemd160', 'ripemd256', 'ripemd320', 'whirlpool'
    ];
    if (ok_algorithms.indexOf(algorithm) === -1) {
        return callback(new CannotPerformOperation(
            'Algorithm is not a secure cryptographic hash function.'
        ));
    }

    if (count <= 0 || keyLength <= 0) {
        return callback(new CannotPerformOperation(
            'Invalid PBKDF2 parameters.'
        ));
    }

    crypto.pbkdf2(password, salt, count, keyLength, algorithm, function(err, key) {
        if (err) {
            return callback(err);
        }
        callback(err, rawOutput ? key : key.toString('hex'));
    });
};


PasswordStorage.prototype.validatePassword = function(password, verifier, callback){
    var params, pbkdf2, saltRaw, storedOutputSize, iterations, self = this;

    params = verifier.split(/\:/g);

    if(params.length !== internal.VERIFIER_SECTIONS) {
        return callback(new InvalidVerifier(
            'Fields are missing from the password verifier.'
        ));
    }

    pbkdf2 = typeof params[internal.VERIFIER_PBKDF2_INDEX] !== 'undefined' &&
                new Buffer(params[internal.VERIFIER_PBKDF2_INDEX], 'base64');

    if (!pbkdf2 || pbkdf2.toString('base64') !== params[internal.VERIFIER_PBKDF2_INDEX]) {
        return callback(new InvalidVerifier(
            'Base64 decoding of pbkdf2 output failed.'
        ));
    }

    saltRaw = typeof params[internal.VERIFIER_SALT_INDEX] !== 'undefined' &&
                new Buffer(params[internal.VERIFIER_SALT_INDEX], 'base64');

    if (!saltRaw || saltRaw.toString('base64') !== params[internal.VERIFIER_SALT_INDEX]) {
        return callback(new InvalidVerifier(
            'Base64 decoding of salt failed.'
        ));
    }

    storedOutputSize = typeof params[internal.VERIFIER_SIZE_INDEX] !== 'undefined' &&
                            parseInt(params[internal.VERIFIER_SIZE_INDEX], 10);

    if (!storedOutputSize || isNaN(storedOutputSize) || pbkdf2.length !== storedOutputSize) {
        return callback(new InvalidVerifier(
            'PBKDF2 output length doesn\'t match stored output length.'
        ));
    }

    iterations = typeof params[internal.VERIFIER_ITERATION_INDEX] !== 'undefined' &&
                    parseInt(params[internal.VERIFIER_ITERATION_INDEX], 10);

    if (!iterations || isNaN(iterations) || iterations < 1) {
        return callback(new InvalidVerifier(
            'Invalid number of iterations. Must be >= 1.'
        ));
    }

    this.pbkdf2(
        params[internal.VERIFIER_ALGORITHM_INDEX],
        password,
        saltRaw,
        iterations,
        pbkdf2.length,
        function(err, result){
            if (err) {
                return callback(err);
            }
            callback(null, self.slowEquals(pbkdf2, result));
        },
        true
    );

};

module.exports.options = options;
module.exports.instance = new PasswordStorage();
module.exports.PasswordStorage = PasswordStorage;