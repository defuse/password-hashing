"use strict";
// Conforms to Node.js >= v4
const crypto = require("crypto");

// These constants may be changed without breaking existing hashes.
const SALT_BYTE_SIZE = 24;
const HASH_BYTE_SIZE = 18;
const PBKDF2_ITERATIONS = 64000;
const DEFAULT_DIGEST = "sha1";

// These constants define the encoding and may not be changed.
const HASH_SECTIONS = 5;
const HASH_ALGORITHM_INDEX = 0;
const ITERATION_INDEX = 1;
const HASH_SIZE_INDEX = 2;
const SALT_INDEX = 3;
const PBKDF2_INDEX = 4;

class PasswordStorage {
  // @param password String Clear text password to be hashed
  // @param digest   String Hash algorithm to apply, enumerate with crypto.getHashes()
  //                         Optional, default: "sha1"
  static createHash(password, digest) {
    digest = digest || DEFAULT_DIGEST;
    return new Promise((resolve, reject) => {
      crypto.randomBytes(SALT_BYTE_SIZE, (error, salt) => {
        if (error) {
          reject(error);
          return;
        }
        crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE, digest,
          (error, hash) => {
            if (error)
              reject(error);
            else
              resolve([
                "sha1",
                PBKDF2_ITERATIONS,
                HASH_BYTE_SIZE,
                salt.toString("base64"),
                hash.toString("base64")
              ].join(":"));
          });
      });
    });
  }
  static verifyPassword(password, correctHash) {
    return new Promise((resolve, reject) => {
      // Decode the hash into its parameters
      const params = correctHash.split(":");
      if (params.length !== HASH_SECTIONS)
        reject(new InvalidHashException(
          "Fields are missing from the password hash."));

      const digest = params[HASH_ALGORITHM_INDEX];
      if (crypto.getHashes().indexOf(digest) === -1)
        reject(new CannotPerformOperationException(
          "Unsupported hash type"));

      const iterations = parseInt(params[ITERATION_INDEX], 10);
      if (isNaN(iterations))
        reject(new InvalidHashException(
          "Could not parse the iteration count as an interger."));

      if (iterations < 1)
        reject(new InvalidHashException(
          "Invalid number of iteration. Must be >= 1."));

      const salt = initBuffer(params[SALT_INDEX]);
      const hash = initBuffer(params[PBKDF2_INDEX]);

      const storedHashSize = parseInt(params[HASH_SIZE_INDEX], 10);
      if (isNaN(storedHashSize))
        reject(new InvalidHashException(
          "Could not parse the hash size as an interger."));
      if (storedHashSize !== hash.length)
        reject(new InvalidHashException(
          "Hash length doesn't match stored hash length." + hash.length));

      // Compute the hash of the provided password, using the same salt,
      // iteration count, and hash length
      crypto.pbkdf2(initBuffer(password, 'utf8'), salt, iterations, storedHashSize, digest,
        (error, testHash) => {
          if (error)
            reject(error);
          else
            // Compare the hashes in constant time. The password is correct if
            // both hashes match.
            resolve(slowEquals(hash, testHash));
        });
    });
  }
}

function initBuffer(input, inputEncoding) {
  inputEncoding = inputEncoding || 'base64';
  if(Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow)
    // Node.js >= 6
    return Buffer.from(input, inputEncoding);
  else
    // Node.js < 6
    return new Buffer(input, inputEncoding);
}

function slowEquals(a, b) {
  let diff = a.length ^ b.length;
  for(let i = 0; i < a.length && i < b.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}

class InvalidHashException extends Error {};
class CannotPerformOperationException extends Error {};

exports.PasswordStorage = PasswordStorage;
exports.InvalidHashException = InvalidHashException;
exports.CannotPerformOperationException = CannotPerformOperationException;
