"use strict";
const assert = require('assert');
const crypto = require('crypto');
const execFile = require('child_process').execFile;
const sps = require('..');

Promise.all([
  (function truncatedHashTest() {
    const testPassword = crypto.randomBytes(3).toString('hex');
    return sps.PasswordStorage.createHash(testPassword)
      .then(hash =>
        sps.PasswordStorage.verifyPassword(testPassword, hash.slice(0, hash.length - 1)))
      .then(accepted => assert(false, 'Should not have accepted password'))
      .catch(reason => {
        if (!(reason instanceof sps.InvalidHashException))
          throw reason;
      });
  })(),
  (function basicTests() {
    const testPassword = crypto.randomBytes(3).toString('hex');
    const anotherPassword = crypto.randomBytes(3).toString('hex');

    return Promise.all([
      sps.PasswordStorage.createHash(testPassword),
      sps.PasswordStorage.createHash(testPassword),
    ]).then(hashes => {
      assert.notStrictEqual(hashes[0], hashes[1], 'Two hashes are equal');
      return Promise.all([
        sps.PasswordStorage.verifyPassword(anotherPassword, hashes[0]),
        sps.PasswordStorage.verifyPassword(testPassword, hashes[0])
      ]);
    }).then(accepted => {
      assert.strictEqual(accepted[0], false, 'Wrong password accepted');
      assert.strictEqual(accepted[1], true, 'Good password not accepted');
    });
  })(),
  (function testHashFunctionChecking() {
    const testPassword = crypto.randomBytes(3).toString('hex');
    return sps.PasswordStorage.createHash(testPassword)
      .then(hash =>
        sps.PasswordStorage.verifyPassword(testPassword, hash.replace(/^sha1/, 'md5')))
      .then(accepted => assert.strictEqual(accepted, false,
        'Should not have accepted password'));
  })(),
  (function testGoodHashInPhp() {
    const testPassword = crypto.randomBytes(3).toString('hex');
    return sps.PasswordStorage.createHash(testPassword)
      .then(hash => phpVerify(testPassword, hash));
  })(),
  (function testBadHashInPhp() {
    const testPassword = crypto.randomBytes(3).toString('hex');
    const errorOccurred = Symbol();
    return sps.PasswordStorage.createHash(testPassword)
      .then(hash => phpVerify(testPassword, hash.slice(0, hash.length - 1)))
      .catch(reason => {
        // Swallow this error, it is expected
        return errorOccurred;
      })
      .then(result => assert.strictEqual(result, errorOccurred,
        'Should not have accepted password'));
  })(),
  (function testHashFromPhp() {
    return phpHashMaker()
      .then(pair => sps.PasswordStorage.verifyPassword(pair.password, pair.hash))
      .then(accepted => assert.strictEqual(accepted, true,
        'Should have accepted password'));
  })(),
  (function testHashFromPhpFailsWithWrongPassword() {
    const testPassword = crypto.randomBytes(3).toString('hex');
    return phpHashMaker()
      .then(pair => sps.PasswordStorage.verifyPassword(testPassword, pair.hash))
      .then(accepted => assert.strictEqual(accepted, false,
        'Should not have accepted password'));
  })(),
])
.then(results => {
  // Test cases can be disabled by NOT immediately invoking their function
  const testCount = results.filter(x=>typeof x !== 'function').length;
  console.log(`✔ ${testCount} Passed`);
})
.catch(reason => {
  if(reason.name === 'AssertionError')
    console.error('AssertionError:',
      reason.actual, reason.operator, reason.expected);

  console.error(reason.stack);
  process.exit(1);
});

function phpVerify(password, hash) {
  return new Promise((resolve, reject) => {
    execFile('php', [ 'tests/phpVerify.php', password, hash ],
      (error, stdout, stderr) => {
        if(error) reject(error);
        else resolve(stdout);
      });
  });
}

function phpHashMaker(password, hash) {
  return new Promise((resolve, reject) => {
    execFile('php', [ 'tests/phpHashMaker.php' ],
      (error, stdout, stderr) => {
        if(error) reject(error);
        else {
          const hashPair = stdout.trim().split(' ');
          if (hashPair[1].length !== parseInt(hashPair[0], 10))
            reject(new Error('Unicode test is invalid'));
          else
            resolve({ password: hashPair[1], hash: hashPair[2] });
        }
      });
  });
}
