Secure Password Storage
=======================

[![Build Status](https://travis-ci.org/defuse/password-hashing.svg?branch=compatible-versions)](https://travis-ci.org/defuse/password-hashing)

This repository containes peer-reviewed libraries for password storage in PHP,
C#, Ruby, and Java. Passwords are "hashed" with PBKDF2 (32,000 iterations of
SHA1 by default) using a cryptographically-random salt.

Usage
------

This library provides two methods: `CreateHash`, and `ValidatePassword`. The
`CreateHash` method takes a password as input and returns a "hash" string that
can be used to check if a password matches the one that was given to
`CreateHash`. The `ValidatePassword` method takes a hash string and a candidate
password, and returns true if the candidate password is the same as the one that
was originally given to `CreateHash`.

The library takes care of salting internally, so the user of this library does
not need to manually add salt or worry about storing the salt. The salt is
encoded into the hash string.

The different implementations are compatibile with each other. So a hash
produced with one implementation can later be used to verify the password in
a different one.

### Creating a Hash

When a user account is created, store their username and their password's
hash string into the database:

    User Registers for Account (username, password):
        Ensure username does not already exist in the database.
        hash = CreateHash(password)
        If CreateHash threw an exception, stop and alert a human.
        Store (username, hash) in the database.

### Validating a Password

When a user attempts to log in, retrieve the password hash from the database
and use it to check if the password is correct:

    User Attempts to Log in (username, password):
        Look up (username, hash) in the database.
        If no record is found for the given username, return false.
        If ValidatePassword(password, hash) is true:
            The password is correct. Return true.
        Otherwise, if it is false:
            The password is wrong. Return false.
        Otherwise, if it threw an exception:
            Stop and alert a human.

### Exception Handling

Both `CreateHash` and `ValidatePassword` can throw the following exceptions. If
your code is secure, it will always catch these exceptions and deal with them.
If either of these exceptions are thrown, it is usually indicative of something
being *seriously* wrong, so a human should be alerted whenever they are.

- `InvalidHashException`: The password hash was corrupted or changed
  between when it was returned by `CreateHash` and passed to `ValidatePassword`.
  If this happens, it could mean your database is configured incorrectly, or the
  code that inserts and retrieves from the database is wrong.

- `CannotPerformOperationException`: This happens when the operation you asked
  for could not be performed securely. For example, if the random number
  generator fails when generating a salt, this exception will be thrown. Another
  example is when the hash algorithm is not supported by the system.

Customization
--------------

Each implementation provides several constants that can be changed. **Only
change these if you know what you are doing, and have help from an expert**:

- `PBKDF2_HASH_ALGORITHM`: The hash function PBKDF2 uses. By default, it is SHA1
  for compatibility across implementations, but you may change it to SHA256 if
  you don't care about compatibility. Although SHA1 has been cryptographically
  broken as a collision-resistant function, it is still perfectly safe for
  password storage with PBKDF2.

- `PBKDF2_ITERATIONS`: The number of PBKDF2 iterations. By default, it is
  32,000. To provide greater protection of passwords, at the expense of needing
  more processing power to validate passwords, increase the number of
  iterations. The number of iterations should not be decreased.

- `PBKDF2_SALT_BYTES`: The number of bytes of salt. By default, 24 bytes, which
  is 192 bits. This is more than enough. This constant should not be changed.

- `PBKDF2_HASH_BYTES`: The number of PBKDF2 output bytes. By default, 18 bytes,
  which is 144 bits. While it may seem useful to increase the number of output
  bytes, doing so can actually give an advantage to the attacker, as it
  introduces unnecessary (avoidable) slowness to the PBKDF2 computation. 144
  bits was chosen because it is (1) Less than SHA1's 160-bit output (to avoid
  unnecessary PBKDF2 overhead), and (2) A multiple of 6 bits, so that the base64
  encoding is optimal.

Note that these constants are encoded into the hash string when it is created
with `CreateHash` so that they can be changed without breaking existing hashes.
The new (changed) values will apply only to newly-created hashes.

More Information
-----------------

For more information on secure password storage, see [Crackstation's page on
Password Hashing Security](https://crackstation.net/hashing-security.htm).
