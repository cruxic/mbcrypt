This folder contains a fork of golang.org/x/crypto/bcrypt.  The fork was made on 2018-12-29.
All modifications are in patch.go (and patch_test.go).  bcrypt.go remains unmodified and can
be kept in sync with upstream changes.

The patch merely adds a new function (GenerateFromPasswordAndSalt) which allows salt to be
passed in to the bcrypt calculation as opposed to using random salt.
