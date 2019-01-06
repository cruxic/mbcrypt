# mbcrypt-go

mbcrypt is a KDF which increases the cost of guessing attacks by executing the hash (bcrypt)
in multiple threads.  Since multi-core processors are commonplace there is no time penalty for
the defender, but the attack efficiency is reduced by a factor of N (where N is the number of threads).

Each thread operates on a different version of the password and salt (sha256).
When all threads finish, the results are combined with sha256 to produce 32 bytes.
Since the plain-text password is first hashed with sha256, it is not subject
 to bcrypt's 72 character limit.

mbcrypt is part of my quest to find a KDF which can run efficiently in a web browser (JavaScript).
If you are not constrained to JavaScript use [Argon2](https://www.argon2.com/) instead.

## Algorithm

In pseudo-code, the algorithm is:

```javascript

function mbcrypt(password, salt, nThreads, cost) {
	h = sha256.New();

	for (p = 1; p <= nThreads; p++) {
		threadPass = sha256(concat(p, password);

		//hex encode to avoid null byte issues with some bcrypt implementations
		threadPassHex = hexEncode(threadPass);

		threadSalt = sha256(concat(p, salt)[0:16];

		threadHash = bcrypt(threadPassHex, threadSalt, cost);

		//We remove the salt prefix from the bcrypt base64.
		threadHash = substr(threadHash, 29, len(threadHash));

		h.Update(threadHash);
	}

	hash = h.Finalize();  //returns 32 bytes
	return hash;
}
```
