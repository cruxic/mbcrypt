# mbcrypt-go

mbcrypt is a KDF which increases the cost of guessing attacks by executing the hash (bcrypt)
in multiple threads.  Since multi-core processors are commonplace there is no time penalty for
the defender, but the attack efficiency is reduced by a factor of N (where N is the number of threads).

Each thread operates on a different version of the password and salt (sha256).
When all threads finish, the results are combined with sha256 to produce 32 bytes.
Since the plain-text password is first hashed with sha256, it is not subject
 to bcrypt's 72 character limit.

Most applications will be better off using a memory-hard KDF like Argon2.  This implementation
is part of my quest to find the most efficient KDF which can be executed in a web browser.
