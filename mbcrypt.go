/*
mbcrypt is a KDF which increases the cost of guessing attacks by executing the hash (bcrypt)
in multiple threads.  Since multi-core processors are commonplace there is no time penalty for
the defender, but the attack efficiency is reduced by a factor of N (where N is the number of threads).

Each thread operates on a different version of the password and salt (sha256).
When all threads finish, the results are combined with sha256 to produce 32 bytes.
Since the plain-text password is first hashed with sha256, it is not subject
 to bcrypt's 72 character limit.

Most applications will be better off using a memory-hard KDF like Argon2.
*/
package mbcrypt

import (
	"github.com/cruxic/mbcrypt-go/x-crypto-bcrypt-fork"
	"crypto/sha256"
	"errors"
	"strconv"
	"encoding/hex"
)

//Salt must be exactly this number of bytes
const BcryptSaltLen = 16

//The number of bytes returned by Hash()
const OutputSize = 32

type thread_result struct {
	threadIndex int
	bcryptHash []byte
	err error
}

/*
Hash given password with N threads (1-32).  There is no length limit on the password
because it is first hashed with sha256 before it goes into bcrypt.
The output hash is always 32 bytes.
*/
func Hash(nThreads int, plaintextPassword []byte, salt []byte, cost int) ([]byte, error) {
	if len(plaintextPassword) == 0 {
		return nil, errors.New("empty password or salt");
	}

	if len(salt) != BcryptSaltLen {
		return nil, errors.New("bcrypt salt must be exactly " + strconv.Itoa(BcryptSaltLen) + " bytes")
	}

	if nThreads < 0 || nThreads > 32 {
		return nil, errors.New("nThreads out of range")
	}


	//
	// Spawn the threads

	resultChan := make(chan *thread_result, nThreads)
	for i := 0; i < nThreads; i++ {
		go bcryptThread(plaintextPassword, salt, cost, i, resultChan)
	}

	//
	// Wait for threads to finish

	bcryptHashes := make([][]byte, nThreads)
	for _ = range bcryptHashes {
		res := <-resultChan
		if res.err != nil {
			//unlikely (bad cost parameter?)
			return nil, res.err
		}

		//sanity
		if bcryptHashes[res.threadIndex] != nil {
			panic("duplicate thread index")
		}

		bcryptHashes[res.threadIndex] = res.bcryptHash
	}

	//Combine all the base64 bcrypt hashes with sha256
	var sha = sha256.New()
	for i := range bcryptHashes {
		sha.Write(bcryptHashes[i])
	}

	finalHash := sha.Sum(nil)
	sha.Reset()

	return finalHash, nil
}

func makeDistinct(key []byte, threadIndex int) []byte {
	threadByte := []byte{byte(threadIndex + 1)}

	h := sha256.New()
	h.Write(threadByte)
	h.Write(key)
	return h.Sum(nil)
}

func bcryptThread(plaintextPassword, salt []byte, cost, threadIndex int, result chan *thread_result) {

	//Derive a distinct password and salt for this thread to work on:
	threadPassword := makeDistinct(plaintextPassword, threadIndex)
	threadSalt := makeDistinct(salt, threadIndex)[0:BcryptSaltLen]

	//Some bcrypt implementations are broken (eg PHP) because they truncate
	// the password at the first null byte!  Therefore I'll pass 64 hex characters.
	//(bcrypt can handle up to 72 bytes)
	hexPass := []byte(hex.EncodeToString(threadPassword))

	var tr thread_result
	tr.threadIndex = threadIndex
	tr.bcryptHash, tr.err = bcrypt.GenerateFromPasswordAndSalt(hexPass, threadSalt, cost)


	if tr.err == nil {
		//sanity: bcrypt hashes are always 60 characters
		if len(tr.bcryptHash) != 60 {
			tr.err = errors.New("wrong bcrypt output length")
		} else {
			//remove the salt and cost prefix (first 29 chars)
			tr.bcryptHash = tr.bcryptHash[29:]
		}
	}

	result <- &tr
}







