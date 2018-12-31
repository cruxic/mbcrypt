package mbcrypt

import (
	"testing"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/cruxic/mbcrypt/go/x-crypto-bcrypt-fork"
)

func Test_bcrypt(t *testing.T) {
	assert := assert.New(t)

	salt := []byte{0x71,0xd7,0x9f,0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,0xab,0xb2,0xdb,0xaf,0xc3};  //"abcdefghijklmnopqrstuu" as bcrypt-base64

	//mbcrypt avoids sending 0x00 bytes to bcrypt because some
	// implementations truncate upon the first null byte! (eg PHP)

	//mbcrypt sends up to 64 bytes to bcrypt.  Prove that the
	// implementation does not truncate it.
	pass64 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	hash, err := bcrypt.GenerateFromPasswordAndSalt(pass64, salt, 5)
	assert.Nil(err)
	assert.Equal("$2a$05$abcdefghijklmnopqrstuusN64mi0Q3MHT4E2PLNsVMiw2Jh1hNE6", string(hash))

	pass64 = []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
	hash, err = bcrypt.GenerateFromPasswordAndSalt(pass64, salt, 5)
	assert.Nil(err)
	assert.Equal("$2a$05$abcdefghijklmnopqrstuulBPHoU3/c65NkXOJMDkVnN3KklTvm1a", string(hash))

	//the above results were verified with PHP's bcrypt
}


func TestBasic(t *testing.T) {
	assert := assert.New(t)

	salt := []byte{0x71,0xd7,0x9f,0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,0xab,0xb2,0xdb,0xaf,0xc3};  //"abcdefghijklmnopqrstuu" as bcrypt-base64

	//these results was verified against PHP's bcrypt
	expected := []string{
		"4c8e4f9b7267c8b2ff82a8b35881335eefee9aec4ac336531b231097a8e6c4ab", //1 threads
		"549fad09e5ac86cf33b9048707dfc7c7cf933002116ea0cbca5af37d26936570", //2 threads
		"b83562e8f0e2d4fd3982959db12a3ddf103abb36677aee45d1178972b4be9113", //3 threads
		"a11b44ca410502c1ff194ebf45eb52a73d806c0e16ec0a8bd300185e897a7454", //4 threads
	}

	pass := []byte("Super Secret Password")

	for i, expect := range expected {
		nThreads := i + 1
		hash, err := Hash(nThreads, pass, salt, 5)
		assert.Nil(err)
		assert.Equal(expect,
			hex.EncodeToString(hash))
	}


}

