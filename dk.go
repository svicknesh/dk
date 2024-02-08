package dk

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/svicknesh/kdf"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// TKey - custom type for key
type TKey []byte

// TSig - custom type for hash signature
type TSig []byte

// DK - structure for
type DK struct {
	Key TKey
	Sig TSig
}

const (
	saltLength = 16
)

// New - creates new instance of the derived key
func New(lock, key []byte) (dk *DK, err error) {

	// create new instance of argon2id with our custom parameters
	k, err := kdf.New(&kdf.ConfigArgon2ID{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  saltLength,
		KeyLength:   32,
	})
	if nil != err {
		return nil, fmt.Errorf("newdk: %w", err)
	}

	// create a custom salt
	salt, err := blake2b.New256(nil)
	if nil != err {
		return nil, fmt.Errorf("newdk: %w", err)
	}
	salt.Write(lock)
	salt.Write(key)
	saltSum := salt.Sum(nil)
	// we only want the bytes up to the maximum length of salt
	//fmt.Println(saltSum[len(saltSum)-saltLength:])
	//fmt.Println(saltSum[:saltLength])

	// create custom input
	input := hmac.New(sha3.New256, key)
	input.Write(lock)

	// derive the key using these new inputs
	k.SetSalt(saltSum[:saltLength])
	k.Generate(input.Sum(nil))

	// save this
	dk = new(DK)
	dk.Key = k.Key()
	sig := sha3.Sum256(dk.Key) // signature of the key for storage in remote systems, the actual key never touches any store ever
	dk.Sig = sig[:]

	return
}

func (tk TKey) String() (str string) {
	return hex.EncodeToString(tk)
}

func (ts TSig) String() (str string) {
	return hex.EncodeToString(ts)
}

// Match - checks if a given input matches the generated signature
func (dk *DK) Match(input []byte) (ok bool) {
	return (subtle.ConstantTimeCompare(dk.Sig, input) == 1)
}
