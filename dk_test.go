package dk_test

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/svicknesh/dk"
)

func TestDK(t *testing.T) {

	lock := []byte("user@example.com")
	key := []byte("hello, world!")

	d, err := dk.New(lock, key)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("key: ", d.Key)
	fmt.Println("sig: ", d.Sig)

	s, err := hex.DecodeString(d.Sig.String())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(d.Match(s))

}
