package dk_test

import (
	"encoding/hex"
	"testing"

	"github.com/svicknesh/dk"
)

func TestDK(t *testing.T) {

	lock := []byte("user@example.com")
	key := []byte("hello, world!")

	d, err := dk.New(lock, key)
	if nil != err {
		t.Fatalf("dk.New() returned error: %v", err)
	}

	// deterministic compatibility regression values, verified against the
	// v1.2.1 kdf dependency prior to the v2 migration
	const wantKeyHex = "c5e2339fd20370fba1d38e395f7b268ed9b6feb833d4bcd05d6bdd8e243e2dcb"
	const wantSigHex = "db149b967942d5f803040f9fd63ef3605ec135be9be1f9fb240157ae03e82d9c"

	if d.Key.String() != wantKeyHex {
		t.Errorf("d.Key.String() = %q, want %q", d.Key.String(), wantKeyHex)
	}
	if d.Sig.String() != wantSigHex {
		t.Errorf("d.Sig.String() = %q, want %q", d.Sig.String(), wantSigHex)
	}

	s, err := hex.DecodeString(d.Sig.String())
	if nil != err {
		t.Fatalf("hex.DecodeString(d.Sig.String()) returned error: %v", err)
	}

	if !d.Match(s) {
		t.Errorf("d.Match(s) = false, want true for the correct signature")
	}

	wrong, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	if nil != err {
		t.Fatalf("hex.DecodeString(wrong signature) returned error: %v", err)
	}

	if d.Match(wrong) {
		t.Errorf("d.Match(wrong) = true, want false for an incorrect signature")
	}

}
