# Golang Derived Key Generator helper library

Library to take 2 inputs (lock and key) to produce a derived key using `argon2id`. Useful to generate master keys and its hash signature for various use cases, such as encryption/decryption keys.

Both the lock and key will be used to generate the salt and the input for `argon2id` will be HMAC.

Only the signature of the key will be stored in databases or such, the actual key never touches any datastore. This allows it to be used and discarded as needed.

## Using this library

```go
lock := []byte("user@example.com")
key := []byte("hello, world!")

d, err := dk.New(lock, key)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(d.Key)
fmt.Println(d.Sig)

// the signature will come from a remote database or such
s, err := hex.DecodeString(d.Sig.String())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Println(d.Match(s))
```

## How it works

Assume the `lock` is the email, and `key` is the password.

1. Create a new instance of `blake2b` with no input key for the salt.
2. Write the bytes of `lock` into this `blake2b` instance.
3. Write the bytes of `key` into this `blake2b` instance.
4. Take the first 16 bytes of this result as `salt`.
5. Create new `hmac` instance using `sha3-384` and `key` as the key.
6. Write the bytes of `lock` into this `hmac` instance.
7. The result of this will be the input to be fed into `argon2id`.
8. Create new `argon2id` instance with the following parameters
    a. `memory` = 64MB (64 * 1024)
    b. `iterations` = 3
    c. `parallelism` = 4 
    d. `saltLength` = 16
    e. `keyLength` = 32
9. Set the salt of `argon2id` with the value from step (4).
10. Using the value from step (7), generate the key using `argon2id`.
11. The signature of this key is a `sha3-256` which can be stored in a database or such.
