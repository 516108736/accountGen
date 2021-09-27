package account

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
)

// Identity include recipient and key
type Identity struct {
	recipient Recipient
	key       Key
}

// NewIdentity new identity include recipient and key
func NewIdentity(recipient Recipient, key Key) Identity {
	return Identity{
		recipient: recipient,
		key:       key,
	}
}

// CreatRandomIdentity create a random identity
func CreatRandomIdentity() (Identity, error) {
	sk, err := crypto.GenerateKey()
	if err != nil {
		return Identity{}, ErrGenIdentityKey
	}

	key := crypto.FromECDSA(sk)
	if len(key) != KeyLength {
		return Identity{}, fmt.Errorf("privateKey To Bytes falied: unexceptd %d ,excepted 32", len(key))
	}
	if len(crypto.FromECDSAPub(&sk.PublicKey)) != 2*KeyLength+1 {
		return Identity{}, fmt.Errorf("fromECDSAPub len is not match :unexcepted %d,excepted 65", len(crypto.FromECDSAPub(&sk.PublicKey)))
	}

	recipient := crypto.Keccak256(crypto.FromECDSAPub(&sk.PublicKey)[1:])
	if len(recipient) != KeyLength {
		return Identity{}, fmt.Errorf("recipient len is not match:unexceptd %d,exceptd 32", len(recipient))
	}
	return newIdentity(recipient, key)

}

// CreatIdentityFromKey creat identity from key
func CreatIdentityFromKey(key Key) (Identity, error) {
	sk, err := crypto.ToECDSA(key.Bytes())
	if err != nil {
		return Identity{}, err
	}
	if len(crypto.FromECDSAPub(&sk.PublicKey)) != 2*KeyLength+1 {
		return Identity{}, fmt.Errorf("fromECDSAPub len is not match :unexcepted %d,excepted %d", len(crypto.FromECDSAPub(&sk.PublicKey)), 2*KeyLength+1)
	}

	recipient := crypto.Keccak256(crypto.FromECDSAPub(&sk.PublicKey)[1:]) //"0x04"+64
	if len(recipient) != KeyLength {
		return Identity{}, fmt.Errorf("recipient len is not match:unexceptd %d,exceptd 32", len(recipient))
	}

	return newIdentity(recipient, key.Bytes())
}


func newIdentity(recipient []byte, key []byte) (Identity, error) {
	recipientType := BytesToIdentityRecipient(recipient[(len(recipient) - RecipientLength):])
	keyType := BytesToIdentityKey(key)
	return NewIdentity(recipientType, keyType), nil
}

// GetRecipient Get it's recipient
func (Self *Identity) GetRecipient() Recipient {
	return Self.recipient
}

// GetKey get it's key
func (Self *Identity) GetKey() Key {
	fmt.Println("logasfsafs")
	fmt.Print("from remote")
	return Self.key
}
