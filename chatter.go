// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	//	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which initiates should be
// the first to choose a new DH ratchet value. Part of this code has been
// provided for you, you will need to fill in the key derivation code.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(),
		PartnerDHRatchet:  nil,
		RootChain:         nil,
		SendChain:         nil,
		ReceiveChain:      nil,
		SendCounter:       0,
		LastUpdate:        0,
		ReceiveCounter:    0,
		// TODO: your code here
	}

	if _, ok := c.Sessions[*partnerIdentity]; ok {
		return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
	}

	// TODO: your code here

	return nil, errors.New("Not implemented")
}

// ReturnHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. Part of this code has been provided for you, you will
// need to fill in the key derivation code. The partner which calls this
// method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(),
		PartnerDHRatchet:  partnerEphemeral,
		RootChain:         nil,
		SendChain:         nil,
		ReceiveChain:      nil,
		SendCounter:       0,
		LastUpdate:        0,
		ReceiveCounter:    0,
		// TODO: your code here
	}

	key1 := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	key2 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	key3 := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	combinedkey := CombineKeys(key1, key2, key3)
	c.Sessions[*partnerIdentity].RootChain = combinedkey
	c.Sessions[*partnerIdentity].ReceiveChain = combinedkey
	finalkey := combinedkey.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, finalkey, nil

	// TODO: your code here

	//return nil, nil, errors.New("Not implemented")
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake. Part of this code has been provided, you will
// need to fill in the key derivation code. The partner which calls this
// method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral
	key1 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	key2 := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	key3 := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	combinedkey := CombineKeys(key1, key2, key3)
	c.Sessions[*partnerIdentity].RootChain = combinedkey
	c.Sessions[*partnerIdentity].SendChain = combinedkey
	finalkey := combinedkey.DeriveKey(HANDSHAKE_CHECK_LABEL)
	// TODO: your code here
	return finalkey, nil
	//return nil, errors.New("Not implemented")
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: nil,
		Counter:       0,
		Ciphertext:    nil,
		IV:            NewIV(),
		// TODO: your code here
	}

	//if sender already owns chain he doesn't need to ratchet the root chain
	if c.Sessions[*partnerIdentity].SendChain != nil {
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
		messagekey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)
		message.Ciphertext = messagekey.AuthenticatedEncrypt(plaintext, nil, message.IV)
	} else { //else he ratchets the root chain
		c.Sessions[*partnerIdentity].MyDHRatchet = GenerateKeyPair()
		message.NextDHRatchet = &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey
		ratchetroot := c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)
		newDH := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(ratchetroot, newDH)
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		messagekey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)
		message.Ciphertext = messagekey.AuthenticatedEncrypt(plaintext, nil, message.IV)
		c.Sessions[*partnerIdentity].ReceiveChain = nil
	}

	c.Sessions[*partnerIdentity].SendCounter++
	return message, nil

	// TODO: your code here

	//return message, errors.New("Not implemented")
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	var plaintext string
	var err error
	// TODO: your code here
	if c.Sessions[*message.Sender].ReceiveChain != nil {
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
		messagekey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
		plaintext, err = messagekey.AuthenticatedDecrypt(message.Ciphertext, nil, message.IV)
	} else {

	}

	return plaintext, err
	//return "", errors.New("Not implemented")
}

//to do, derive new dhratchet and assign it to variables in session and then to dhratchet in message.
// do if sent ==0 use old ratchet, else you do something(figure out how to know who sent last),
//maybe check send and receive chain? update one to nil when not being used
