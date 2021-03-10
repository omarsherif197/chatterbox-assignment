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
	}

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
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
	}

	key1 := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	key2 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	key3 := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	combinedkey := CombineKeys(key1, key2, key3)
	c.Sessions[*partnerIdentity].RootChain = combinedkey
	c.Sessions[*partnerIdentity].ReceiveChain = combinedkey
	finalkey := combinedkey.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, finalkey, nil
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
	return finalkey, nil
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
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		Counter:       0,
		LastUpdate:    0,
		Ciphertext:    nil,
		IV:            NewIV(),
	}

	//if sender already owns chain he doesn't need to ratchet the root chain
	if c.Sessions[*partnerIdentity].SendChain != nil {
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
	} else { //else he ratchets the root chain
		c.Sessions[*partnerIdentity].MyDHRatchet = GenerateKeyPair()
		message.NextDHRatchet = &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey
		ratchetroot := c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)
		newDH := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(ratchetroot, newDH)
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter + 1
	}
	message.LastUpdate = c.Sessions[*partnerIdentity].LastUpdate
	message.Counter = c.Sessions[*partnerIdentity].SendCounter + 1
	messagekey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)
	extra := message.EncodeAdditionalData()
	message.Ciphertext = messagekey.AuthenticatedEncrypt(plaintext, extra, message.IV)

	c.Sessions[*partnerIdentity].SendCounter++
	return message, nil
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	ses := c.Sessions[*message.Sender]

	if message.Counter > ses.ReceiveCounter+1 {
		//this means root key has been updated
		if message.LastUpdate > ses.ReceiveCounter {
			//store keys that used the old root key
			cachekeys(ses, ses.ReceiveCounter, message.LastUpdate)
			//ratchet and then store keys that use new root key
			ratchetkey(ses, message)
			//this is because ratchetkey function already derives the Receive chain key, deriving it again would be incorrect
			ses.CachedReceiveKeys[message.LastUpdate] = ses.ReceiveChain.DeriveKey(KEY_LABEL)
			//the +1 is because we've already derived the message key for such message
			cachekeys(ses, message.LastUpdate+1, message.Counter)
		} else { //this means root key has not been updated
			cachekeys(ses, ses.ReceiveCounter, message.Counter)
		}
		//After you've stored everything, now decrypt the message
		ses.ReceiveChain = ses.ReceiveChain.DeriveKey(CHAIN_LABEL)
		messagekey := ses.ReceiveChain.DeriveKey(KEY_LABEL)
		return decrypt(ses, message, messagekey)

	} else if message.Counter < ses.ReceiveCounter { //handling late messages
		messagekey := ses.CachedReceiveKeys[message.Counter]
		return decrypt(ses, message, messagekey)

	} else { //otherwise the message is in sequence
		if message.LastUpdate <= ses.ReceiveCounter {
			ses.ReceiveChain = ses.ReceiveChain.DeriveKey(CHAIN_LABEL)
		} else {
			ratchetkey(ses, message)
			ses.SendChain = nil
		}
		messagekey := ses.ReceiveChain.DeriveKey(KEY_LABEL)
		return decrypt(ses, message, messagekey)
	}
}

//This caches late messages' keys
func cachekeys(ses *Session, begin int, end int) {
	for i := begin; i < end; i++ {
		ses.ReceiveChain = ses.ReceiveChain.DeriveKey(CHAIN_LABEL)
		ses.CachedReceiveKeys[i] = ses.ReceiveChain.DeriveKey(KEY_LABEL)
	}
	return
}

//This just ratchets the receive key
func ratchetkey(ses *Session, message *Message) {
	ratchetroot := ses.RootChain.DeriveKey(ROOT_LABEL)
	ses.PartnerDHRatchet = message.NextDHRatchet
	newDH := DHCombine(ses.PartnerDHRatchet, &ses.MyDHRatchet.PrivateKey)
	ses.RootChain = CombineKeys(ratchetroot, newDH)
	ses.ReceiveChain = ses.RootChain.DeriveKey(CHAIN_LABEL)
}

//decrypts the message and returns plaintext
func decrypt(ses *Session, message *Message, messagekey *SymmetricKey) (string, error) {
	extra := message.EncodeAdditionalData()
	ses.ReceiveCounter = message.Counter
	return messagekey.AuthenticatedDecrypt(message.Ciphertext, extra, message.IV)
}
