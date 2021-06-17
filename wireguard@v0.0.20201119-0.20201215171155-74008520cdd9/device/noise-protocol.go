/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/tai64n"
)

type handshakeState int

// TODO(crawshaw): add commentary describing each state and the transitions
const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148                                           // size of handshake initiation message
	MessageResponseSize        = 92                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte       // hash value -
	chainKey                  [blake2s.Size]byte       // chain key -
	pqkexKey				  [blake2s.Size]byte		// post quantum key -
	presharedKey              NoiseSymmetricKey        // psk -
	localEphemeral            NoisePrivateKey          // ephemeral secret key -
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key -
	remoteEphemeral           NoisePublicKey           // ephemeral public key -
	precomputedStaticStatic   [NoisePublicKeySize]byte // precomputed shared secret -
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	var errZeroECDHResult = errors.New("ECDH returned all zeros")

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.publicKey(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key
	ss := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if isZero(ss[:]) {
		return nil, errZeroECDHResult
	}
	var key [chacha20poly1305.KeySize]byte
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		ss[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], handshake.hash[:])
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errZeroECDHResult
	}
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])
	//
	//>> Convert Dr. YIwen's C++ code to go here:
	// set the session ID
	device.log.Debug.Printf(">> Start to get the PQKey")
	sessionID := hex.EncodeToString(handshake.hash[:])
	// set own ID
	//ownID := hex.EncodeToString(device.staticIdentity.publicKey[:])
	// set peer ID
	//peerID := hex.EncodeToString(handshake.remoteStatic[:])
	peerID:= "46e269d10519d23b42c262867907b1f6a3f44de65f156e05a877e3d1fe62a52b"
	sendMsg := sessionID+"\n"+peerID


	/*
	//start the UDP socket to send the message
	pqk :=  make([]byte, 1024)
	conn, err := net.Dial("udp", "127.0.0.1:9527")
	//conn, err := net.Dial("udp", "192.168.1.100:9527")
	//srcIP := &net.UDPAddr{IP: net.IPv4zero, Port:0}
	//dstIP :=&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port:9527}
	//conn, err := net.DialUDP("udp", srcIP, dstIP)
	if err != nil {
		//fmt.Printf("Some error %v", err)
		device.log.Debug.Printf(">> Some error1 %v", err)
		return nil, nil
	}
	fmt.Fprintf(conn, sendMsg)
	_, err = bufio.NewReader(conn).Read(pqk)
	if err == nil {
		//fmt.Printf("%s\n", pqk)
		device.log.Debug.Printf(">> PQK: %s", pqk)
	} else {
		//fmt.Printf("Some error %v\n", err)
		device.log.Debug.Printf(">> Some error2 %v", err)
	}
	conn.Close()
	*/

	//record the session info in a file
	filePath := "/storage/emulated/0/Download/sessionInfo"
	err = ioutil.WriteFile(filePath, []byte(sendMsg), 0777)
	// handle this error
	if err != nil {
		device.log.Debug.Printf(">> Can not log session info %v", err)
	}
	pqkSSPath := "/storage/emulated/0/Download/pqkss.data"
	if _, err := os.Stat(pqkSSPath); err == nil {
		// path/to/whatever exists
		// read byte data:
		f, err := os.Open(pqkSSPath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		reader := bufio.NewReader(f)
		buf := make([]byte, 32)
		for _ = range [32]int{}{
			_, err := reader.Read(buf)
			if err != nil {
				if err != io.EOF {
					device.log.Debug.Printf(">> Some error %v", err)
				}
				break
			}
			copy(handshake.pqkexKey[:], buf)
			device.log.Debug.Printf(">> read in qpk ss: %s", hex.Dump(buf))
		}
	} else {
		// Schrodinger: file may or may not exist. See err for details.
		// Therefore, do *NOT* use !os.IsNotExist(err) to test for file existence
		device.log.Debug.Printf(">> PQC shared secret not exist %v")
	}
	device.log.Info.Printf(">> pqkexKey: %s", hex.EncodeToString(handshake.pqkexKey[:]))

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key
	var err error
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
	if isZero(ss[:]) {
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Debug.Printf("%v - ConsumeMessageInitiation: handshake replay @ %v\n", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Debug.Printf("%v - ConsumeMessageInitiation: handshake flood\n", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	func() {
		ss := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
		handshake.mixKey(ss[:])
		ss = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
		handshake.mixKey(ss[:])
	}()

	// add preshared key

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	func() {
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
		handshake.mixHash(msg.Empty[:])
	}()

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {

		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		func() {
			ss := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		func() {
			ss := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript

		aead, _ := chacha20poly1305.New(key[:])
		_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.sendNonce = 0
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.loadNext()
	current := keypairs.current
	//>> Convert Dr. YIwen's C++ code to xor the key  here:
	device.log.Debug.Printf(">> Mix the chainkey")
	for i := 0; i < blake2s.Size; i++ {
		handshake.chainKey[i] ^= handshake.pqkexKey[i]
	}
	device.log.Debug.Printf(">> chainkey: %s", hex.EncodeToString(handshake.chainKey[:]))
	//<
	if isInitiator {
		if next != nil {
			keypairs.storeNext(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.storeNext(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.loadNext() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.loadNext() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.loadNext()
	keypairs.storeNext(nil)
	return true
}
