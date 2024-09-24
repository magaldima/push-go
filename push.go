package push

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/hkdf"
)

const MaxRecordSize uint32 = 4096

var ErrMaxPadExceeded = errors.New("payload has exceeded the maximum length")

// saltFunc generates a salt of 16 bytes
var saltFunc = func() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return salt, err
	}

	return salt, nil
}

// Options are config and extra params needed to send a notification
type Options struct {
	Transport       http.RoundTripper // Will replace with *http.Client by default if not included
	RecordSize      uint32            // Limit the record size
	Subscriber      string            // Sub in VAPID JWT token
	Topic           string            // Set the Topic header to collapse a pending messages (Optional)
	TTL             int               // Set the TTL on the endpoint POST request
	Urgency         Urgency           // Set the Urgency header to change a message priority (Optional)
	VAPIDPublicKey  string            // VAPID public key, passed in VAPID Authorization header
	VAPIDPrivateKey string            // VAPID private key, used to sign VAPID JWT token
	VapidExpiration time.Time         // optional expiration for VAPID JWT token (defaults to now + 12 hours)
}

// SendNotification calls SendNotificationWithContext with default context for backwards-compatibility
func SendNotification(message []byte, s *Subscription, options *Options) (*http.Response, error) {
	return SendNotificationWithContext(context.Background(), message, s, options)
}

// SendNotificationWithContext sends a push notification to a subscription's endpoint
// Message Encryption for Web Push, and VAPID protocols.
// FOR MORE INFORMATION SEE RFC8291: https://datatracker.ietf.org/doc/rfc8291
func SendNotificationWithContext(ctx context.Context, message []byte, s *Subscription, options *Options) (*http.Response, error) {
	// Authentication secret (auth_secret)
	authSecret, err := decodeSubscriptionKey(s.Keys.Auth)
	if err != nil {
		return nil, err
	}

	// dh (Diffie Hellman)
	dh, err := decodeSubscriptionKey(s.Keys.P256dh)
	if err != nil {
		return nil, err
	}

	// Generate 16 byte salt
	salt, err := saltFunc()
	if err != nil {
		return nil, err
	}

	// Create the ecdh_secret shared key pair
	curve := ecdh.P256()

	// Application server key pairs (single use)
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	localPublicKey := privateKey.PublicKey().Bytes()

	// Combine application keys with receiver's EC public key
	receiverPublicKey, err := curve.NewPublicKey(dh)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a valid ECDH public key: %w", err)
	}

	// Derive ECDH shared secret
	sharedSecret, err := privateKey.ECDH(receiverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ECDH shared secret: %w", err)
	}

	hash := sha256.New

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(dh)
	prkInfoBuf.Write(localPublicKey)

	prkHKDF := hkdf.New(hash, sharedSecret, authSecret, prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return nil, err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(hash, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return nil, err
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(hash, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return nil, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Get the record size
	recordSize := options.RecordSize
	if recordSize == 0 {
		recordSize = MaxRecordSize
	}

	recordLength := int(recordSize) - 16

	// Encryption Content-Coding Header
	recordBuf := bytes.NewBuffer(salt)

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, recordSize)

	recordBuf.Write(rs)
	recordBuf.Write([]byte{byte(len(localPublicKey))})
	recordBuf.Write(localPublicKey)

	// Data
	dataBuf := bytes.NewBuffer(message)

	// Pad content to max record size - 16 - header
	// Padding ending delimeter
	dataBuf.Write([]byte("\x02"))
	if err := pad(dataBuf, recordLength-recordBuf.Len()); err != nil {
		return nil, err
	}

	// Compose the ciphertext
	ciphertext := gcm.Seal([]byte{}, nonce, dataBuf.Bytes(), nil)
	recordBuf.Write(ciphertext)

	// POST request
	req, err := http.NewRequest("POST", s.Endpoint, recordBuf)
	if err != nil {
		return nil, err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Length", strconv.Itoa(len(ciphertext)))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Сheck the optional headers
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}

	expiration := options.VapidExpiration
	if expiration.IsZero() {
		expiration = time.Now().Add(time.Hour * 12)
	}

	// Get VAPID Authorization header
	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		options.Subscriber,
		options.VAPIDPublicKey,
		options.VAPIDPrivateKey,
		expiration,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", vapidAuthHeader)

	// Send the request
	var transport http.RoundTripper
	if options.Transport != nil {
		transport = options.Transport
	} else {
		transport = http.DefaultTransport
	}
	client := http.Client{
		Transport: transport,
	}

	return client.Do(req)
}

// Returns a key of length "length" given an hkdf function
func getHKDFKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		return key, err
	}

	return key, nil
}

func pad(payload *bytes.Buffer, maxPadLen int) error {
	if payload.Len() > maxPadLen {
		return ErrMaxPadExceeded
	}

	padding := make([]byte, maxPadLen-payload.Len())
	if _, err := payload.Write(padding); err != nil {
		return err
	}

	return nil
}
