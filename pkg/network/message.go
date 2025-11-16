// Package network - Message serialization and handling
package network

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"time"
)

// MessageHeader contains message metadata
type MessageHeader struct {
	Version     uint16
	Type        MessageType
	From        int32
	To          int32
	Sequence    uint64
	Timestamp   int64
	NonceSize   uint16
	PayloadSize uint32
	MACSize     uint16
}

const (
	// CurrentProtocolVersion is the current protocol version
	CurrentProtocolVersion uint16 = 1

	// HeaderSize is the fixed size of the message header
	HeaderSize = 2 + 1 + 4 + 4 + 8 + 8 + 2 + 4 + 2 // 35 bytes

	// MaxNonceSize is the maximum nonce size
	MaxNonceSize = 32

	// MaxMACSize is the maximum MAC size
	MaxMACSize = 64
)

// Serialize serializes a message to bytes
func (m *Message) Serialize() ([]byte, error) {
	// Calculate sizes
	nonceSize := len(m.Nonce)
	if nonceSize > MaxNonceSize {
		return nil, ErrMessageTooLarge
	}

	payloadSize := len(m.Payload)
	macSize := len(m.MAC)
	if macSize > MaxMACSize {
		return nil, ErrMessageTooLarge
	}

	sessionIDSize := len(m.SessionID)

	// Create buffer
	totalSize := HeaderSize + sessionIDSize + nonceSize + payloadSize + macSize
	buf := make([]byte, totalSize)

	// Write header
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:], CurrentProtocolVersion)
	offset += 2

	buf[offset] = byte(m.Type)
	offset += 1

	binary.BigEndian.PutUint32(buf[offset:], uint32(m.From))
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:], uint32(m.To))
	offset += 4

	binary.BigEndian.PutUint64(buf[offset:], m.Sequence)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(m.Timestamp.Unix()))
	offset += 8

	binary.BigEndian.PutUint16(buf[offset:], uint16(nonceSize))
	offset += 2

	binary.BigEndian.PutUint32(buf[offset:], uint32(payloadSize))
	offset += 4

	binary.BigEndian.PutUint16(buf[offset:], uint16(macSize))
	offset += 2

	// Write SessionID (16 bytes assumed)
	copy(buf[offset:offset+sessionIDSize], m.SessionID)
	offset += sessionIDSize

	// Write nonce
	copy(buf[offset:offset+nonceSize], m.Nonce)
	offset += nonceSize

	// Write payload
	copy(buf[offset:offset+payloadSize], m.Payload)
	offset += payloadSize

	// Write MAC
	copy(buf[offset:offset+macSize], m.MAC)

	return buf, nil
}

// Deserialize deserializes a message from bytes
func DeserializeMessage(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, ErrInvalidMessage
	}

	offset := 0

	// Read header
	version := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if version != CurrentProtocolVersion {
		return nil, ErrInvalidMessage
	}

	msgType := MessageType(data[offset])
	offset += 1

	from := int32(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	to := int32(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	sequence := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	timestamp := int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	nonceSize := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	payloadSize := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	macSize := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// Validate sizes
	if nonceSize > MaxNonceSize || macSize > MaxMACSize {
		return nil, ErrInvalidMessage
	}

	// Assume SessionID is 16 bytes for now
	sessionIDSize := 16
	expectedSize := HeaderSize + sessionIDSize + nonceSize + payloadSize + macSize

	if len(data) < expectedSize {
		return nil, ErrInvalidMessage
	}

	// Read SessionID
	sessionID := make([]byte, sessionIDSize)
	copy(sessionID, data[offset:offset+sessionIDSize])
	offset += sessionIDSize

	// Read nonce
	nonce := make([]byte, nonceSize)
	copy(nonce, data[offset:offset+nonceSize])
	offset += nonceSize

	// Read payload
	payload := make([]byte, payloadSize)
	copy(payload, data[offset:offset+payloadSize])
	offset += payloadSize

	// Read MAC
	mac := make([]byte, macSize)
	copy(mac, data[offset:offset+macSize])

	return &Message{
		Type:      msgType,
		From:      int(from),
		To:        int(to),
		SessionID: sessionID,
		Payload:   payload,
		MAC:       mac,
		Timestamp: time.Unix(timestamp, 0),
		Nonce:     nonce,
		Sequence:  sequence,
	}, nil
}

// NewMessage creates a new message
func NewMessage(msgType MessageType, from, to int, sessionID, payload []byte) (*Message, error) {
	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return &Message{
		Type:      msgType,
		From:      from,
		To:        to,
		SessionID: sessionID,
		Payload:   payload,
		Timestamp: time.Now(),
		Nonce:     nonce,
		Sequence:  0, // Will be set by sender
	}, nil
}

// EncodePayload encodes arbitrary data into payload
func EncodePayload(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodePayload decodes payload into data
func DecodePayload(payload []byte, data interface{}) error {
	buf := bytes.NewBuffer(payload)
	dec := gob.NewDecoder(buf)

	return dec.Decode(data)
}

// ValidateMessage validates message fields
func ValidateMessage(msg *Message, maxPayloadSize int) error {
	if msg == nil {
		return ErrInvalidMessage
	}

	if msg.From < 0 {
		return ErrInvalidPartyID
	}

	if msg.To < -1 {
		return ErrInvalidPartyID
	}

	if len(msg.SessionID) == 0 {
		return ErrInvalidMessage
	}

	if len(msg.Payload) > maxPayloadSize {
		return ErrMessageTooLarge
	}

	if len(msg.Nonce) == 0 {
		return ErrInvalidNonce
	}

	if msg.Timestamp.IsZero() {
		return ErrInvalidMessage
	}

	return nil
}

// Clone creates a deep copy of a message
func (m *Message) Clone() *Message {
	clone := &Message{
		Type:      m.Type,
		From:      m.From,
		To:        m.To,
		Sequence:  m.Sequence,
		Timestamp: m.Timestamp,
	}

	if m.SessionID != nil {
		clone.SessionID = make([]byte, len(m.SessionID))
		copy(clone.SessionID, m.SessionID)
	}

	if m.Payload != nil {
		clone.Payload = make([]byte, len(m.Payload))
		copy(clone.Payload, m.Payload)
	}

	if m.MAC != nil {
		clone.MAC = make([]byte, len(m.MAC))
		copy(clone.MAC, m.MAC)
	}

	if m.Nonce != nil {
		clone.Nonce = make([]byte, len(m.Nonce))
		copy(clone.Nonce, m.Nonce)
	}

	return clone
}

// String returns a string representation of message type
func (mt MessageType) String() string {
	switch mt {
	case MessageTypeDKGRound1:
		return "DKG_ROUND_1"
	case MessageTypeDKGRound2:
		return "DKG_ROUND_2"
	case MessageTypeDKGRound3:
		return "DKG_ROUND_3"
	case MessageTypeSignRound1:
		return "SIGN_ROUND_1"
	case MessageTypeSignRound2:
		return "SIGN_ROUND_2"
	case MessageTypeSignRound3:
		return "SIGN_ROUND_3"
	case MessageTypeSignRound4:
		return "SIGN_ROUND_4"
	case MessageTypePreSignRound1:
		return "PRESIGN_ROUND_1"
	case MessageTypePreSignRound2:
		return "PRESIGN_ROUND_2"
	case MessageTypeHeartbeat:
		return "HEARTBEAT"
	case MessageTypeAck:
		return "ACK"
	case MessageTypeError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// IsProtocolMessage returns true if message is part of core protocol
func (mt MessageType) IsProtocolMessage() bool {
	switch mt {
	case MessageTypeDKGRound1, MessageTypeDKGRound2, MessageTypeDKGRound3,
		MessageTypeSignRound1, MessageTypeSignRound2, MessageTypeSignRound3, MessageTypeSignRound4,
		MessageTypePreSignRound1, MessageTypePreSignRound2:
		return true
	default:
		return false
	}
}
