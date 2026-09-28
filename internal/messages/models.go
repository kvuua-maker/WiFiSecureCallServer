package messages

import "time"

const (
	SchemaVersion      = 1
	ProtocolVersion    = 1
	Retention          = 30 * 24 * time.Hour
	MaxCiphertextBytes = 16 * 1024
	MaxEnvelopes       = 32
)

type Envelope struct {
	DeviceID           string `json:"deviceID"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
	Tag                string `json:"tag"`
	KeyVersion         uint64 `json:"keyVersion"`
}

type MessageInput struct {
	MessageID       string     `json:"messageID"`
	ClientMessageID string     `json:"clientMessageID"`
	ProtocolVersion uint64     `json:"protocolVersion"`
	KeyVersion      uint64     `json:"keyVersion"`
	Nonce           string     `json:"nonce"`
	Ciphertext      string     `json:"ciphertext"`
	Tag             string     `json:"tag"`
	Envelopes       []Envelope `json:"envelopes"`
	Signature       string     `json:"signature"`
}

type Receipt struct {
	DeviceID    string     `json:"deviceID"`
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
	ReadAt      *time.Time `json:"readAt,omitempty"`
}

type Message struct {
	MessageID       string     `json:"messageID"`
	ConversationID  string     `json:"conversationID"`
	ClientMessageID string     `json:"clientMessageID"`
	SenderUserID    string     `json:"senderUserID"`
	SenderDeviceID  string     `json:"senderDeviceID"`
	RecipientUserID string     `json:"recipientUserID"`
	CreatedAt       time.Time  `json:"createdAt"`
	ProtocolVersion uint64     `json:"protocolVersion"`
	KeyVersion      uint64     `json:"keyVersion"`
	Nonce           string     `json:"nonce"`
	Ciphertext      string     `json:"ciphertext"`
	Tag             string     `json:"tag"`
	Envelopes       []Envelope `json:"envelopes"`
	Signature       string     `json:"signature"`
	Receipts        []Receipt  `json:"receipts"`
}

type Conversation struct {
	ConversationID string    `json:"conversationID"`
	Participants   []string  `json:"participants"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type Page struct {
	Messages   []Message `json:"messages"`
	NextCursor string    `json:"nextCursor,omitempty"`
}
