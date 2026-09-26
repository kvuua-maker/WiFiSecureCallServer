package smsclub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	token, originator, baseURL string
	http                       *http.Client
}

type sendRequest struct {
	Phone    []string `json:"phone"`
	Message  string   `json:"message"`
	Source   string   `json:"src_addr"`
	Lifetime int      `json:"lifetime"`
}

type statusRequest struct {
	MessageIDs []string `json:"id_sms"`
}

const (
	StatusEnroute     = "ENROUTE"
	StatusDelivered   = "DELIVRD"
	StatusExpired     = "EXPIRED"
	StatusUndelivered = "UNDELIV"
	StatusRejected    = "REJECTD"
)

type Error struct {
	Status    int
	Retryable bool
	Message   string
}

func (e *Error) Error() string { return e.Message }

func New(token, originator string) *Client {
	return &Client{token: token, originator: originator, baseURL: "https://im.smsclub.mobi", http: &http.Client{Timeout: 8 * time.Second}}
}

func NewWithHTTP(token, originator, baseURL string, client *http.Client) *Client {
	return &Client{token: token, originator: originator, baseURL: strings.TrimRight(baseURL, "/"), http: client}
}

func (c *Client) Send(ctx context.Context, phoneE164, message string) (string, error) {
	if !strings.HasPrefix(phoneE164, "+") {
		return "", errors.New("phone must be canonical E.164")
	}
	body, err := json.Marshal(sendRequest{Phone: []string{strings.TrimPrefix(phoneE164, "+")}, Message: message, Source: c.originator, Lifetime: 10})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/sms/send", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", &Error{Status: resp.StatusCode, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, Message: fmt.Sprintf("SMSClub status %d", resp.StatusCode)}
	}
	var payload struct {
		Success struct {
			Info json.RawMessage `json:"info"`
		} `json:"success_request"`
	}
	if json.Unmarshal(data, &payload) != nil || len(payload.Success.Info) == 0 {
		return "", errors.New("invalid SMSClub response")
	}
	id := messageID(payload.Success.Info, strings.TrimPrefix(phoneE164, "+"))
	if id == "" {
		return "", errors.New("SMSClub response missing message ID")
	}
	return id, nil
}

func (c *Client) Status(ctx context.Context, messageID string) (string, error) {
	if strings.TrimSpace(messageID) == "" {
		return "", errors.New("message ID is required")
	}
	body, err := json.Marshal(statusRequest{MessageIDs: []string{messageID}})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/sms/status", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", &Error{Status: resp.StatusCode, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, Message: fmt.Sprintf("SMSClub status %d", resp.StatusCode)}
	}
	var payload struct {
		Success struct {
			Info map[string]string `json:"info"`
		} `json:"success_request"`
	}
	if json.Unmarshal(data, &payload) != nil {
		return "", errors.New("invalid SMSClub response")
	}
	status := payload.Success.Info[messageID]
	switch status {
	case StatusEnroute, StatusDelivered, StatusExpired, StatusUndelivered, StatusRejected:
		return status, nil
	default:
		return "", errors.New("SMSClub response missing delivery status")
	}
}

func messageID(raw json.RawMessage, expectedPhone string) string {
	var info map[string]json.RawMessage
	if json.Unmarshal(raw, &info) != nil {
		return ""
	}
	for id, encodedPhone := range info {
		var phone string
		if json.Unmarshal(encodedPhone, &phone) == nil && phone == expectedPhone {
			return id
		}
	}
	return ""
}
