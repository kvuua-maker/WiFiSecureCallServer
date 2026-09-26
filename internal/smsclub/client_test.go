package smsclub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSendContractAndSuccessID(t *testing.T) {
	client := NewWithHTTP("test-token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/sms/send" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("unexpected request")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		phones := body["phone"].([]any)
		if phones[0] != "380501234567" || body["message"] != "message" || body["src_addr"] != "Alpha" || body["lifetime"] != float64(10) {
			t.Fatalf("unexpected body: %#v", body)
		}
		return smsResponse(200, `{"success_request":{"info":{"sms-id":"380501234567"}}}`), nil
	})})
	id, err := client.Send(context.Background(), "+380501234567", "message")
	if err != nil || id != "sms-id" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestSendDoesNotMistakePhoneNumberForMessageID(t *testing.T) {
	client := NewWithHTTP("token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return smsResponse(200, `{"success_request":{"info":{"380501234567":"sms-id"}}}`), nil
	})})
	if _, err := client.Send(context.Background(), "+380501234567", "message"); err == nil {
		t.Fatal("reversed SMSClub response accepted")
	}
}

func TestStatusContractAndDeliveryStates(t *testing.T) {
	for _, expected := range []string{StatusEnroute, StatusDelivered, StatusExpired, StatusUndelivered, StatusRejected} {
		t.Run(expected, func(t *testing.T) {
			client := NewWithHTTP("test-token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Path != "/sms/status" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != "application/json" {
					t.Fatal("unexpected request")
				}
				var body struct {
					MessageIDs []string `json:"id_sms"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.MessageIDs) != 1 || body.MessageIDs[0] != "sms-id" {
					t.Fatalf("unexpected body: %#v err=%v", body, err)
				}
				return smsResponse(200, `{"success_request":{"info":{"sms-id":"`+expected+`"}}}`), nil
			})})
			status, err := client.Status(context.Background(), "sms-id")
			if err != nil || status != expected {
				t.Fatalf("status=%q err=%v", status, err)
			}
		})
	}
}

func TestStatusRejectsMissingAndUnknownProviderState(t *testing.T) {
	client := NewWithHTTP("token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return smsResponse(200, `{"success_request":{"info":{"sms-id":"UNKNOWN"}}}`), nil
	})})
	if _, err := client.Status(context.Background(), ""); err == nil {
		t.Fatal("empty message ID accepted")
	}
	if _, err := client.Status(context.Background(), "sms-id"); err == nil {
		t.Fatal("unknown status accepted")
	}
}

func TestSendErrorsMalformedAndCancellation(t *testing.T) {
	for _, status := range []int{400, 401, 429, 453, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := NewWithHTTP("token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return smsResponse(status, `{}`), nil })})
			_, err := client.Send(context.Background(), "+380501234567", "message")
			var typed *Error
			if !errors.As(err, &typed) || typed.Status != status || typed.Retryable != (status == 429 || status >= 500) {
				t.Fatalf("error=%#v", err)
			}
		})
	}
	malformed := NewWithHTTP("token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return smsResponse(200, `{oops`), nil })})
	if _, err := malformed.Send(context.Background(), "+380501234567", "message"); err == nil {
		t.Fatal("malformed response accepted")
	}
	cancelled := NewWithHTTP("token", "Alpha", "https://example.invalid", &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cancelled.Send(ctx, "+380501234567", "message"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func smsResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
