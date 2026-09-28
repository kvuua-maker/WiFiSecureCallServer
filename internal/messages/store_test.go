package messages

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	userA   = "11111111-1111-4111-8111-111111111111"
	userB   = "22222222-2222-4222-8222-222222222222"
	userC   = "33333333-3333-4333-8333-333333333333"
	deviceA = "44444444-4444-4444-8444-444444444444"
	deviceB = "55555555-5555-4555-8555-555555555555"
)

func opaqueInput(messageID, requestID string) MessageInput {
	encoded := func(size int, fill byte) string { return base64.StdEncoding.EncodeToString(makeBytes(size, fill)) }
	return MessageInput{MessageID: messageID, ClientMessageID: requestID, ProtocolVersion: 1, KeyVersion: 1, Nonce: encoded(12, 1), Ciphertext: encoded(32, 2), Tag: encoded(16, 3), Signature: encoded(64, 4), Envelopes: []Envelope{{DeviceID: deviceB, EphemeralPublicKey: encoded(32, 5), Nonce: encoded(12, 6), Ciphertext: encoded(32, 7), Tag: encoded(16, 8), KeyVersion: 1}}}
}
func makeBytes(size int, fill byte) []byte {
	value := make([]byte, size)
	for i := range value {
		value[i] = fill
	}
	return value
}

func TestEncryptedMessagePersistencePaginationReceiptsAndAuthorization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	conversation, created, err := store.CreateConversation("66666666-6666-4666-8666-666666666666", userA, userB)
	if err != nil || !created {
		t.Fatalf("conversation created=%v err=%v", created, err)
	}
	firstInput := opaqueInput("77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888")
	first, created, err := store.Send(conversation.ConversationID, userA, deviceA, firstInput)
	if err != nil || !created {
		t.Fatalf("send created=%v err=%v", created, err)
	}
	if _, created, err = store.Send(conversation.ConversationID, userA, deviceA, firstInput); err != nil || created {
		t.Fatalf("idempotent created=%v err=%v", created, err)
	}
	secondInput := opaqueInput("99999999-9999-4999-8999-999999999999", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if _, _, err = store.Send(conversation.ConversationID, userA, deviceA, secondInput); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(conversation.ConversationID, userB, "", 1)
	if err != nil || len(page.Messages) != 1 || page.NextCursor == "" || page.Messages[0].MessageID != secondInput.MessageID {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	page2, err := store.Page(conversation.ConversationID, userB, page.NextCursor, 1)
	if err != nil || len(page2.Messages) != 1 || page2.Messages[0].MessageID != first.MessageID {
		t.Fatalf("page2=%+v err=%v", page2, err)
	}
	if _, _, err = store.Mark(conversation.ConversationID, first.MessageID, userC, deviceB, true); ErrorCode(err) != "conversation_not_participant" {
		t.Fatalf("nonparticipant err=%v", err)
	}
	marked, changed, err := store.Mark(conversation.ConversationID, first.MessageID, userB, deviceB, true)
	if err != nil || !changed || len(marked.Receipts) != 1 || marked.Receipts[0].DeliveredAt == nil || marked.Receipts[0].ReadAt == nil {
		t.Fatalf("receipt=%+v changed=%v err=%v", marked, changed, err)
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reloaded.Page(conversation.ConversationID, userA, "", 10)
	if err != nil || len(loaded.Messages) != 2 || len(loaded.Messages[0].Receipts) != 1 || loaded.Messages[0].MessageID != first.MessageID {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || containsPlaintext(raw) {
		t.Fatal("persistent state contained plaintext sentinel")
	}
}

func TestNewestFirstStablePaginationPreservesChronologicalPages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pagination.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tick := 0
	store.SetClock(func() time.Time {
		value := base.Add(time.Duration(tick) * time.Second)
		tick++
		return value
	})
	conversation, _, err := store.CreateConversation("10101010-1010-4010-8010-101010101010", userA, userB)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 35; index++ {
		input := opaqueInput(uuidForIndex(index), uuidForIndex(index+1000))
		input.Ciphertext = base64.StdEncoding.EncodeToString(makeBytes(32, byte(index)))
		if _, _, err = store.Send(conversation.ConversationID, userA, deviceA, input); err != nil {
			t.Fatalf("send %d: %v", index, err)
		}
	}

	newest, err := store.Page(conversation.ConversationID, userB, "", 0)
	if err != nil || len(newest.Messages) != 30 || newest.NextCursor == "" {
		t.Fatalf("newest count=%d cursor=%q err=%v", len(newest.Messages), newest.NextCursor, err)
	}
	for offset, message := range newest.Messages {
		index := offset + 6
		if message.MessageID != uuidForIndex(index) {
			t.Fatalf("newest[%d]=%s want=%s", offset, message.MessageID, uuidForIndex(index))
		}
		wantCiphertext := base64.StdEncoding.EncodeToString(makeBytes(32, byte(index)))
		if message.Ciphertext != wantCiphertext {
			t.Fatalf("ciphertext changed for %s", message.MessageID)
		}
	}

	older, err := store.Page(conversation.ConversationID, userB, newest.NextCursor, 30)
	if err != nil || len(older.Messages) != 5 || older.NextCursor != "" {
		t.Fatalf("older count=%d cursor=%q err=%v", len(older.Messages), older.NextCursor, err)
	}
	for offset, message := range older.Messages {
		if message.MessageID != uuidForIndex(offset+1) {
			t.Fatalf("older[%d]=%s want=%s", offset, message.MessageID, uuidForIndex(offset+1))
		}
	}
	combined := append(append([]Message(nil), older.Messages...), newest.Messages...)
	if len(combined) != 35 {
		t.Fatalf("combined count=%d", len(combined))
	}
	for offset, message := range combined {
		if message.MessageID != uuidForIndex(offset+1) {
			t.Fatalf("combined[%d]=%s want=%s", offset, message.MessageID, uuidForIndex(offset+1))
		}
	}

	input := opaqueInput(uuidForIndex(36), uuidForIndex(1036))
	input.Ciphertext = base64.StdEncoding.EncodeToString(makeBytes(32, byte(36)))
	if _, _, err = store.Send(conversation.ConversationID, userA, deviceA, input); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	restartNewest, err := reloaded.Page(conversation.ConversationID, userB, "", 30)
	if err != nil || len(restartNewest.Messages) != 30 || restartNewest.Messages[0].MessageID != uuidForIndex(7) || restartNewest.Messages[29].MessageID != uuidForIndex(36) {
		t.Fatalf("restart newest=%+v err=%v", restartNewest, err)
	}
	for offset, message := range restartNewest.Messages {
		index := offset + 7
		wantCiphertext := base64.StdEncoding.EncodeToString(makeBytes(32, byte(index)))
		if message.Ciphertext != wantCiphertext {
			t.Fatalf("restart ciphertext changed for %s", message.MessageID)
		}
	}
	stableOlder, err := reloaded.Page(conversation.ConversationID, userB, newest.NextCursor, 30)
	if err != nil || len(stableOlder.Messages) != 5 {
		t.Fatalf("stable older=%d err=%v", len(stableOlder.Messages), err)
	}
	for offset, message := range stableOlder.Messages {
		index := offset + 1
		if message.MessageID != uuidForIndex(index) {
			t.Fatalf("stable older[%d]=%s", offset, message.MessageID)
		}
		wantCiphertext := base64.StdEncoding.EncodeToString(makeBytes(32, byte(index)))
		if message.Ciphertext != wantCiphertext {
			t.Fatalf("stable older ciphertext changed for %s", message.MessageID)
		}
	}
	if _, err = store.Page(conversation.ConversationID, userB, "not-a-valid-cursor", 30); ErrorCode(err) != "invalid_cursor" {
		t.Fatalf("malformed cursor err=%v", err)
	}
	unknown := base64.RawURLEncoding.EncodeToString([]byte(uuidForIndex(9999)))
	if _, err = store.Page(conversation.ConversationID, userB, unknown, 30); ErrorCode(err) != "invalid_cursor" {
		t.Fatalf("unknown cursor err=%v", err)
	}
}

func TestMessagePageLimitIsCappedAtOneHundred(t *testing.T) {
	store := NewMemory()
	base := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	tick := 0
	store.SetClock(func() time.Time {
		value := base.Add(time.Duration(tick) * time.Second)
		tick++
		return value
	})
	conversation, _, err := store.CreateConversation("20202020-2020-4020-8020-202020202020", userA, userB)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 105; index++ {
		if _, _, err = store.Send(conversation.ConversationID, userA, deviceA, opaqueInput(uuidForIndex(index), uuidForIndex(index+2000))); err != nil {
			t.Fatalf("send %d: %v", index, err)
		}
	}
	page, err := store.Page(conversation.ConversationID, userB, "", 101)
	if err != nil || len(page.Messages) != 100 {
		t.Fatalf("page count=%d err=%v", len(page.Messages), err)
	}
	if page.Messages[0].MessageID != uuidForIndex(6) || page.Messages[99].MessageID != uuidForIndex(105) || page.NextCursor == "" {
		t.Fatalf("first=%v last=%v cursor=%q", page.Messages[0].MessageID, page.Messages[99].MessageID, page.NextCursor)
	}
}

func TestConcurrentSendsRemainAtomic(t *testing.T) {
	store := NewMemory()
	conversation, _, err := store.CreateConversation("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", userA, userB)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := 0; i < 20; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			messageID := uuidForIndex(index + 1)
			requestID := uuidForIndex(index + 101)
			if _, _, sendErr := store.Send(conversation.ConversationID, userA, deviceA, opaqueInput(messageID, requestID)); sendErr != nil {
				t.Errorf("send %d: %v", index, sendErr)
			}
		}(i)
	}
	wait.Wait()
	page, err := store.Page(conversation.ConversationID, userA, "", 100)
	if err != nil || len(page.Messages) != 20 {
		t.Fatalf("messages=%d err=%v", len(page.Messages), err)
	}
}

func uuidForIndex(value int) string { return "00000000-0000-4000-8000-" + leftPad12(value) }
func leftPad12(value int) string {
	text := "000000000000" + strconv.Itoa(value)
	return text[len(text)-12:]
}
func containsPlaintext(data []byte) bool {
	return bytes.Contains(data, []byte("private message sentinel"))
}
