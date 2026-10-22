// Package diagnostics stores structured client and server events as JSON lines.
//
// One file, append only, one JSON object per line. That keeps a failed read cheap
// (the whole file is never parsed during a request), and it means a crash during a
// write can lose at most the last line instead of the file.
//
// Nothing personal is stored: no phone numbers, no names, no tokens, no audio. A
// device is identified by the opaque installation id the app already uses, and free
// text is truncated.
package diagnostics

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is one diagnostic event.
type Record struct {
	Timestamp time.Time `json:"timestamp"`
	Device    string    `json:"device"`
	Category  string    `json:"category"`
	Step      string    `json:"step"`
	Status    string    `json:"status"`
	Details   string    `json:"details,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Store appends records to a file and reads them back with filters.
type Store struct {
	mu   sync.Mutex
	path string

	// maxFileBytes bounds the file so a device stuck in a loop cannot fill the
	// disk. When it is exceeded the file is rotated to <path>.1.
	maxFileBytes int64
}

// New opens (and creates) the store at path.
func New(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("diagnostics: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("diagnostics: create directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: open: %w", err)
	}
	_ = file.Close()
	return &Store{path: path, maxFileBytes: 64 << 20}, nil
}

// Path is where records are written.
func (s *Store) Path() string { return s.path }

// Append writes a batch. A batch is either fully appended or not at all.
func (s *Store) Append(records []Record) error {
	if len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("diagnostics: open for append: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	now := time.Now().UTC()
	for _, record := range records {
		if record.Timestamp.IsZero() {
			record.Timestamp = now
		}
		record.Device = sanitise(record.Device, 64)
		record.Category = sanitise(record.Category, 48)
		record.Step = sanitise(record.Step, 64)
		record.Status = sanitise(record.Status, 32)
		record.Details = sanitise(record.Details, 512)
		record.Error = sanitise(record.Error, 512)

		line, err := json.Marshal(record)
		if err != nil {
			continue
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("diagnostics: write: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("diagnostics: flush: %w", err)
	}
	if info, err := file.Stat(); err == nil && info.Size() > s.maxFileBytes {
		s.rotateLocked()
	}
	return nil
}

// rotateLocked moves the current file aside so the next write starts clean.
func (s *Store) rotateLocked() {
	_ = os.Rename(s.path, s.path+".1")
}

// Filter selects records for reading.
type Filter struct {
	Device   string
	Category string
	Status   string
	Limit    int
}

// Read returns matching records, oldest first.
func (s *Store) Read(filter Filter) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("diagnostics: open for read: %w", err)
	}
	defer file.Close()

	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 200
	}

	var matched []Record
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		if filter.Device != "" && !strings.EqualFold(record.Device, filter.Device) {
			continue
		}
		if filter.Category != "" && !strings.EqualFold(record.Category, filter.Category) {
			continue
		}
		if filter.Status != "" && !strings.EqualFold(record.Status, filter.Status) {
			continue
		}
		matched = append(matched, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("diagnostics: scan: %w", err)
	}

	// Newest last, but only the last Limit records are wanted.
	if len(matched) > filter.Limit {
		matched = matched[len(matched)-filter.Limit:]
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Timestamp.Before(matched[j].Timestamp)
	})
	return matched, nil
}

// Summary counts records by category, then by status within each category.
func Summary(records []Record) map[string]map[string]int {
	out := map[string]map[string]int{}
	for _, record := range records {
		if out[record.Category] == nil {
			out[record.Category] = map[string]int{}
		}
		out[record.Category][record.Status]++
	}
	return out
}

// sanitise trims a value to a length and strips control characters, so a record
// cannot smuggle newlines into the file or carry a phone number by accident.
func sanitise(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
