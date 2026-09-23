package config

import "testing"

func baseEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("WSC_TOKEN_A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("WSC_TOKEN_B", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	t.Setenv("APNS_ENABLED", "false")
	t.Setenv("SMS_PROVIDER", "disabled")
	t.Setenv("SMSCLUB_TOKEN", "")
	t.Setenv("SMSCLUB_ORIGINATOR", "")
	t.Setenv("WSC_OTP_PEPPER", "")
	t.Setenv("SMS_MAX_SENDS_PER_DAY", "")
}

func TestSMSDisabledIsSafeDefault(t *testing.T) {
	baseEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMSProvider != "disabled" || cfg.AccountStatePath != "/opt/wifi-secure-call/state/accounts.json" {
		t.Fatalf("config=%+v", cfg)
	}
}

func TestSMSClubFailsClosedUnlessComplete(t *testing.T) {
	baseEnvironment(t)
	t.Setenv("SMS_PROVIDER", "smsclub")
	if _, err := Load(); err == nil {
		t.Fatal("incomplete SMSClub config accepted")
	}
	t.Setenv("SMSCLUB_TOKEN", "secret")
	t.Setenv("SMSCLUB_ORIGINATOR", "Alpha")
	t.Setenv("WSC_OTP_PEPPER", "0123456789abcdef0123456789abcdef")
	t.Setenv("SMS_MAX_SENDS_PER_DAY", "100")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMSProvider != "smsclub" || cfg.SMSMaxSendsPerDay != 100 {
		t.Fatalf("config=%+v", cfg)
	}
}

func TestSMSDisabledCanKeepAccountAuthenticationEnabled(t *testing.T) {
	baseEnvironment(t)
	t.Setenv("WSC_OTP_PEPPER", "0123456789abcdef0123456789abcdef")
	t.Setenv("SMS_MAX_SENDS_PER_DAY", "100")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AccountAuthEnabled || cfg.SMSProvider != "disabled" {
		t.Fatalf("config=%+v", cfg)
	}

	t.Setenv("SMS_MAX_SENDS_PER_DAY", "")
	if _, err := Load(); err == nil {
		t.Fatal("partial disabled account-auth configuration accepted")
	}
}
