package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address, StatePath, TokenA, TokenB                                                                              string
	APNSEnabled                                                                                                     bool
	APNSTeamID, APNSKeyID, APNSKeyPath                                                                              string
	APNSTopicIOS, APNSTopicWatch, APNSTopicIOSVoIP, APNSTopicWatchVoIP                                              string
	RingTimeout                                                                                                     time.Duration
	SMSProvider, SMSClubToken, SMSClubOriginator, AccountStatePath, DeviceKeyStatePath, MessageStatePath, OTPPepper string
	SMSMaxSendsPerDay                                                                                               int
	AccountAuthEnabled                                                                                              bool
}

func Load() (Config, error) {
	c := Config{
		Address: getenv("WSC_ADDRESS", "127.0.0.1:8790"), StatePath: getenv("WSC_STATE_PATH", "/opt/wifi-secure-call/state/devices.json"),
		TokenA: os.Getenv("WSC_TOKEN_A"), TokenB: os.Getenv("WSC_TOKEN_B"), APNSEnabled: os.Getenv("APNS_ENABLED") == "true",
		APNSTeamID: os.Getenv("APNS_TEAM_ID"), APNSKeyID: os.Getenv("APNS_KEY_ID"), APNSKeyPath: os.Getenv("APNS_KEY_PATH"),
		APNSTopicIOS: getenv("APNS_TOPIC_IOS", "com.vkapps.wifisecurecall"), APNSTopicWatch: getenv("APNS_TOPIC_WATCH", "com.vkapps.wifisecurecall.watchkitapp"),
		APNSTopicIOSVoIP: getenv("APNS_TOPIC_IOS_VOIP", "com.vkapps.wifisecurecall.voip"), APNSTopicWatchVoIP: getenv("APNS_TOPIC_WATCH_VOIP", "com.vkapps.wifisecurecall.watchkitapp.voip"),
		RingTimeout:  30 * time.Second,
		SMSProvider:  getenv("SMS_PROVIDER", "disabled"),
		SMSClubToken: os.Getenv("SMSCLUB_TOKEN"), SMSClubOriginator: os.Getenv("SMSCLUB_ORIGINATOR"),
		AccountStatePath:   getenv("WSC_ACCOUNT_STATE_PATH", "/opt/wifi-secure-call/state/accounts.json"),
		DeviceKeyStatePath: getenv("WSC_DEVICE_KEY_STATE_PATH", "/opt/wifi-secure-call/state/device-keys.json"),
		MessageStatePath:   getenv("WSC_MESSAGE_STATE_PATH", "/opt/wifi-secure-call/state/messages.json"),
		OTPPepper:          os.Getenv("WSC_OTP_PEPPER"),
	}
	if raw := os.Getenv("SMS_MAX_SENDS_PER_DAY"); raw != "" {
		c.SMSMaxSendsPerDay, _ = strconv.Atoi(raw)
	}
	if len(c.TokenA) < 32 || len(c.TokenB) < 32 || c.TokenA == c.TokenB || strings.ContainsAny(c.TokenA+c.TokenB, " \t\r\n") {
		return Config{}, errors.New("distinct WSC_TOKEN_A and WSC_TOKEN_B are required")
	}
	if c.APNSEnabled && (c.APNSTeamID == "" || c.APNSKeyID == "" || c.APNSKeyPath == "") {
		return Config{}, errors.New("APNs enabled but key configuration is incomplete")
	}
	if c.SMSProvider != "disabled" && c.SMSProvider != "smsclub" {
		return Config{}, errors.New("invalid SMS_PROVIDER")
	}
	accountConfigPresent := c.OTPPepper != "" || os.Getenv("SMS_MAX_SENDS_PER_DAY") != ""
	if c.SMSProvider == "disabled" && accountConfigPresent {
		if len(c.OTPPepper) < 32 || c.SMSMaxSendsPerDay <= 0 {
			return Config{}, errors.New("account authentication configuration is incomplete")
		}
		c.AccountAuthEnabled = true
	}
	if c.SMSProvider == "smsclub" && (c.SMSClubToken == "" || c.SMSClubOriginator == "" || len(c.OTPPepper) < 32 || c.SMSMaxSendsPerDay <= 0) {
		return Config{}, errors.New("SMSClub configuration is incomplete")
	}
	if c.SMSProvider == "smsclub" {
		c.AccountAuthEnabled = true
	}
	return c, nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
