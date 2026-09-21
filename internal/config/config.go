package config

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	Address, StatePath, TokenA, TokenB                                 string
	APNSEnabled                                                        bool
	APNSTeamID, APNSKeyID, APNSKeyPath                                 string
	APNSTopicIOS, APNSTopicWatch, APNSTopicIOSVoIP, APNSTopicWatchVoIP string
	RingTimeout, MediaGrace                                            time.Duration
}

func Load() (Config, error) {
	c := Config{
		Address: getenv("WSC_ADDRESS", "127.0.0.1:8790"), StatePath: getenv("WSC_STATE_PATH", "/opt/wifi-secure-call/state/devices.json"),
		TokenA: os.Getenv("WSC_TOKEN_A"), TokenB: os.Getenv("WSC_TOKEN_B"), APNSEnabled: os.Getenv("APNS_ENABLED") == "true",
		APNSTeamID: os.Getenv("APNS_TEAM_ID"), APNSKeyID: os.Getenv("APNS_KEY_ID"), APNSKeyPath: os.Getenv("APNS_KEY_PATH"),
		APNSTopicIOS: getenv("APNS_TOPIC_IOS", "com.vkapps.wifisecurecall"), APNSTopicWatch: getenv("APNS_TOPIC_WATCH", "com.vkapps.wifisecurecall.watchkitapp"),
		APNSTopicIOSVoIP: getenv("APNS_TOPIC_IOS_VOIP", "com.vkapps.wifisecurecall.voip"), APNSTopicWatchVoIP: getenv("APNS_TOPIC_WATCH_VOIP", "com.vkapps.wifisecurecall.watchkitapp.voip"),
		RingTimeout: 30 * time.Second, MediaGrace: 10 * time.Second,
	}
	if c.TokenA == "" || c.TokenB == "" || c.TokenA == c.TokenB {
		return Config{}, errors.New("distinct WSC_TOKEN_A and WSC_TOKEN_B are required")
	}
	if c.APNSEnabled && (c.APNSTeamID == "" || c.APNSKeyID == "" || c.APNSKeyPath == "") {
		return Config{}, errors.New("APNs enabled but key configuration is incomplete")
	}
	return c, nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
