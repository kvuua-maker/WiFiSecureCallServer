package server

import (
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/usercalls"
)

type combinedCallValidator struct {
	account *accountcalls.Store
	user    *usercalls.Store
}

func (v combinedCallValidator) ValidateMedia(id, side, token string) bool {
	return v.account != nil && v.account.ValidateMedia(id, side, token) || v.user != nil && v.user.ValidateMedia(id, side, token)
}

func (v combinedCallValidator) MediaPeerJoined(id, side, epoch string) bool {
	accountReady := v.account != nil && v.account.MediaPeerJoined(id, side, epoch)
	userReady := v.user != nil && v.user.MediaPeerJoined(id, side, epoch)
	return accountReady || userReady
}

func (v combinedCallValidator) MediaPeerLeft(id, side, epoch string) {
	if v.account != nil {
		v.account.MediaPeerLeft(id, side, epoch)
	}
	if v.user != nil {
		v.user.MediaPeerLeft(id, side, epoch)
	}
}

func (v combinedCallValidator) IsAccepted(id string) bool {
	return v.account != nil && v.account.IsAccepted(id) || v.user != nil && v.user.IsAccepted(id)
}
