package rtsp-engine

import (
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/format"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/rtcpsender"
)

type serverStreamFormat struct {
	format     format.Format
	rtcpSender *rtcpsender.RTCPSender
}
