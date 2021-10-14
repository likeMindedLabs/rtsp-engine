package gortsplib

import (
	"github.com/likeMindedLabs/rtsp-engine/pkg/base"
)

// StreamType is the stream type.
type StreamType = base.StreamType

const (
	// StreamTypeRTP means that the stream contains RTP packets
	StreamTypeRTP StreamType = base.StreamTypeRTP

	// StreamTypeRTCP means that the stream contains RTCP packets
	StreamTypeRTCP StreamType = base.StreamTypeRTCP
)
