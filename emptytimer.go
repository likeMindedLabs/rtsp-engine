package rtsp-engine

import (
	"time"
)

func emptyTimer() *time.Timer {
	t := time.NewTimer(0)
	<-t.C
	return t
}
