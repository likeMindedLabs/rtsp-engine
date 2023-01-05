package main

import (
	"log"

	"github.com/likeMindedLabs/rtsp-engine/v2"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/format"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/media"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/url"
	"github.com/pion/rtp"
)

// This example shows how to
// 1. connect to a RTSP server and read all medias on a path
// 2. re-publish all medias on another path.

func main() {
	reader := rtsp-engine.Client{}

	// parse source URL
	sourceURL, err := url.Parse("rtsp://localhost:8554/mystream")
	if err != nil {
		panic(err)
	}

	// connect to the server
	err = reader.Start(sourceURL.Scheme, sourceURL.Host)
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	// find published medias
	medias, baseURL, _, err := reader.Describe(sourceURL)
	if err != nil {
		panic(err)
	}

	log.Printf("republishing %d medias", len(medias))

	// setup all medias
	// this must be called before StartRecording(), that overrides the control attribute.
	err = reader.SetupAll(medias, baseURL)
	if err != nil {
		panic(err)
	}

	// connect to the server and start recording the same medias
	publisher := rtsp-engine.Client{}
	err = publisher.StartRecording("rtsp://localhost:8554/mystream2", medias)
	if err != nil {
		panic(err)
	}
	defer publisher.Close()

	// read RTP packets from reader and write them to publisher
	reader.OnPacketRTPAny(func(medi *media.Media, forma format.Format, pkt *rtp.Packet) {
		publisher.WritePacketRTP(medi, pkt)
	})

	// start playing
	_, err = reader.Play(nil)
	if err != nil {
		panic(err)
	}

	// wait until a fatal error
	panic(reader.Wait())
}
