//go:build enable_highlevel_tests
// +build enable_highlevel_tests

package highleveltests

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/require"

	"github.com/likeMindedLabs/rtsp-engine/v2"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/base"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/format"
	"github.com/likeMindedLabs/rtsp-engine/v2/pkg/media"
)

var serverCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIUHFnymlrkEnz3ThpFvSrqybBepn4wDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MB4X
DTIxMTIwMzIxNDg0MFoXDTMxMTIwMTIxNDg0MFowWTELMAkGA1UEBhMCQVUxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAv8h21YDIAYNzewrfQqQTlODJjuUZKxMCO7z1wIapem5I+1I8n+vD
v8qvuyZk1m9CKQPfXxhJz0TT5kECoUY0KaDtykSzfaUK34F9J1d5snDkaOtN48W+
8l39Wtcvc5JW17jNwabppAkHHYAMQryO8urKLWKbZmLhYCJdYgNqb8ciWPsnYNA0
zcnKML9zQphh7dxPq1wCsy/c/XZUzxTLAe8hsCKuqpESEX3MMJA9gOLmiOF0JgpT
9h6eqvJU8IK0QMIv3tekJWSBvTLyz4ghENs10sMKKNqR6NWt2SsOloeBkOhIDLOk
byLaPEvugrQsga99uhANRpXp+CHnVeAH8QIDAQABo1MwUTAdBgNVHQ4EFgQUwyEH
cMynEoy1/TnbIhgpEAs038gwHwYDVR0jBBgwFoAUwyEHcMynEoy1/TnbIhgpEAs0
38gwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAiV56KhDoUVzW
qV1X0QbfLaifimsN3Na3lUgmjcgyUe8rHj09pXuAD/AcQw/zwKzZ6dPtizBeNLN8
jV1dbJmR7DE3MDlndgMKTOKFsqzHjG9UTXkBGFUEM1shn2GE8XcvDF0AzKU82YjP
B0KswA1NoYTNP2PW4IhZRzv2M+fnmkvc8DSEZ+dxEMg3aJfe/WLPvYjDpFXLvuxl
YnerRQ04hFysh5eogPFpB4KyyPs6jGnQFmZCbFyk9pjKRbDPJc6FkDglkzTB6j3Q
TSfgNJswOiap13vQQKf5Vu7LTuyO4Wjfjr74QNqMLLNIgcC7n2jfQj1g5Xa0bnF5
G4tLrCLUUw==
-----END CERTIFICATE-----
`)

var serverKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC/yHbVgMgBg3N7
Ct9CpBOU4MmO5RkrEwI7vPXAhql6bkj7Ujyf68O/yq+7JmTWb0IpA99fGEnPRNPm
QQKhRjQpoO3KRLN9pQrfgX0nV3mycORo603jxb7yXf1a1y9zklbXuM3BpumkCQcd
gAxCvI7y6sotYptmYuFgIl1iA2pvxyJY+ydg0DTNycowv3NCmGHt3E+rXAKzL9z9
dlTPFMsB7yGwIq6qkRIRfcwwkD2A4uaI4XQmClP2Hp6q8lTwgrRAwi/e16QlZIG9
MvLPiCEQ2zXSwwoo2pHo1a3ZKw6Wh4GQ6EgMs6RvIto8S+6CtCyBr326EA1Glen4
IedV4AfxAgMBAAECggEAOqcJSNSA1o2oJKo3i374iiCRJAWGw/ilRzXMBtxoOow9
/7av2czV6fMH+XmNf1M5bafEiaW49Q28rH+XWVFKJK0V7DVEm5l9EMveRcjn7B3A
jSHhiVZxxlfeYwjKd1L7AjB/pMjyTXuBVJFTrplSMpKB0I2GrzJwcOExpAcdZx98
K0s5pauJH9bE0kI3p585SGQaIjrz0LvAmf6cQ5HhKfahJdWNnKZ/S4Kdqe+JCgyd
NawREHhf3tU01Cd3DOgXn4+5V/Ts6XtqY1RuSvonNv3nyeiOpX8C4cHKD5u2sNOC
3J4xWrrs0W3e8IATgAys56teKbEufHTUx52wNhAbzQKBgQD56W0tPCuaKrsjxsvE
dNHdm/9aQrN1jCJxUcGaxCIioXSyDvpSKcgxQbEqHXRTtJt5/Kadz9omq4vFTVtl
5Gf+3Lrf3ZT82SvYHtlIMdBZLlKwk6MolEa0KGAuJBNJVRIOkm5YjV/3bJebeTIb
WrLEyNCOXFAh3KVzBPU8nJ1aTwKBgQDEdISg3UsSOLBa0BfoJ5FlqGepZSufYgqh
xAJn8EbopnlzfmHBZAhE2+Igh0xcHhQqHThc3OuLtAkWu6fUSLiSA+XjU9TWPpA1
C/325rhT23fxzYIlYFegR9BToxYhv14ufkcTXRfHRAhffk7K5A2nlJfldDZRmUh2
5KIjXQ0pvwKBgQCa7S6VgFu3cw4Ym8DuxUzlCTRADGGcWYdwoLJY84YF2fmx+L8N
+ID2qDbgWOooiipocUwJQTWIC4jWg6JJhFNEGCpxZbhbF3aqwFULAHadEq6IcL4R
Bfre7LjTYeHi8C4FgpmNo/b+N/+0jmmVs6BnheZkmq3CkDqxFz3AmYai2QKBgQC1
kzAmcoJ5U/YD6YO/Khsjx3QQSBb6mCZVf5HtuVIApCVqzuvRUACojEbDY+n61j4y
8pDum64FkKA557Xl6lTVeE7ZPtlgL7EfpnbT5kmGEDobPqPEofg7h0SQmRLSnEqT
VFmjFw7sOQA4Ksjuk7vfIOMHy9KMts0YPpdxcgbBhwKBgQCP8MeRPuhZ26/oIESr
I8ArLEaPebYmLXCT2ZTudGztoyYFxinRGHA4PdamSOKfB1li52wAaqgRA3cSqkUi
kabimVOvrOAWlnvznqXEHPNx6mbbKs08jh+uRRmrOmMrxAobpTqarL2Sdxb6afID
NkxNic7oHgsZpIkZ8HK+QjAAWA==
-----END PRIVATE KEY-----
`)

type testServerHandler struct {
	onConnOpen     func(*rtsp-engine.ServerHandlerOnConnOpenCtx)
	onConnClose    func(*rtsp-engine.ServerHandlerOnConnCloseCtx)
	onSessionOpen  func(*rtsp-engine.ServerHandlerOnSessionOpenCtx)
	onSessionClose func(*rtsp-engine.ServerHandlerOnSessionCloseCtx)
	onDescribe     func(*rtsp-engine.ServerHandlerOnDescribeCtx) (*base.Response, *rtsp-engine.ServerStream, error)
	onAnnounce     func(*rtsp-engine.ServerHandlerOnAnnounceCtx) (*base.Response, error)
	onSetup        func(*rtsp-engine.ServerHandlerOnSetupCtx) (*base.Response, *rtsp-engine.ServerStream, error)
	onPlay         func(*rtsp-engine.ServerHandlerOnPlayCtx) (*base.Response, error)
	onRecord       func(*rtsp-engine.ServerHandlerOnRecordCtx) (*base.Response, error)
	onPause        func(*rtsp-engine.ServerHandlerOnPauseCtx) (*base.Response, error)
	onSetParameter func(*rtsp-engine.ServerHandlerOnSetParameterCtx) (*base.Response, error)
	onGetParameter func(*rtsp-engine.ServerHandlerOnGetParameterCtx) (*base.Response, error)
}

func (sh *testServerHandler) OnConnOpen(ctx *rtsp-engine.ServerHandlerOnConnOpenCtx) {
	if sh.onConnOpen != nil {
		sh.onConnOpen(ctx)
	}
}

func (sh *testServerHandler) OnConnClose(ctx *rtsp-engine.ServerHandlerOnConnCloseCtx) {
	if sh.onConnClose != nil {
		sh.onConnClose(ctx)
	}
}

func (sh *testServerHandler) OnSessionOpen(ctx *rtsp-engine.ServerHandlerOnSessionOpenCtx) {
	if sh.onSessionOpen != nil {
		sh.onSessionOpen(ctx)
	}
}

func (sh *testServerHandler) OnSessionClose(ctx *rtsp-engine.ServerHandlerOnSessionCloseCtx) {
	if sh.onSessionClose != nil {
		sh.onSessionClose(ctx)
	}
}

func (sh *testServerHandler) OnDescribe(ctx *rtsp-engine.ServerHandlerOnDescribeCtx) (*base.Response, *rtsp-engine.ServerStream, error) {
	if sh.onDescribe != nil {
		return sh.onDescribe(ctx)
	}
	return nil, nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnAnnounce(ctx *rtsp-engine.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	if sh.onAnnounce != nil {
		return sh.onAnnounce(ctx)
	}
	return nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnSetup(ctx *rtsp-engine.ServerHandlerOnSetupCtx) (*base.Response, *rtsp-engine.ServerStream, error) {
	if sh.onSetup != nil {
		return sh.onSetup(ctx)
	}
	return nil, nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnPlay(ctx *rtsp-engine.ServerHandlerOnPlayCtx) (*base.Response, error) {
	if sh.onPlay != nil {
		return sh.onPlay(ctx)
	}
	return nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnRecord(ctx *rtsp-engine.ServerHandlerOnRecordCtx) (*base.Response, error) {
	if sh.onRecord != nil {
		return sh.onRecord(ctx)
	}
	return nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnPause(ctx *rtsp-engine.ServerHandlerOnPauseCtx) (*base.Response, error) {
	if sh.onPause != nil {
		return sh.onPause(ctx)
	}
	return nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnSetParameter(ctx *rtsp-engine.ServerHandlerOnSetParameterCtx) (*base.Response, error) {
	if sh.onSetParameter != nil {
		return sh.onSetParameter(ctx)
	}
	return nil, fmt.Errorf("unimplemented")
}

func (sh *testServerHandler) OnGetParameter(ctx *rtsp-engine.ServerHandlerOnGetParameterCtx) (*base.Response, error) {
	if sh.onGetParameter != nil {
		return sh.onGetParameter(ctx)
	}
	return nil, fmt.Errorf("unimplemented")
}

type container struct {
	name string
}

func newContainer(image string, name string, args []string) (*container, error) {
	c := &container{
		name: name,
	}

	exec.Command("docker", "kill", "rtsp-engine-test-"+name).Run()
	exec.Command("docker", "wait", "rtsp-engine-test-"+name).Run()

	cmd := []string{
		"docker", "run",
		"--network=host",
		"--name=rtsp-engine-test-" + name,
		"rtsp-engine-test-" + image,
	}
	cmd = append(cmd, args...)
	ecmd := exec.Command(cmd[0], cmd[1:]...)
	ecmd.Stdout = nil
	ecmd.Stderr = os.Stderr

	err := ecmd.Start()
	if err != nil {
		return nil, err
	}

	time.Sleep(1 * time.Second)

	return c, nil
}

func (c *container) close() {
	exec.Command("docker", "kill", "rtsp-engine-test-"+c.name).Run()
	exec.Command("docker", "wait", "rtsp-engine-test-"+c.name).Run()
	exec.Command("docker", "rm", "rtsp-engine-test-"+c.name).Run()
}

func (c *container) wait() int {
	exec.Command("docker", "wait", "rtsp-engine-test-"+c.name).Run()
	out, _ := exec.Command("docker", "inspect", "rtsp-engine-test-"+c.name,
		"--format={{.State.ExitCode}}").Output()
	code, _ := strconv.ParseInt(string(out[:len(out)-1]), 10, 64)
	return int(code)
}

func buildImage(image string) error {
	ecmd := exec.Command("docker", "build", filepath.Join("images", image),
		"-t", "rtsp-engine-test-"+image)
	ecmd.Stdout = nil
	ecmd.Stderr = os.Stderr
	return ecmd.Run()
}

func TestServerRecordRead(t *testing.T) {
	files, err := os.ReadDir("images")
	require.NoError(t, err)

	for _, file := range files {
		err := buildImage(file.Name())
		require.NoError(t, err)
	}

	for _, ca := range []struct {
		publisherSoft  string
		publisherProto string
		readerSoft     string
		readerProto    string
	}{
		{"ffmpeg", "udp", "ffmpeg", "udp"},
		{"ffmpeg", "udp", "gstreamer", "udp"},
		{"gstreamer", "udp", "ffmpeg", "udp"},
		{"gstreamer", "udp", "gstreamer", "udp"},

		{"ffmpeg", "tcp", "ffmpeg", "tcp"},
		{"ffmpeg", "tcp", "gstreamer", "tcp"},
		{"gstreamer", "tcp", "ffmpeg", "tcp"},
		{"gstreamer", "tcp", "gstreamer", "tcp"},

		{"ffmpeg", "tcp", "ffmpeg", "udp"},
		{"ffmpeg", "udp", "ffmpeg", "tcp"},

		{"ffmpeg", "tls", "ffmpeg", "tls"},
		{"ffmpeg", "tls", "gstreamer", "tls"},
		{"gstreamer", "tls", "ffmpeg", "tls"},
		{"gstreamer", "tls", "gstreamer", "tls"},

		{"ffmpeg", "udp", "ffmpeg", "multicast"},
		{"ffmpeg", "udp", "gstreamer", "multicast"},
	} {
		t.Run(ca.publisherSoft+"_"+ca.publisherProto+"_"+
			ca.readerSoft+"_"+ca.readerProto, func(t *testing.T) {
			var mutex sync.Mutex
			var stream *rtsp-engine.ServerStream
			var publisher *rtsp-engine.ServerSession

			s := &rtsp-engine.Server{
				Handler: &testServerHandler{
					onSessionClose: func(ctx *rtsp-engine.ServerHandlerOnSessionCloseCtx) {
						mutex.Lock()
						defer mutex.Unlock()

						if stream != nil {
							if ctx.Session == publisher {
								stream.Close()
								stream = nil
							}
						}
					},
					onDescribe: func(ctx *rtsp-engine.ServerHandlerOnDescribeCtx) (*base.Response, *rtsp-engine.ServerStream, error) {
						if ctx.Path != "test/stream" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, nil, fmt.Errorf("invalid path (%s)", ctx.Request.URL)
						}
						if ctx.Query != "key=val" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, nil, fmt.Errorf("invalid query (%s)", ctx.Query)
						}

						mutex.Lock()
						defer mutex.Unlock()

						if stream == nil {
							return &base.Response{
								StatusCode: base.StatusNotFound,
							}, nil, nil
						}

						return &base.Response{
							StatusCode: base.StatusOK,
						}, stream, nil
					},
					onAnnounce: func(ctx *rtsp-engine.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
						if ctx.Path != "test/stream" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("invalid path (%s)", ctx.Request.URL)
						}
						if ctx.Query != "key=val" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("invalid query (%s)", ctx.Query)
						}

						mutex.Lock()
						defer mutex.Unlock()

						if stream != nil {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("someone is already publishing")
						}

						stream = rtsp-engine.NewServerStream(ctx.Medias)
						publisher = ctx.Session

						return &base.Response{
							StatusCode: base.StatusOK,
						}, nil
					},
					onSetup: func(ctx *rtsp-engine.ServerHandlerOnSetupCtx) (*base.Response, *rtsp-engine.ServerStream, error) {
						if ctx.Path != "test/stream" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, nil, fmt.Errorf("invalid path (%s)", ctx.Request.URL)
						}
						if ctx.Query != "key=val" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, nil, fmt.Errorf("invalid query (%s)", ctx.Query)
						}

						if stream == nil {
							return &base.Response{
								StatusCode: base.StatusNotFound,
							}, nil, nil
						}

						return &base.Response{
							StatusCode: base.StatusOK,
						}, stream, nil
					},
					onPlay: func(ctx *rtsp-engine.ServerHandlerOnPlayCtx) (*base.Response, error) {
						if ctx.Path != "test/stream" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("invalid path (%s)", ctx.Request.URL)
						}
						if ctx.Query != "key=val" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("invalid query (%s)", ctx.Query)
						}

						return &base.Response{
							StatusCode: base.StatusOK,
						}, nil
					},
					onRecord: func(ctx *rtsp-engine.ServerHandlerOnRecordCtx) (*base.Response, error) {
						if ctx.Path != "test/stream" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("invalid path (%s)", ctx.Request.URL)
						}
						if ctx.Query != "key=val" {
							return &base.Response{
								StatusCode: base.StatusBadRequest,
							}, fmt.Errorf("invalid query (%s)", ctx.Query)
						}

						ctx.Session.OnPacketRTPAny(func(medi *media.Media, forma format.Format, pkt *rtp.Packet) {
							stream.WritePacketRTP(medi, pkt)
						})

						return &base.Response{
							StatusCode: base.StatusOK,
						}, nil
					},
				},
				RTSPAddress: "localhost:8554",
			}

			var proto string
			if ca.publisherProto == "tls" {
				proto = "rtsps"
				cert, err := tls.X509KeyPair(serverCert, serverKey)
				require.NoError(t, err)
				s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			} else {
				proto = "rtsp"
				s.UDPRTPAddress = "127.0.0.1:8000"
				s.UDPRTCPAddress = "127.0.0.1:8001"
				s.MulticastIPRange = "224.1.0.0/16"
				s.MulticastRTPPort = 8002
				s.MulticastRTCPPort = 8003
			}

			err := s.Start()
			require.NoError(t, err)
			defer s.Close()

			switch ca.publisherSoft {
			case "ffmpeg":
				ts := func() string {
					switch ca.publisherProto {
					case "udp", "tcp":
						return ca.publisherProto
					}
					return "tcp"
				}()

				cnt1, err := newContainer("ffmpeg", "publish", []string{
					"-re",
					"-stream_loop", "-1",
					"-i", "emptyvideo.mkv",
					"-c", "copy",
					"-f", "rtsp",
					"-rtsp_transport", ts,
					proto + "://localhost:8554/test/stream?key=val",
				})
				require.NoError(t, err)
				defer cnt1.close()

			case "gstreamer":
				ts := func() string {
					switch ca.publisherProto {
					case "udp", "tcp":
						return ca.publisherProto
					}
					return "tcp"
				}()

				cnt1, err := newContainer("gstreamer", "publish", []string{
					"filesrc location=emptyvideo.mkv ! matroskademux ! video/x-h264 ! rtspclientsink " +
						"location=" + proto + "://127.0.0.1:8554/test/stream?key=val protocols=" + ts +
						" tls-validation-flags=0 latency=0 timeout=0 rtx-time=0",
				})
				require.NoError(t, err)
				defer cnt1.close()

				time.Sleep(1 * time.Second)
			}

			time.Sleep(1 * time.Second)

			switch ca.readerSoft {
			case "ffmpeg":
				ts := func() string {
					switch ca.readerProto {
					case "udp", "tcp":
						return ca.readerProto
					case "multicast":
						return "udp_multicast"
					}
					return "tcp"
				}()

				cnt2, err := newContainer("ffmpeg", "read", []string{
					"-rtsp_transport", ts,
					"-i", proto + "://localhost:8554/test/stream?key=val",
					"-vframes", "1",
					"-f", "image2",
					"-y", "/dev/null",
				})
				require.NoError(t, err)
				defer cnt2.close()
				require.Equal(t, 0, cnt2.wait())

			case "gstreamer":
				ts := func() string {
					switch ca.readerProto {
					case "udp", "tcp":
						return ca.readerProto
					case "multicast":
						return "udp-mcast"
					}
					return "tcp"
				}()

				cnt2, err := newContainer("gstreamer", "read", []string{
					"rtspsrc location=" + proto + "://127.0.0.1:8554/test/stream?key=val protocols=" + ts +
						" tls-validation-flags=0 latency=0 " +
						"! application/x-rtp,media=video ! decodebin ! exitafterframe ! fakesink",
				})
				require.NoError(t, err)
				defer cnt2.close()
				require.Equal(t, 0, cnt2.wait())
			}
		})
	}
}
