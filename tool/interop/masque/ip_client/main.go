// connect-ip-go v0.6.0 client against a pqtransport CONNECT-IP proxy.
// The peer certificate must verify as ML-DSA-65.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	proxy := flag.String("proxy", "", "host:port of the CONNECT-IP proxy")
	caPath := flag.String("ca", "", "PEM trust anchor")
	flag.Parse()
	if *proxy == "" || *caPath == "" {
		fmt.Fprintln(os.Stderr, "usage: ip-client -proxy host:port -ca ca.pem")
		os.Exit(64)
	}
	pem, err := os.ReadFile(*caPath)
	if err != nil {
		fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fatal(fmt.Errorf("ca pem was not a certificate"))
	}
	var peerAlg x509.SignatureAlgorithm
	tlsConf := &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			peerAlg = cs.PeerCertificates[0].SignatureAlgorithm
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	template := "https://" + *proxy + "/.well-known/masque/ip/*/*/"
	req, err := connectip.NewRequest(ctx, uritemplate.MustNew(template))
	if err != nil {
		fatal(err)
	}
	conn, err := quic.DialAddr(ctx, *proxy, tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  10 * time.Second,
	})
	if err != nil {
		fatal(err)
	}
	defer conn.CloseWithError(0, "")
	tr := &http3.Transport{EnableDatagrams: true}
	ipConn, rsp, err := connectip.NewClientConn(tr.NewClientConn(conn)).Dial(req)
	if err != nil {
		fatal(err)
	}
	defer ipConn.Close()
	if rsp.StatusCode != 200 {
		fatal(fmt.Errorf("status %d", rsp.StatusCode))
	}
	assigned, err := ipConn.ReceiveAddressAssignment(ctx)
	if err != nil {
		fatal(err)
	}
	if len(assigned) != 1 || assigned[0].IPPrefix.String() != "192.0.2.11/32" {
		fatal(fmt.Errorf("assignment %v", assigned))
	}
	routes, err := ipConn.Routes(ctx)
	if err != nil {
		fatal(err)
	}
	if len(routes) != 1 || routes[0].IPProtocol != 0 {
		fatal(fmt.Errorf("routes %v", routes))
	}
	packet := ipv4(net4(192, 0, 2, 11), net4(198, 51, 100, 1), 17)
	if _, err = ipConn.WritePacket(packet); err != nil {
		fatal(err)
	}
	buf := make([]byte, 1500)
	type readResult struct {
		n   int
		err error
	}
	readDone := make(chan readResult, 1)
	go func() {
		n, err := ipConn.ReadPacket(buf)
		readDone <- readResult{n, err}
	}()
	var n int
	select {
	case got := <-readDone:
		if got.err != nil {
			fatal(got.err)
		}
		n = got.n
	case <-ctx.Done():
		fatal(ctx.Err())
	}
	if n != len(packet) || buf[9] != 17 ||
		buf[12] != 198 || buf[13] != 51 || buf[14] != 100 || buf[15] != 1 ||
		buf[16] != 192 || buf[17] != 0 || buf[18] != 2 || buf[19] != 11 {
		fatal(fmt.Errorf("reply %x", buf[:n]))
	}
	if peerAlg != x509.MLDSA65 {
		fatal(fmt.Errorf("peer signature %s", peerAlg))
	}
	fmt.Printf("connect-ip status=200 assign=192.0.2.11/32 echo=%d peer=%s\n", n, peerAlg)
}

func net4(a, b, c, d byte) [4]byte { return [4]byte{a, b, c, d} }

func ipv4(src, dst [4]byte, proto byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], 20)
	h[8] = 64
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(h[10:12], checksum)
	return h
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "connect-ip-go: %v\n", err)
	os.Exit(1)
}
