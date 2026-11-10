// masque-go v0.6.0 client against a pqtransport CONNECT-UDP proxy.
// The peer certificate must verify as ML-DSA-65. InsecureSkipVerify
// is not set.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	proxy := flag.String("proxy", "", "host:port of the CONNECT-UDP proxy")
	caPath := flag.String("ca", "", "PEM trust anchor")
	target := flag.String("target", "", "host:port to open through the proxy")
	flag.Parse()
	if *proxy == "" || *caPath == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: udp-client -proxy host:port -ca ca.pem -target host:port")
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
	template := "https://" + *proxy + "/.well-known/masque/udp/{target_host}/{target_port}/"
	req, err := masque.NewRequest(ctx, uritemplate.MustNew(template), *target)
	if err != nil {
		fatal(err)
	}
	tr := &masque.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			MaxIdleTimeout:  10 * time.Second,
		},
	}
	conn, rsp, err := tr.Dial(req)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()
	payload := []byte("ping-masque")
	if _, err = conn.WriteTo(payload, nil); err != nil {
		fatal(err)
	}
	buf := make([]byte, 1500)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		fatal(fmt.Errorf("payload %q", buf[:n]))
	}
	if peerAlg != x509.MLDSA65 {
		fatal(fmt.Errorf("peer signature %s", peerAlg))
	}
	fmt.Printf("connect-udp status=%d payload=%s peer=%s\n", rsp.StatusCode, payload, peerAlg)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "masque-go: %v\n", err)
	os.Exit(1)
}
