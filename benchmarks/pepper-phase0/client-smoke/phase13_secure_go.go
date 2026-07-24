// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	certificate, err := os.ReadFile("/qualification/phase13-ca.pem")
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		panic("invalid qualification CA")
	}
	options := []kgo.Opt{
		kgo.SeedBrokers("127.0.0.1:19092"),
		kgo.DialTLSConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}),
		kgo.SASL(scram.Auth{
			User: "qualification",
			Pass: "qualification-password",
		}.AsSha256Mechanism()),
	}
	client, err := kgo.NewClient(options...)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	const topic = "phase13-secure-franz-go"
	admin := kadm.NewClient(client)
	created, err := admin.CreateTopics(ctx, 1, 3, nil, topic)
	if err != nil || created[topic].Err != nil {
		panic(fmt.Sprintf("create: %v %v", err, created[topic].Err))
	}
	if err := client.ProduceSync(ctx, &kgo.Record{
		Topic: topic,
		Value: []byte("franz-secure"),
	}).FirstErr(); err != nil {
		panic(err)
	}
	client.Close()
	client, err = kgo.NewClient(append(options,
		kgo.ConsumerGroup("phase13-secure-franz-go"),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)...)
	if err != nil {
		panic(err)
	}
	fetched := client.PollRecords(ctx, 1)
	if len(fetched.Errors()) != 0 || len(fetched.Records()) != 1 ||
		string(fetched.Records()[0].Value) != "franz-secure" {
		panic(fmt.Sprintf("fetch: %#v %#v", fetched.Errors(), fetched.Records()))
	}
	if err := client.CommitRecords(ctx, fetched.Records()...); err != nil {
		panic(err)
	}
	client.Close()
	client, err = kgo.NewClient(options...)
	if err != nil {
		panic(err)
	}
	deleted, err := kadm.NewClient(client).DeleteTopics(ctx, topic)
	if err != nil || deleted[topic].Err != nil {
		panic(fmt.Sprintf("delete: %v %v", err, deleted[topic].Err))
	}
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, module := range info.Deps {
			if module.Path == "github.com/twmb/franz-go" {
				version = module.Version
			}
		}
	}
	fmt.Println("franz-go", version, "TLS/SCRAM/group flow ok")
}
