package main

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

func main() {
	ctx := context.Background()
	const bootstrap = "127.0.0.1:19092"
	const topic = "go-smoke"
	client, err := kgo.NewClient(
		kgo.SeedBrokers(bootstrap),
		kgo.DisableIdempotentWrite(),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.NoCompression()),
	)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	admin := kadm.NewClient(client)
	created, err := admin.CreateTopics(ctx, 1, 3, nil, topic)
	if err != nil || created[topic].Err != nil {
		panic(fmt.Sprintf("create: %v %v", err, created[topic].Err))
	}
	metadata, err := admin.Metadata(ctx, topic)
	if err != nil || len(metadata.Topics) != 1 {
		panic(fmt.Sprintf("metadata: %v", err))
	}
	for _, value := range []string{"go-one", "go-two"} {
		client.Close()
		client, err = kgo.NewClient(
			kgo.SeedBrokers(bootstrap),
			kgo.DisableIdempotentWrite(),
			kgo.RequiredAcks(kgo.AllISRAcks()),
			kgo.ProducerBatchCompression(kgo.NoCompression()),
		)
		if err != nil {
			panic(err)
		}
		if err = client.ProduceSync(ctx, &kgo.Record{Topic: topic, Value: []byte(value)}).FirstErr(); err != nil {
			panic(err)
		}
	}
	client.Close()
	client, err = kgo.NewClient(
		kgo.SeedBrokers(bootstrap),
		kgo.ConsumerGroup("phase10-franz-go"),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		panic(err)
	}
	fetched := client.PollRecords(ctx, 2)
	if errs := fetched.Errors(); len(errs) != 0 {
		panic(errs)
	}
	values := []string{}
	for _, record := range fetched.Records() {
		values = append(values, string(record.Value))
	}
	if len(values) != 2 || values[0] != "go-one" || values[1] != "go-two" {
		panic(fmt.Sprintf("values: %#v", values))
	}
	if err := client.CommitRecords(ctx, fetched.Records()...); err != nil {
		panic(err)
	}
	client.Close()
	client, err = kgo.NewClient(
		kgo.SeedBrokers(bootstrap),
		kgo.DisableIdempotentWrite(),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.NoCompression()),
	)
	if err != nil {
		panic(err)
	}
	if err = client.ProduceSync(ctx, &kgo.Record{Topic: topic, Value: []byte("go-three")}).FirstErr(); err != nil {
		panic(err)
	}
	client.Close()
	client, err = kgo.NewClient(
		kgo.SeedBrokers(bootstrap),
		kgo.ConsumerGroup("phase10-franz-go"),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		panic(err)
	}
	resumed := client.PollRecords(ctx, 1)
	if errs := resumed.Errors(); len(errs) != 0 {
		panic(errs)
	}
	if len(resumed.Records()) != 1 || string(resumed.Records()[0].Value) != "go-three" {
		panic(fmt.Sprintf("resume: %#v", resumed.Records()))
	}
	client.Close()
	client, _ = kgo.NewClient(kgo.SeedBrokers(bootstrap))
	defer client.Close()
	admin = kadm.NewClient(client)
	deleted, err := admin.DeleteTopics(ctx, topic)
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
	fmt.Println("franz-go", version, "ok", values, "go-three")
}
