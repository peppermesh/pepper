#!/usr/bin/env python3

import kafka
from kafka import KafkaConsumer, KafkaProducer
from kafka.admin import KafkaAdminClient, NewTopic

BOOTSTRAP = "127.0.0.1:19092"
TOPIC = "python-smoke"

print("kafka-python-ng", kafka.__version__)
probe = KafkaAdminClient(bootstrap_servers=BOOTSTRAP, client_id="pepper-python-probe")
probe.close()
admin = KafkaAdminClient(
    bootstrap_servers=BOOTSTRAP,
    client_id="pepper-python-admin",
    api_version=(0, 11, 0),
)
admin.create_topics([NewTopic(TOPIC, num_partitions=1, replication_factor=3)])
assert admin.describe_topics([TOPIC])[0]["topic"] == TOPIC

for value in (b"python-one", b"python-two"):
    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        acks="all",
        compression_type=None,
        api_version=(0, 11, 0),
    )
    producer.send(TOPIC, value=value).get(timeout=10)
    producer.close(timeout=10)

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BOOTSTRAP,
    group_id="phase10-python",
    enable_auto_commit=False,
    auto_offset_reset="earliest",
    consumer_timeout_ms=10_000,
    api_version=(0, 11, 0),
)
values = [next(consumer).value, next(consumer).value]
consumer.commit()
consumer.close()
assert values == [b"python-one", b"python-two"], values

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP,
    acks="all",
    compression_type=None,
    api_version=(0, 11, 0),
)
producer.send(TOPIC, value=b"python-three").get(timeout=10)
producer.close(timeout=10)
consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BOOTSTRAP,
    group_id="phase10-python",
    enable_auto_commit=False,
    auto_offset_reset="earliest",
    consumer_timeout_ms=10_000,
    api_version=(0, 11, 0),
)
resumed = next(consumer).value
consumer.close()
assert resumed == b"python-three", resumed
admin.delete_topics([TOPIC])
admin.close()
print("ok", [value.decode() for value in values], resumed.decode())
