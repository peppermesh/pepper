#!/usr/bin/env python3

from confluent_kafka import Consumer, Producer, libversion
from confluent_kafka.admin import AdminClient, NewTopic

BOOTSTRAP = "127.0.0.1:19092"
TOPIC = "librdkafka-smoke"

print("librdkafka", libversion())
admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
admin.create_topics([NewTopic(TOPIC, num_partitions=1, replication_factor=3)])[TOPIC].result(10)
metadata = admin.list_topics(TOPIC, timeout=10)
assert TOPIC in metadata.topics

producer = Producer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "enable.idempotence": False,
        "acks": "all",
        "compression.type": "none",
    }
)
producer.produce(TOPIC, value=b"librdkafka-one")
producer.flush(10)
producer = Producer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "enable.idempotence": False,
        "acks": "all",
        "compression.type": "none",
    }
)
producer.produce(TOPIC, value=b"librdkafka-two")
assert producer.flush(10) == 0

consumer = Consumer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "group.id": "phase10-librdkafka",
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    }
)
consumer.subscribe([TOPIC])
values = []
while len(values) < 2:
    message = consumer.poll(10)
    assert message is not None, "consumer poll timed out"
    assert message.error() is None, message.error()
    values.append(message.value())
consumer.commit(asynchronous=False)
consumer.close()
assert values == [b"librdkafka-one", b"librdkafka-two"], values

producer.produce(TOPIC, value=b"librdkafka-three")
assert producer.flush(10) == 0
consumer = Consumer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "group.id": "phase10-librdkafka",
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
    }
)
consumer.subscribe([TOPIC])
resumed = consumer.poll(10)
assert resumed is not None and resumed.error() is None
assert resumed.value() == b"librdkafka-three", resumed.value()
consumer.close()
admin.delete_topics([TOPIC])[TOPIC].result(10)
print("ok", [value.decode() for value in values], resumed.value().decode())
