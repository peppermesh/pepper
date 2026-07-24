# SPDX-License-Identifier: Apache-2.0

from confluent_kafka import Consumer, Producer, libversion
from confluent_kafka.admin import AdminClient, NewTopic

BOOTSTRAP = "127.0.0.1:19092"
TOPIC = "phase11-librdkafka"

print("librdkafka", libversion())
admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
admin.create_topics([NewTopic(TOPIC, num_partitions=1, replication_factor=3)])[
    TOPIC
].result(15)

producer = Producer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "enable.idempotence": True,
        "acks": "all",
    }
)
producer.produce(TOPIC, value=b"idempotent")
producer.flush(15)

transactional = Producer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "transactional.id": "phase11-librdkafka-transaction",
        "transaction.timeout.ms": 15000,
    }
)
transactional.init_transactions(15)
transactional.begin_transaction()
transactional.produce(TOPIC, value=b"committed")
transactional.commit_transaction(15)
transactional.begin_transaction()
transactional.produce(TOPIC, value=b"aborted")
transactional.abort_transaction(15)

consumer = Consumer(
    {
        "bootstrap.servers": BOOTSTRAP,
        "group.id": "phase11-read-committed",
        "auto.offset.reset": "earliest",
        "isolation.level": "read_committed",
    }
)
consumer.subscribe([TOPIC])
values = []
while len(values) < 2:
    message = consumer.poll(15)
    assert message is not None, values
    assert message.error() is None, message.error()
    values.append(message.value())
consumer.close()
assert values == [b"idempotent", b"committed"], values
print("phase11 idempotence and transactions ok", values)
