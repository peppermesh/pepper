# SPDX-License-Identifier: Apache-2.0

from confluent_kafka import Consumer, Producer, libversion
from confluent_kafka.admin import AdminClient, NewTopic

BOOTSTRAP = "127.0.0.1:19092"
TOPIC = "phase13-secure-librdkafka"
SECURITY = {
    "bootstrap.servers": BOOTSTRAP,
    "security.protocol": "SASL_SSL",
    "sasl.mechanism": "SCRAM-SHA-256",
    "sasl.username": "qualification",
    "sasl.password": "qualification-password",
    "ssl.ca.location": "/qualification/phase13-ca.pem",
}

print("librdkafka", libversion())
admin = AdminClient(SECURITY)
admin.create_topics([NewTopic(TOPIC, num_partitions=1, replication_factor=3)])[
    TOPIC
].result(15)

producer = Producer({**SECURITY, "enable.idempotence": True, "acks": "all"})
producer.produce(TOPIC, key=b"secure", value=b"idempotent")
assert producer.flush(15) == 0

transactional = Producer(
    {
        **SECURITY,
        "transactional.id": "phase13-secure-transaction",
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
        **SECURITY,
        "group.id": "phase13-secure-group",
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
consumer.commit(asynchronous=False)
consumer.close()
assert values == [b"idempotent", b"committed"], values
admin.delete_topics([TOPIC])[TOPIC].result(15)
print("phase13 TLS/SCRAM/idempotence/transactions/groups ok", values)
