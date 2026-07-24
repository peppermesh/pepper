# SPDX-License-Identifier: Apache-2.0

import kafka
from kafka import KafkaConsumer, KafkaProducer
from kafka.admin import KafkaAdminClient, NewTopic

TOPIC = "phase13-secure-kafka-python"
SECURITY = {
    "bootstrap_servers": "127.0.0.1:19092",
    "security_protocol": "SASL_SSL",
    "ssl_cafile": "/qualification/phase13-ca.pem",
    "sasl_mechanism": "SCRAM-SHA-256",
    "sasl_plain_username": "qualification",
    "sasl_plain_password": "qualification-password",
    "api_version": (0, 11, 0),
}

print("kafka-python-ng", kafka.__version__)
admin = KafkaAdminClient(**SECURITY, client_id="phase13-secure-admin")
admin.create_topics([NewTopic(TOPIC, num_partitions=1, replication_factor=3)])
producer = KafkaProducer(**SECURITY, acks="all", compression_type=None)
producer.send(TOPIC, value=b"python-secure").get(timeout=15)
producer.close(timeout=15)
consumer = KafkaConsumer(
    TOPIC,
    **SECURITY,
    group_id="phase13-secure-python",
    enable_auto_commit=False,
    auto_offset_reset="earliest",
    consumer_timeout_ms=15_000,
)
message = next(consumer)
assert message.value == b"python-secure", message.value
consumer.commit()
consumer.close()
admin.delete_topics([TOPIC])
admin.close()
print("kafka-python-ng TLS/SCRAM/group flow ok")
