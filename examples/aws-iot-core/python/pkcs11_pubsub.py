# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.
from awscrt import mqtt, http
from awscrt import io
from awsiot import mqtt_connection_builder
import sys
import threading
import time
import json
import pkcs11
from pkcs11 import ObjectClass, Attribute
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_der_x509_certificate
import base64
from types import SimpleNamespace

# This modified example from https://github.com/aws/aws-iot-device-sdk-python-v2/blob/main/samples/pkcs11_connect.py and https://github.com/aws/aws-iot-device-sdk-python-v2/blob/main/samples/pubsub.py
# Using IoT Safe PKCS11 middleware
#
# WARNING: Unix only. Currently, TLS integration with PKCS#11 is only available on Unix devices.

# cmdData is modified command_line_utils from aws example
# please configure this properly before run the application
cmdData = {
    "input_pkcs11_user_pin":"0000",
    "input_pkcs11_token_label":"Card #0000000000000000",
    "input_pkcs11_key_label":"01",
    "input_pkcs11_client_cert_id":"02",
    "input_pkcs11_ca_cert_id":"03",
    "input_endpoint":"", # please configure the URL
    "input_port":8883,
    "input_clientId":"basicPubSub",
    "input_pkcs11_lib_path":"/usr/local/lib/libgtosepkcs11.so", # or /usr/lib/libgtosepkcs11.so
    "input_count":0,
    "input_topic":"", # configure the correct topic
    "input_pkcs11_slot_id":None,
    "input_is_ci":None,
    "input_message":"Hello World from IOT Safe"
}
cmdData = SimpleNamespace(**cmdData)
received_count = 0
received_all_event = threading.Event()


def get_cert(id):
    lib = pkcs11.lib(cmdData.input_pkcs11_lib_path)
    tokens = list(lib.get_tokens())
    if not tokens:
        raise Exception("No PKCS#11 tokens found.")
    # Open a session with the first token
    session = tokens[0].open(user_pin=cmdData.input_pkcs11_user_pin)
    # Find certificates
    certs = list(session.get_objects({
        Attribute.CLASS: ObjectClass.CERTIFICATE,
        Attribute.ID:id.encode()  # ID must be bytes
    }))
    # Get the DER-encoded certificate bytes
    der_cert = certs[0][Attribute.VALUE]

    # Convert DER to PEM
    x509_cert = load_der_x509_certificate(der_cert)
    pem_cert = x509_cert.public_bytes(encoding=serialization.Encoding.PEM)

    session.close()
    return pem_cert
    
# Callback when connection is accidentally lost.
def on_connection_interrupted(connection, error, **kwargs):
    print("Connection interrupted. error: {}".format(error))

# Callback when an interrupted connection is re-established.
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))

    if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
        print("Session did not persist. Resubscribing to existing topics...")
        resubscribe_future, _ = connection.resubscribe_existing_topics()

        # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
        # evaluate result with a callback instead.
        resubscribe_future.add_done_callback(on_resubscribe_complete)

# Callback when the connection successfully connects
def on_connection_success(connection, callback_data):
    assert isinstance(callback_data, mqtt.OnConnectionSuccessData)
    print("Connection Successful with return code: {} session present: {}".format(callback_data.return_code, callback_data.session_present))

# Callback when a connection attempt fails
def on_connection_failure(connection, callback_data):
    assert isinstance(callback_data, mqtt.OnConnectionFailureData)
    print("Connection failed with error code: {}".format(callback_data.error))

def on_resubscribe_complete(resubscribe_future):
    resubscribe_results = resubscribe_future.result()
    print("Resubscribe results: {}".format(resubscribe_results))

    for topic, qos in resubscribe_results['topics']:
        if qos is None:
            sys.exit("Server rejected resubscribe to topic: {}".format(topic))


# Callback when the subscribed topic receives a message
def on_message_received(topic, payload, dup, qos, retain, **kwargs):
    print("Received message from topic '{}': {}".format(topic, payload))
    global received_count
    received_count += 1
    if received_count == cmdData.input_count:
        received_all_event.set()

# Callback when a connection has been disconnected or shutdown successfully
def on_connection_closed(connection, callback_data):
    print("Connection closed")

if __name__ == '__main__':

    print(f"Loading PKCS#11 library '{cmdData.input_pkcs11_lib_path}' ...")

    client_cert = get_cert(cmdData.input_pkcs11_client_cert_id)
    ca_cert = get_cert(cmdData.input_pkcs11_ca_cert_id)

    pkcs11_lib = io.Pkcs11Lib(
        file=cmdData.input_pkcs11_lib_path,
        behavior=io.Pkcs11Lib.InitializeFinalizeBehavior.DEFAULT)
    print("Loaded!")

    pkcs11_slot_id = None
    if (cmdData.input_pkcs11_slot_id):
        pkcs11_slot_id = int(cmdData.input_pkcs11_slot_id)

   
    # Create MQTT connection
    mqtt_connection = mqtt_connection_builder.mtls_with_pkcs11(
        pkcs11_lib=pkcs11_lib,
        user_pin=cmdData.input_pkcs11_user_pin,
        slot_id=pkcs11_slot_id,
        token_label=cmdData.input_pkcs11_token_label,
        private_key_label=cmdData.input_pkcs11_key_label,
        cert_bytes =client_cert,
        endpoint=cmdData.input_endpoint,
        port=cmdData.input_port,
        ca_bytes =ca_cert,
        on_connection_interrupted=on_connection_interrupted,
        on_connection_resumed=on_connection_resumed,
        on_connection_success=on_connection_success,
        on_connection_failure=on_connection_failure,
        on_connection_closed=on_connection_closed,
        client_id=cmdData.input_clientId,
        clean_session=False,
        keep_alive_secs=30)

    if not cmdData.input_is_ci:
        print(f"Connecting to {cmdData.input_endpoint} with client ID '{cmdData.input_clientId}'...")
    else:
        print("Connecting to endpoint with client ID")

    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    connect_future.result()
    print("Connected!")
    message_count = cmdData.input_count
    message_topic = cmdData.input_topic
    message_string = cmdData.input_message

    # Subscribe
    print("Subscribing to topic '{}'...".format(message_topic))
    subscribe_future, packet_id = mqtt_connection.subscribe(
        topic=message_topic,
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_message_received)

    subscribe_result = subscribe_future.result()
    print("Subscribed with {}".format(str(subscribe_result['qos'])))

    # Publish message to server desired number of times.
    # This step is skipped if message is blank.
    # This step loops forever if count was set to 0.
    if message_string:
        if message_count == 0:
            print("Sending messages until program killed")
        else:
            print("Sending {} message(s)".format(message_count))

        publish_count = 1
        while (publish_count <= message_count) or (message_count == 0):
            message = "{} [{}]".format(message_string, publish_count)
            print("Publishing message to topic '{}': {}".format(message_topic, message))
            message_json = json.dumps(message)
            mqtt_connection.publish(
                topic=message_topic,
                payload=message_json,
                qos=mqtt.QoS.AT_LEAST_ONCE)
            time.sleep(1)
            publish_count += 1

    # Wait for all messages to be received.
    # This waits forever if count was set to 0.
    if message_count != 0 and not received_all_event.is_set():
        print("Waiting for all messages to be received...")

    received_all_event.wait()
    print("{} message(s) received.".format(received_count))

    # Disconnect
    print("Disconnecting...")
    disconnect_future = mqtt_connection.disconnect()
    disconnect_future.result()
    print("Disconnected!")
