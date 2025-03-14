# AWS IOT Core

This example demonstrates How to use IoT Safe PKCS11 middleware to connect to AWS IOT Core. There are two example, one is written in 
1. [pkcs11_pubsub.py](python/pkcs11_pubsub.py), python application written based on two example application in [aws-iot-device-sdk-python-v2](https://github.com/aws/aws-iot-device-sdk-python-v2) version [9518299](https://github.com/aws/aws-iot-device-sdk-python-v2/commit/9518299b90b5979bae2140ed69123c809fdd1609), which are [pubsub.py](https://github.com/aws/aws-iot-device-sdk-python-v2/blob/main/samples/pubsub.py) and [pkcs11_connect.py](https://github.com/aws/aws-iot-device-sdk-python-v2/blob/main/samples/pkcs11_connect.py).

2. [pkcs11_pubsub.cpp](cpp/pkcs11_pubsub.cpp)

## pkcs11_pubsub.py
### Dependencies
To run this example, you need Python 3.x and dependency below

- awscrt
- python-pkcs11

You can install these dependencies using the following command:

```bash
pip3 install awscrt python-pkcs11
```

### Build

please configure the `cmdData` inside the source code 
```
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
```


### Run

you can run the application by executing this command
```
python3 pkcs11_pubsub.py
```