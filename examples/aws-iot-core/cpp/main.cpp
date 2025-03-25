/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/crt/Api.h>
#include <aws/crt/UUID.h>
#include <aws/crt/io/Pkcs11.h>
#include <aws/crt/UUID.h>

#include "utils/CommandLineUtils.h"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <thread>
using namespace Aws::Crt;

int main(int argc, char *argv[])
{

    /************************ Setup ****************************/

    // Do the global initialization for the API.
    ApiHandle apiHandle;

    /**
     * cmdData is the arguments/input from the command line placed into a single struct for
     * use in this sample. This handles all of the command line parsing, validating, etc.
     * See the Utils/CommandLineUtils for more information.
     */
    Utils::cmdData cmdData;
    cmdData.input_pkcs11UserPin = "0000";
    cmdData.input_pkcs11LibPath = "/usr/local/lib/libgtosepkcs11.so";
    cmdData.input_pkcs11TokenLabel = "Card #0000000000000000";
    cmdData.input_pkcs11KeyLabel = "0B";
    cmdData.input_pkcs11SlotId = 0;
    cmdData.input_endpoint = "";
    cmdData.input_clientId = "basicPubSub";
    cmdData.input_ca = "";
    cmdData.input_cert = "";
    cmdData.input_message = "Hello World from IOT Safe";
    cmdData.input_topic = "";

    String messagePayload = "\"" + cmdData.input_message + "\"";

    // Create the MQTT builder and populate it with data from cmdData.
    
    std::shared_ptr<Aws::Crt::Io::Pkcs11Lib> pkcs11Lib = Aws::Crt::Io::Pkcs11Lib::Create(cmdData.input_pkcs11LibPath);
    if (!pkcs11Lib)
    {
        fprintf(stderr, "Pkcs11Lib failed: %s\n", Aws::Crt::ErrorDebugString(Aws::Crt::LastError()));
        exit(-1);
    }
    Aws::Crt::Io::TlsContextPkcs11Options pkcs11Options(pkcs11Lib);
    pkcs11Options.SetCertificateFilePath(cmdData.input_cert);
    pkcs11Options.SetUserPin(cmdData.input_pkcs11UserPin);
    if (cmdData.input_pkcs11TokenLabel != "")
    {
        pkcs11Options.SetTokenLabel(cmdData.input_pkcs11TokenLabel);
    }
    if (cmdData.input_pkcs11SlotId != 0)
    {
        pkcs11Options.SetSlotId(cmdData.input_pkcs11SlotId);
    }
    if (cmdData.input_pkcs11KeyLabel != "")
    {
        pkcs11Options.SetPrivateKeyObjectLabel(cmdData.input_pkcs11KeyLabel);
    }
    
    Aws::Iot::MqttClientConnectionConfigBuilder clientConfigBuilder(pkcs11Options);
    if (!clientConfigBuilder)
    {
        fprintf(
            stderr,
            "MqttClientConnectionConfigBuilder failed: %s\n",
            Aws::Crt::ErrorDebugString(Aws::Crt::LastError()));
        exit(-1);
    }
    clientConfigBuilder.WithEndpoint(cmdData.input_endpoint);
    if (cmdData.input_ca != "")
    {
        clientConfigBuilder.WithCertificateAuthority(cmdData.input_ca.c_str());
    }
    

    // Create the MQTT connection from the MQTT builder
    auto clientConfig = clientConfigBuilder.Build();
    if (!clientConfig)
    {
        fprintf(
            stderr,
            "Client Configuration initialization failed with error %s\n",
            Aws::Crt::ErrorDebugString(clientConfig.LastError()));
        exit(-1);
    }
    Aws::Iot::MqttClient client = Aws::Iot::MqttClient();
    auto connection = client.NewConnection(clientConfig);
    if (!*connection)
    {
        fprintf(
            stderr,
            "MQTT Connection Creation failed with error %s\n",
            Aws::Crt::ErrorDebugString(connection->LastError()));
        exit(-1);
    }

    /**
     * In a real world application you probably don't want to enforce synchronous behavior
     * but this is a sample console application, so we'll just do that with a condition variable.
     */
    std::promise<bool> connectionCompletedPromise;
    std::promise<void> connectionClosedPromise;

    // Invoked when a MQTT connect has completed or failed
    auto onConnectionCompleted =
        [&](Aws::Crt::Mqtt::MqttConnection &, int errorCode, Aws::Crt::Mqtt::ReturnCode returnCode, bool) {
            if (errorCode)
            {
                fprintf(stdout, "Connection failed with error %s\n", Aws::Crt::ErrorDebugString(errorCode));
                connectionCompletedPromise.set_value(false);
            }
            else
            {
                fprintf(stdout, "Connection completed with return code %d\n", returnCode);
                connectionCompletedPromise.set_value(true);
            }
        };

    // Invoked when a MQTT connection was interrupted/lost
    auto onInterrupted = [&](Aws::Crt::Mqtt::MqttConnection &, int error) {
        fprintf(stdout, "Connection interrupted with error %s\n", Aws::Crt::ErrorDebugString(error));
    };

    // Invoked when a MQTT connection was interrupted/lost, but then reconnected successfully
    auto onResumed = [&](Aws::Crt::Mqtt::MqttConnection &, Aws::Crt::Mqtt::ReturnCode, bool) {
        fprintf(stdout, "Connection resumed\n");
    };

    // Invoked when a disconnect message has completed.
    auto onDisconnect = [&](Aws::Crt::Mqtt::MqttConnection &) {
        fprintf(stdout, "Disconnect completed\n");
        connectionClosedPromise.set_value();
    };

    // Assign callbacks
    connection->OnConnectionCompleted = std::move(onConnectionCompleted);
    connection->OnDisconnect = std::move(onDisconnect);
    connection->OnConnectionInterrupted = std::move(onInterrupted);
    connection->OnConnectionResumed = std::move(onResumed);

    /************************ Run the sample ****************************/

    // Connect
    fprintf(stdout, "Connecting...\n");
    if (!connection->Connect(cmdData.input_clientId.c_str(), false /*cleanSession*/, 1000 /*keepAliveTimeSecs*/))
    {
        fprintf(stderr, "MQTT Connection failed with error %s\n", ErrorDebugString(connection->LastError()));
        exit(-1);
    }

    if (connectionCompletedPromise.get_future().get())
    {
        std::mutex receiveMutex;
        std::condition_variable receiveSignal;
        uint32_t receivedCount = 0;

        // This is invoked upon the receipt of a Publish on a subscribed topic.
        auto onMessage = [&](Mqtt::MqttConnection &,
                             const String &topic,
                             const ByteBuf &byteBuf,
                             bool /*dup*/,
                             Mqtt::QOS /*qos*/,
                             bool /*retain*/) {
            {
                std::lock_guard<std::mutex> lock(receiveMutex);
                ++receivedCount;
                fprintf(stdout, "Publish #%d received on topic %s\n", receivedCount, topic.c_str());
                fprintf(stdout, "Message: ");
                fwrite(byteBuf.buffer, 1, byteBuf.len, stdout);
                fprintf(stdout, "\n");
            }

            receiveSignal.notify_all();
        };

        // Subscribe for incoming publish messages on topic.
        std::promise<void> subscribeFinishedPromise;
        auto onSubAck =
            [&](Mqtt::MqttConnection &, uint16_t packetId, const String &topic, Mqtt::QOS QoS, int errorCode) {
                if (errorCode)
                {
                    fprintf(stderr, "Subscribe failed with error %s\n", aws_error_debug_str(errorCode));
                    exit(-1);
                }
                else
                {
                    if (!packetId || QoS == AWS_MQTT_QOS_FAILURE)
                    {
                        fprintf(stderr, "Subscribe rejected by the broker.");
                        exit(-1);
                    }
                    else
                    {
                        fprintf(stdout, "Subscribe on topic %s on packetId %d Succeeded\n", topic.c_str(), packetId);
                    }
                }
                subscribeFinishedPromise.set_value();
            };

        connection->Subscribe(cmdData.input_topic.c_str(), AWS_MQTT_QOS_AT_LEAST_ONCE, onMessage, onSubAck);
        subscribeFinishedPromise.get_future().wait();

        uint32_t publishedCount = 0;
        while (publishedCount < cmdData.input_count)
        {
            ByteBuf payload = ByteBufFromArray((const uint8_t *)messagePayload.data(), messagePayload.length());

            auto onPublishComplete = [](Mqtt::MqttConnection &, uint16_t, int) {};
            connection->Publish(
                cmdData.input_topic.c_str(), AWS_MQTT_QOS_AT_LEAST_ONCE, false, payload, onPublishComplete);
            ++publishedCount;

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }

        {
            std::unique_lock<std::mutex> receivedLock(receiveMutex);
            receiveSignal.wait(receivedLock, [&] { return receivedCount >= cmdData.input_count; });
        }

        // Unsubscribe from the topic.
        std::promise<void> unsubscribeFinishedPromise;
        connection->Unsubscribe(cmdData.input_topic.c_str(), [&](Mqtt::MqttConnection &, uint16_t, int) {
            unsubscribeFinishedPromise.set_value();
        });
        unsubscribeFinishedPromise.get_future().wait();

        // Disconnect
        if (connection->Disconnect())
        {
            connectionClosedPromise.get_future().wait();
        }
    }
    else
    {
        exit(-1);
    }
    return 0;
}
