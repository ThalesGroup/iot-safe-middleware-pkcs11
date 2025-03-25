#pragma once
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/crt/Api.h>
#include <aws/crt/Types.h>
#include <aws/iot/MqttClient.h>

namespace Utils
{

    struct cmdData
    {
        // General use
        Aws::Crt::String input_endpoint;
        Aws::Crt::String input_cert;
        Aws::Crt::String input_key;
        Aws::Crt::String input_ca;
        Aws::Crt::String input_clientId;
        uint64_t input_port;
        bool input_isCI;
        // Proxy
        Aws::Crt::String input_proxyHost;
        uint64_t input_proxyPort;
        // PubSub
        Aws::Crt::String input_topic;
        Aws::Crt::String input_message;
        uint64_t input_count;
        // Websockets
        Aws::Crt::String input_signingRegion;

        Aws::Crt::String input_accessKeyId;
        Aws::Crt::String input_secretAccessKey;
        Aws::Crt::String input_sessionToken;
        // Cognito
        Aws::Crt::String input_cognitoIdentity;
        Aws::Crt::String input_cognitoEndpoint;
        // Custom auth
        Aws::Crt::String input_customAuthUsername;
        Aws::Crt::String input_customAuthorizerName;
        Aws::Crt::String input_customAuthorizerSignature;
        Aws::Crt::String input_customAuthPassword;
        Aws::Crt::String input_customTokenKeyName;
        Aws::Crt::String input_customTokenValue;
        // Fleet provisioning
        Aws::Crt::String input_templateName;
        Aws::Crt::String input_templateParameters;
        Aws::Crt::String input_csrPath;
        // Services (Shadow, Jobs, Greengrass, etc)
        Aws::Crt::String input_thingName;
        Aws::Crt::String input_mode;
        // Java Keystore
        Aws::Crt::String input_keystore;
        Aws::Crt::String input_keystorePassword;
        Aws::Crt::String input_keystoreFormat;
        Aws::Crt::String input_certificateAlias;
        Aws::Crt::String input_certificatePassword;
        // Shared Subscription
        Aws::Crt::String input_groupIdentifier;
        // PKCS#11
        Aws::Crt::String input_pkcs11LibPath;
        Aws::Crt::String input_pkcs11UserPin;
        Aws::Crt::String input_pkcs11TokenLabel;
        uint64_t input_pkcs11SlotId;
        Aws::Crt::String input_pkcs11KeyLabel;
        // X509
        Aws::Crt::String input_x509Endpoint;
        Aws::Crt::String input_x509Role;
        Aws::Crt::String input_x509ThingName;
        Aws::Crt::String input_x509Cert;
        Aws::Crt::String input_x509Key;
        Aws::Crt::String input_x509Ca;
        // Device Defender
        uint64_t input_reportTime;
        // Jobs
        Aws::Crt::String input_jobId;
        // Cycle PubSub
        uint64_t input_clients;
        uint64_t input_tps;
        uint64_t input_seconds;
        // Secure Tunnel
        Aws::Crt::String input_accessTokenFile;
        Aws::Crt::String input_accessToken;
        Aws::Crt::String input_localProxyModeSource;
        Aws::Crt::String input_clientTokenFile;
        Aws::Crt::String input_clientToken;
        Aws::Crt::String input_proxyUserName;
        Aws::Crt::String input_proxyPassword;
        // Shadow
        Aws::Crt::String input_shadowProperty;
        Aws::Crt::String input_shadowName;
        Aws::Crt::String input_shadowValue;
        // PKCS12
        Aws::Crt::String input_pkcs12File;
        Aws::Crt::String input_pkcs12Password;
        // Greengrass Discovery
        bool input_PrintDiscoverRespOnly;
        // MQTT protocol version
        uint64_t input_mqtt_version;
    };

} // namespace Utils
