find_package(Boost 1.67 REQUIRED COMPONENTS serialization system thread date_time )

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library (gtosepkcs11 SHARED "algo_des.cpp" "algo_utils.cpp" "Application.cpp" "Array.cpp" "attrcert.cpp" "beroctet.cpp" 
"Cache.cpp" "CardManager.cpp" "CardModuleAPI.cpp" "CardModuleAppletIoTSAFE.cpp" "cert_utils.cpp" "Configuration.cpp" 
"cr_digit.cpp" "cr_nn.cpp" "cr_random.cpp" "cr_rsa.cpp" "DataShare.cpp" "des.cpp" "Device.cpp" "Digest.cpp" "EccUtils.cpp" 
"filesystem.cpp" "gem_aes.cpp" "gem_des.cpp" "Log.cpp" "MiniDriverAuthentication.cpp" "MiniDriverCardCacheFile.cpp" 
"MiniDriverContainer.cpp" "MiniDriverContainerMapFile.cpp" "MiniDriver.cpp" "MiniDriverFiles.cpp" 
"MiniDriverModuleService.cpp" "MiniDriverPinPolicy.cpp" "Module.cpp" "PinPolicy.cpp" "PKCS11.cpp" 
"Pkcs11ObjectCertificate.cpp" "Pkcs11ObjectCertificateX509PublicKey.cpp" "Pkcs11ObjectData.cpp" "Pkcs11ObjectKey.cpp" 
"Pkcs11ObjectKeyGenericSecret.cpp" "Pkcs11ObjectKeyPrivate.cpp" "Pkcs11ObjectKeyPrivateECC.cpp" 
"Pkcs11ObjectKeyPrivateRSA.cpp" "Pkcs11ObjectKeyPublic.cpp" "Pkcs11ObjectKeyPublicECC.cpp" "Pkcs11ObjectKeyPublicRSA.cpp" 
"Pkcs11ObjectKeySecret.cpp" "Pkcs11ObjectKeySecretAES.cpp" "Pkcs11ObjectStorage.cpp" "Session.cpp" "Slot.cpp" 
"symmalgo.cpp" "tdes.cpp" "Template.cpp" "Timer.cpp" "Token.cpp" "util.cpp" "x509cert.cpp")

set_target_properties(gtosepkcs11 PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(gtosepkcs11 PROPERTIES SOVERSION 1)

target_include_directories (gtosepkcs11 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(gtosepkcs11  PRIVATE cinmodem_access  Boost::serialization Boost::system Boost::thread Boost::date_time   OpenSSL::Crypto  rt z)
install(TARGETS gtosepkcs11
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/config/" DESTINATION /etc/IDGo800)