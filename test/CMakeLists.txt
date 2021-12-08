
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable (pkcs11-test  "aes.c"  "delete.c"  "digest.c"  "ecc.c"  "ecdh_openssl.c" "getinfo.c" "main.c"  "random.c"  
"rsa.c"  "utils.c")

target_include_directories (pkcs11-test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(pkcs11-test PRIVATE cinmodem_access gtosepkcs11  OpenSSL::Crypto  ) 
