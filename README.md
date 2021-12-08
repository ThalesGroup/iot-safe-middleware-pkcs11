# Introduction

This project is a project for PKCS#11 provider implementation.

This PKCS#11 provider conforms the v2.40.

Refer to the below references for further technical specification on PKCS#11:
- PKCS#11 v2.40

  https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html

- PKCS#11 v3.0

  https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html

The token for this PKCS#11 provider project is a Secure Element that hosts IoTSAFE smartcard applet.

Since the Secure Element hosts a smartcard applet, most of the time, the SE is some form-factor of an ICC.

Several popular ICC form factors are:
- ID-1 form-factor, aka smartcard
- Mini / micro / nano SIM card
- eSIM
- iSIM

This PKCS#11 provider implementation in fact, does not care about the ICC form-factor; It only cares about the hardware interface between the PC and the ICC containing the smartcard applet.

The current SE hardware interfaces supported for this PKCS#11 provider implementation are:
- Modem

  Suitable for mini / micro / nano SIM card.

# Prepare this repository

```
git clone  --recurse-submodules https://github.com/ThalesGroup/iot-safe-middleware-pkcs11
```
or
```
git clone https://github.com/ThalesGroup/iot-safe-middleware-pkcs11
git submodule init
git submodule update
```

# Build the modem library first
```
cd se-access-lib\cinterion-modem\build
make && make install
```

# Building and Installing the PKCS#11 library

This PKCS#11 provider implementation will by default, communicate with a "/dev/ttyACM0" device.

To update the correct path to a SE hardware interface device, update the following file:
- se-pkcs11-lib/Cardmanager.cpp

  ```
  #define STR_CINTERION_MODEM_NAME "/dev/ttyACM0"
  ```

To build and install the PKCS#11 provider:
```
export PROJECT_DIR=/home/pi/experiment/iot-safe-middleware-pkcs11
sudo chmod u+x project-build.sh
./project-build.sh Release
```

This will build a release version of the PKCS#11 provider, a modem library used by the PKCS#11 provider, and several test suites in the `binaries/Release/` from the root directory of this project.

The PKCS#11 provider will be built in the `binaries/Release/libgtosepkcs11`, and will be installed as the `/usr/local/lib/libgtosepkcs11.so`.

The modem library will be built in the `binaries/Release/libcinmodem_access`, and will be installed as the `/usr/local/lib/libcinmodem_access.so`.

The test suites will be built in the `binaries/Release/*-test`.

Lastly, a configuration file for the PKCS#11 provider will be installed as the `/etc/IDGo800/Gemalto.PKCS11.ini` file.

The following are other types of building the project:
- Building with debug suitable for gdb.

  ```
  ./project-build.sh Debug
  ```
  
  The build will be located at `binaries/Debug`.
  
- Building with code coverage suitable for gcov.

  ```
  ./project-build.sh CodeCoverage
  ```
  
  The build will be located at `binaries/CodeCoverage`.
  
  The required files for gcov (`*.gcno`, `*.gcda`, and source files) will be placed in `binaries/CodeCoverage/libgtosepkcs11` and `binaries/CodeCoverage/libcinmodem_access`.
  
  Note that the `*.gcda` files can be generated by running the PKCS#11 provider installed as the `/usr/local/lib/libgtosepkcs11.so`.
  
- Building with code profiling with gprof.

  ```
  ./project-build.sh CodeProfile
  ```
  

The build will be located at `binaries/CodeProfile`.

The required files for gprof (`gmon*` and object files) will be placed in `binaries/CodeProfile/libgtosepkcs11` and `binaries/CodeProfile/libcinmodem_access`.

Note that the `gmon*` files can be generated by running the PKCS#11 provider installed as the `/usr/local/lib/libgtosepkcs11.so`.

# Configuration File

The PKCS#11 provider configuration file will be installed as the `/etc/IDGo800/Gemalto.PKCS11.ini` file.

The content of the configuration file is self-documented.

Below are the short descriptions of each configuration variables:
- Enable

  Set this variable to 0 to disable logging to stdout and stderr.

  Set this variable to 1 to enable logging to stdout and stderr.

- Path

  Set this field to an additional file to output logs.

- Apdu

  Set this variable to 0 to disable tracing non-sensitive APDU in the log.

  Set this variable to 1 to enable tracing non-sensitive APDU in the log.

- Enable

  Set this variable to 0 to disable caching to secodary storage.

  Set this variable to 1 to enable caching to secodary storage.

  This variable is ignored for now.

- ForcePinUser = 1

  Set this variable to 0 to disable forcing generated keys to be associated to PIN User.

  Set this variable to 1 to enable forcing generated keys to be associated to PIN User.

- HideStaticSlots

  Set this variable to 0 to not hide virtual slots for cards with static profile.

  Set this variable to 1 to hide virtual slots for cards with static profile.

- DisableCertificateValidation

  Set this variable to 0 to default validation of all certificate attributes.

  Set this variable to 1 to validation of CKA_ISSUER and CKA_SUBJECT or 0 to default validation of all certificate attributes.

- PIN_*

  PINs used for the PKCS#11 provider.

  This variable is ignored for now.

# Running Tests

To run the PKCS#11 provider test, first go to `binaries/release/pkcs11-test` from the root directory of this project, then run the pkcs11-test executable found in this directory.

The printed help usage of the test is as follow:
```
(c)2021 Thales Development
            usage:  program  [Options]

 Options

      -p:<pincode>                     pin value
      -i:<slotid>                      slot id value
      -l:<cryptoki/library/path>       cryptoki library path
      -f                               Prints all the objects and their
                                       attributes in the token.
      -R                               Remove all objects from the token.
      -r:<id>                          Remove object identified by id from
                                       the token.
      -k:<algo:length:id>              Generate a new key pair public
                                       private pair and aes key.
                                       for example -k:rsa:1024 -k:aes:128.
      -s:<algo:id:data>                Signature with verification
                                       Sign data using a private key identified by id.
                                       Verify the sgnature using the related public key
                                       Example : -s:rsa:keyid:data -s:ec:keyid:data
      -e:<algo:id:data>                Encryption / decryption
                                       Encrypt plain text data using a public key identified by id
                                       Decrypt the encrypted data using the private key to get the plain text data
                                       Example : -e:rsa:keyid of pubk -e:aes:keyid
      -c                               Perform AES CMAC 128-bit signature.      -g                               Random generation 8 bytes.
      -a:<nb tests>                    Perform nb iteration of all tests.

      -h                               Perform a Diffie-Hellman.

      All arguments are optional. Defaults are:
                <pincode>
                <slotid> 0
                <cryptokidll> /usr/local/lib/libgtosepkcs11.so
the main test is located in:
```

Below are the examples on how to run the test:
- To test generating a random number:

  ```
  ./pkcs11-test -p:1234 -i:0 -p:0000 -g
  ```
  ```
  Using slot ID : 0
  Using PIN : 1234
  Opening serial port...Found serial /dev/ttyACM0 4
  
  Opening a new session ... successful.
  Login into the token using PIN '1234' ... successful.
  
  Generating a random ...
          Random :
          0000  6D 1D C0 9D 6D 2D 7E 4C                          m...m-~L
  
  Closing the session ... successful.

- To test signing and verifying an ECDSA signature:

```  
./pkcs11-test -p:1234 -i:0 -p:0000 -s:ecc:01:hello
```

  ```
  Using slot ID : 0
  Using PIN : 1234
  Signature : ecc:01:hello
          Key algo : ecc
          Key ID   : 01
          Data     : hello
  Opening serial port...Found serial /dev/ttyACM0 4
  
  Opening a new session ... successful.
  Login into the token using PIN '1234' ... successful.
  
  Signing data using ECC private key ...
          Signature :
          0000  87 4F 1A 53 9A CC 70 70-44 7B 02 03 E3 CB 0E 03  .O.S..ppD{......
          0010  D6 52 6A 10 6C 23 6C A7-BB 95 DD 85 9D 18 58 6F  .Rj.l#l.......Xo
          0020  C8 15 D3 F4 71 4F FD 9A-2A 27 D1 08 AF 8B 03 D9  ....qO..*'......
          0030  37 D3 6C CD D9 53 71 3F-0C E6 5E B7 2C A7 27 25  7.l..Sq?..^.,.'%
  
  Verifying signature ...
          Signature verification successful.
  
  Closing the session ... successful.
  ```
- To test performing ECDHE:

 `````
  ./pkcs11-test -p:1234 -i:0 -l:/usr/local/lib/libgtosepkcs11.so -h
 `````

-l is optional

```
Using slot ID : 0
Using PIN : 1234
Opening serial port...Found serial /dev/ttyACM0 4

Opening a new session ... successful.
Login into the token using PIN '1234' ... successful.

Generating DH secret ...
 ->Generating ECDHE 256 Key Pair ...
    ->ECDHE 256 ephemeral private key handle at generation 4883  .
    DER-encoding of ANSI X9.62 EC Point value Q :
    0000  04 41 04 DF 76 21 01 F5-A5 3D D0 65 C5 D9 38 BE  .A..v!...=.e..8.
    0010  21 1A E6 73 96 04 6A ED-30 FE DB F3 EF EB 20 89  !..s..j.0..... .
    0020  B1 A0 22 B1 EA 7E D4 74-C8 D7 03 44 AA 99 CC 78  .."..~.t...D...x
    0030  32 69 CF 5D 0A 75 6B 3E-53 55 A7 2C 9A F1 5F 30  2i.].uk>SU.,.._0
    0040  88 66 2B                                         .f+
    ->ECDHE 256 Key Pair generation successful.
    DER-encoding of ANSI X9.62 EC Point value Q :
    0000  04 41 04 DF 76 21 01 F5-A5 3D D0 65 C5 D9 38 BE  .A..v!...=.e..8.
    0010  21 1A E6 73 96 04 6A ED-30 FE DB F3 EF EB 20 89  !..s..j.0..... .
    0020  B1 A0 22 B1 EA 7E D4 74-C8 D7 03 44 AA 99 CC 78  .."..~.t...D...x
    0030  32 69 CF 5D 0A 75 6B 3E-53 55 A7 2C 9A F1 5F 30  2i.].uk>SU.,.._0
    0040  88 66 2B                                         .f+
    ->Derive Key... successful.
    Shared Secret (Client Side) Key :
    0000  E8 5B B7 84 63 53 D3 2D-0A D2 90 36 05 1A 09 A7  .[..cS.-...6....
    0010  5A 97 36 F5 03 DB BE 89-F1 3A 5A BE F3 51 85 FB  Z.6......:Z..Q..
    Shared Secret (Server Side) Key :
    0000  E8 5B B7 84 63 53 D3 2D-0A D2 90 36 05 1A 09 A7  .[..cS.-...6....
    0010  5A 97 36 F5 03 DB BE 89-F1 3A 5A BE F3 51 85 FB  Z.6......:Z..Q..
    Success: Key Agreement Shared Keys match
        ECDH secret computed... successful .

Closing the session ... successful.
```

- To test performing AES CMAC:

```
./pkcs11-test -p:1234 -i:0 -l:/usr/local/lib/libgtosepkcs11.so -c
```

 -l is optional


# Other Related Projects

This PKCS#11 library could be integrated with other projects mentioned below:
- https://github.com/p11-glue/p11-kit
- https://github.com/OpenSC/libp11
- https://www.gnutls.org/manual/html_node/PKCS11-Initialization.html
- https://botan.randombit.net/handbook/api_ref/pkcs11.html

