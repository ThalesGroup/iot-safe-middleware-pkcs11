project("cinmodem_access" VERSION 1.0.1 DESCRIPTION "Cinterion Modem Access library")

add_library (${PROJECT_NAME}  SHARED "../iotsafe-middleware/iotsafelib/platform/modem/src/ATInterface.cpp" "../iotsafe-middleware/iotsafelib/platform/modem/src/GenericModem.cpp" 
                                   "../iotsafe-middleware/iotsafelib/platform/modem/src/LSerial.cpp" "./src/ModemAccess.cpp" "../iotsafe-middleware/iotsafelib/platform/modem/src/Serial.cpp"
                                   "${CMAKE_CURRENT_SOURCE_DIR}/../iotsafe-middleware/iotsafelib/common/src/SEInterface.cpp")
set_target_properties(${PROJECT_NAME}  PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME}  PROPERTIES SOVERSION 1)
#set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/libse-gto.h")

target_include_directories (${PROJECT_NAME}  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc"  )
target_include_directories (${PROJECT_NAME}  PUBLIC   "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_include_directories (${PROJECT_NAME}  PUBLIC   "${CMAKE_CURRENT_SOURCE_DIR}/../iotsafe-middleware/iotsafelib/platform/modem/inc")
target_include_directories (${PROJECT_NAME}  PUBLIC   "${CMAKE_CURRENT_SOURCE_DIR}/../iotsafe-middleware/iotsafelib/common/inc")


install(TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})