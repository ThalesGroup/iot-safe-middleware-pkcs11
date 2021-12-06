project("cinmodem_access" VERSION 1.0.1 DESCRIPTION "Cinterion Modem Access library")

add_library (${PROJECT_NAME}  SHARED "src/ATInterface.cpp" "src/CinterionModem.cpp" 
                                   "src/LSerial.cpp" "src/ModemAccess.cpp" "src/Serial.cpp")
set_target_properties(${PROJECT_NAME}  PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME}  PROPERTIES SOVERSION 1)
#set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/libse-gto.h")

target_include_directories (${PROJECT_NAME}  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc"  )
target_include_directories (${PROJECT_NAME}  PUBLIC   "${CMAKE_CURRENT_SOURCE_DIR}/..")



install(TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})