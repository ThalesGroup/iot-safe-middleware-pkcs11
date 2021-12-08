#------------------------------------------------------------------------------
# Makefile for the Secure Element PKCS#11 library Test
#
# Required :
#        PROJECT_DIR environment variable should be set to the absolute
#                    root path of the project folder
#                    The parent of 'src' directory
#
# To build, use one of this command lines :
#       make                        (release mode)
#       make BUILDTYPE=Release      (release mode)
#       make BUILDTYPE=Debug        (debug mode)
#------------------------------------------------------------------------------

# Check that given variables are set and all have non-empty values,
# Abort with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

# Check if the evironment variable is defined and stop if not
$(call check_defined, PROJECT_DIR, The root path of the project : The parent of 'src' directory)

ifeq ($(BUILDTYPE), Debug)
    BUILDMODE := Debug
else ifeq ($(BUILDTYPE), CodeCoverage)
    BUILDMODE := CodeCoverage
else ifeq ($(BUILDTYPE), CodeProfile)
    BUILDMODE := CodeProfile
else
    BUILDMODE := Release
endif

###################################
# Project configuration variables #
###################################
# Release number
RELEASE := 1.0.0

# Library name
LIBRARY_NAME := libgtosepkcs11
LIBRARY_EXT  := so
TARGET_NAME  := $(LIBRARY_NAME)-$(RELEASE).$(LIBRARY_EXT)

# Library installation prefix
INSTALL_PREFIX := /usr/local

# Library configuration file location
CONFIGURATION_DIR := /etc/IDGo800

# Uncommenting the following line will remove the following features
#     - Disk cache (secure element files cache)
#     - Configuration file management
#     - Log files management
# NOFILESYSTEM := true

CC  := gcc
CXX := g++

BUILDDIR := $(PROJECT_DIR)/binaries/$(BUILDMODE)/$(LIBRARY_NAME)
TARGET   := $(BUILDDIR)/$(TARGET_NAME)

SRCDIR := ..

INCLUDES := -I../include -I../../se-access-lib

SOURCES := \
	algo_des.cpp \
	Application.cpp \
	Array.cpp \
	attrcert.cpp \
	beroctet.cpp \
	Cache.cpp \
	CardManager.cpp \
	CardModuleAPI.cpp \
	CardModuleAppletIoTSAFE.cpp \
	Configuration.cpp \
	cr_digit.cpp \
	cr_nn.cpp \
	cr_random.cpp \
	cr_rsa.cpp \
	DataShare.cpp \
	Device.cpp \
	Digest.cpp \
	EccUtils.cpp \
	filesystem.cpp \
	Log.cpp \
	MiniDriverAuthentication.cpp \
	MiniDriverCardCacheFile.cpp \
	MiniDriverContainer.cpp \
	MiniDriverContainerMapFile.cpp \
	MiniDriver.cpp \
	MiniDriverFiles.cpp \
	MiniDriverModuleService.cpp \
	MiniDriverPinPolicy.cpp \
	Module.cpp \
	PKCS11.cpp \
	Pkcs11ObjectCertificate.cpp \
	Pkcs11ObjectCertificateX509PublicKey.cpp \
	Pkcs11ObjectData.cpp \
	Pkcs11ObjectKey.cpp \
	Pkcs11ObjectKeyGenericSecret.cpp \
	Pkcs11ObjectKeyPrivate.cpp \
	Pkcs11ObjectKeyPrivateECC.cpp \
	Pkcs11ObjectKeyPrivateRSA.cpp \
	Pkcs11ObjectKeyPublic.cpp \
	Pkcs11ObjectKeyPublicECC.cpp \
	Pkcs11ObjectKeyPublicRSA.cpp \
	Pkcs11ObjectKeySecret.cpp \
	Pkcs11ObjectKeySecretAES.cpp \
	Pkcs11ObjectStorage.cpp \
	Session.cpp \
	Slot.cpp \
	symmalgo.cpp \
	tdes.cpp \
	Template.cpp \
	Timer.cpp \
	Token.cpp \
	util.cpp \
	x509cert.cpp

OBJECTS := $(patsubst %.cpp, $(BUILDDIR)/%.o, $(notdir $(SOURCES)))

ifeq ($(BUILDTYPE), CodeCoverage)
	CODE_COV_GCNO := $(patsubst %.cpp, $(BUILDDIR)/%.gcno, $(notdir $(SOURCES)))
	CODE_COV_GCDA := $(patsubst %.cpp, $(BUILDDIR)/%.gcda, $(notdir $(SOURCES)))
endif

CXXFLAGS := \
	-Wall \
	-Wextra \
	-pedantic \
	-std=c++11 \
	-fPIC \
	-DCRYPTOKI_EXPORTS=1 \
	-DUNIX \
	-fpermissive

ifeq ($(BUILDMODE), Debug)
	CXXFLAGS += -O0 -g -DDEBUG
else ifeq ($(BUILDMODE), CodeCoverage)
	CXXFLAGS += -O0 -g -DDEBUG --coverage -Wl,--dynamic-list-data
else ifeq ($(BUILDMODE), CodeProfile)
	CXXFLAGS += -O0 -pg
else
	CXXFLAGS += -O0
endif

ifdef NOFILESYSTEM
	CXXFLAGS += -DNO_FILESYSTEM
endif

LDFLAGS := -shared

LIBS := \
	-ldl \
	-lcrypto \
	-lz \
	-lrt

ifndef NOFILESYSTEM
LIBS += \
	-lboost_serialization \
	-lboost_system
endif

LIBS += \
	-lboost_date_time \
	-lboost_thread \
	-lpthread \
	-lcinmodem_access

$(TARGET): $(OBJECTS)
	@echo "   Build mode : $(BUILDMODE) - Building target $@ ..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $^ $(LIBS)
ifeq ($(BUILDMODE), CodeCoverage)
	-cp $(SRCDIR)/*.c $(BUILDDIR)
	-cp $(SRCDIR)/*.cpp $(BUILDDIR)
	-cp $(SRCDIR)/include/*.h $(BUILDDIR)
	-cp $(SRCDIR)/include/*.hpp $(BUILDDIR)
endif

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@echo "   Build mode : $(BUILDMODE) - Compiling $< ..."
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

install:
ifndef NOFILESYSTEM
	@echo "   Installing the configuration file in $(CONFIGURATION_DIR) directory ..."
	@sudo mkdir -p $(CONFIGURATION_DIR)
	@sudo cp ../config/Gemalto.PKCS11.ini  $(CONFIGURATION_DIR)
endif
	@echo "   Installing the libarary in $(INSTALL_PREFIX)/lib directory ..."
	sudo mkdir -p $(INSTALL_PREFIX)/lib
	sudo rm -f $(INSTALL_PREFIX)/lib/$(LIBRARY_NAME).$(LIBRARY_EXT) $(INSTALL_PREFIX)/lib/$(TARGET_NAME)
	sudo cp $(TARGET) $(INSTALL_PREFIX)/lib
	sudo ln -s $(INSTALL_PREFIX)/lib/$(TARGET_NAME) $(INSTALL_PREFIX)/lib/$(LIBRARY_NAME).$(LIBRARY_EXT)
	sudo ldconfig

clean:
	@echo "   Cleaning $(BUILDDIR) directory ..."
	$(RM) $(OBJECTS) $(TARGET)
ifeq ($(BUILDMODE), CodeCoverage)
	$(RM) $(CODE_COV_GCNO)
	$(RM) $(CODE_COV_GCDA)
	$(RM) *.c *.cpp *.h *.hpp
endif

.PHONY: clean install
