#------------------------------------------------------------------------------
# Makefile for the Cinterion Modem Access Mockup library
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
LIBRARY_NAME := libcinmodem_access
LIBRARY_EXT  := so
TARGET_NAME  := $(LIBRARY_NAME)-$(RELEASE).$(LIBRARY_EXT)

# Library installation prefix
INSTALL_PREFIX := /usr/local

# Uncommenting the following line will remove the following features
#     - Disk cache (secure element files cache)
#     - Configuration file management
#     - Log files management
# NOFILESYSTEM := true

CC  := gcc
CXX := g++

BUILDDIR := $(PROJECT_DIR)/binaries/$(BUILDMODE)/$(LIBRARY_NAME)
TARGET   := $(BUILDDIR)/$(TARGET_NAME)

SRCDIR := ../src

INCLUDES := -I../inc

SOURCES := $(SRCDIR)/ATInterface.cpp \
	$(SRCDIR)/CinterionModem.cpp \
	$(SRCDIR)/LSerial.cpp \
	$(SRCDIR)/ModemAccess.cpp \
	$(SRCDIR)/Serial.cpp

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

ifeq ($(BUILDMODE), Debug)
	CXXFLAGS += -O0 -g -DDEBUG
else ifeq ($(BUILDMODE), CodeCoverage)
	CXXFLAGS += -O0 -g -DDEBUG --coverage -Wl,--dynamic-list-data
else ifeq ($(BUILDMODE), CodeProfile)
	CXXFLAGS += -O0 -pg
else
	CXXFLAGS += -O2
endif

LDFLAGS := -shared

$(TARGET): $(OBJECTS)
	@echo "   Build mode : $(BUILDMODE) - Building target $@ ..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $^ $(LIBS)
ifeq ($(BUILDMODE), CodeCoverage)
	-cp $(SRCDIR)/*.c $(BUILDDIR)
	-cp $(SRCDIR)/*.cpp $(BUILDDIR)
	-cp $(SRCDIR)/../inc/*.h $(BUILDDIR)
	-cp $(SRCDIR)/../inc/*.hpp $(BUILDDIR)
endif

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@echo "   Build mode : $(BUILDMODE) - Compiling $< ..."
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

install:
	@echo "   Installing the library in $(INSTALL_PREFIX)/lib directory ..."
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
