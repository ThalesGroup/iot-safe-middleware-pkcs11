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

TARGETNAME := pkcs11-test
BUILDDIR   := $(PROJECT_DIR)/binaries/$(BUILDMODE)/$(TARGETNAME)
TARGET     := $(BUILDDIR)/$(TARGETNAME)

SRCDIR := ..
SRCEXT := c

SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst %.$(SRCEXT), $(BUILDDIR)/%.o, $(notdir $(SOURCES)))

ifeq ($(BUILDTYPE), CodeCoverage)
	CODE_COV_GCNO := $(patsubst %.$(SRCEXT), $(BUILDDIR)/%.gcno, $(notdir $(SOURCES)))
	CODE_COV_GCDA := $(patsubst %.$(SRCEXT), $(BUILDDIR)/%.gcda, $(notdir $(SOURCES)))
endif

LIB := -ldl -lcrypto
INC := -I../include -I../include/pkcs11

CFLAGS := -Wall

ifeq ($(BUILDMODE), Debug)
	CFLAGS += -O0 -g -DDEBUG
else ifeq ($(BUILDMODE), CodeCoverage)
	CFLAGS += -O0 -g -DDEBUG --coverage -Wl,--dynamic-list-data
else ifeq ($(BUILDMODE), CodeProfile)
	CFLAGS += -O0 -pg
else
	CFLAGS += -O2
endif

$(TARGET): $(OBJECTS)
	@echo "   Build mode : $(BUILDMODE) - Building target $@ ..."
	$(CC) $(CFLAGS) -o $(TARGET) $^ $(LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@echo "   Build mode : $(BUILDMODE) - Compiling $< ..."
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	@echo "   Cleaning $(BUILDDIR) directory ..."
	$(RM) $(OBJECTS) $(TARGET)
ifeq ($(BUILDMODE), CodeCoverage)
	$(RM) $(CODE_COV_GCNO)
	$(RM) $(CODE_COV_GCDA)
endif

.PHONY: clean
