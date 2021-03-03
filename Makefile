#  Makefile template for Static library. 
# 1. Compile every *.cpp in the folder 
# 2. All obj files under obj folder
# 3. static library .a at lib folder
# 4. run 'make dirmake' before calling 'make'

CC = g++

CFLAGS= -fPIC -O0 -g -Wall -c -fpermissive

INC = -I ./include/project
CXX ?= g++

# path #
SRC_PATH = src
LIB_SRC_PATH = lib
BUILD_PATH = build
BIN_PATH = $(BUILD_PATH)/bin

# executable # 
BIN_NAME = out
OUTPUT_LIB_NAME = libchacha.a
# unix adds the lib prefix and .a suffix automatically.
LIB_NAME_LINKING = chacha
# extensions #
SRC_EXT = cpp

# code lists #
# Find all source files in the source directory, sorted by
# most recently modified
SOURCES = $(shell find $(SRC_PATH) -name '*.$(SRC_EXT)' | sort -k 1nr | cut -f2-)

LIB_SOURCES = $(shell find $(LIB_SRC_PATH) -name '*.$(SRC_EXT)' | sort -k 1nr | cut -f2-)
LIB_OBJECTS = $(SOURCES:$(LIB_SRC_PATH)/%.$(SRC_EXT)=$(BUILD_PATH)/%.o)

# Set the object file names, with the source directory stripped
# from the path, and the build path prepended in its place
OBJECTS = $(SOURCES:$(SRC_PATH)/%.$(SRC_EXT)=$(BUILD_PATH)/%.o)
# Set the dependency files that will be used to add header dependencies
DEPS = $(OBJECTS:.o=.d)

# flags #
COMPILE_FLAGS = -Wall -Wextra -g -std=c++17
INCLUDES = -I include/ -I /usr/local/include 
# Space-separated pkg-config libraries used by this project
LIBS = $(LIB_NAME_LINKING)

.PHONY: default_target
default_target: release

.PHONY: release
release: export CXXFLAGS := $(CXXFLAGS) $(COMPILE_FLAGS)
release: dirs
	@$(MAKE) all

.PHONY: dirs
dirs:
	@echo "Creating directories"
	@mkdir -p $(dir $(OBJECTS))
	@mkdir -p $(BIN_PATH)

.PHONY: clean
clean:
	@echo "Deleting $(BIN_NAME) symlink"
	@$(RM) $(BIN_NAME)
	@echo "Deleting directories"
	@$(RM) -r $(BUILD_PATH)
	@$(RM) -r $(BIN_PATH)

# checks the executable and symlinks to the output
.PHONY: all
all: $(BIN_PATH)/$(OUTPUT_LIB_NAME) $(BIN_PATH)/$(BIN_NAME)
	@echo "Making symlink: $(BIN_NAME) -> $<"
	
	@$(RM) $(BIN_NAME)
	@ln -s $(BIN_PATH)/$(BIN_NAME) $(BIN_NAME)

# Created the static library
$(BIN_PATH)/$(OUTPUT_LIB_NAME): $(LIB_OBJECTS)
	@echo "Building library..."

	$(CXX) $(INCLUDES) -c $(LIB_SOURCES) -o $@ -std=c++17
	ar r $(BIN_PATH)/$(OUTPUT_LIB_NAME) $(LIB_SOURCES)
	ranlib $(BIN_PATH)/$(OUTPUT_LIB_NAME)

# Creation of the executable
$(BIN_PATH)/$(BIN_NAME): $(BIN_PATH)/$(OUTPUT_LIB_NAME) $(OBJECTS)
	@echo "Linking: $@"
	$(CXX) $(OBJECTS) $(INCLUDES) -o $@ -L./$(BIN_PATH)/ -l$(LIBS)



# Add dependency files, if they exist
-include $(DEPS)

# Source file rules
# After the first compilation they will be joined with the rules from the
# dependency files to provide header dependencies
$(BUILD_PATH)/%.o: $(SRC_PATH)/%.$(SRC_EXT)
	@echo "Compiling: $< -> $@"
	$(CXX) $(CXXFLAGS) $(INCLUDES) -MP -MMD -c $< -o $@ 