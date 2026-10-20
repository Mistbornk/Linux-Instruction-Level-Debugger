CXX = g++
CPPFLAGS = -Iinclude
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -g
LDLIBS = -lcapstone
BUILD_DIR ?= build
TARGET ?= sdb
SRCS = $(wildcard src/*.cpp)
OBJS = $(patsubst src/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean test
all: $(TARGET)
$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	chmod +x $@
$(BUILD_DIR)/%.o: src/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@
-include $(OBJS:.o=.d)
$(BUILD_DIR)/memory_transaction: tests/memory_transaction.cpp $(filter-out $(BUILD_DIR)/main.o,$(OBJS))
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wl,--wrap=pwrite -o $@ $^ $(LDLIBS)
	chmod +x $@
$(BUILD_DIR)/command_test: tests/command_test.cpp $(BUILD_DIR)/command.o $(BUILD_DIR)/cli_options.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o $@ $^
$(BUILD_DIR)/ptrace_probe: tests/ptrace_probe.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o $@ $<
$(BUILD_DIR)/loop: tests/fixtures/loop.S
	@mkdir -p $(BUILD_DIR)
	$(CC) -nostdlib -no-pie $< -o $@
	chmod +x $@
test: $(TARGET) $(BUILD_DIR)/command_test $(BUILD_DIR)/ptrace_probe $(BUILD_DIR)/memory_transaction $(BUILD_DIR)/loop
	$(BUILD_DIR)/command_test
	python3 tests/runner_test.py
	python3 tests/run_checked.py $(BUILD_DIR)/ptrace_probe python3 tests/baseline.py $(abspath $(TARGET))
	python3 tests/run_checked.py $(BUILD_DIR)/ptrace_probe python3 tests/regression.py $(abspath $(TARGET))
	python3 tests/run_checked.py $(BUILD_DIR)/ptrace_probe python3 tests/stage2.py $(abspath $(TARGET))
	python3 tests/run_checked.py $(BUILD_DIR)/ptrace_probe $(BUILD_DIR)/memory_transaction $(BUILD_DIR)/loop
clean:
	rm -f $(TARGET) $(OBJS) $(OBJS:.o=.d) $(BUILD_DIR)/memory_transaction $(BUILD_DIR)/memory_transaction.d $(BUILD_DIR)/loop $(BUILD_DIR)/command_test $(BUILD_DIR)/command_test.d $(BUILD_DIR)/ptrace_probe $(BUILD_DIR)/ptrace_probe.d
