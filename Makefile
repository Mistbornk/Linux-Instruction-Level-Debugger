CXX ?= g++
CPPFLAGS += -Iinclude
CXXFLAGS ?= -O0 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wpedantic -MMD -MP
LDLIBS += -lcapstone

SOURCES = src/main.cpp src/debugger.cpp src/signal_monitor.cpp src/tracee.cpp src/memory.cpp \
          src/breakpoint.cpp src/disassembler.cpp src/elf_image.cpp src/command_parser.cpp \
          src/watchpoint.cpp src/register_file.cpp src/backtrace.cpp src/syscall_decoder.cpp
OBJECTS = $(SOURCES:src/%.cpp=build/make/%.o)

.PHONY: all clean test ci benchmark
all: sdb

sdb: $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)
	chmod +x $@

build/make/%.o: src/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

build/make/elf_image_test_pie: tests/elf_image_test.cpp build/make/elf_image.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fPIE -pie $(LDFLAGS) $^ -ldl -o $@
	chmod +x $@

build/make/elf_image_test_exec: tests/elf_image_test.cpp build/make/elf_image.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fno-pie -no-pie $(LDFLAGS) $^ -ldl -o $@
	chmod +x $@

build/make/tracee_memory_test: tests/tracee_memory_test.cpp build/make/tracee.o build/make/signal_monitor.o build/make/memory.o build/make/breakpoint.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wl,--wrap=pread,--wrap=pwrite,--wrap=open $^ -o $@
	chmod +x $@

build/make/inspection_test: tests/inspection_test.cpp build/make/tracee.o build/make/signal_monitor.o build/make/memory.o build/make/elf_image.o build/make/register_file.o build/make/backtrace.o build/make/syscall_decoder.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fno-omit-frame-pointer -fno-optimize-sibling-calls $(LDFLAGS) $^ -pthread -o $@
	chmod +x $@

build/make/task_control_test: tests/task_control_test.cpp build/make/tracee.o build/make/signal_monitor.o build/make/memory.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ -pthread -o $@
	chmod +x $@

build/make/detach_test: tests/detach_test.cpp $(filter-out build/make/main.o,$(OBJECTS))
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wl,--wrap=ptrace $^ -pthread $(LDLIBS) -o $@
	chmod +x $@

test: sdb build/make/elf_image_test_pie build/make/elf_image_test_exec build/make/tracee_memory_test build/make/inspection_test build/make/task_control_test build/make/detach_test
	timeout 60s ./build/make/elf_image_test_pie
	timeout 60s ./build/make/elf_image_test_exec
	timeout 60s ./build/make/tracee_memory_test
	timeout 90s ./build/make/inspection_test
	timeout 90s ./build/make/task_control_test
	timeout 90s ./build/make/detach_test
	python3 tests/integration.py ./sdb
	python3 tests/extensions.py ./sdb
	python3 tests/elf_process.py ./sdb
	python3 tests/signals.py ./sdb
	python3 tests/interview_demo.py ./sdb

ci:
	./scripts/ci.sh

benchmark: sdb
	python3 scripts/benchmark.py ./sdb --output build/benchmark.json

clean:
	rm -rf build/make sdb

-include $(OBJECTS:.o=.d)
