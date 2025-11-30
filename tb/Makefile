SIM ?= verilator
TOPLEVEL_LANG ?= verilog
VERILOG_SOURCES += $(PWD)/../rtl/sentinel_core.sv
TOPLEVEL = sentinel_core
MODULE = test_sentinel

# Enable Waveform Dumping in Verilator
EXTRA_ARGS += --trace --trace-structs

include $(shell cocotb-config --makefiles)/Makefile.sim