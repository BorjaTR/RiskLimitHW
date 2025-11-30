import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer
import random

# -----------------------------------------------------------------------------
# CONSTANTS & ADDRESS MAP
# -----------------------------------------------------------------------------
ADDR_CTRL       = 0x00
ADDR_LIMIT      = 0x04
ADDR_VIOL_CNT   = 0x08
ADDR_SNAP_LO    = 0x0C
ADDR_SNAP_HI    = 0x10

# -----------------------------------------------------------------------------
# HELPER: AXI-Lite Driver
# -----------------------------------------------------------------------------
async def cpu_write(dut, addr, data):
    dut.s_axil_awaddr.value = addr
    dut.s_axil_awvalid.value = 1
    dut.s_axil_wdata.value = data
    dut.s_axil_wvalid.value = 1
    while True:
        await RisingEdge(dut.aclk)
        if dut.s_axil_awready.value and dut.s_axil_wready.value: break
    dut.s_axil_awvalid.value = 0
    dut.s_axil_wvalid.value = 0
    while True:
        await RisingEdge(dut.aclk)
        if dut.s_axil_bvalid.value:
            dut.s_axil_bready.value = 1
            break
    await RisingEdge(dut.aclk)
    dut.s_axil_bready.value = 0

async def cpu_read(dut, addr):
    dut.s_axil_araddr.value = addr
    dut.s_axil_arvalid.value = 1
    while True:
        await RisingEdge(dut.aclk)
        if dut.s_axil_arready.value: break
    dut.s_axil_arvalid.value = 0
    while True:
        await RisingEdge(dut.aclk)
        if dut.s_axil_rvalid.value:
            data = dut.s_axil_rdata.value
            dut.s_axil_rready.value = 1
            break
    await RisingEdge(dut.aclk)
    dut.s_axil_rready.value = 0
    return data

# -----------------------------------------------------------------------------
# THE SCOREBOARD
# -----------------------------------------------------------------------------
class RiskModel:
    def __init__(self):
        self.limit = 1000
        self.total_drops = 0
        self.last_dropped_data = 0
        
    def update_limit(self, new_limit):
        self.limit = new_limit
        
    def check_packet(self, data_int):
        amount = data_int & 0xFFFFFFFFFF
        if amount > self.limit:
            self.total_drops += 1
            self.last_dropped_data = data_int
            return False 
        return True 

# -----------------------------------------------------------------------------
# THE TEST
# -----------------------------------------------------------------------------
@cocotb.test()
async def test_sentinel_stochastic(dut):
    """
    Level 3: The Drunken Agent Stress Test
    """
    cocotb.start_soon(Clock(dut.aclk, 5, unit="ns").start()) 
    model = RiskModel()
    
    # 1. Robust Reset Sequence
    dut.aresetn.value = 0
    await RisingEdge(dut.aclk)
    await Timer(1, units="ns") # Hold reset a bit past edge
    dut.aresetn.value = 1
    await RisingEdge(dut.aclk)
    
    # 2. Init
    dut.m_axis_tready.value = 1
    dut.s_axil_awvalid.value = 0
    dut.s_axil_wvalid.value = 0
    dut.s_axil_arvalid.value = 0
    dut.s_axil_rready.value = 0
    dut.s_axil_bready.value = 0
    
    dut._log.info("SYSTEM: Starting Stochastic Fuzzing...")

    for i in range(1000):
        
        # --- A. Randomly Reconfigure ---
        if random.random() < 0.1:
            new_limit = random.randint(500, 5000)
            await cpu_write(dut, ADDR_LIMIT, new_limit)
            model.update_limit(new_limit)
            # dut._log.info(f"CPU: Limit updated to {new_limit}")

        # --- B. Generate Random Transaction ---
        is_dangerous = random.choice([True, False])
        if is_dangerous:
            amount = random.randint(model.limit + 1, model.limit * 10)
        else:
            # Ensure amount is at least 1
            limit_safe = max(1, model.limit)
            amount = random.randint(1, limit_safe)
            
        dest_id = 0x1234
        tx_data = (dest_id << 40) | amount
        
        # --- C. Drive to DUT ---
        dut.s_axis_tdata.value = tx_data
        dut.s_axis_tvalid.value = 1
        dut.s_axis_tlast.value = 1
        
        # --- D. Wait for Hardware Pipeline ---
        # Hardware Latency is 1 Cycle.
        # We wait 1 Edge to latch input, then we sample output.
        await RisingEdge(dut.aclk) 
        
        # Clear inputs immediately to prevent double-counting next cycle
        dut.s_axis_tvalid.value = 0 
        dut.s_axis_tlast.value = 0
        
        # --- E. Robust Sampling ---
        # Wait 1ns to allow signals to settle (Post-Clock Sampling)
        await Timer(1, units="ns")
        
        actual_valid = dut.m_axis_tvalid.value
        expected_pass = model.check_packet(tx_data)
        
        if expected_pass:
            assert actual_valid == 1, f"Iter {i}: Safe packet {amount} (Limit {model.limit}) was dropped!"
        else:
            assert actual_valid == 0, f"Iter {i}: Dangerous packet {amount} (Limit {model.limit}) leaked!"
            
        # Wait gap
        await RisingEdge(dut.aclk)

    # 3. Final Forensic Check
    dut._log.info("TRAFFIC: Fuzzing Complete. Checking Forensics...")
    
    hw_drops = await cpu_read(dut, ADDR_VIOL_CNT)
    assert hw_drops == model.total_drops, f"Counter Mismatch! HW: {int(hw_drops)}, Model: {model.total_drops}"
    
    snap_lo = await cpu_read(dut, ADDR_SNAP_LO)
    snap_hi = await cpu_read(dut, ADDR_SNAP_HI)
    hw_snapshot = (snap_hi.integer << 32) | snap_lo.integer
    
    if model.total_drops > 0:
        assert hw_snapshot == model.last_dropped_data, f"Snapshot Mismatch! HW: {hex(hw_snapshot)}, Model: {hex(model.last_dropped_data)}"
    
    dut._log.info(f"SUCCESS: Processed 1000 packets. Drops: {int(hw_drops)}. Forensics Match. 🛡️")