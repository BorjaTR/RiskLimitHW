`timescale 1ns/1ps

module sentinel_core (
    input  logic        aclk,
    input  logic        aresetn,

    // ---------------------------------------------------------
    // 1. AXI4-Stream Interface (The Data Path)
    // ---------------------------------------------------------
    input  logic [63:0] s_axis_tdata,
    input  logic        s_axis_tvalid,
    input  logic        s_axis_tlast,
    output logic        s_axis_tready,

    output logic [63:0] m_axis_tdata,
    output logic        m_axis_tvalid,
    output logic        m_axis_tlast,
    input  logic        m_axis_tready,

    // ---------------------------------------------------------
    // 2. AXI4-Lite Interface (The Control Path)
    // ---------------------------------------------------------
    input  logic [31:0] s_axil_awaddr,
    input  logic        s_axil_awvalid,
    output logic        s_axil_awready,
    input  logic [31:0] s_axil_wdata,
    input  logic        s_axil_wvalid,
    output logic        s_axil_wready,
    output logic [1:0]  s_axil_bresp,
    output logic        s_axil_bvalid,
    input  logic        s_axil_bready,
    input  logic [31:0] s_axil_araddr,
    input  logic        s_axil_arvalid,
    output logic        s_axil_arready,
    output logic [31:0] s_axil_rdata,
    output logic [1:0]  s_axil_rresp,
    output logic        s_axil_rvalid,
    input  logic        s_axil_rready
);

    // ---------------------------------------------------------
    // Internal Registers (Memory Map)
    // ---------------------------------------------------------
    // 0x00: Control (Bit 0 = Enable)
    // 0x04: Limit Amount (Shadow Register)
    // 0x08: Violation Counter (Read Only)
    // 0x0C: Snapshot Data [31:0] (Read Only)
    // 0x10: Snapshot Data [63:32] (Read Only)

    logic [31:0] reg_control;
    logic [31:0] reg_limit_shadow; 
    logic [31:0] reg_violation_count;
    logic [63:0] reg_dropped_snapshot; // New Forensic Register
    
    // Active limit is 40 bits to match data format
    logic [39:0] active_limit; 

    // AXI-Lite Handshake Logic
    logic aw_en;

    // ---------------------------------------------------------
    // AXI-Lite Write State Machine
    // ---------------------------------------------------------
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            s_axil_awready <= 0;
            s_axil_wready  <= 0;
            s_axil_bvalid  <= 0;
            s_axil_bresp   <= 0;
            reg_control    <= 1; // Enabled by default
            reg_limit_shadow <= 1000; // Default limit
            aw_en          <= 1;
        end else begin
            // 1. Address Handshake
            if (~s_axil_awready && s_axil_awvalid && s_axil_wvalid && aw_en) begin
                s_axil_awready <= 1;
                s_axil_wready  <= 1;
            end else begin
                s_axil_awready <= 0;
                s_axil_wready  <= 0;
            end

            // 2. Write Data Logic
            if (s_axil_awready && s_axil_wready && s_axil_awvalid && s_axil_wvalid) begin
                // Decode using lower 5 bits to handle up to 0x10
                case (s_axil_awaddr[4:0]) 
                    5'h00: reg_control      <= s_axil_wdata;
                    5'h04: reg_limit_shadow <= s_axil_wdata;
                    default: ; // Ignore writes to read-only regs
                endcase
            end

            // 3. Response Logic
            if (s_axil_awready && s_axil_wready && s_axil_awvalid && s_axil_wvalid) begin
                s_axil_bvalid <= 1;
                s_axil_bresp  <= 2'b00; // OKAY
            end else if (s_axil_bready && s_axil_bvalid) begin
                s_axil_bvalid <= 0;
            end
        end
    end

    // ---------------------------------------------------------
    // AXI-Lite Read Logic (Updated for Forensics)
    // ---------------------------------------------------------
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            s_axil_arready <= 0;
            s_axil_rvalid  <= 0;
            s_axil_rdata   <= 0;
            s_axil_rresp   <= 0;
        end else begin
            // Read Address Handshake
            if (~s_axil_arready && s_axil_arvalid) begin
                s_axil_arready <= 1;
            end else begin
                s_axil_arready <= 0;
            end

            // Read Data Handshake
            if (s_axil_arready && s_axil_arvalid && ~s_axil_rvalid) begin
                s_axil_rvalid <= 1;
                s_axil_rresp  <= 2'b00; 
                
                // Mux output data based on address
                case (s_axil_araddr[4:0])
                    5'h00: s_axil_rdata <= reg_control;
                    5'h04: s_axil_rdata <= reg_limit_shadow;
                    5'h08: s_axil_rdata <= reg_violation_count;
                    5'h0C: s_axil_rdata <= reg_dropped_snapshot[31:0];  // Snap Lo
                    5'h10: s_axil_rdata <= reg_dropped_snapshot[63:32]; // Snap Hi
                    default: s_axil_rdata <= 0;
                endcase
            end else if (s_axil_rvalid && s_axil_rready) begin
                s_axil_rvalid <= 0;
            end
        end
    end

    // ---------------------------------------------------------
    // Hitless Update Logic
    // ---------------------------------------------------------
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            active_limit <= 40'd1000;
        end else begin
            // Update Limit when:
            // 1. End of Packet (tlast)
            // 2. OR Bus Idle (!tvalid)
            // 3. OR Module Disabled
            if ((s_axis_tlast && s_axis_tvalid && m_axis_tready) || !s_axis_tvalid || reg_control[0] == 0) begin
                active_limit <= {8'b0, reg_limit_shadow}; 
            end
        end
    end

    // ---------------------------------------------------------
    // Data Path Logic (With Forensic Capture)
    // ---------------------------------------------------------
    logic pass_check;
    logic [63:0] data_reg;
    logic valid_reg;
    logic last_reg;
    logic violation_detected;

    logic [39:0] amount;
    // dest_id unused in this simplified check, but kept for future use
    logic [15:0] dest_id; 

    assign amount  = s_axis_tdata[39:0];
    assign dest_id = s_axis_tdata[55:40];

    // The Logic Gate
    always_comb begin
        if ((amount > active_limit) && reg_control[0]) begin
            pass_check = 1'b0; 
            violation_detected = 1'b1;
        end else begin
            pass_check = 1'b1;
            violation_detected = 1'b0;
        end
    end

    // Pipeline Register
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            valid_reg <= 0;
            data_reg  <= 0;
            last_reg  <= 0;
            reg_violation_count <= 0;
            reg_dropped_snapshot <= 0;
        end else begin
            if (m_axis_tready || !valid_reg) begin
                // 1. Forwarding Logic
                valid_reg <= s_axis_tvalid && pass_check;
                data_reg  <= s_axis_tdata;
                last_reg  <= s_axis_tlast;
                
                // 2. Forensic Logic (Audit Trail)
                if (s_axis_tvalid && violation_detected) begin
                    reg_violation_count <= reg_violation_count + 1;
                    reg_dropped_snapshot <= s_axis_tdata; // Capture the evidence!
                end
            end
        end
    end

    // Output Assignments
    assign m_axis_tvalid = valid_reg;
    assign m_axis_tdata  = data_reg;
    assign m_axis_tlast  = last_reg;
    assign s_axis_tready = m_axis_tready; 

endmodule