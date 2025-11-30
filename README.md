# Sentinel: Hardware-Accelerated Risk Engine for Agentic AI

![Status](https://img.shields.io/badge/Status-Verified-green)
![Stack](https://img.shields.io/badge/Stack-SystemVerilog%20%7C%20Cocotb%20%7C%20Verilator-blue)
![Latency](https://img.shields.io/badge/Latency-1%20Cycle-orange)

**A deterministic, nanosecond-scale firewall for autonomous financial agents.**

## 🚀 The Problem
AI Agents (LLMs) are beginning to execute autonomous financial transactions. However, software-based guardrails (Python/Solidity) suffer from:
1.  **Latency:** Software risk checks take microseconds.
2.  **Jitter:** Garbage collection and OS interrupts cause non-deterministic delays.
3.  **Opacity:** When a transaction is blocked, it's often unclear *why* or *what* the agent tried to do.

## 🛡 The Solution: Sentinel
Sentinel is a **SystemVerilog IP Core** that enforces risk limits at the hardware level. It acts as a "Digital Fuse," physically blocking dangerous transactions before they reach the network interface (NIC).

### Key Features
* **Cut-Through Architecture:** 1-clock cycle latency decision engine.
* **Hitless Reconfiguration:** Shadow registers allow risk limits to be updated by the CPU *without* pausing traffic or glitching active packets.
* **Forensic Capture:** Hardware automatically snapshots the payload of any dropped packet into a readable register for audit trails.

## 🏗 System Architecture

```mermaid
graph TD
    subgraph FPGA_Fabric
        A[Agent Traffic] -->|AXI-Stream 64b| B(Sentinel Core);
        B -->|Valid/Ready Handshake| C{Risk Logic};
        C -- Pass --> D[Network Interface];
        C -- Fail --> E[Drop & Log];
        
        subgraph Control_Plane
            CPU[Risk Manager CPU] -.->|AXI-Lite 32b| F[Shadow Registers];
            F -.->|Idle Update| C;
            E -.->|Forensic Snapshot| G[Audit Registers];
            CPU -.->|Read| G;
        end
    end