<div align="center">

![argus Banner](https://capsule-render.vercel.app/api?type=waving&color=0:0f1724,100:0b5ed7&height=160&section=header&text=argus&fontSize=80&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&rotate=2&stroke=0b5ed7&strokeWidth=2&desc=High-performance%20entropy-based%20secret%20scanner&descSize=16&descAlignY=60)

![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/license-AGPL_3.0-blue.svg?style=for-the-badge)
![Version](https://img.shields.io/badge/version-1.1.0-green.svg?style=for-the-badge)

[Installation](#installation) • [Usage](#usage) • [Deep Analysis](#deep-analysis-and-security-heuristics) • [Output Modes](#output-modes) • [License](#license)

</div>

**argus** is a high-performance security scanner for detecting secrets and sensitive information. It utilizes Shannon entropy analysis and multi-pattern matching to identify both known and unknown credentials with high precision.

---

## Core Capabilities

- **Hybrid Engine**: Combines **Aho-Corasick** keyword matching with **Shannon Entropy** analysis.
- **AST-Aware Analysis**: Precise control-flow and scope resolution for JavaScript, Python, Go, Rust, and Java.
- **Attack Surface Mapping**: HTTP request tracing (`fetch`, `axios`, `curl`) to map application dependencies.
- **Git Integration**: Diff-only scanning (`--diff`) and baseline management for CI/CD workflows.
- **Machine-Readable Output**: Exports to JSON, NDJSON, SARIF, CSV, and JUnit XML.

---

## Installation

```bash
cargo install --path .
```

---

## Usage

```bash
argus -t <path_or_url> [OPTIONS]
```

### Examples

**1. Entropy Scan**
```bash
argus -t ./src --entropy --threshold 4.8
```

**2. Keyword Audit**
```bash
argus -t . -k API_KEY -k "Bearer "
```

**3. CI/CD Pipeline (JUnit)**
```bash
argus -t . --entropy --output report.xml --output-format junit
```

**4. Deep Security Audit**
```bash
argus -t . --deep-scan --flow-scan --request-trace
```

---

## Output Modes

| Format | Flag | Description |
|--------|------|-------------|
| **Human** | (default) | Styled terminal output with risk heatmaps. |
| **JSON** | `--json` | Pretty-printed JSON to stdout. |
| **NDJSON** | `--output-format ndjson` | Streamed newline-delimited JSON. |
| **SARIF** | `--output-format sarif` | Static Analysis Results Interchange Format. |
| **CSV** | `--output-format csv` | Comma-separated values for spreadsheet analysis. |
| **JUnit** | `--output-format junit` | XML report for CI/CD test integration. |
| **Story** | `--output-format story` | Markdown-based narrative report. |

---

## Deep Analysis and Security Heuristics

When using `--deep-scan`, the following analysis modules are activated:

### Context & Provenance
- **Story Mode**: Natural language explanation of match risk.
- **Sink Provenance**: Identifies data flow to Network (`fetch`), Disk (`fs.write`), or Log (`console.log`) sinks.
- **Leak Velocity**: Estimates exposure speed based on surrounding code context.

### Structural Heuristics
- **Credential Shadowing**: Detects placeholder shadowing (e.g., TODO replaced by real key).
- **Lateral Linkage**: Identifies identical tokens across disparate source files.
- **Surface Tension**: Measures code complexity surrounding secrets to filter test data.

### Protocol & Auth Logic
- **Protocol Drift**: Flags insecure protocol downgrades (https to http).
- **Auth Drift**: Detects requests lacking authentication headers relative to siblings.
- **Capability Inference**: Infers endpoint risk level (e.g., `DELETE` implies destructive capability).

---

## Advanced Configuration

### Control Flow Analysis (`--flow-scan`)
Provides lightweight control flow context:
- **Scope**: Current function/class/block.
- **Control**: Nearest `if`, `while`, `return`.
- **Distance**: Byte distance to assignments or returns.

> [!NOTE]
> For high-precision analysis, enable AST-based parsing:
> - **JS/TS**: `cargo build --features js-ast`
> - **Python**: `cargo build --features py-ast`
> - **Go**: `cargo build --features go-ast`
> - **Rust**: `cargo build --features rust-ast`
> - **Java**: `cargo build --features java-ast`

### Optional Features
- **Language ASTs**: `cargo build --features js-ast,py-ast,go-ast,rust-ast,java-ast`
- **Syntax Highlighting**: `cargo build --features highlighting`

---

## Options Reference

| Category | Flag | Description |
|----------|------|-------------|
| **Core** | `-t, --target <PATH>` | Target file, directory, or URL. |
| | `-k, --keyword <STR>` | Literal keyword search. |
| | `--entropy` | Enable Shannon entropy scanning. |
| **Tuning** | `--threshold <FLOAT>` | Entropy threshold (default: 4.5). |
| | `--diff` | Scan only lines added in git diff. |
| **Output** | `--output <PATH>` | Output path or directory. |
| | `--output-format <FMT>` | `single`, `ndjson`, `per-file`, `story`, `sarif`, `csv`, `junit`. |
| **Analysis** | `--deep-scan` | Enable heuristic analysis modules. |
| | `--flow-scan` | Enable control-flow context. |
| | `--request-trace` | Enable HTTP traffic analysis. |

---

<div align="center">

**Author:** Seuriin ([SSL-ACTX](https://github.com/SSL-ACTX))

*v1.1.0*

</div>
