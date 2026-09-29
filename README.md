# ForensiRecover: C-Based Digital Forensics File Recovery Simulator

**ForensiRecover** is an educational Digital Forensics & File Recovery Simulator developed as a **Data Structures Semester Course Project**.

The project simulates a virtual storage device in memory and demonstrates how real-world filesystems store, delete, fragment, scan, carve, reconstruct, and verify data remnants using fundamental **Data Structures and Algorithms**.

---

## 🎯 9-Step Forensic Workflow

```
[1. CREATE] -> [2. STORE] -> [3. DELETE] -> [4. FRAGMENT] -> [5. SCAN] -> [6. IDENTIFY] -> [7. RECOVER] -> [8. VERIFY] -> [9. REPORT]
```

1. **CREATE**: File payloads (PDF, PNG, JPG, TXT, ZIP) are generated or loaded.
2. **STORE**: Files are divided into 512-byte blocks and indexed via Inodes and Bitmaps.
3. **DELETE**: Simulates real-world OS deletion — removes directory metadata while preserving raw remnant bytes in unallocated sectors.
4. **FRAGMENT**: Intentionally scatters file blocks across non-contiguous clusters.
5. **SCAN**: Deep disk scanner inspects unallocated sectors using a FIFO queue.
6. **IDENTIFY**: Detects file signatures via a Magic Bytes database.
7. **RECOVER**: Reconstructs fragmented block sequences using a **Directed Graph** and ranks candidates in a **Max-Heap**.
8. **VERIFY**: Performs cryptographic **SHA-256** and **CRC-32** integrity checks against expected hashes.
9. **REPORT**: Organizes evidence into a **Binary Search Tree (BST)** and generates formal forensic investigation reports.

---

## 🧩 Data Structures & Algorithmic Mapping

| Data Structure | Implementation File | Role in Digital Forensics | Time / Space Complexity |
| :--- | :--- | :--- | :--- |
| **Array & Bit Array** | [`include/ds/array_bitmap.h`](file:///include/ds/array_bitmap.h) | Physical 512-byte block storage matrix & allocation tracking | $O(1)$ block bit testing & allocation |
| **Doubly Linked List** | [`include/ds/linked_list.h`](file:///include/ds/linked_list.h) | Active directory inodes and deleted file remnant tracking | $O(1)$ insertion/deletion at head/tail |
| **Chained Hash Table** | [`include/ds/hash_table.h`](file:///include/ds/hash_table.h) | O(1) metadata lookup by filename or hash (DJB2 hashing) | $O(1)$ average search & insertion |
| **FIFO Task Queue** | [`include/ds/queue.h`](file:///include/ds/queue.h) | Chunked scanner pipeline for high-throughput disk inspection | $O(1)$ enqueue & dequeue |
| **LIFO History Stack** | [`include/ds/stack.h`](file:///include/ds/stack.h) | Investigator audit logs, carving backtrack states, and undo | $O(1)$ push & pop |
| **Binary Search Tree** | [`include/ds/bst.h`](file:///include/ds/bst.h) | Hierarchical evidence ledger indexed by unique Evidence ID | $O(\log N)$ search, in-order chronological export |
| **Max-Heap Priority Queue** | [`include/ds/heap.h`](file:///include/ds/heap.h) | Ranking recovered candidate files by forensic confidence (0-100%) | $O(\log N)$ extraction of highest confidence files |
| **Directed Weighted Graph** | [`include/ds/graph.h`](file:///include/ds/graph.h) | Modeling fragmented block adjacency & DFS path defragmentation | $O(V + E)$ graph construction & path traversal |

---

## 🔬 Forensic Confidence Scoring Algorithm

The recovery engine evaluates candidate files across 5 weighted factors:

$$\text{Confidence} = \text{Header Match (30\%)} + \text{Footer Match (25\%)} + \text{Continuity (20\%)} + \text{Structure (15\%)} + \text{Metadata (10\%)}$$

- **High Confidence ($\ge 90\%$)**: Valid header, matching footer, strong structure, and verified checksum.
- **Medium Confidence ($60\% - 89\%$)**: Valid header with partial fragmentation or missing footer.
- **Low Confidence ($< 60\%$)**: Corrupted or incomplete block sequences.

---

## 🛠️ Project Structure

```
ForensiRecover/
├── include/
│   ├── common.h                     # Global constants, ANSI colors, status codes
│   ├── ds/                          # Core Data Structure Headers
│   │   ├── array_bitmap.h           # Array & Bitmap Allocation
│   │   ├── linked_list.h            # Doubly Linked List
│   │   ├── hash_table.h             # Chained Hash Table
│   │   ├── queue.h                  # FIFO Queue
│   │   ├── stack.h                  # LIFO Stack
│   │   ├── bst.h                    # Binary Search Tree
│   │   ├── heap.h                   # Max-Heap Priority Queue
│   │   └── graph.h                  # Directed Weighted Graph
│   ├── storage/                     # Storage Device Subsystem
│   │   ├── inode.h                  # File Inode & Metadata definitions
│   │   ├── vdisk.h                  # Virtual Storage Device & Sector Array
│   │   └── fragmentation.h          # Cluster Fragmentation Engine
│   ├── forensics/                   # Forensics & Recovery Subsystem
│   │   ├── signatures.h             # Magic Bytes & File Signatures Database
│   │   ├── scanner.h                # Queue-driven Deep Disk Scanner
│   │   ├── confidence.h             # Multi-Factor Confidence Scoring
│   │   ├── reconstructor.h          # Graph Defragmentation & Carving
│   │   ├── integrity.h              # Pure C SHA-256 & CRC-32 Engine
│   │   ├── evidence_store.h         # BST-backed Evidence Ledger
│   │   └── report.h                 # Report Generator (Terminal & Markdown)
│   └── ui/
│       ├── terminal_ui.h            # Terminal UI, Banners, Hex Dumps
│       └── demo_scenarios.h         # 9-Step Guided Simulation
├── src/                             # C Source Code Implementations
│   ├── ds/                          # Data structure implementations
│   ├── storage/                     # Virtual disk & fragmentation
│   ├── forensics/                   # Forensic carver, scanner, hash, report
│   ├── ui/                          # Terminal UI & scenarios
│   └── main.c                       # Interactive Dashboard CLI
├── Makefile                         # GNU Make build script
├── build.bat                        # Windows batch build script
└── README.md                        # Documentation & Architecture Guide
```

---

## 🚀 Building and Running

### Prerequisites
- GCC or Clang supporting C99/C11
- Windows, Linux, or macOS

### Option 1: Using GCC directly
```bash
gcc -Wall -Wextra -std=c99 -Iinclude -O2 src/main.c src/ds/*.c src/storage/*.c src/forensics/*.c src/ui/*.c -o forensirecover.exe
./forensirecover.exe
```

### Option 2: Using Makefile
```bash
make
make run
```

### Option 3: Windows Batch Script
```cmd
build.bat
```

---

## 📊 Sample Investigation Report Preview

When the 9-step simulation or manual scan finishes, ForensiRecover exports a report to `forensic_investigation_report.md`:

```markdown
# DIGITAL FORENSICS INVESTIGATION REPORT
**System:** ForensiRecover v1.0.0
**Case ID:** CASE-2026-FORENSI-01
**Lead Investigator:** Forensic Unit (Data Structures)

## 1. Executive Summary
| Metric | Value |
| :--- | :--- |
| Total Blocks Scanned | 2048 blocks (1024 KB) |
| Detected Deleted Signatures | 3 |
| Successfully Recovered Files | 3 |
| Cryptographically Verified Files | 2 |
| Average Recovery Confidence | 86.02% |

## 2. Recovered Files & Cryptographic Verification
| ID | Filename | Type | Size (Bytes) | Confidence | Verification Status | SHA-256 Checksum |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | suspect_photo.png | PNG | 125 | 100.0% (HIGH) | PASSED (SHA-256 MATCH) | `e38a102c3f0a6c...` |
| 2 | evidence_document.pdf | PDF | 582 | 88.0% (MEDIUM) | PASSED (SHA-256 MATCH) | `f54c4426cacfd0...` |
```

---

## 🎓 Academic Value & Course Evaluation

This project is tailored specifically for **Data Structures & Algorithms (2nd Year Computer Engineering / Computer Science)** courses:
- Demonstrates how theoretical data structures directly solve real-world system-level engineering challenges.
- Features clean, modular C code with memory management (`malloc`/`free`), zero memory leaks, and structured encapsulation.
- Provides interactive menus, block allocation visualizations, hex dumps, and graph-based defragmentation.
