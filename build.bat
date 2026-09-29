@echo off
echo =======================================================
echo Compiling ForensiRecover - Digital Forensics Simulator
echo =======================================================

gcc -Wall -Wextra -std=c99 -Iinclude -O2 ^
  src/main.c ^
  src/ds/array_bitmap.c ^
  src/ds/linked_list.c ^
  src/ds/hash_table.c ^
  src/ds/queue.c ^
  src/ds/stack.c ^
  src/ds/bst.c ^
  src/ds/heap.c ^
  src/ds/graph.c ^
  src/storage/vdisk.c ^
  src/storage/fragmentation.c ^
  src/forensics/signatures.c ^
  src/forensics/integrity.c ^
  src/forensics/confidence.c ^
  src/forensics/evidence_store.c ^
  src/forensics/scanner.c ^
  src/forensics/reconstructor.c ^
  src/forensics/report.c ^
  src/ui/terminal_ui.c ^
  src/ui/demo_scenarios.c ^
  -o forensirecover.exe

if %ERRORLEVEL% equ 0 (
    echo [OK] Compilation Succeeded! Binary created: forensirecover.exe
    echo Running ForensiRecover...
    forensirecover.exe
) else (
    echo [ERROR] Compilation failed.
)
