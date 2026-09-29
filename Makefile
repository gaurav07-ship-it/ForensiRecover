CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Iinclude -O2
LDFLAGS = 

SRC = src/main.c \
      src/ds/array_bitmap.c \
      src/ds/linked_list.c \
      src/ds/hash_table.c \
      src/ds/queue.c \
      src/ds/stack.c \
      src/ds/bst.c \
      src/ds/heap.c \
      src/ds/graph.c \
      src/storage/vdisk.c \
      src/storage/fragmentation.c \
      src/forensics/signatures.c \
      src/forensics/integrity.c \
      src/forensics/confidence.c \
      src/forensics/evidence_store.c \
      src/forensics/scanner.c \
      src/forensics/reconstructor.c \
      src/forensics/report.c \
      src/ui/terminal_ui.c \
      src/ui/demo_scenarios.c

TARGET = forensirecover.exe

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)
