#ifndef GRAPH_H
#define GRAPH_H

#include "common.h"

/**
 * @brief Adjacency Edge in Block Transition Graph
 */
typedef struct GraphEdge {
    int target_block;             /* Target block index */
    double weight;                /* Weight: transition likelihood / correlation score (0.0 - 1.0) */
    struct GraphEdge *next;
} GraphEdge;

/**
 * @brief Adjacency List Node representing a Disk Block
 */
typedef struct {
    int block_index;              /* Disk block index */
    bool is_header;               /* True if this block contains a file magic header */
    bool is_footer;               /* True if this block contains a file footer */
    GraphEdge *edges;             /* Linked list of outgoing edges */
} GraphNode;

/**
 * @brief Directed Weighted Graph
 * Used to model fragmented block relationships and reconstruct scattered file segments.
 */
typedef struct {
    GraphNode nodes[MAX_GRAPH_NODES];
    int num_nodes;
    int node_map[VDISK_TOTAL_BLOCKS]; /* Fast mapping from disk block index to graph node index */
} BlockGraph;

/* Graph Operations */
BlockGraph* graph_create(void);
void graph_destroy(BlockGraph *graph);
int graph_add_node(BlockGraph *graph, int block_index, bool is_header, bool is_footer);
void graph_add_edge(BlockGraph *graph, int src_block, int dst_block, double weight);
int graph_find_node(const BlockGraph *graph, int block_index);

/**
 * @brief Reconstructs the best block sequence from a header block to a footer block (or up to max_blocks).
 * Uses Depth-First Search with heuristic edge-weight maximization.
 * 
 * @param graph Pointer to the BlockGraph
 * @param start_block Block index of header
 * @param max_blocks Maximum number of blocks expected
 * @param out_path Array to store reconstructed block indices
 * @param out_path_len Pointer to store the number of blocks in reconstructed path
 * @return double Total path confidence score
 */
double graph_find_best_path(const BlockGraph *graph, int start_block, int max_blocks, int *out_path, int *out_path_len);

#endif /* GRAPH_H */
