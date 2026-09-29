#include "ds/graph.h"

/**
 * @file graph.c
 * @brief Directed Weighted Graph Implementation for Block Reconstruction
 * 
 * In fragmented storage, files are split into non-contiguous blocks.
 * We model the disk blocks as vertices in a directed graph where edge weights
 * indicate the probabilistic transition score (byte continuity, offset similarity,
 * entropy matching). Graph search algorithms (DFS / Greedy path) are then applied
 * to trace the most probable block sequence from Header to Footer.
 */

BlockGraph* graph_create(void) {
    BlockGraph *graph = (BlockGraph*)malloc(sizeof(BlockGraph));
    if (!graph) return NULL;

    graph->num_nodes = 0;
    for (int i = 0; i < VDISK_TOTAL_BLOCKS; i++) {
        graph->node_map[i] = -1;
    }
    for (int i = 0; i < MAX_GRAPH_NODES; i++) {
        graph->nodes[i].block_index = -1;
        graph->nodes[i].is_header = false;
        graph->nodes[i].is_footer = false;
        graph->nodes[i].edges = NULL;
    }
    return graph;
}

void graph_destroy(BlockGraph *graph) {
    if (!graph) return;
    for (int i = 0; i < graph->num_nodes; i++) {
        GraphEdge *edge = graph->nodes[i].edges;
        while (edge) {
            GraphEdge *next = edge->next;
            free(edge);
            edge = next;
        }
    }
    free(graph);
}

int graph_find_node(const BlockGraph *graph, int block_index) {
    if (!graph || block_index < 0 || block_index >= VDISK_TOTAL_BLOCKS) return -1;
    return graph->node_map[block_index];
}

int graph_add_node(BlockGraph *graph, int block_index, bool is_header, bool is_footer) {
    if (!graph || graph->num_nodes >= MAX_GRAPH_NODES) return -1;
    if (block_index < 0 || block_index >= VDISK_TOTAL_BLOCKS) return -1;

    int existing = graph_find_node(graph, block_index);
    if (existing != -1) {
        graph->nodes[existing].is_header |= is_header;
        graph->nodes[existing].is_footer |= is_footer;
        return existing;
    }

    int idx = graph->num_nodes++;
    graph->nodes[idx].block_index = block_index;
    graph->nodes[idx].is_header = is_header;
    graph->nodes[idx].is_footer = is_footer;
    graph->nodes[idx].edges = NULL;
    graph->node_map[block_index] = idx;
    return idx;
}

void graph_add_edge(BlockGraph *graph, int src_block, int dst_block, double weight) {
    if (!graph) return;
    int u = graph_find_node(graph, src_block);
    int v = graph_find_node(graph, dst_block);
    if (u == -1 || v == -1) return;

    /* Check if edge already exists */
    GraphEdge *curr = graph->nodes[u].edges;
    while (curr) {
        if (curr->target_block == dst_block) {
            curr->weight = weight;
            return;
        }
        curr = curr->next;
    }

    /* Add new edge */
    GraphEdge *edge = (GraphEdge*)malloc(sizeof(GraphEdge));
    if (!edge) return;
    edge->target_block = dst_block;
    edge->weight = weight;
    edge->next = graph->nodes[u].edges;
    graph->nodes[u].edges = edge;
}

/* Helper DFS to find the maximum confidence path from start_block */
static void dfs_find_path(const BlockGraph *graph, 
                          int current_block, 
                          int max_blocks, 
                          bool *visited_blocks, 
                          int *current_path, 
                          int current_len, 
                          double current_score, 
                          int *best_path, 
                          int *best_len, 
                          double *best_score) {
    
    current_path[current_len] = current_block;
    current_len++;

    int u = graph_find_node(graph, current_block);
    bool is_footer = (u != -1 && graph->nodes[u].is_footer);

    /* Base case: reached footer or max block limit */
    if (is_footer || current_len >= max_blocks) {
        double avg_score = current_len > 0 ? (current_score / current_len) : 0.0;
        if (avg_score > *best_score || (*best_score == 0.0 && current_len > *best_len)) {
            *best_score = avg_score;
            *best_len = current_len;
            for (int i = 0; i < current_len; i++) {
                best_path[i] = current_path[i];
            }
        }
        if (is_footer) return;
    }

    if (u == -1) return;

    /* Explore outgoing edges */
    GraphEdge *edge = graph->nodes[u].edges;
    bool has_unvisited = false;

    while (edge) {
        int v_block = edge->target_block;
        if (v_block >= 0 && v_block < VDISK_TOTAL_BLOCKS && !visited_blocks[v_block]) {
            has_unvisited = true;
            visited_blocks[v_block] = true;
            dfs_find_path(graph, v_block, max_blocks, visited_blocks, 
                          current_path, current_len, current_score + edge->weight, 
                          best_path, best_len, best_score);
            visited_blocks[v_block] = false;
        }
        edge = edge->next;
    }

    /* If dead end with no further edges, evaluate current path */
    if (!has_unvisited && current_len > 0) {
        double avg_score = current_score / current_len;
        if (avg_score > *best_score) {
            *best_score = avg_score;
            *best_len = current_len;
            for (int i = 0; i < current_len; i++) {
                best_path[i] = current_path[i];
            }
        }
    }
}

double graph_find_best_path(const BlockGraph *graph, int start_block, int max_blocks, int *out_path, int *out_path_len) {
    if (!graph || start_block < 0 || max_blocks <= 0 || !out_path || !out_path_len) return 0.0;

    int *current_path = (int*)calloc(max_blocks + 1, sizeof(int));
    bool *visited = (bool*)calloc(VDISK_TOTAL_BLOCKS, sizeof(bool));
    if (!current_path || !visited) {
        if (current_path) free(current_path);
        if (visited) free(visited);
        return 0.0;
    }

    int best_len = 0;
    double best_score = 0.0;

    visited[start_block] = true;
    dfs_find_path(graph, start_block, max_blocks, visited, current_path, 0, 1.0, out_path, &best_len, &best_score);

    *out_path_len = best_len;
    free(current_path);
    free(visited);
    return best_score;
}
