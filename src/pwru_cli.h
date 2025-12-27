#ifndef __PWRU_CLI_H
#define __PWRU_CLI_H

#include <stdint.h>
#include <stdbool.h>
#include "pwru_error.h"
#include "pwru_backend.h"

enum pwru_cmd {
    PWRU_CMD_TRACE = 0, // Default command
    PWRU_CMD_LIST,      // --list-funcs
};

struct pwru_config {
    enum pwru_cmd cmd;
    
    // Filter options
    uint32_t filter_src_ip;
    uint32_t filter_dst_ip;
    uint16_t filter_sport;
    uint16_t filter_dport;
    uint8_t filter_proto;
    uint32_t filter_pid;
    uint16_t filter_family;
    
    // Execution options
    bool all_kprobes;
    bool test_attach;
    enum backend backend;
    
    // PCAP filter (positional argument)
    char *pcap_filter;
};

/**
 * @brief Parse command line arguments into config structure
 */
pwru_err_t pwru_cli_parse(int argc, char **argv, struct pwru_config *cfg);

#endif
