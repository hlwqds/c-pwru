#ifndef __PWRU_ERROR_H
#define __PWRU_ERROR_H

#include <errno.h>

/**
 * @brief Unified error codes for C-pwru
 * 
 * All internal functions should return this enum instead of raw errno.
 */
typedef enum {
    PWRU_OK = 0,

    /* Generic Errors */
    PWRU_ERR_GENERIC = -1000,
    PWRU_ERR_NOMEM,         /* Memory allocation failed */
    PWRU_ERR_INVALID_ARG,   /* Invalid argument provided */
    PWRU_ERR_NOT_FOUND,     /* Resource not found */
    PWRU_ERR_PERMISSION,    /* Permission denied (e.g. root required) */
    PWRU_ERR_TIMEOUT,       /* Operation timed out */

    /* BPF/Libbpf Related Errors */
    PWRU_ERR_BPF_OPEN,      /* Failed to open BPF object */
    PWRU_ERR_BPF_LOAD,      /* Failed to load BPF object/verifier error */
    PWRU_ERR_BPF_ATTACH,    /* Failed to attach BPF program */
    PWRU_ERR_BPF_MAP,       /* BPF map operation failed */
    
    /* Internal logic errors */
    PWRU_ERR_TOO_MANY_ARGS, /* Exceeded MAX_ARGS_SUPPORTED */
    
} pwru_err_t;

/**
 * @brief Convert system errno to pwru_err_t
 */
pwru_err_t pwru_errno_to_err(int sys_errno);

/**
 * @brief Convert libbpf error (which is usually -errno) to pwru_err_t
 */
pwru_err_t pwru_libbpf_to_err(int libbpf_err);

/**
 * @brief Get a string description of the error
 */
const char *pwru_strerror(pwru_err_t err);

#endif // __PWRU_ERROR_H
