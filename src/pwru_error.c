#include "pwru_error.h"
#include <string.h>

/**
 * Define starting base for error codes to avoid collision with standard errno
 * but we use negative values as per convention.
 */
#define PWRU_ERR_BASE 1000

pwru_err_t pwru_errno_to_err(int sys_errno)
{
	switch (sys_errno) {
	case 0:
		return PWRU_OK;
	case ENOMEM:
		return PWRU_ERR_NOMEM;
	case EINVAL:
		return PWRU_ERR_INVALID_ARG;
	case ENOENT:
		return PWRU_ERR_NOT_FOUND;
	case EACCES:
	case EPERM:
		return PWRU_ERR_PERMISSION;
	case ETIMEDOUT:
		return PWRU_ERR_TIMEOUT;
	default:
		return PWRU_ERR_GENERIC;
	}
}

pwru_err_t pwru_libbpf_to_err(int libbpf_err)
{
	if (libbpf_err >= 0)
		return PWRU_OK;

	/* libbpf often returns -errno */
	return pwru_errno_to_err(-libbpf_err);
}

const char *pwru_strerror(pwru_err_t err)
{
	switch (err) {
	case PWRU_OK:
		return "Success";
	case PWRU_ERR_NOMEM:
		return "Out of memory";
	case PWRU_ERR_INVALID_ARG:
		return "Invalid argument";
	case PWRU_ERR_NOT_FOUND:
		return "Resource not found";
	case PWRU_ERR_PERMISSION:
		return "Permission denied (root required?)";
	case PWRU_ERR_TIMEOUT:
		return "Operation timed out";
	case PWRU_ERR_BPF_OPEN:
		return "Failed to open BPF object";
	case PWRU_ERR_BPF_LOAD:
		return "Failed to load BPF object (verifier error?)";
	case PWRU_ERR_BPF_ATTACH:
		return "Failed to attach BPF program";
	case PWRU_ERR_BPF_MAP:
		return "BPF map operation failed";
	case PWRU_ERR_TOO_MANY_ARGS:
		return "Exceeded maximum supported arguments";
	case PWRU_ERR_GENERIC:
	default:
		return "Generic error";
	}
}
