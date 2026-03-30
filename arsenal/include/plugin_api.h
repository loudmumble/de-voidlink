/*
 * de-voidlink Arsenal Plugin API
 *
 * Mirrors VoidLink's BOF-style plugin interface.
 * Plugins are compiled as ELF relocatable objects (.o / ET_REL)
 * and loaded in-memory by the Zig implant's custom relocator.
 *
 * Each plugin exports a standard entry table:
 *   - plugin_info()   → metadata (name, version, description)
 *   - plugin_init()   → one-time setup, returns 0 on success
 *   - plugin_exec()   → main execution, receives context + output buffer
 *   - plugin_cleanup() → teardown, free resources
 *
 * Plugins communicate with the implant through the PluginContext
 * struct, which provides:
 *   - output buffer for results
 *   - runtime config (dry-run mode, safety flags)
 *   - syscall dispatch table (for direct syscall access)
 *
 * SAFETY: All shipped plugins contain benign payloads.
 * The API supports payload swapping for controlled research.
 */

#ifndef DE_VOIDLINK_PLUGIN_API_H
#define DE_VOIDLINK_PLUGIN_API_H

#include <stdint.h>
#include <stddef.h>

/* Plugin API version — must match implant loader */
#define PLUGIN_API_VERSION 1

/* Maximum output buffer size (64 KB) */
#define PLUGIN_MAX_OUTPUT (64 * 1024)

/* Plugin capability flags */
#define PLUGIN_CAP_NETWORK   (1 << 0)  /* Requires network access */
#define PLUGIN_CAP_FILESYSTEM (1 << 1) /* Requires filesystem access */
#define PLUGIN_CAP_PROCESS   (1 << 2)  /* Requires process operations */
#define PLUGIN_CAP_PRIVILEGED (1 << 3) /* Requires root/CAP_* */
#define PLUGIN_CAP_STEALTH   (1 << 4)  /* Uses evasion techniques */

/* Plugin execution mode */
typedef enum {
    EXEC_MODE_NORMAL = 0,    /* Full execution */
    EXEC_MODE_DRY_RUN = 1,   /* Log actions, don't execute */
    EXEC_MODE_VERBOSE = 2,   /* Full execution with detailed logging */
} ExecMode;

/* Plugin metadata */
typedef struct {
    const char *name;         /* Short identifier (e.g. "recon") */
    const char *version;      /* Semantic version string */
    const char *description;  /* Human-readable description */
    const char *author;       /* Author identifier */
    uint32_t    api_version;  /* Must equal PLUGIN_API_VERSION */
    uint32_t    capabilities; /* Bitfield of PLUGIN_CAP_* flags */
} PluginInfo;

/* Output buffer for plugin results */
typedef struct {
    uint8_t *data;            /* Buffer pointer (provided by loader) */
    size_t   capacity;        /* Buffer capacity in bytes */
    size_t   length;          /* Current data length */
} OutputBuffer;

/* Syscall dispatch table — for direct syscall access
 * Each entry is a function pointer: long (*)(long nr, ...) */
typedef struct {
    long (*syscall0)(long nr);
    long (*syscall1)(long nr, long a1);
    long (*syscall2)(long nr, long a1, long a2);
    long (*syscall3)(long nr, long a1, long a2, long a3);
    long (*syscall4)(long nr, long a1, long a2, long a3, long a4);
    long (*syscall5)(long nr, long a1, long a2, long a3, long a4, long a5);
    long (*syscall6)(long nr, long a1, long a2, long a3, long a4, long a5, long a6);
} SyscallTable;

/* Runtime context passed to plugin_exec */
typedef struct {
    ExecMode     mode;        /* Execution mode */
    OutputBuffer output;      /* Output buffer for results */
    SyscallTable *syscalls;   /* Direct syscall dispatch (NULL if unavailable) */
    const char   *c2_addr;    /* C2 server address (for network plugins) */
    uint16_t      c2_port;    /* C2 server port */
    uint32_t      flags;      /* Runtime flags (reserved) */
} PluginContext;

/* Return codes */
#define PLUGIN_OK        0
#define PLUGIN_ERR      -1
#define PLUGIN_SKIP     -2   /* Plugin chose not to execute (e.g. wrong OS) */
#define PLUGIN_DRY_RUN  -3   /* Dry run completed (no side effects) */

/*
 * Plugin export table — every plugin MUST define these symbols.
 * The loader resolves them by name from the ELF .o symbol table.
 */

/* Returns plugin metadata. Called before init. */
PluginInfo* plugin_info(void);

/* One-time initialization. Return PLUGIN_OK on success. */
int plugin_init(PluginContext *ctx);

/* Main execution entry point. Write results to ctx->output. */
int plugin_exec(PluginContext *ctx);

/* Cleanup. Free any resources allocated during init/exec. */
int plugin_cleanup(PluginContext *ctx);

/*
 * Helper macros for plugin output
 */
#define OUTPUT_WRITE(ctx, buf, len) do { \
    size_t _avail = (ctx)->output.capacity - (ctx)->output.length; \
    size_t _copy = (len) < _avail ? (len) : _avail; \
    if (_copy > 0) { \
        __builtin_memcpy((ctx)->output.data + (ctx)->output.length, (buf), _copy); \
        (ctx)->output.length += _copy; \
    } \
} while(0)

#define OUTPUT_STRING(ctx, str) do { \
    const char *_s = (str); \
    size_t _len = 0; \
    while (_s[_len]) _len++; \
    OUTPUT_WRITE(ctx, _s, _len); \
} while(0)

#endif /* DE_VOIDLINK_PLUGIN_API_H */
