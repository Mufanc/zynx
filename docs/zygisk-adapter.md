# Zygisk Adapter Integration Guide

## Overview

Zynx supports external filter programs that decide whether to inject into specific processes. Each Magisk module can place a `zynx-configs.toml` configuration file in its directory to declare the filter type and connection method.

When the zynx daemon starts, it scans all modules under `/data/adb/modules`, reads their configurations, and communicates with filters on each process fork to perform a two-phase check.

## Module Directory Structure

```
/data/adb/modules/<module_id>/
    zynx-configs.toml    # Zynx adapter configuration
    disable              # If present, the module is skipped
    module.prop          # Magisk module metadata
    ...
```

## Configuration Format

The configuration file is `zynx-configs.toml` and must contain a `[filter]` section. The `type` field determines the filter type. `stdio`, `socket_file`, and `unix_abstract` are mutually exclusive.

### Stdio

Zynx launches the specified executable and communicates via stdin/stdout.

```toml
[filter]
type = "stdio"
path = "/data/adb/modules/<module_id>/bin/filter"
args = ["--some-flag"]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | Must be `"stdio"` |
| `path` | string | yes | Absolute path to the executable |
| `args` | string[] | no | Command-line arguments, defaults to empty |

### Socket File

Zynx connects to the specified Unix domain socket.

```toml
[filter]
type = "socket_file"
path = "/data/adb/modules/<module_id>/run/filter.sock"
```

| Field  | Type   | Required | Description                           |
|--------|--------|----------|---------------------------------------|
| `type` | string | yes      | Must be `"socket_file"`               |
| `path` | string | yes      | Absolute path to the Unix socket file |

### Unix Abstract

Zynx connects to a Linux abstract namespace Unix socket. The configuration only specifies a prefix; zynx discovers matching sockets at connect time by scanning `/proc/net/unix`.

```toml
[filter]
type = "unix_abstract"
prefix = "myapp_filter"
```

| Field    | Type   | Required | Description                      |
|----------|--------|----------|----------------------------------|
| `type`   | string | yes      | Must be `"unix_abstract"`        |
| `prefix` | string | yes      | Socket name prefix for discovery |

**Socket naming convention**: The filter server must listen on an abstract socket named `<prefix>_<seq>_<random>`, where:

- `<seq>` is a `u64` sequence number, not necessarily contiguous. Common choices include a Unix timestamp or `SystemClock.uptimeMillis()`.
- `<random>` is an arbitrary string matching `[a-zA-Z0-9-]+`.

Zynx always connects to the socket with the **highest** `<seq>` value (the newest). If that socket cannot be reached, the connection is considered failed (no fallback to older sockets).

## Protocol

### Message Framing

All messages use length-prefix framing:

```
[4 bytes: payload_length (u32, little-endian)] [N bytes: protobuf payload]
```

- Maximum message size: 1 MB
- IO timeout: 1 second

### Protobuf Definitions

The proto file is located at `src/core/proto/embryo_check_args.proto`, package `zynx_policy`.

```protobuf
message PackageInfo {
    string package_name = 1;
    bool debuggable = 2;
    string data_dir = 3;
    string seinfo = 4;
    repeated uint32 gids = 5;
}

message CheckArgsFast {
    uint32 uid = 1;
    uint32 gid = 2;
    bool is_system_server = 3;
    bool is_child_zygote = 4;
    repeated PackageInfo package_info = 5;
}

message CheckArgsSlow {
    CheckArgsFast fast = 1;
    optional string nice_name = 2;
    optional string app_data_dir = 3;
}

enum CheckResult {
    ALLOW = 0;
    DENY = 1;
    MORE_INFO = 2;
}

message CheckResponse {
    CheckResult result = 1;
}
```

### Interaction Flow

On each process fork, zynx communicates with the filter as follows:

```
Zynx (client)                          Filter (server)
     |                                       |
     |--- [len][CheckArgsFast] ------------->|
     |                                       |  process fast args
     |<-- [len][CheckResponse] --------------|
     |                                       |
     |  if result == MORE_INFO:              |
     |                                       |
     |--- [len][CheckArgsSlow] ------------->|
     |                                       |  process slow args
     |<-- [len][CheckResponse] --------------|
     |                                       |
     |--- close connection ----------------->|
```

**Phase 1 (Fast Check)**:

1. Zynx establishes a connection (connect to socket or exec process).
2. Zynx sends a `CheckArgsFast` message.
3. Filter returns a `CheckResponse`:
   - `ALLOW` — permit injection, connection closes.
   - `DENY` — reject injection, connection closes.
   - `MORE_INFO` — more information needed, connection stays alive.

**Phase 2 (Slow Check, only if Fast Check returned `MORE_INFO`)**:

1. Zynx sends a `CheckArgsSlow` message (includes `nice_name` and `app_data_dir`).
2. Filter returns a `CheckResponse`:
   - `ALLOW` — permit injection.
   - `DENY` — reject injection.
   - `MORE_INFO` — treated as `DENY` (not allowed to request more info in the slow phase).
3. Connection closes.

The entire interaction completes within **a single connection / process lifetime**.

## CheckArgsFast vs CheckArgsSlow

| Field              | Fast | Slow | Description                                            |
|--------------------|------|------|--------------------------------------------------------|
| `uid`              | yes  | yes  | Application UID                                        |
| `gid`              | yes  | yes  | Application GID                                        |
| `is_system_server` | yes  | yes  | Whether this is system_server                          |
| `is_child_zygote`  | yes  | yes  | Whether this is a child zygote                         |
| `package_info`     | yes  | yes  | Package information list                               |
| `nice_name`        | no   | yes  | Process name (e.g. `com.example.app`)                  |
| `app_data_dir`     | no   | yes  | App data directory (e.g. `/data/data/com.example.app`) |

Fast args are available immediately at zygote fork time with no extra cost. Slow args require reading from the app process JVM, which is more expensive. If the filter can make a decision based on UID / package info alone, it should return `ALLOW` or `DENY` in the fast phase to avoid triggering the slow phase.

## Error Handling

Zynx treats the adapter result as `DENY` in the following cases:

- Connection failure or process spawn failure
- IO timeout (1 second)
- Message size exceeds 1 MB
- Protobuf decode failure
- Connection drops between the two phases
- `MORE_INFO` returned in the slow phase

Errors from one adapter do not affect other adapters.
