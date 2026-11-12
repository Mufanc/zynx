# Zynx Module Filters and Zygisk Compatibility

This guide describes how modules configure Zynx:

- where `zynx.toml` and libraries live;
- how static and external filters decide whether a process is injected;
- the external filter protocol;
- how Zynx loads Zygisk modules.

## Module layout

```
/data/adb/modules/<module_id>/
    zynx.toml              # Zynx configuration
    lib/main.so            # libraries referenced by rules
    zygisk/arm64-v8a.so    # optional Zygisk module library
```

`zynx.toml` lives in the module directory, and library paths in rules are
relative to it. Modules marked with a `disable` file are ignored. Zynx reads
module configuration at startup, so restart it after changing `zynx.toml` or a
library.

Module configuration applies when Zynx runs as a module; standalone builds do
not read `zynx.toml`.

## Manifest

`zynx.toml` declares `manifest_version = 2` and contains at least one
`[[inject]]` rule or a `[zygisk]` section. Unknown fields are rejected.

```toml
manifest_version = 2

[[inject]]
source = "zygote"
library = "lib/main.so"

[inject.filter]
type = "static"
packages = ["com.example.app"]
process_name = "com.example.app"

[[inject]]
source = "zygote"
library = "lib/worker.so"

[inject.filter]
type = "static"
process_name_matches = '^com\.example\.app:worker$'

[zygisk.filter]
type = "static"
packages = ["com.example.app"]
```

Rule fields:

| Field     | Description                                                                 |
|-----------|-----------------------------------------------------------------------------|
| `source`  | `zygote` or `init`                                                          |
| `library` | Relative path inside the module directory. `..` is rejected.                |
| `filter`  | Typed filter; required for every rule.                                      |

Rules are evaluated in order. For each library, the first rule whose filter
allows the process injects it; later rules for the same library are ignored.
Within a module, each library is injected at most once per process. Rules in
different modules are independent.

### Init rules (WIP)

Init injection is WIP: `source = "init"` rules currently have no effect. Use
`source = "zygote"` rules for injection.

### Static and external filters

Zygote rules and the `[zygisk]` section share the same filter schema. Static
conditions are evaluated directly by Zynx; `stdio`, `socket_file` and
`unix_abstract` defer the decision to an external program or service.

## Static filters

```toml
[inject.filter]
type = "static"
uid = "10000-"                        # full Linux UID
user_id = "0"                         # Android user ID (uid / 100000)
packages = ["com.example.app"]        # any package name associated with the UID
process_name = "com.example.app"      # exact process name
# process_name_matches = '^com\.example\.app(:.*)?$'
is_system_server = false
is_child_zygote = false
```

- At least one condition is required.
- Set conditions are combined with **AND**; omitted conditions impose no
  restriction.
- `packages` must be non-empty. It matches when the process UID is associated
  with one of the listed package names.
- `process_name` matches the process name exactly. `process_name_matches` is an
  unanchored `regex-lite` pattern; anchor it explicitly (`^...$`) when needed.
  The two fields are mutually exclusive.
- `uid` and `user_id` accept the same numeric-set syntax, evaluated against the
  full UID and against `uid / 100000` respectively:

  | Input                 | Meaning                                  |
  |-----------------------|------------------------------------------|
  | `"12000"`             | exactly 12000                            |
  | `"0-9999"`            | 0 through 9999, endpoints inclusive      |
  | `"0-9999,12000"`      | union of a range and a single value      |
  | `"10000-"`            | 10000 and above                          |
  | `"-9999"`             | 0 through 9999                           |

  Values are `u32`. Items are trimmed, so surrounding whitespace and a leading
  `+` are accepted; empty items, an item with both endpoints omitted, and
  reversed ranges are rejected.

## External filters

External filters are available when Zynx runs as a module. Instead of
`type = "static"`, a zygote or Zygisk filter can use one of the transports
below.

### Stdio

```toml
[inject.filter]
type = "stdio"
path = "/data/adb/modules/example/bin/filter"
args = ["--profile", "example"]
```

| Field  | Required | Description                                        |
|--------|----------|----------------------------------------------------|
| `path` | yes      | Absolute path to the executable                    |
| `args` | no       | Argument vector; defaults to empty                 |

The executable must be a root-owned regular file. Zynx runs it for each check,
writes one request to its stdin, reads one response from its stdout, then
terminates it. stderr is discarded.

### Socket file

```toml
[inject.filter]
type = "socket_file"
path = "/data/adb/modules/example/run/filter.sock"
```

Zynx connects to this Unix socket for each check. It must be a root-owned
socket, and the peer must have root credentials.

### Unix abstract socket

```toml
[inject.filter]
type = "unix_abstract"
prefix = "example"
```

The server listens on an abstract socket named:

```
<prefix>/v1:p=<pid>;f=<fd>;s=<sequence>;?=<random>
```

For example:

```
example/v1:p=1234;f=7;s=42;?=0123456789abcdef0123456789abcdef
```

Name grammar:

- The name starts with the configured `prefix` followed by `/v1:`. `v1` is the
  only supported name version.
- Fields are separated by `;` and written as `key=value`. All four fields are
  required and may appear in any order:
  - `p` — positive PID advertising the listening socket;
  - `f` — nonnegative FD referring to that same socket;
  - `s` — `u64` sequence number;
  - `?` — nonempty random suffix.
- Duplicate keys, empty keys/values and values for `p`/`f`/`s` that are not
  ASCII digits are rejected. Unknown keys are ignored.
- The complete abstract name must fit within the kernel limit of 107 bytes.
- The server keeps the advertised PID and FD valid while listening.

For each check, Zynx selects the listening socket with the highest sequence
number whose advertised PID and FD refer to that same root-owned socket, and
connects only to it. The peer must have root credentials. If the selected socket
cannot be connected, the check fails.

Filters run with Zynx's privileges, which are root. Keep their executables,
sockets and libraries root-owned and not writable by apps.

## Wire protocol

All messages use length-prefix framing:

```
[4 bytes: payload length, u32 little-endian] [N bytes: Protobuf payload]
```

- Requests and responses are limited to **1 MiB**.
- Connect, send and receive are each bounded by a **1 second** timeout.
- Each connection carries exactly **one request and one response** and is then
  closed. All process information is sent in that single request.

Protocol messages:

```protobuf
message CheckRequest {
    uint32 protocol_version = 1;
    ProcessInfo process = 2;
}

message ProcessInfo {
    uint32 uid = 1;
    uint32 gid = 2;
    bool is_system_server = 3;
    bool is_child_zygote = 4;
    repeated PackageInfo package_info = 5;
    optional string nice_name = 6;
    optional string app_data_dir = 7;
}

message CheckResponse {
    uint32 protocol_version = 1;
    optional bool allow = 2;
}
```

Rules:

- The request carries `protocol_version = 2` and a populated `process`.
- The response must carry exactly `protocol_version = 2` and must explicitly set
  `allow`. A missing `allow`, a different version, or a decode error is treated
  as a denial.
- `nice_name` and `app_data_dir` are included when available.
- `package_info[].gids` are raw Linux GIDs; `package_info[].debuggable` reflects
  the system package database.

Example exchange for one check:

```
Zynx (client)                          Filter (server)
     |--- [len][CheckRequest] ------------->|
     |<-- [len][CheckResponse allow=true] --|
     |--- close --------------------------->|
```

### Error handling

Any of the following rejects the rule that produced the check:

- endpoint is not root-owned, is not the expected type, or the peer is not root;
- connection, spawn or I/O failure, including the 1 second timeouts;
- message larger than 1 MiB;
- Protobuf decode failure;
- response protocol version mismatch, or missing `allow`.

An error only affects that one rule. Other rules are still evaluated, and
another rule may still allow the same library. Errors are logged as warnings.

## Zygisk compatibility (WIP)

Zygisk support requires a Zynx build with the `zygisk` feature, and Zynx must be
started with the runtime feature enabled:

```shell
zynx --bridge /path/to/libzynx_bridge.so daemon --wait-bpfloader \
    --features zygisk
```

Declare a filter in `zynx.toml` and place the module library at
`zygisk/arm64-v8a.so`:

```toml
[zygisk.filter]
type = "static"
packages = ["com.example.app"]
user_id = "0"
```

Only 64-bit ARM is supported, and the library path is fixed. The filter uses
the same schema as zygote rules; a static filter still needs at least one
condition, so use `uid = "0-"` to match every UID.

### Zygisk module ABI

Zynx implements Zygisk API **v4 and v5**:

- For each matching process, Zynx loads the library and calls
  `zygisk_module_entry(const ApiAbi *, JNIEnv)` before the specialize callbacks.
  The entry point registers the module through
  `api->register_module(&module_abi)`. Entries that do not register are ignored.
- `ModuleAbi.version` must be 4 or 5, and `remote_impl`, `app_pre`, `app_pos`,
  `server_pre`, `server_pos` must all be non-null.
- Registered callbacks receive `AppSpecializeArgs` for app processes or
  `ServerSpecializeArgs` for `system_server`. `fds_to_ignore` is always null;
  `mount_sysprop_overrides` is present only in v5.

Options:

| Option                    | Behavior                                                 |
|---------------------------|----------------------------------------------------------|
| `DLCLOSE_MODULE_LIBRARY`  | The library is unloaded after the specialize callbacks.   |
| `FORCE_DENYLIST_UNMOUNT`  | Zynx logs a warning and performs no unmount.             |

Process selection is controlled solely by `[zygisk.filter]`. Zynx provides no
companion process, does not consult Magisk's denylist, and does not expose
`PROCESS_GRANTED_ROOT`.

The `ApiAbi` leaves these function slots null; modules must not call them:

- `hookJniNativeMethods`
- `pltHookRegister`
- `pltHookCommit`
- `exemptFd`
- `connectCompanion`
- `getModuleDir`
- `getFlags`

`registerModule` and `setOption` are available. Calling a null slot crashes the
process, so modules must stay within the supported subset.
