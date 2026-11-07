# Zynx

Zynx (**Zy**gote **N**e**x**us) is a dynamic code injection framework for Android, written in Rust. It uses eBPF for kernel-level process monitoring and ptrace for runtime injection, loading custom code into app processes during initialization.

## Features

- **eBPF-based process monitoring** — efficiently tracks Zygote fork events in kernel space
- **Ptrace-driven injection** — injects code into app processes at the `SpecializeCommon` stage
- **Stealthy** — traceless operation with no mounts; non-target processes are left completely untouched
- **Policy framework** — determines per-app injection decisions using complete process information

## Daemon Mode

`zynx daemon` starts the daemon in the background and exits once initialization is complete. This makes it suitable for use in scripts like `post-fs-data.sh`.

## Usage

### Modules

Place `zynx.toml` in a module directory next to the Zynx module. Zynx scans the parent of `MODDIR` at startup and skips modules with a `disable` marker. Configuration and libraries are loaded once at startup.

Only `manifest_version = 2` is supported. A manifest must contain at least one `[[inject]]` rule or a `[zygisk]` section. A module can declare multiple libraries with independent rules:

```toml
manifest_version = 2

[[inject]]
library = "lib/main.so"
source = "zygote"

[inject.filter]
type = "static"
packages = ["com.example.app"]
process_name = "com.example.app"
user_id = "0"

[[inject]]
library = "lib/worker.so"
source = "zygote"

[inject.filter]
type = "static"
packages = ["com.example.app"]
process_name_matches = '^com\.example\.app:worker$'
uid = "10000-"
```

Each static filter combines its conditions with AND. All matching rules contribute libraries, in rule order. The same module-relative library path is loaded once per process, including paths with redundant `./` components. Paths must stay beneath the module directory. A missing or invalid zygote library causes the module to be skipped.

Alternatively, a zygote rule can delegate its decision to an external filter:

```toml

[[inject]]
source = "zygote"
library = "lib/example.so"

[inject.filter]
type = "stdio"
path = "/data/adb/modules/example/bin/filter"
args = ["--profile", "example"]
```

Every injection rule and Zygisk section requires a typed `filter`. Use `type = "static"` for built-in matching and specify at least one condition. Empty static filters are rejected; Zynx does not implicitly inject into every process. Individual omitted conditions impose no additional restriction. Static conditions cannot be placed outside `filter` or mixed into an external filter. Each rule decides independently: rejection or communication failure skips that rule, and another rule can still allow the same library. External filters are currently supported only for `source = "zygote"`. Native module filters do not require Zygisk support or a runtime feature switch. Transport options and the shared protocol are described below.

The optional `uid` and `user_id` fields accept decimal strings with single values, inclusive ranges, comma-separated unions, and an omitted range endpoint. Examples include `"12000"`, `"0-9999,12000"`, `"10000-"` (10000 through `u32::MAX`), and `"-9999"` (0 through 9999). Both endpoints are inclusive. `*` and a range with both endpoints omitted (`"-"`) are rejected. `uid` matches the full Linux UID and `user_id` matches `uid / 100000`. Omit a field to leave it unrestricted.

`packages` matches any package associated with the process UID. `process_name` matches the exact zygote nice name, while `process_name_matches` uses regular expression search. Use anchors for a full-name match and set only one of these fields per rule. Optional `is_system_server` and `is_child_zygote` fields match the corresponding process flags. Unknown fields and invalid rules cause the module to be skipped.

Rules with `source = "init"` are also accepted. They require exactly one of `path` (an absolute executable path) or `name` (the exec basename), both using exact matching, and support optional `uid` and `user_id` conditions. A `name` must be nonempty, cannot be `.` or `..`, and cannot contain `/` or NUL. All conditions belong in a `type = "static"` filter. Zygote-specific matching fields are rejected:

```toml

[[inject]]
source = "init"
library = "lib/service.so"

[inject.filter]
type = "static"
path = "/vendor/bin/example-service"
uid = "0-9999"

[[inject]]
source = "init"
library = "lib/other-service.so"

[inject.filter]
type = "static"
name = "other-service"
```

Init injection is not implemented yet. These rules are parsed and produce a warning, while library preparation and injection are skipped. Zygote rules in the same module continue to work.

### LiteLoader

> Requires `--features liteloader` to be enabled.

Place shared libraries (`.so`) or dex files (`.dex`) in `/data/adb/zynx/liteloader/` with the naming convention `<package_name>@<library_name>.(so|dex)`. They will be automatically loaded into the target app process.

For `.dex` files, the entry class must be `xyz.mufanc.zynx.Main` with a `public static void main(String[])` method.

### Force Debuggable

> Requires `--features debugger` to be enabled.

Set the system property `debug.zynx.debuggable.<package_name>` to `1` to force-enable debugging for the specified app:

```shell
setprop debug.zynx.debuggable.com.example.app 1
```

### Zygisk (WIP)

> Requires `--features zygisk` to be enabled.

Enables Zygisk compatibility layer, allowing Zynx to load Zygisk modules.

Zygisk uses the same module-local `zynx.toml`, with a separate section:

```toml
manifest_version = 2

[zygisk.filter]
type = "static"
packages = ["com.example.app"]
user_id = "0"
```

`[zygisk.filter]` shares the injection rules' filter type and validation. Alternatively, use an external filter:

```toml
manifest_version = 2

[zygisk.filter]
type = "socket_file"
path = "/path/to/filter.sock"
```

A `[zygisk.filter]` with `type = "static"` must specify at least one condition; an empty static filter is invalid. An empty `[zygisk]` or a missing filter type is invalid; omitting the section disables the module's Zygisk component. `library` and `source` are not accepted in the Zygisk section; its static filter also rejects init-only `path` and `name`. Zynx prepares the standard `zygisk/arm64-v8a.so` automatically for the supported arm64 target. Both `[zygisk]` and `[[inject]]` can appear in one manifest and decide independently. Without compiled Zygisk support or the runtime `zygisk` flag, Zygisk library preparation and arbitration are skipped while native injection rules continue to work. The old `zynx-configs.toml` entry point is no longer read.

### External Filters

The same filter transports and protocol are used by `[zygisk.filter]` and `[inject.filter]`.

Supported transports are `stdio` (`path`, optional `args`), `socket_file` (`path`), and `unix_abstract` (`prefix`, resolving the highest sequence in `<prefix>_<seq>_<suffix>`).

Each connection handles one request and one response. Each frame has a 4-byte little-endian payload length followed by Protobuf bytes, with a 1 MiB limit. Connection, send, and receive operations each have a 1-second timeout. A stdio filter starts a child per check, which is terminated when the check finishes.

The protocol is defined in [embryo_check_args.proto](src/core/proto/embryo_check_args.proto). Zynx sends a `CheckRequest` with `protocol_version = 2` and complete `ProcessInfo`, including the process name and app data directory when available. The filter must respond with `CheckResponse`, set `protocol_version = 2`, and explicitly set `allow` to either `true` or `false`. Missing decisions, unsupported versions, and I/O failures deny injection. The old fast/slow protocol is unsupported; existing filters must be updated.


## License

Unlicense
