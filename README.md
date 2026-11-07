# Zynx

Zynx (**Zy**gote **N**e**x**us) is an Android code injection framework written in Rust. It uses eBPF to monitor processes and ptrace to inject a bridge at `SpecializeCommon`.

## Build Modes

The default `standalone` build embeds the bridge and provides LiteLoader and Debugger. Module builds use `--no-default-features`, require `--bridge PATH`, and support daemon mode and module configuration. Add the Cargo feature `zygisk` for Zygisk compatibility.

Standalone runs in the foreground. Attach to a running zygote with:

```shell
zynx --features debugger:liteloader attach-zygote <pid>
```

Without a subcommand, standalone watches for zygote startup. Module builds can start a daemon for boot scripts:

```shell
zynx --bridge /path/to/libzynx_bridge.so daemon --wait-bpfloader
```

Runtime `--features` accepts colon-separated names: `debugger`, `liteloader`, and `zygisk` when compiled in. These capabilities are disabled by default. Standalone and Zygisk build features are mutually exclusive.

## Module Configuration

Module builds read `zynx.toml` from module directories alongside the Zynx module. At startup, they scan the parent of `MODDIR`, skip directories with a `disable` marker, and cache configuration and libraries.

A manifest requires `manifest_version = 2` and at least one `[[inject]]` rule or a `[zygisk]` section:

```toml
manifest_version = 2

[[inject]]
source = "zygote"
library = "lib/main.so"

[inject.filter]
type = "static"
packages = ["com.example.app"]
process_name = "com.example.app"
user_id = "0"

[[inject]]
source = "zygote"
library = "lib/worker.so"

[inject.filter]
type = "static"
process_name_matches = '^com\.example\.app:worker$'
```

Every rule requires a typed `filter`. Static filters require at least one condition and combine conditions with AND. Matching rules load libraries in rule order, once per module-relative path per process. Library paths must stay beneath the module directory. Invalid configuration or an unreadable required library causes the module to be skipped.

### Static Conditions

```toml
[inject.filter]
type = "static"
uid = "10000-"                       # Full Linux UID
user_id = "0"                        # Android user ID (uid / 100000)
packages = ["com.example.app"]        # Any package associated with the process UID
process_name = "com.example.app"      # Exact zygote process name
# Or use a regular expression: process_name_matches = '^com\.example\.app(:.*)?$'
is_system_server = false
is_child_zygote = false
```

Set at most one of `process_name` and `process_name_matches`. Omitted conditions impose no restriction. Unknown fields are rejected.

`uid` and `user_id` accept decimal strings: `"12000"`, `"0-9999"`, `"0-9999,12000"`, `"10000-"` (10000 and above), or `"-9999"` (0 through 9999). Range endpoints are inclusive; at least one endpoint is required.

### Init Rules

Init rules are parsed but not injected. They require a static filter with exactly one of `path` (absolute executable path) or `name` (exec basename), plus optional `uid` and `user_id` conditions:

```toml
[[inject]]
source = "init"
library = "lib/service.so"

[inject.filter]
type = "static"
name = "example-service"
uid = "0-9999"
```

### Zygisk

Requires a Zygisk-enabled module build and runtime `--features zygisk`. Configure the module's Zygisk component in the same manifest:

```toml
[zygisk.filter]
type = "static"
packages = ["com.example.app"]
user_id = "0"
```

Zygisk uses the same filters as zygote injection rules. Zynx loads the standard `zygisk/arm64-v8a.so`; no library path is configured. The Zygisk component is enabled only when its section is present and the runtime feature is enabled.

### External Filters

Zygote rules and Zygisk can use `stdio`, `socket_file`, or `unix_abstract` instead of a static filter:

```toml
[inject.filter]
type = "stdio"
path = "/data/adb/modules/example/bin/filter"
args = ["--profile", "example"]
```

For a file socket:

```toml
[inject.filter]
type = "socket_file"
path = "/data/adb/example/filter.sock"
```

For an abstract socket, Zynx selects the highest sequence in `<prefix>_<seq>_<suffix>`:

```toml
[inject.filter]
type = "unix_abstract"
prefix = "example"
```

Each connection exchanges one request and one response. Stdio starts a child per check and terminates it afterward. Frames contain a 4-byte little-endian length followed by Protobuf data, limited to 1 MiB. Sending and receiving each have a 1-second timeout.

The [protocol definition](src/core/proto/embryo_check_args.proto) specifies `CheckRequest` and `CheckResponse`. Requests contain `protocol_version = 2` and process information. Responses must use the same version and explicitly set `allow`. Protocol and communication errors reject the rule; another rule can still allow the same library.

## LiteLoader

Enable with runtime `--features liteloader`. Place libraries in `/data/adb/zynx/liteloader/`, named `<package_name>@<library_name>.so` or `<package_name>@<library_name>.dex`. LiteLoader loads them into matching app processes and watches the directory for changes.

Dex entry points must be `xyz.mufanc.zynx.Main` with a `public static void main(String[])` method.

## Debugger

Enable with runtime `--features debugger`, then select an app with:

```shell
setprop debug.zynx.debuggable.com.example.app 1
```

Debugging is enabled when the app process next starts.

## License

Unlicense
