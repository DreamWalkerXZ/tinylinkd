# 单文件可执行短链接服务：技术栈调研（决策支持）

- 日期：2026-11-05
- 状态：调研笔记，**不构成选型结论**
- 目标读者：后续 grilling / 架构决策
- 项目前提：单人/少数用户、必须登录后创建链接、自定义 slug、可选密码、可选过期、点击统计（次数/IP/设备）、**最终交付单一可执行文件**、很可能内嵌 SQLite

证据标记约定：

- **[文档]**：候选方案的官方文档、官方包注册表或官方源码仓库明确写明。
- **[实测]**：本文在本地实际构建/运行得到的观测值；方法与版本见 §2.3。
- **[推断]**：基于文档事实的工程判断，未被一手来源直接证实。

---

## 1. Scope 与 Method

### 1.1 Scope

覆盖：Go、Rust、Bun（`bun build --compile`）、Node.js SEA；并纳入两个"确认存在单文件方案"的补充候选（.NET single-file / NativeAOT、Deno compile）。Zig 仅做排除说明，不展开。

对每个方案回答：单文件的确切含义、HTTP server/框架、SQLite 驱动与 cgo/本地编译要求、模板与静态资源 embed、迁移工具、认证/session/密码哈希、交叉编译到 linux/amd64、linux/arm64、darwin/arm64、体积与启动、开发体验、许可证。

### 1.2 Method

- 只采信一手来源：官方文档、官方包注册表（pkg.go.dev / docs.rs / nodejs.org / bun.com / learn.microsoft.com / sqlite.org / rfc-editor.org）、官方源码仓库与 release notes。
- 所有网页访问日期均为 **2026-11-05**。
- 版本核实：Go 1.27.3（go.dev/dl）；Rust 最新 1.99.1（blog.rust-lang.org），本机为 1.96.0；Node 最新 LTS 26.13.0，本机为 24.21.0；Bun 1.4.4（2026-10-22）；.NET 10.0.14 LTS。
- 官方文档没有给出可信数字的地方，**不引用二手博客、不编造 benchmark**；改为明确写"未找到一手数据"。
- 为回答"体积/启动/单文件程度"，另外做了一个**受控最小应用实测**（§2.3），仅用于同一台机器上的横向对照，不当作框架性能评测。

### 1.3 本次调研的已知盲区

- 未能实测 Rust 的 linux/musl 构建（本机无 Zig/cross/Docker 工具链）；相关结论来自官方文档。
- 未能实测 Node SEA 的 Linux 产物（需要目标平台 Node 二进制）；相关结论来自官方文档。
- 未安装 .NET SDK，.NET 的体积/启动无实测数据。
- Bun 的 `--trim` 在本文测试中未改变产物体积；官方标注其 experimental，行为可能随版本变化，未下结论。

---

## 2. 总览对比

### 2.1 对比表

| 维度 | Go | Rust | Bun `--compile` | Node SEA | .NET single-file / NativeAOT | Deno `compile` |
|---|---|---|---|---|---|---|
| 单文件程度 | 单 ELF；Linux `CGO_ENABLED=0` 实测**静态链接**；macOS 仍动态链接系统框架 | 单 ELF；gnu target 动态链接 libc，musl target 可全静态 [文档] | 单文件内嵌 Bun 运行时；Linux 产物为 **glibc 动态链接** [实测] | node 二进制 + 注入 blob；产物≈node 二进制；glibc 动态链接 [文档] | managed DLL 打进单文件，但原生运行时库默认**不**打包，除非 `IncludeNativeLibrariesForSelfExtract`；可能自解压到磁盘 [文档] | 单文件内嵌 `denort` 运行时 [文档] |
| SQLite | `modernc.org/sqlite` 纯 Go、无 cgo；或 `mattn/go-sqlite3` 需 cgo | `rusqlite` + `bundled` 用 `cc` 编译 C 合并源；需 C 编译器 | 内置 `bun:sqlite`；**macOS 用系统 SQLite**，Linux/Windows 用内置 [文档] | 内置 `node:sqlite`，Stability **1.2 RC** [文档] | `Microsoft.Data.Sqlite` + SQLitePCLRaw 原生库 [文档] | `node:sqlite`（Deno 2.2+）[文档] |
| 模板/静态资源 embed | `//go:embed` + `embed.FS`（Go 1.16） | `include_str!`/`include_bytes!`；`rust-embed` 可选 | HTML/text/file import；`--asset`；`Bun.embeddedFiles` | SEA `assets` + `node:sea.getAsset()`；可选 VFS | Embedded resources / 单文件打包 | `--include` |
| 交叉编译 | `GOOS/GOARCH` + `CGO_ENABLED=0`，实测 macOS→linux/amd64、arm64 成功 | 需目标 target + C 交叉编译器；`cargo-zigbuild` 或 `cross`（Docker） | `--target=bun-linux-x64` 等 8 个目标；实测 macOS→linux-x64 成功（构建时下载目标运行时） | 必须使用**目标平台、版本匹配**的 node 二进制；跨平台需关 code cache/snapshot | 按 RID 发布；NativeAOT 需目标平台工具链 | `--target` 支持全平台交叉编译 |
| 认证/密码哈希生态 | `x/crypto/argon2`、bcrypt；`gorilla/sessions`、`scs`；`x/time/rate` | `argon2` crate；`tower-sessions`；`axum-login` | `Bun.password` 内置 argon2id/bcrypt；cookie 无签名 API | `node:crypto` scrypt 内置；argon2 需原生模块（与 SEA 冲突） | ASP.NET Core Identity / Cookie 认证 | `node:crypto` / Web Crypto |
| 迁移工具 | `goose`（可 embed.FS）、`golang-migrate` | `sqlx::migrate!`（编译期嵌入）、`refinery` | 无内置；drizzle-kit 或自建 | 无内置；drizzle-kit 或自建 | EF Core migrations 等 | 无内置 |
| 体积（macOS arm64，最小应用）[实测] | **12.8 MB** | **1.5 MB**（size-optimized） | **89.2 MB** | **121.9 MB** | 官方称 self-contained "large"；未实测 | 未实测 |
| 启动到首个 HTTP 200（中位数）[实测] | 16.1 ms | 8.2 ms | 21.2 ms | 51.7 ms | 未实测 | 未实测 |
| 许可证 | BSD-3-Clause | MIT OR Apache-2.0 | Bun MIT；**静态链接 JSC = LGPL-2**，官方 LICENSE 明示 relink 义务 | MIT | MIT | MIT |

### 2.2 三句话摘要（事实层面）

1. **"单文件"不是二元属性**：Go/Rust 是"一个原生可执行文件、无运行时"；Bun/Node/Deno 是"把 JS 运行时塞进可执行文件"；.NET 的 single-file 还可能在启动时解压到磁盘。
2. **体积差了一个数量级**：本文最小应用实测 Go 12.8 MB、Rust 1.5 MB，而 Bun 89 MB、Node SEA 122 MB。
3. **SQLite 的"无 cgo"只在 Go（modernc）和 JS 运行时（内置驱动）成立**；Rust 的 `bundled` 必须能调用 C 编译器，这是交叉编译的主要摩擦点。

### 2.3 实测方法（可复现）

- 机器：Apple M4，16 GB，macOS 15.7.7（Darwin 24.6.0），arm64。
- 四个应用功能对齐：`GET /` 返回一张内嵌 HTML；`POST /api/click` 向 SQLite 插入一行（slug、UTC 时间、IP、UA）；SQLite 开 WAL + `busy_timeout=5000`。
- 版本：Go 1.27.3 + modernc.org/sqlite 1.61.1（`CGO_ENABLED=0`，`-trimpath -ldflags="-s -w"`）；Rust 1.96.0 + axum 0.8.9 + rusqlite 0.37.0（`opt-level="z"`, LTO, `panic=abort`, strip）；Bun 1.4.4（`--compile --minify`）；Node 24.21.0（legacy SEA：`--experimental-sea-config` + postject，ad-hoc codesign）。
- Go 未做系统安装：benchmark 使用临时下载到 `/tmp/tinylinkd-bench/toolchain` 的 `go1.27.3.darwin-arm64` tarball，通过绝对路径调用，并设置 `GOTOOLCHAIN=local`、`GOPATH`/`GOMODCACHE` 指向 `/tmp/tinylinkd-bench`；系统 `PATH` 中没有 `go`。
- 体积：`stat -f%z`。
- 启动：从 `spawn` 到首次 `GET /` 返回 200 的墙钟时间，每个二进制 7 次，取中位数；每次运行前杀掉进程，文件系统缓存已预热。首次运行出现 577–935 ms 的离群值（推测与代码签名校验/首次页缓存有关，未验证）。
- 这些数字**只用于同机对照**，不代表 Linux 产物、真实业务负载或框架上限。

---

## 3. 候选逐一分析

## 3.1 Go

### 单文件到底意味着什么

- `CGO_ENABLED=0` 时 Go 不依赖 C 运行时；交叉编译时 cgo 默认关闭，若开启则必须提供 `CC` 交叉编译器 [文档：https://go.googlesource.com/go/+/refs/heads/master/src/cmd/cgo/doc.go]。
- 本文实测：macOS 上 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64 go build` 产物被 `file` 识别为 **statically linked** [实测]。
- macOS 产物仍动态链接 `/usr/lib/libSystem.dylib`、CoreFoundation、Security 等**系统框架** [实测，`otool -L`]；这些是操作系统自带的，不需要随应用分发。因此"单文件"成立，但"完全静态"只在 Linux 上成立。
- 无外部模板/静态文件依赖（`embed`）。

### HTTP server / 框架

- 标准库 `net/http` 足够：`ServeMux` 提供路由，TLS 在标准库内。
- `chi`（MIT）是薄路由层，"100% compatible with net/http"，无标准库之外的依赖 [文档：https://pkg.go.dev/github.com/go-chi/chi/v5]。

### SQLite 驱动

- `modernc.org/sqlite`：纯 Go、无 cgo，把 SQLite C 源码转译成 Go；本文用 v1.61.1，内置 SQLite **3.54.1**，覆盖 20 个 OS/arch 组合；许可证 BSD-3-Clause [文档：https://pkg.go.dev/modernc.org/sqlite]。
- 官方页面自述性能：CPU 密集型操作比 C SQLite 慢，2026-09 的 linux/amd64 测量中，无索引 `ORDER BY ... LIMIT` 为 2.0x、`GROUP BY` 聚合 1.9x、有索引相关子查询 1.3x（页面给出了对照版本与选项）[文档，同上]。这是**厂商自测**，方法写在页面上，但不是独立第三方。
- `mattn/go-sqlite3`：README 明确 "go-sqlite3 is cgo package"，需要 `CGO_ENABLED=1` 和 gcc；可交叉编译但通常要设 `CC` [文档：https://pkg.go.dev/github.com/mattn/go-sqlite3]。
- 并发建议：modernc 文档建议用 `SetMaxOpenConns` 限制连接池；配合 SQLite 的单写者模型，常见做法是写连接池=1 [文档 + 推断]。

### 模板与静态资源 embed

- `//go:embed` 自 Go 1.16 起支持，`embed.FS` 实现 `fs.FS`；目录匹配默认跳过 `.`/`_` 开头文件，可用 `all:` 前缀包含 [文档：https://pkg.go.dev/embed；https://go.dev/doc/go1.16]。
- `html/template` 默认按上下文自动转义（HTML/JS/CSS/URL），只有显式 `template.HTML` 等类型才绕过 [文档：https://pkg.go.dev/html/template]。这对"链接目标 URL 由用户输入"的场景是实打实的安全资产。

### 数据库迁移

- `pressly/goose`（MIT）：SQL 文件 + Go 迁移，默认在事务中执行；可用 `SetBaseFS(embed.FS)` 把迁移编译进二进制 [文档：https://pkg.go.dev/github.com/pressly/goose/v3]。
- 备选 `golang-migrate/migrate`；本文未展开。

### 认证、session、密码哈希

- `golang.org/x/crypto/argon2`（BSD-3-Clause）：`IDKey` 为 Argon2id [文档：https://pkg.go.dev/golang.org/x/crypto/argon2]；`bcrypt` 同包。
- `gorilla/sessions`（BSD-3-Clause）：CookieStore 把 gob 序列化的 session 放在**已认证**（可选加密）的 cookie 里，支持密钥轮换 [文档：https://pkg.go.dev/github.com/gorilla/sessions]。也支持自定义 store（含 SQLite）。
- 限流：`golang.org/x/time/rate`（BSD-3-Clause）是 token bucket [文档：https://pkg.go.dev/golang.org/x/time/rate]。

### 交叉编译

- 官方文档把 `GOOS/GOARCH` 定义为目标环境，并列出合法组合（linux/amd64、linux/arm64、darwin/arm64 均在列）[文档：https://go.dev/doc/install/source]。
- 本文实测从 macOS 交叉编译到 linux/amd64 与 linux/arm64 均成功，产物静态链接 [实测]。
- 使用 `modernc` 时无需 C 工具链；使用 `mattn` 时需要目标平台 C 编译器 [文档 + 推断]。

### 体积 / 启动

- 12,815,298 bytes（12.8 MB），启动中位数 16.1 ms [实测]。

### 开发体验

- `go test` 内置、`go vet`、`delve` 调试、`air` 热重载；编译速度快；单模块、依赖少。未找到需要引用的官方"DX"文档，故不评分。

### 许可证

- Go 本身 BSD-3-Clause（GitHub license API：`golang/go` → BSD-3-Clause）；modernc.org/sqlite BSD-3-Clause；chi/goose/gorilla/x-crypto 均为 MIT 或 BSD-3-Clause。

### 该方案特有的坑

- `database/sql` 是连接池，SQLite 是单写者；不限制连接数会放大 `SQLITE_BUSY`（见 §4.1）。
- 纯 Go SQLite 在 CPU 密集查询上比 C 版慢（官方自述 1.3–2.0x）；对本项目的点击写入量级大概率不是瓶颈，但需要用自己的查询验证 [推断]。

---

## 3.2 Rust

### 单文件到底意味着什么

- Rust 官方平台支持页把 `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、`aarch64-apple-darwin` 列为 Tier 1；musl 目标（`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`）为 Tier 2 with Host Tools [文档：https://doc.rust-lang.org/rustc/platform-support.html]。
- 该页**没有**直接讲"静态链接"。`cargo-zigbuild` 文档明确建议：需要完全静态可执行文件时用 musl，因为 **static glibc linking is unsupported** [文档：https://github.com/rust-cross/cargo-zigbuild]。
- 默认 gnu target 动态链接 libc；本文 macOS 产物只动态依赖 `libSystem` 与 `libiconv`（系统库）[实测，`otool -L`]。
- `rusqlite` 的 `bundled` 特性会用 `cc` crate 编译 SQLite 合并源并静态链接；这要求构建机有 C 编译器，交叉编译时要有目标平台的 C 交叉编译器 [文档：rusqlite README / docs.rs]。

### HTTP server / 框架

- `axum` 0.8（MIT）：路由 + extractor，基于 Tower/Hyper/Tokio；不追求 runtime/transport 无关，TLS 不在核心 [文档：https://docs.rs/axum/latest/axum/]。
- 备选 `actix-web`（MIT/Apache）；本文未展开。

### SQLite 驱动

- `rusqlite` 0.41.1（MIT），`bundled` 特性编译并静态链接 SQLite [文档：https://docs.rs/rusqlite/latest/rusqlite/；README]。
- 异步侧 `sqlx`（MIT OR Apache-2.0）也支持 SQLite，其 SQLite 驱动同样通过 `libsqlite3-sys`，`bundled` 时需 C 编译器 [文档：https://docs.rs/sqlx/latest/sqlx/]。
- 本文实测 `rusqlite 0.37.0 + bundled` 在 macOS 上构建成功，耗时 22 s（含依赖）[实测]。

### 模板与静态资源 embed

- 标准宏 `include_str!` / `include_bytes!` 即可嵌入单文件；本文用 `include_str!` [实测]。
- `rust-embed`（MIT）：release 构建把目录嵌进二进制，dev 构建从文件系统读，支持 axum/actix 等集成 [文档：https://docs.rs/rust-embed/latest/rust_embed/]。
- `askama`（MIT OR Apache-2.0）：编译期检查、默认 HTML 自动转义 [文档：https://docs.rs/askama/latest/askama/]。

### 数据库迁移

- `sqlx::migrate!` 在编译期把 `migrations/` 展开成静态 `Migrator` 嵌入二进制 [文档：https://docs.rs/sqlx/latest/sqlx/macro.migrate.html]。
- `refinery`（MIT）是另一种选择；`rusqlite_migration` 亦可。

### 认证、session、密码哈希

- `argon2` 0.6（MIT OR Apache-2.0，RustCrypto）：Argon2d/i/id，默认 Argon2id，输出 PHC 字符串 [文档：https://docs.rs/argon2/latest/argon2/]。
- `tower-sessions`（MIT）：Tower 中间件，内置 MemoryStore，第三方 store 含 SQLite（rusqlite/sqlx）[文档：https://docs.rs/tower-sessions/latest/tower_sessions/]。
- `axum-login` 可做登录态封装（未展开）。

### 交叉编译

- 目标三元组由 rustc 支持；但**带 C 依赖的 crate 需要目标平台 C 工具链**。
- `cargo-zigbuild`（MIT）：用 `zig cc` 作为链接器，支持 Linux gnu/musl 与 macOS 目标；文档明确"目前只支持 Linux 和 macOS 目标" [文档：https://github.com/rust-cross/cargo-zigbuild]。
- `cross`（MIT OR Apache-2.0）：提供交叉工具链容器，需要 Docker 20.10+/Podman；测试依赖 QEMU，可能不稳定 [文档：https://github.com/cross-rs/cross]。
- 本文**未实测** linux 交叉编译；这是本方案最大的未验证点。

### 体积 / 启动

- 1,494,208 bytes（1.5 MB），启动中位数 8.2 ms [实测]；构建配置为 size 优化（`opt-level="z"` + LTO + strip + panic=abort），默认 release 会更大。

### 开发体验

- `cargo test`、`cargo watch`/`bacon`、`lldb`/`rust-gdb`；编译时间明显长于 Go（本文 22 s 只是小项目增量构建）。无官方 DX 基准，不做量化。

### 许可证

- Rust 本身 "MIT license and the Apache License (Version 2.0)"（rust-lang/rust README）；axum/rusqlite/rust-embed MIT；argon2/tower-sessions/sqlx/askama 为 MIT 或 MIT OR Apache-2.0。

### 该方案特有的坑

- `bundled` SQLite 把"交叉编译"从纯 Rust 问题变成 C 交叉编译问题；这是引入 `cargo-zigbuild`/`cross` 的根本原因 [文档 + 推断]。
- musl 静态产物与 glibc 产物的行为差异（DNS、locale）需要实测；本文未覆盖。

---

## 3.3 Bun（`bun build --compile`）

### 单文件到底意味着什么

- `bun build --compile` 把应用、依赖和 **Bun 运行时**打成一个可执行文件；运行时包含包管理器、测试运行器、类型检查器，官方自述产物"large" [文档：https://bun.com/docs/compiler/executables]。
- 支持的目标（文档原文）：`bun-linux-x64`、`bun-linux-arm64`、`bun-linux-x64-musl`、`bun-linux-arm64-musl`、`bun-windows-x64`、`bun-windows-arm64`、`bun-darwin-x64`、`bun-darwin-arm64`；API 另列 `bun-linux-x64-baseline-musl` [文档，同上]。
- 交叉编译：`--target` 会下载目标平台的 Bun 运行时（可用 `--compile-executable-path` 指定本地文件）；本文实测 macOS→linux-x64 构建成功，构建日志显示下载 `bun-linux-x64-v1.4.4`，耗时 5.3 s [实测]。
- Linux 产物 `file` 显示 "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2" [实测]；官方安装文档给出 Linux 要求：glibc **2.17+**（musl 变体用于 Alpine/Void）、kernel 5.6+ 推荐、x64 需要 SSE4.2 [文档：https://bun.com/docs/installation]。

### HTTP server / 框架

- `Bun.serve` 内置：静态/参数路由、method handlers、通配、重定向、直接 import HTML 作为路由、TLS 配置；HTTP/2 与 HTTP/3 文档标注 **experimental** [文档：https://bun.com/docs/runtime/http/server]。
- 也可用 Hono（MIT，跨运行时，`hono/tiny` 声称 <14 kB）[文档：https://hono.dev/docs/]。

### SQLite 驱动

- `bun:sqlite` 内置、同步 API；支持 prepared statement、`db.transaction()`（deferred/immediate/exclusive，异常回滚，嵌套 savepoint）；WAL 通过 `PRAGMA journal_mode = WAL` 开启 [文档：https://bun.com/docs/runtime/sqlite]。
- **平台差异（重要）**：文档明确 "macOS: Bun uses the system-provided SQLite, which Apple builds with persistent WAL enabled" [文档，同上]。本文实测 macOS 上 `sqlite_version()` 为 **3.43.2** [实测]，而同一台机器上 Go/modernc 是 3.54.1、Node 24.21 是 3.53.4 [实测]。这意味着 macOS 上的 SQLite 行为/特性跟随操作系统版本，Linux/Windows 才是 Bun 自带版本。
- macOS 上关闭连接后可能残留 `-wal`/`-shm`，需要关闭 persistent WAL 并做 truncating checkpoint 才能清理 [文档，同上]。

### 模板与静态资源 embed

- `import html from "./index.html" with { type: "text" }` 得到字符串；`with { type: "file" }` 在编译产物中变成 `/$bunfs/` 内部路径；`--asset ./public` 嵌入目录，只读（EROFS），符号链接与空目录跳过；`Bun.embeddedFiles` 可枚举 [文档：https://bun.com/docs/compiler/executables]。
- HTML 全栈入口会 prebundle 客户端 JS/CSS 并由 Bun 按 manifest 提供 [文档，同上]。
- 本文实测 `type: "text"` 的 HTML 在 `--compile` 后可正常返回 [实测]。

### 数据库迁移

- 官方 `bun:sqlite` 文档未提供迁移 API/工具。可用 `drizzle-kit`（drizzle-orm 为 Apache-2.0）或自建 `PRAGMA user_version` 迁移 [文档 + 推断]。
- 注意：Bun 编译产物默认禁用 `tsconfig.json`/`package.json` 自动加载，`--compile-autoload-*` 可开启 [文档，同上]；迁移文件若在运行时从磁盘读，会破坏"单文件"假设。

### 认证、session、密码哈希

- `Bun.password` 内置：Argon2id（默认）/Argon2i/Argon2d 与 bcrypt；`hash`/`verify` 及 Sync 版本；Argon2 默认 `m=65536` KiB、`t=2`、`p=1`；bcrypt 对超过 72 字节的密码先做 SHA-512 [文档：https://bun.com/docs/api/hashing]。
- Cookie：`Bun.Cookie` / `Bun.CookieMap`，`req.cookies` 的修改会自动写回响应头；但文档**没有**签名/加密/完整性保护 API [文档：https://bun.com/docs/runtime/cookies]。session 需要自己用 HMAC 签名或建表存随机 token [推断]。
- 没有内置限流；自建 token bucket 或反向代理限流 [推断]。

### 交叉编译

- 8 个目标覆盖题目要求的 linux/amd64、linux/arm64、darwin/arm64；本文实测 macOS 主机产出 linux-x64 成功 [文档 + 实测]。
- 产物动态链接 glibc；若要"完全静态/无 glibc"需选 musl target（Alpine 场景）[文档 + 实测]。

### 体积 / 启动

- 89,159,906 bytes（89.2 MB）macOS arm64；linux-x64 产物 109 MB [实测]。
- 启动中位数 21.2 ms [实测]。
- `--trim` 文档标注 **experimental**，会移除包管理器/测试运行器/类型检查器；本文用 `--trim` 构建产物仍为 89 MB，未见变化 [实测，未下结论]。

### 开发体验

- `bun --watch`、`bun test`、`bun check`（1.4.3 加入内置 TypeScript 检查）、inspector；单命令构建，无需额外 bundler [文档：https://bun.com/blog]。
- 本文未做 DX 量化。

### 许可证

- Bun 本体 MIT；但官方 LICENSE 明确："Bun statically links JavaScriptCore (and WebKit) which is LGPL-2 licensed"，并引用 LGPL2 第 (1) 条：静态链接 LGPL 库时，必须同时以 object 形式提供应用，使用户有机会修改该库并重新链接 [文档：https://github.com/oven-sh/bun/blob/main/LICENSE.md]。
- **这是分发编译产物时需要考虑的义务**，是否需要法务评估取决于项目许可证与分发方式；本文不替用户判断 [推断]。

### 该方案特有的坑

- 体积约为 Go 的 7 倍、Rust 的 60 倍。
- macOS 用系统 SQLite，导致跨平台行为/版本不一致（macOS 实测 3.43.2，而同机 Go/Node 分别为 3.54.1 / 3.53.4）[实测 + 文档]。
- `Bun.serve` 的 HTTP/2、HTTP/3 是 experimental [文档]；本项目若只做 HTTP/1.1 + 反代 TLS，影响有限 [推断]。

---

## 3.4 Node.js SEA（Single Executable Applications）

### 单文件到底意味着什么

- SEA 的做法是：把一个 preparation blob（主脚本 + 可选 assets）注入到 **node 二进制**中；运行时若检测到 blob 就执行内嵌脚本，否则表现为普通 node [文档：https://nodejs.org/api/single-executable-applications.html]。
- 官方目的就是分发到"没有安装 Node.js 的系统"；产物包含 Node 运行时。
- Stability：**1.1 — Active development**（不是稳定 API）；v19.7.0/v18.16.0 引入，`--build-sea` 在 **v25.5.0** 加入 [文档，同上]。
- 本文实测 Node 24.21 只有 `--experimental-sea-config`，需要外部 `postject` 注入 + macOS ad-hoc codesign；产物 121,906,128 bytes（121.9 MB），与 node 二进制本身同量级 [实测]。

### HTTP server / 框架

- `node:http` 内置即可；Fastify（MIT）、Hono（MIT）都可打包，但 SEA 的主脚本必须是**单个文件**。
- 文档明确：注入脚本的 `require()`/`import` 默认**只能加载内置模块**，文件系统模块不可用；CommonJS 可用 `module.createRequire(__filename)` 回到真实文件系统 [文档，同上]。因此所有业务依赖必须先用 esbuild/rollup 之类打成单文件 [推断，直接由该限制推出]。

### SQLite 驱动

- `node:sqlite` 内置，当前 Stability **1.2 — Release candidate**；v22.5.0 加入，v25.7.0 升级为 RC；所有 API **同步执行**；在 Node 26 文档中 `DatabaseSync` 已是 `Database` 的 deprecated alias（DEP0210）[文档：https://nodejs.org/api/sqlite.html]。
- 本文实测 Node 24.21 的 `process.versions.sqlite` 为 **3.53.4**，且无需 flag 即可 `require('node:sqlite')` [实测]。
- 事务没有专用 helper，需 `exec('BEGIN')`/`COMMIT`/`ROLLBACK`，可用 `database.isTransaction` 判断 [文档，同上]。
- 备选 `better-sqlite3` 是原生 addon，会触发下一节的 SEA 限制 [推断]。

### 模板与静态资源 embed

- `sea-config.json` 的 `assets` 字典在构建期读入并打进 blob；运行时 `node:sea.getAsset()/getAssetAsBlob()/getRawAsset()/getAssetKeys()` 取用 [文档，同上]。
- v26.9.0 起有 `useVfs`（Stability **1.0 — Early development**）把 assets 挂成只读 VFS；`vfsArchive` 可放 ZIP 以减小体积，但不能与 `assets` 同时用 [文档，同上]。
- 本文实测 `assets` + `getAsset(..., "utf8")` 在 Node 24.21 可用 [实测]。

### 数据库迁移

- `node:sqlite` 没有迁移 API（文档只覆盖 Database/Statement/Session/constants）[文档，同上]。需要第三方（drizzle-kit，Apache-2.0）或自建 `user_version` 迁移；迁移 SQL 必须能被打进单文件 [推断]。

### 认证、session、密码哈希

- `node:crypto` 内置 `scrypt`/`scryptSync`：默认 `N=16384, r=8, p=1`，默认 `maxmem=32 MiB`；文档给出 `128*N*r` 的内存估算，并建议每密码 16 字节随机 salt、`timingSafeEqual` 比较、服务端用异步版本 [文档：https://nodejs.org/api/crypto.html]。
- **Argon2 在 SEA 里是逆风局**：`argon2`/`@node-rs/argon2` 是原生 addon；SEA 文档说 `.node` 只能作为 asset 嵌入、运行时写到临时文件再用 `process.dlopen()` 加载，且明确记录"Linux arm64 Docker 构建的 SEA 可能在 `process.dlopen()` 崩溃"的 caveat [文档：SEA 页]。因此 Node 方案要么用内置 scrypt，要么承担原生 addon 的复杂度 [推断]。
- session：无内置签名 cookie；可用纯 JS 库（express-session 等）或自建 HMAC token [推断]。

### 交叉编译

- 必须使用**目标平台、且版本与 blob 匹配**的 node 二进制（`executable` 字段可指定）[文档]。
- 跨平台生成时 `useCodeCache` 与 `useSnapshot` 必须为 `false`，否则产物不兼容 [文档，原文："When generating cross-platform SEAs … `useCodeCache` and `useSnapshot` must be set to false"）。
- 官方常规 CI 只覆盖 Windows、macOS **arm64 only**（macOS x64 不支持、测试跳过）、Linux（除 Alpine、除 s390x）[文档，同上]。
- 官方 Linux 二进制要求 **kernel ≥ 5.14、glibc ≥ 2.34**（Tier 1，RHEL 9 构建）；Node 25 起还动态链接 `libatomic`，目标机必须安装 [文档：https://github.com/nodejs/node/blob/main/BUILDING.md]。
- 这意味着 SEA 产物的"可移植性下限"比 Go/Bun 更高（需要较新的 glibc）[推断，由上述版本要求推出]。

### 体积 / 启动

- 121.9 MB（macOS arm64），启动中位数 51.7 ms [实测]。
- 官方文档**没有**给出 SEA 的体积/启动数字；唯一的体积表述是压缩 `vfsArchive` 可以"substantially reduce" [文档]。

### 开发体验

- `node --watch`、`node --test`、inspector；但 SEA 构建在 24.x 仍是多步（生成 blob → 复制 node → postject → 签名），26.x 的 `--build-sea` 简化为一步 [文档 + 实测]。
- 依赖必须预先 bundle，调试"打包后"的问题比源码直接运行更麻烦 [推断]。

### 许可证

- Node.js 是 MIT（nodejs/node LICENSE）；`node:sqlite` 捆绑的 SQLite 为 public domain。

### 该方案特有的坑

- Stability 1.1（Active development），官方说创建流程"subject to change" [文档]。
- 原生 addon 支持是二等公民；这直接限制了密码哈希库的选择 [文档 + 推断]。
- glibc 2.34 / kernel 5.14 的下限会排除仍在使用较老 glibc 的发行版 [推断，基于上述版本要求]。

---

## 3.5 其他候选（确认有单文件方案）

### 3.5.1 .NET single-file / Native AOT

- `PublishSingleFile=true` + `SelfContained=true` 产出单文件；但文档明确：**只有 managed DLL 会被打进单文件，core runtime 的原生二进制默认是独立文件**；要真正一个文件需 `IncludeNativeLibrariesForSelfExtract=true`，代价是启动时**解压到磁盘**（Linux/macOS 默认 `$HOME/.net`，Windows `%TEMP%/.net`；systemd 下 `$HOME` 未定义会失败）[文档：https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview]。
- 官方自述 self-contained 单文件"large"，可用 `EnableCompressionInSingleFile` 压缩，但启动要解压 [文档，同上]。
- Native AOT 产出真正的原生单文件，但有限制：无动态加载、无运行时代码生成、必须 trimming、ASP.NET Core 仅部分特性支持；发布按 RID，文档要求在各目标 OS 上安装对应工具链（未记载跨 OS 的 NativeAOT 编译）[文档：https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/]。
- SQLite：`Microsoft.Data.Sqlite` + SQLitePCLRaw 原生库；单文件打包原生库同样走 self-extract [文档：https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/]。
- 版本/许可：.NET 10.0.14 为当前 LTS（EOS 2028-11-14），MIT [文档：https://dotnet.microsoft.com/en-us/download/dotnet；GitHub API dotnet/runtime → MIT]。
- 结论（判断）：能满足"单文件"，但"单文件"的代价是自解压或 NativeAOT 的 trimming 约束；对这个规模的项目偏重。未实测。

### 3.5.2 Deno `deno compile`

- `deno compile` 把程序嵌入 stripped-down `denort` 运行时，产出 self-contained executable；`--target` 支持从任意宿主交叉编译到 Windows/macOS/Linux 的 x64/arm64 [文档：https://docs.deno.com/runtime/reference/cli/compile/]。
- `--include` 嵌入文件/目录，默认内存 VFS，`--self-extracting` 可改为首次运行写盘 [文档，同上]。
- `node:sqlite` 自 Deno 2.2 起可用 [文档：https://docs.deno.com/api/node/sqlite/]。
- 许可 MIT（GitHub API denoland/deno → MIT）。
- 文档未给 `deno compile` 的整体稳定性承诺；`--bundle`、`--minify`、QuickJS `--engine` 标注 experimental [文档]。
- 未实测；列入是因为它是"单文件 + 内置 SQLite + 全平台交叉编译"的少数组合之一。

### 3.5.3 Zig（排除说明）

- Zig 的卖点是可以轻松交叉编译出静态单文件；但本项目的关键依赖是 HTTP server、session、密码哈希、迁移工具，Zig 生态在这些方面没有 Go/Rust/JS 同等成熟的一手方案。
- 本文未对 Zig 做深入验证（`ziglang.org` 在本次环境中不可访问，仓库已迁移到 Codeberg）。将其排除是**基于生态成熟度的判断**，不是"单文件能力"不足。

---

## 4. 跨方案关注点（与本项目硬约束）

## 4.1 SQLite 并发写入与事务正确性

- WAL 模式下：读不阻塞写、写不阻塞读，但**同一时刻只有一个写者**（"since there is only one WAL file, there can only be one writer at a time"）；长读事务会阻止 checkpoint 前进 [文档：https://www.sqlite.org/wal.html]。
- `busy_timeout` 只是"至少睡这么久后返回 SQLITE_BUSY"，不是严格墙钟上限；busy handler 是 per-connection 的 [文档：https://www.sqlite.org/c3ref/busy_timeout.html]。
- 默认 `BEGIN DEFERRED` 先开读事务，后续写会尝试升级；若其他连接已修改/正在修改，升级失败返回 `SQLITE_BUSY`。**读-改-写事务应使用 `BEGIN IMMEDIATE`** 以避免升级失败 [文档：https://www.sqlite.org/lang_transaction.html]。
- 工程含义（推断）：单进程、写连接数=1（Go 的 `SetMaxOpenConns(1)`、Rust 的 `Mutex<Connection>`、Bun/Node 的单连接同步 API）能显著简化正确性；不要用多进程共享同一个 DB 文件。
- SQLite 官方对适用场景的表述："any site that gets fewer than 100K hits/day should work fine with SQLite"，且"only one writer at a time … writers queue up"；写密集或多服务器场景建议换 client/server 数据库 [文档：https://www.sqlite.org/whentouse.html]。

## 4.2 点击统计写入对 SQLite 的压力

- 若每次点击 `INSERT` 一行：按 100K hits/day 估算约 1.2 次写/秒，远低于 SQLite 的写入能力；真正的风险是**突发**与**每次 commit 的 fsync**，不是日均值 [推断，基于 SQLite 官方 100K/day 表述]。
- WAL + `synchronous=NORMAL` 可避免每次 commit 都 fsync，但官方明确此时**事务不再 durable**，断电可能回滚最近提交 [文档：WAL 页]。
- 可行模式（推断）：每次点击仍写一行但合并到批量事务；或维护"链接 + 时间桶"的聚合计数表，异步 flush；或写内存队列 + 定期落盘（会丢最近数据）。
- IP/UA 是变长文本，点击表会快速膨胀；需要保留期/归档策略与索引设计（按 slug + 时间查询）[推断]。
- 备份：在线备份 API 或 `VACUUM INTO` 可在运行中生成一致快照 [文档：https://www.sqlite.org/backup.html]。

## 4.3 过期时间与时区

- SQLite 没有专用日期类型；日期函数内部使用 UTC；`'now'` 返回 UTC；`localtime` 假定输入是 UTC，否则行为未定义，且本地时区计算依赖平台、`localtime_r()` 通常只支持 1970–2037 [文档：https://www.sqlite.org/lang_datefunc.html]。
- 建议（推断）：DB 存 UTC epoch 秒或 RFC3339 UTC 字符串；比较用 `unixepoch()`；**不要**存本地时间，也不要在 SQL 里做 `localtime` 转换。
- Go：`time/tzdata` 可把 tzdb 嵌入二进制，约 +450 KB；`-tags timetzdata` 自动引入 [文档：https://pkg.go.dev/time/tzdata]。
- Rust：`chrono-tz` 在编译期从 tzdb 生成时区数据并嵌入 [文档：https://docs.rs/chrono-tz/latest/chrono_tz/]。
- Node/Bun：自带 ICU/tzdata；但 Bun 在 macOS 用系统 SQLite，SQLite 侧的日期行为可能随 OS 变化 [文档 + 推断]。
- 产品语义（需用户决策）：过期时间由用户在哪个时区输入、如何显示；服务端一律按 UTC 存储与比较。

## 4.4 密码保护链接的哈希与限流

- 算法：Argon2id 是 RFC 9106 的推荐通用变体；"SECOND RECOMMENDED" 参数为 t=3、p=4、m=2^16 KiB（64 MiB），内存受限时使用 [文档：https://www.rfc-editor.org/rfc/rfc9106]。
- 代价：64 MiB/次的哈希不能在高频路径上无限制调用；密码链接的校验应"验证一次 → 发短期签名 cookie"，并对尝试做 per-IP + per-link 限流 [推断]。
- 各栈现状：Go `x/crypto/argon2`；Rust `argon2`；Bun `Bun.password` 内置（默认 m=65536 KiB、t=2、p=1）；Node 内置只有 scrypt，Argon2 需原生 addon（与 SEA 冲突）。这是 Node 方案的一个实质性差异 [文档，见各节]。
- 细节：常量时间比较；不要把密码或哈希写日志；哈希参数要随哈希一起存（PHC 字符串天然满足）[推断，PHC 格式为文档所述]。

## 4.5 单文件部署时的配置、日志、数据文件

- 配置：单文件应用没有"安装目录"概念，推荐 flags > 环境变量 > 默认值；不要把配置写进二进制 [推断]。
- 日志：写 stderr（容器/ systemd 友好），不要写文件轮转；单文件不应依赖外部日志配置 [推断]。
- 数据文件：SQLite 文件路径必须显式可配（默认如 `./tinylinkd.db` 或 XDG data dir）；注意 WAL 会产生 `-wal`/`-shm` 旁文件，**"单文件交付"不等于"运行时只有一个文件"** [文档：WAL 页 + 推断]。
- 迁移：启动时自动跑 embedded migrations（Goose/sqlx migrate 均支持），失败则拒绝启动；迁移必须幂等/有版本表 [推断]。
- 单实例：SQLite 不适合多实例共享同一文件；需要文件锁或文档明确"只跑一个实例" [推断]。
- 备份：提供 `VACUUM INTO` 或在线备份命令，避免用户直接拷贝正在写的 DB [文档：backup 页]。

---

## 5. 给后续 grilling 的开放问题（只列问题，不做决定）

### 交付与平台

1. "单一可执行文件"是否允许**首次运行自解压到磁盘**？（这直接决定 .NET single-file 是否算合格；Node SEA 的原生 addon 也走临时文件。）
2. 需要支持的最低 Linux 基线是什么：任意内核（Go 静态）、glibc 2.17+（Bun）、还是 glibc 2.34+/kernel 5.14+（Node 官方二进制）？
3. 是否必须从 macOS 一条命令交叉编译出三个目标？还是 CI matrix / Docker 可以接受？
4. 可接受的二进制体积上限是多少？89–122 MB 是否可接受，还是必须 <20 MB？

### 运行时与依赖

5. 是否接受 RC/实验性 API：`node:sqlite`（1.2 RC）、Node SEA（1.1 Active development）、Bun `--trim`（experimental）、Bun HTTP/2-3（experimental）？
6. Bun 静态链接 JavaScriptCore（LGPL-2）带来的 relink 义务，项目/license 是否能接受？是否需要法务确认？
7. SQLite 驱动选择：纯 Go（无 cgo、构建简单、CPU 密集查询慢 1.3–2.0x）vs cgo（构建复杂、性能接近 C）？
8. 是否需要支持 macOS 上的 SQLite 行为与 Linux 一致？Bun 在 macOS 用系统 SQLite 是否构成问题？

### 产品与数据

9. 统计精度：每次点击一行原始记录，还是聚合计数？保留多久？是否需要按链接/时间范围查询？
10. 密码保护链接：密码错误是否要限流/锁定？按 IP、按链接还是全局？锁定时长？
11. 管理端 UI：服务端渲染模板，还是 SPA/静态前端？（影响 embed 方案与模板引擎选择。）
12. 会话模型：签名 cookie（无状态）还是服务端 session 表（可撤销）？是否需要"退出所有设备"？
13. 过期时间：用户在哪个时区输入/查看？是否允许"永不过期"？
14. 是否需要内置 TLS，还是统一由反向代理终止？

### 运维

15. 配置优先级与默认数据目录：flags/env/文件？默认放当前目录还是 XDG？
16. 迁移策略：启动时自动迁移，还是提供显式 `migrate` 子命令？
17. 升级/回滚：是否需要保留旧版本二进制可读旧 schema 的兼容窗口？
18. 备份与恢复：是否需要内置 `backup` 命令？RPO 要求是什么？

---

## 6. Sources（访问日期均为 2026-11-05）

### Go

- Go `embed` 包文档 — https://pkg.go.dev/embed
- Go 1.16 release notes（embed 引入）— https://go.dev/doc/go1.16
- Go 源码安装/交叉编译（GOOS/GOARCH）— https://go.dev/doc/install/source
- cgo 文档（CGO_ENABLED、交叉编译默认关闭）— https://go.googlesource.com/go/+/refs/heads/master/src/cmd/cgo/doc.go
- `time/tzdata` — https://pkg.go.dev/time/tzdata
- `html/template` — https://pkg.go.dev/html/template
- `modernc.org/sqlite` — https://pkg.go.dev/modernc.org/sqlite
- `mattn/go-sqlite3` — https://pkg.go.dev/github.com/mattn/go-sqlite3
- `pressly/goose/v3` — https://pkg.go.dev/github.com/pressly/goose/v3
- `golang.org/x/crypto/argon2` — https://pkg.go.dev/golang.org/x/crypto/argon2
- `gorilla/sessions` — https://pkg.go.dev/github.com/gorilla/sessions
- `go-chi/chi/v5` — https://pkg.go.dev/github.com/go-chi/chi/v5
- `golang.org/x/time/rate` — https://pkg.go.dev/golang.org/x/time/rate
- Go 下载页（1.27.3）— https://go.dev/dl/

### Rust

- Rust 平台支持（tier、musl targets）— https://doc.rust-lang.org/rustc/platform-support.html
- `rusqlite` — https://docs.rs/rusqlite/latest/rusqlite/
- `sqlx::migrate!` — https://docs.rs/sqlx/latest/sqlx/macro.migrate.html
- `rust-embed` — https://docs.rs/rust-embed/latest/rust_embed/
- `argon2` — https://docs.rs/argon2/latest/argon2/
- `tower-sessions` — https://docs.rs/tower-sessions/latest/tower_sessions/
- `chrono-tz` — https://docs.rs/chrono-tz/latest/chrono_tz/
- `axum` — https://docs.rs/axum/latest/axum/
- `askama` — https://docs.rs/askama/latest/askama/
- `cargo-zigbuild` — https://github.com/rust-cross/cargo-zigbuild
- `cross` — https://github.com/cross-rs/cross
- Rust 官方博客（最新 1.99.1）— https://blog.rust-lang.org/
- Rust README（MIT OR Apache-2.0）— https://github.com/rust-lang/rust

### Bun

- Compiled executables（targets、assets、limitations）— https://bun.com/docs/compiler/executables
- `bun:sqlite` — https://bun.com/docs/runtime/sqlite
- `Bun.password` — https://bun.com/docs/api/hashing
- `Bun.serve` — https://bun.com/docs/runtime/http/server
- Cookies — https://bun.com/docs/runtime/cookies
- Linux 安装要求（glibc 2.17+、SSE4.2）— https://bun.com/docs/installation
- Bun 博客（1.4.4，2026-10-22）— https://bun.com/blog
- Bun LICENSE（MIT + JSC LGPL-2 静态链接说明）— https://github.com/oven-sh/bun/blob/main/LICENSE.md

### Node.js

- Single executable applications（Stability 1.1、assets、cross-platform 限制）— https://nodejs.org/api/single-executable-applications.html
- `node:sqlite`（Stability 1.2 RC、同步 API）— https://nodejs.org/api/sqlite.html
- `node:crypto` scrypt — https://nodejs.org/api/crypto.html
- Node 版本/LTS 状态（26.13.0 LTS，2026-10-28）— https://nodejs.org/en/about/previous-releases
- Node 官方构建平台要求（glibc 2.34、kernel 5.14、libatomic）— https://github.com/nodejs/node/blob/main/BUILDING.md

### .NET

- Single-file 部署（原生库/自解压）— https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview
- Native AOT（限制、RID）— https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/
- `Microsoft.Data.Sqlite` — https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/
- .NET 下载（10.0.14 LTS）— https://dotnet.microsoft.com/en-us/download/dotnet

### Deno

- `deno compile`（targets、--include）— https://docs.deno.com/runtime/reference/cli/compile/
- `node:sqlite` in Deno（2.2+）— https://docs.deno.com/api/node/sqlite/

### SQLite / 标准

- WAL 模式 — https://www.sqlite.org/wal.html
- 事务（DEFERRED/IMMEDIATE、SQLITE_BUSY）— https://www.sqlite.org/lang_transaction.html
- busy timeout — https://www.sqlite.org/c3ref/busy_timeout.html
- 适用场景（100K hits/day、单写者）— https://www.sqlite.org/whentouse.html
- 日期/时间函数（UTC、localtime 限制）— https://www.sqlite.org/lang_datefunc.html
- 在线备份 / VACUUM INTO — https://www.sqlite.org/backup.html
- RFC 9106（Argon2）— https://www.rfc-editor.org/rfc/rfc9106

### 许可证核查（GitHub License API，2026-11-05）

- golang/go → BSD-3-Clause
- rust-lang/rust → Apache-2.0（README 声明 MIT OR Apache-2.0）
- nodejs/node → MIT
- oven-sh/bun → MIT（LICENSE 另有 JSC LGPL-2 说明）
- dotnet/runtime → MIT
- denoland/deno → MIT
- mattn/go-sqlite3 → MIT
- modernc-org/sqlite → BSD-3-Clause
- go-chi/chi → MIT
- tokio-rs/axum → MIT
- rusqlite/rusqlite → MIT
- fastify/fastify → MIT
- honojs/hono → MIT
- launchbadge/sqlx → Apache-2.0
- rust-db/refinery → MIT
- drizzle-team/drizzle-orm → Apache-2.0
- alexedwards/scs → MIT
- ziglang/zig → MIT
