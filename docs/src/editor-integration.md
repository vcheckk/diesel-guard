# Editor Integration

diesel-guard includes a stdio Language Server Protocol server for editor
diagnostics:

```sh
diesel-guard lsp
```

Install `diesel-guard` so the binary is on the editor's `PATH`, or configure the
editor with an absolute path to the binary.

## Helix

Add a project-local `.helix/languages.toml`, or put the same settings in your
global Helix `languages.toml`:

```toml
[language-server.diesel-guard]
command = "diesel-guard"
args = ["lsp"]

[[language]]
name = "sql"
language-servers = ["diesel-guard"]
```

If Helix cannot find the binary, use an absolute path:

```toml
[language-server.diesel-guard]
command = "/absolute/path/to/diesel-guard"
args = ["lsp"]
```

If you already use another SQL language server, include every server name in the
SQL `language-servers` array:

```toml
[[language]]
name = "sql"
language-servers = ["sql-language-server", "diesel-guard"]
```

Verify the setup with:

```sh
hx --health sql
```

Open a `.sql` migration file. After changing `languages.toml`, restart the
language servers for the editor session with `:lsp-restart`.

## Zed

diesel-guard currently ships the LSP server, not a published Zed extension. Zed
needs a registered language-server adapter before it can attach a new server to
SQL files. Use `diesel-guard lsp` from a lightweight Zed extension, a
development extension, or a future/native adapter that registers diesel-guard.

Once an adapter exists, configure that adapter to run:

```sh
diesel-guard lsp
```

Use an absolute binary path when the Zed process cannot see the same `PATH` as
your shell. Check Zed's language-server logs or start Zed in the foreground when
debugging adapter startup.

## Behavior

The server handles `.sql` `file://` document URIs only. Other buffers are
ignored, and stale diesel-guard diagnostics are cleared when needed.

Workspace root selection happens during `initialize`:

1. `workspaceFolders[0]`
2. `rootUri`
3. the directory where `diesel-guard lsp` was launched

The server loads `diesel-guard.toml` from that selected root for each diagnostic
pass. When no config exists, it uses the default config, including
`framework = "diesel"`. SQLx projects should add `diesel-guard.toml` with:

```toml
framework = "sqlx"
```

Relative `custom_checks_dir` values are resolved under the selected workspace
root. Custom Rhai checks configured by the workspace run as part of editor
diagnostics when they fit the LSP safety limits. The editor server uses tighter
limits than the CLI: at most 16 custom check files and 256 KiB of custom check
source are loaded for LSP diagnostics. If a workspace exceeds those limits,
custom checks are disabled for that LSP session and built-in diagnostics keep
running. The compiled checker is cached between diagnostic passes and refreshed
when the config or custom check files change. Review `diesel-guard.toml` before
enabling the LSP automatically for untrusted repositories.

The server advertises full text synchronization and save notifications. It does
not scan unopened files or promise incremental text sync.

Live diagnostics from `didOpen` and full-sync `didChange` use the in-memory SQL.
While you type malformed SQL, diesel-guard clears stale diagnostics without
publishing parse diagnostics. Very large live and saved SQL documents are skipped
to keep the editor responsive.

Saved diagnostics from `didSave` prefer reading the saved file path. That lets
diesel-guard use migration metadata such as Diesel `metadata.toml` or SQLx file
names when the editor supplies a readable `file://` URI. If a `.sql` `file://`
path cannot be read but the editor includes saved text, diesel-guard falls back
to checking that in-memory text without migration metadata. Non-`file://` buffers
are ignored. Malformed saved SQL publishes a `ParseError` diagnostic.

Diagnostics use:

- `source = "diesel-guard"`
- error or warning severity from the matching diesel-guard check
- the check name as the diagnostic code when available

stdout is reserved for LSP protocol messages. Server warnings and recoverable
errors are sent as LSP messages instead of being printed to stdout.

## Troubleshooting

No diagnostics:

- Confirm the opened document URI is a readable `.sql` `file://` URI.
- Confirm the editor is running `diesel-guard lsp`.
- For Helix, run `hx --health sql` and restart with `:lsp-restart`.

Wrong config:

- Open the project root in the editor so `workspaceFolders[0]` points to the
  directory containing `diesel-guard.toml`.
- If the editor uses another root, put the config there or start the editor from
  the intended root.

Binary not found:

- Use an absolute binary path in the editor configuration.
- Remember that GUI editors may not inherit your shell `PATH`.

Unexpected saved-file results:

- Make sure the saved file is readable from the path in the editor URI.
- If a `.sql` `file://` path cannot be read, saved-file diagnostics can fall
  back to editor-provided text without migration metadata.
- Non-`file://` buffers are outside the first server scope.
- Live malformed SQL clears stale diagnostics quietly; save the file to see a
  parse diagnostic for malformed SQL.
