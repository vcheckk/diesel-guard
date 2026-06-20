use crate::checks::{Check, CheckDoc, MigrationContext};
use crate::config::Config;
use crate::violation::Violation;
use camino::Utf8Path;
use pg_query::protobuf::node::Node as NodeEnum;
use rhai::{AST, Dynamic, Engine};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

pub const MAX_CUSTOM_CHECK_SOURCE_BYTES: u64 = 64 * 1024;
pub const MAX_CUSTOM_CHECK_FILES: usize = 512;
pub const MAX_CUSTOM_CHECK_DIR_ENTRIES: usize = 2_048;
pub const MAX_CUSTOM_CHECK_TOTAL_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

struct CustomCheckFile {
    path: PathBuf,
    stem: String,
}

struct ScriptInputs {
    node: Dynamic,
    config: Dynamic,
    ctx: Dynamic,
}

struct CustomCheckLoadState {
    checks: Vec<Box<dyn Check>>,
    errors: Vec<ScriptError>,
    total_source_bytes: u64,
}

enum ScriptSource {
    Source(String, u64),
    TooLarge,
}

/// Error encountered while loading or running a custom Rhai check script.
#[derive(thiserror::Error, Debug)]
#[error("{file}: {message}")]
pub struct ScriptError {
    pub file: String,
    pub message: String,
}

/// A custom check backed by a compiled Rhai script.
pub struct CustomCheck {
    name: String,
    engine: Arc<Engine>,
    ast: AST,
    path: String,
}

pub fn custom_check_names(dir: &Utf8Path) -> Vec<String> {
    let (files, _errors) = discover_custom_check_files(dir);
    files.into_iter().map(|file| file.stem).collect()
}

impl CheckDoc for CustomCheck {}

impl CustomCheck {
    fn internal_error(&self, err: &dyn std::fmt::Display) -> Vec<Violation> {
        vec![Violation::new(
            format!("SCRIPT ERROR: {}", self.name),
            format!("Error in custom check '{}': {err}", self.name),
            "This is likely a diesel-guard bug. Please report it.",
        )]
    }

    fn script_scope(
        node: &NodeEnum,
        config: &Config,
        ctx: &MigrationContext,
    ) -> std::result::Result<rhai::Scope<'static>, String> {
        script_inputs(node, config, ctx).map(script_scope_from_inputs)
    }
}

fn script_inputs(
    node: &NodeEnum,
    config: &Config,
    ctx: &MigrationContext,
) -> std::result::Result<ScriptInputs, String> {
    let node = script_node_input(node)?;
    script_inputs_with_node(node, config, ctx)
}

fn script_inputs_with_node(
    node: Dynamic,
    config: &Config,
    ctx: &MigrationContext,
) -> std::result::Result<ScriptInputs, String> {
    let config = script_config_input(config)?;
    script_inputs_with_node_config(node, config, ctx)
}

fn script_inputs_with_node_config(
    node: Dynamic,
    config: Dynamic,
    ctx: &MigrationContext,
) -> std::result::Result<ScriptInputs, String> {
    Ok(ScriptInputs {
        node,
        config,
        ctx: script_context_input(ctx)?,
    })
}

fn script_node_input(node: &NodeEnum) -> std::result::Result<Dynamic, String> {
    rhai::serde::to_dynamic(node).map_err(|err| err.to_string())
}

fn script_config_input(config: &Config) -> std::result::Result<Dynamic, String> {
    rhai::serde::to_dynamic(config).map_err(|err| err.to_string())
}

fn script_context_input(ctx: &MigrationContext) -> std::result::Result<Dynamic, String> {
    rhai::serde::to_dynamic(ctx).map_err(|err| err.to_string())
}

fn script_scope_from_inputs(inputs: ScriptInputs) -> rhai::Scope<'static> {
    let mut scope = rhai::Scope::new();
    scope.push("node", inputs.node);
    scope.push("config", inputs.config);
    scope.push("ctx", inputs.ctx);
    scope
}

impl CustomCheck {
    fn evaluate_custom_check(&self, scope: &mut rhai::Scope<'_>) -> Vec<Violation> {
        match self.engine.eval_ast_with_scope::<Dynamic>(scope, &self.ast) {
            Ok(result) => parse_script_result(&self.name, result),
            Err(err) => vec![self.runtime_error_violation(&err)],
        }
    }

    fn runtime_error_violation(&self, err: &dyn std::fmt::Display) -> Violation {
        Violation::new(
            format!("SCRIPT ERROR: {}", self.name),
            format!("Runtime error in custom check '{}': {err}", self.name),
            "Fix the custom check script to eliminate the runtime error.",
        )
    }
}

impl Check for CustomCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn script_path(&self) -> Option<&str> {
        Some(&self.path)
    }

    fn describe(&self) -> Option<String> {
        // clone_functions_only() strips the script body so call_fn won't
        // try to evaluate statements that reference `node`.
        let fns_ast = self.ast.clone_functions_only();
        let mut scope = rhai::Scope::new();
        if let Ok(result) =
            self.engine
                .call_fn::<rhai::Dynamic>(&mut scope, &fns_ast, "describe", ())
        {
            return result.into_string().ok();
        }
        None
    }

    fn check(&self, node: &NodeEnum, config: &Config, ctx: &MigrationContext) -> Vec<Violation> {
        let mut scope = match Self::script_scope(node, config, ctx) {
            Ok(scope) => scope,
            Err(err) => return self.internal_error(&err),
        };
        self.evaluate_custom_check(&mut scope)
    }
}

/// Parse the return value of a Rhai script into violations.
///
/// Accepted return types:
/// - `()` — no violation
/// - `#{ operation: "...", problem: "...", safe_alternative: "..." }` — one violation
/// - Array of maps — multiple violations
fn parse_script_result(check_name: &str, result: Dynamic) -> Vec<Violation> {
    if result.is_unit() {
        return vec![];
    }

    if result.is_map() {
        return single_script_violation(check_name, result);
    }

    if result.is_array() {
        return array_script_violations(check_name, result);
    }

    vec![invalid_script_result_violation(check_name, &result)]
}

fn single_script_violation(check_name: &str, result: Dynamic) -> Vec<Violation> {
    match map_to_violation(check_name, result) {
        Some(violation) => vec![violation],
        None => vec![],
    }
}

fn array_script_violations(check_name: &str, result: Dynamic) -> Vec<Violation> {
    result
        .into_array()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| map_to_violation(check_name, value))
        .collect()
}

fn invalid_script_result_violation(check_name: &str, result: &Dynamic) -> Violation {
    Violation::new(
        format!("SCRIPT ERROR: {check_name}"),
        format!(
            "Custom check returned {}, expected (), map, or array",
            result.type_name()
        ),
        "Fix the custom check script to return a valid type.",
    )
}

/// Convert a Rhai map Dynamic to a Violation.
fn map_to_violation(check_name: &str, value: Dynamic) -> Option<Violation> {
    let map = value.try_cast::<rhai::Map>()?;
    violation_from_map_fields(&map).or_else(|| Some(invalid_map_violation(check_name, &map)))
}

fn violation_from_map_fields(map: &rhai::Map) -> Option<Violation> {
    let operation = string_map_field(map, "operation");
    let problem = string_map_field(map, "problem");
    let safe_alternative = string_map_field(map, "safe_alternative");

    match (operation, problem, safe_alternative) {
        (Some(op), Some(prob), Some(alt)) => Some(Violation::new(op, prob, alt)),
        _ => None,
    }
}

fn string_map_field(map: &rhai::Map, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|value| value.clone().into_string().ok())
}

fn invalid_map_violation(check_name: &str, map: &rhai::Map) -> Violation {
    Violation::new(
        format!("SCRIPT ERROR: {check_name}"),
        format!(
            "Custom check returned an invalid map: {}",
            invalid_map_issues(map).join(", ")
        ),
        "Fix the custom check script to return all three required string keys.",
    )
}

fn invalid_map_issues(map: &rhai::Map) -> Vec<String> {
    ["operation", "problem", "safe_alternative"]
        .into_iter()
        .filter_map(|key| invalid_map_issue(map, key))
        .collect()
}

fn invalid_map_issue(map: &rhai::Map, key: &str) -> Option<String> {
    match map.get(key) {
        None => Some(format!("'{key}' is missing")),
        Some(value) if value.clone().into_string().is_err() => Some(format!(
            "'{key}' must be a string (got {})",
            value.type_name()
        )),
        _ => None,
    }
}

/// Build a Rhai module exposing commonly needed pg_query protobuf enum constants.
///
/// Scripts access these as `pg::OBJECT_TABLE`, `pg::AT_ADD_COLUMN`, etc.
fn create_pg_constants_module() -> rhai::Module {
    use pg_query::protobuf::{AlterTableType, ConstrType, DropBehavior, ObjectType};

    let mut m = rhai::Module::new();

    // ObjectType — used by DropStmt.remove_type, RenameStmt.rename_type, etc.
    m.set_var("OBJECT_INDEX", ObjectType::ObjectIndex as i64);
    m.set_var("OBJECT_TABLE", ObjectType::ObjectTable as i64);
    m.set_var("OBJECT_COLUMN", ObjectType::ObjectColumn as i64);
    m.set_var("OBJECT_DATABASE", ObjectType::ObjectDatabase as i64);
    m.set_var("OBJECT_SCHEMA", ObjectType::ObjectSchema as i64);
    m.set_var("OBJECT_SEQUENCE", ObjectType::ObjectSequence as i64);
    m.set_var("OBJECT_VIEW", ObjectType::ObjectView as i64);
    m.set_var("OBJECT_FUNCTION", ObjectType::ObjectFunction as i64);
    m.set_var("OBJECT_EXTENSION", ObjectType::ObjectExtension as i64);
    m.set_var("OBJECT_TRIGGER", ObjectType::ObjectTrigger as i64);
    m.set_var("OBJECT_TYPE", ObjectType::ObjectType as i64);

    // AlterTableType — used by AlterTableCmd.subtype
    m.set_var("AT_ADD_COLUMN", AlterTableType::AtAddColumn as i64);
    m.set_var("AT_COLUMN_DEFAULT", AlterTableType::AtColumnDefault as i64);
    m.set_var("AT_DROP_NOT_NULL", AlterTableType::AtDropNotNull as i64);
    m.set_var("AT_SET_NOT_NULL", AlterTableType::AtSetNotNull as i64);
    m.set_var("AT_DROP_COLUMN", AlterTableType::AtDropColumn as i64);
    m.set_var(
        "AT_ALTER_COLUMN_TYPE",
        AlterTableType::AtAlterColumnType as i64,
    );
    m.set_var("AT_ADD_CONSTRAINT", AlterTableType::AtAddConstraint as i64);
    m.set_var(
        "AT_DROP_CONSTRAINT",
        AlterTableType::AtDropConstraint as i64,
    );
    m.set_var(
        "AT_VALIDATE_CONSTRAINT",
        AlterTableType::AtValidateConstraint as i64,
    );

    // ConstrType — used by Constraint.contype
    m.set_var("CONSTR_NOTNULL", ConstrType::ConstrNotnull as i64);
    m.set_var("CONSTR_DEFAULT", ConstrType::ConstrDefault as i64);
    m.set_var("CONSTR_IDENTITY", ConstrType::ConstrIdentity as i64);
    m.set_var("CONSTR_GENERATED", ConstrType::ConstrGenerated as i64);
    m.set_var("CONSTR_CHECK", ConstrType::ConstrCheck as i64);
    m.set_var("CONSTR_PRIMARY", ConstrType::ConstrPrimary as i64);
    m.set_var("CONSTR_UNIQUE", ConstrType::ConstrUnique as i64);
    m.set_var("CONSTR_EXCLUSION", ConstrType::ConstrExclusion as i64);
    m.set_var("CONSTR_FOREIGN", ConstrType::ConstrForeign as i64);

    // DropBehavior — used by DropStmt.behavior
    m.set_var("DROP_RESTRICT", DropBehavior::DropRestrict as i64);
    m.set_var("DROP_CASCADE", DropBehavior::DropCascade as i64);

    m
}

/// Create a sandboxed Rhai engine with safety limits.
fn create_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(100_000);
    engine.set_max_string_size(10_000);
    engine.set_max_array_size(1_000);
    engine.set_max_map_size(1_000);
    engine.register_static_module("pg", create_pg_constants_module().into());
    engine
}

/// Load all `.rhai` files from a directory and compile them into custom checks.
///
/// Returns successfully compiled checks and any errors encountered.
/// Compilation errors are non-fatal — they're collected as `ScriptError`s.
pub fn load_custom_checks(
    dir: &Utf8Path,
    config: &crate::config::Config,
) -> (Vec<Box<dyn Check>>, Vec<ScriptError>) {
    let engine = Arc::new(create_engine());
    let (entries, errors) = discover_custom_check_files(dir);
    let state = load_custom_check_entries(dir, config, &engine, entries, errors);
    (state.checks, state.errors)
}

fn load_custom_check_entries(
    dir: &Utf8Path,
    config: &Config,
    engine: &Arc<Engine>,
    entries: Vec<CustomCheckFile>,
    errors: Vec<ScriptError>,
) -> CustomCheckLoadState {
    let mut state = CustomCheckLoadState {
        checks: Vec::new(),
        errors,
        total_source_bytes: 0,
    };
    for entry in entries {
        if !load_custom_check_entry(dir, config, engine, entry, &mut state) {
            break;
        }
    }
    state
}

fn load_custom_check_entry(
    dir: &Utf8Path,
    config: &Config,
    engine: &Arc<Engine>,
    entry: CustomCheckFile,
    state: &mut CustomCheckLoadState,
) -> bool {
    if !config.is_check_enabled(&entry.stem) {
        return true;
    }

    let Some(source) = script_source_for_entry(dir, &entry, state) else {
        return state.total_source_bytes <= MAX_CUSTOM_CHECK_TOTAL_SOURCE_BYTES;
    };
    compile_custom_check(engine, entry, &source, &mut state.checks, &mut state.errors);
    true
}

fn script_source_for_entry(
    dir: &Utf8Path,
    entry: &CustomCheckFile,
    state: &mut CustomCheckLoadState,
) -> Option<String> {
    match read_script_source(&entry.path) {
        Ok(ScriptSource::Source(source, bytes_read)) => {
            add_script_source_bytes(dir, bytes_read, state).then_some(source)
        }
        Ok(ScriptSource::TooLarge) => {
            push_oversized_script_error(entry, &mut state.errors);
            None
        }
        Err(error) => {
            push_script_read_error(entry, &error, &mut state.errors);
            None
        }
    }
}

fn add_script_source_bytes(
    dir: &Utf8Path,
    bytes_read: u64,
    state: &mut CustomCheckLoadState,
) -> bool {
    let next_total = state.total_source_bytes.saturating_add(bytes_read);
    if next_total > MAX_CUSTOM_CHECK_TOTAL_SOURCE_BYTES {
        push_total_script_size_error(dir, &mut state.errors);
        state.total_source_bytes = next_total;
        return false;
    }
    state.total_source_bytes = next_total;
    true
}

fn push_total_script_size_error(dir: &Utf8Path, errors: &mut Vec<ScriptError>) {
    errors.push(ScriptError {
        file: dir.to_string(),
        message: format!(
            "Custom check scripts are larger than {MAX_CUSTOM_CHECK_TOTAL_SOURCE_BYTES} bytes in total"
        ),
    });
}

fn push_oversized_script_error(entry: &CustomCheckFile, errors: &mut Vec<ScriptError>) {
    errors.push(ScriptError {
        file: entry.path.display().to_string(),
        message: format!(
            "Custom check script is larger than {MAX_CUSTOM_CHECK_SOURCE_BYTES} bytes"
        ),
    });
}

fn push_script_read_error(
    entry: &CustomCheckFile,
    error: &std::io::Error,
    errors: &mut Vec<ScriptError>,
) {
    errors.push(ScriptError {
        file: entry.path.display().to_string(),
        message: format!("Failed to read: {error}"),
    });
}

fn compile_custom_check(
    engine: &Arc<Engine>,
    entry: CustomCheckFile,
    source: &str,
    checks: &mut Vec<Box<dyn Check>>,
    errors: &mut Vec<ScriptError>,
) {
    match engine.compile(source) {
        Ok(ast) => push_compiled_custom_check(engine, entry, ast, checks),
        Err(error) => push_script_compile_error(&entry, &error, errors),
    }
}

fn push_compiled_custom_check(
    engine: &Arc<Engine>,
    entry: CustomCheckFile,
    ast: AST,
    checks: &mut Vec<Box<dyn Check>>,
) {
    checks.push(Box::new(CustomCheck {
        name: entry.stem,
        engine: Arc::clone(engine),
        ast,
        path: entry.path.display().to_string(),
    }));
}

fn push_script_compile_error(
    entry: &CustomCheckFile,
    error: &rhai::ParseError,
    errors: &mut Vec<ScriptError>,
) {
    errors.push(ScriptError {
        file: entry.path.display().to_string(),
        message: format!("Compilation error: {error}"),
    });
}

fn discover_custom_check_files(dir: &Utf8Path) -> (Vec<CustomCheckFile>, Vec<ScriptError>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(e) => {
            return (
                Vec::new(),
                vec![ScriptError {
                    file: dir.to_string(),
                    message: format!("Failed to read directory: {e}"),
                }],
            );
        }
    };
    collect_custom_check_files(dir, read_dir)
}

fn collect_custom_check_files(
    dir: &Utf8Path,
    read_dir: std::fs::ReadDir,
) -> (Vec<CustomCheckFile>, Vec<ScriptError>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for (index, entry) in read_dir.enumerate() {
        if !process_custom_check_dir_entry(dir, index, entry, &mut files, &mut errors) {
            break;
        }
    }

    sort_custom_check_files(&mut files);
    (files, errors)
}

fn process_custom_check_dir_entry(
    dir: &Utf8Path,
    index: usize,
    entry: std::io::Result<std::fs::DirEntry>,
    files: &mut Vec<CustomCheckFile>,
    errors: &mut Vec<ScriptError>,
) -> bool {
    if !custom_check_entry_limit_allows(dir, index, errors) {
        return false;
    }

    let Some(file) = custom_check_file_from_entry(dir, entry, errors) else {
        return true;
    };
    push_custom_check_file(dir, file, files, errors)
}

fn sort_custom_check_files(files: &mut [CustomCheckFile]) {
    files.sort_by(|left, right| left.path.file_name().cmp(&right.path.file_name()));
}

fn custom_check_entry_limit_allows(
    dir: &Utf8Path,
    index: usize,
    errors: &mut Vec<ScriptError>,
) -> bool {
    if index < MAX_CUSTOM_CHECK_DIR_ENTRIES {
        return true;
    }

    errors.push(ScriptError {
        file: dir.to_string(),
        message: format!(
            "Custom checks directory has more than {MAX_CUSTOM_CHECK_DIR_ENTRIES} entries"
        ),
    });
    false
}

fn custom_check_file_from_entry(
    dir: &Utf8Path,
    entry: std::io::Result<std::fs::DirEntry>,
    errors: &mut Vec<ScriptError>,
) -> Option<CustomCheckFile> {
    let entry = readable_custom_check_entry(dir, entry, errors)?;
    let path = rhai_entry_path(&entry)?;
    if !custom_check_entry_is_regular_file(&entry, &path, errors) {
        return None;
    }
    Some(custom_check_file(path))
}

fn readable_custom_check_entry(
    dir: &Utf8Path,
    entry: std::io::Result<std::fs::DirEntry>,
    errors: &mut Vec<ScriptError>,
) -> Option<std::fs::DirEntry> {
    match entry {
        Ok(entry) => Some(entry),
        Err(e) => {
            errors.push(ScriptError {
                file: dir.to_string(),
                message: format!("Failed to read directory entry: {e}"),
            });
            None
        }
    }
}

fn rhai_entry_path(entry: &std::fs::DirEntry) -> Option<std::path::PathBuf> {
    let path = entry.path();
    path.extension()
        .is_some_and(|ext| ext == "rhai")
        .then_some(path)
}

fn custom_check_entry_is_regular_file(
    entry: &std::fs::DirEntry,
    path: &std::path::Path,
    errors: &mut Vec<ScriptError>,
) -> bool {
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(e) => {
            errors.push(ScriptError {
                file: path.display().to_string(),
                message: format!("Failed to inspect file type: {e}"),
            });
            return false;
        }
    };
    if file_type.is_file() {
        return true;
    }

    errors.push(ScriptError {
        file: path.display().to_string(),
        message: "Custom check path is not a regular file".to_string(),
    });
    false
}

fn custom_check_file(path: std::path::PathBuf) -> CustomCheckFile {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    CustomCheckFile { path, stem }
}

fn push_custom_check_file(
    dir: &Utf8Path,
    file: CustomCheckFile,
    files: &mut Vec<CustomCheckFile>,
    errors: &mut Vec<ScriptError>,
) -> bool {
    if files.len() >= MAX_CUSTOM_CHECK_FILES {
        errors.push(ScriptError {
            file: dir.to_string(),
            message: format!(
                "Custom checks directory has more than {MAX_CUSTOM_CHECK_FILES} .rhai files"
            ),
        });
        return false;
    }
    files.push(file);
    true
}

fn read_script_source(path: &std::path::Path) -> std::io::Result<ScriptSource> {
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(MAX_CUSTOM_CHECK_SOURCE_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if bytes_read > MAX_CUSTOM_CHECK_SOURCE_BYTES {
        return Ok(ScriptSource::TooLarge);
    }
    String::from_utf8(bytes)
        .map(|source| ScriptSource::Source(source, bytes_read))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::pg_helpers::extract_node;
    use std::fs;
    use tempfile::tempdir;

    /// Helper: run a script against a node and return violations.
    fn run_script(script: &str, sql: &str) -> Vec<Violation> {
        run_script_with_config(script, sql, &crate::config::Config::default())
    }

    /// Helper: run a script against a node with explicit config and return violations.
    fn run_script_with_config(
        script: &str,
        sql: &str,
        config: &crate::config::Config,
    ) -> Vec<Violation> {
        run_script_with_ctx(
            script,
            sql,
            config,
            &crate::checks::MigrationContext::default(),
        )
    }

    /// Helper: run a script against a node with explicit config and ctx and return violations.
    fn run_script_with_ctx(
        script: &str,
        sql: &str,
        config: &crate::config::Config,
        ctx: &crate::checks::MigrationContext,
    ) -> Vec<Violation> {
        let engine = Arc::new(create_engine());
        let ast = engine.compile(script).expect("script should compile");
        let check = CustomCheck {
            name: "test_check".to_string(),
            engine,
            ast,
            path: String::new(),
        };

        let stmts = crate::parser::parse(sql).expect("SQL should parse");
        let mut all_violations = Vec::new();
        for raw_stmt in &stmts {
            if let Some(node) = extract_node(raw_stmt) {
                all_violations.extend(check.check(node, config, ctx));
            }
        }
        all_violations
    }

    #[test]
    fn test_script_returns_unit_no_violations() {
        let violations = run_script(
            r"
            // Script that always returns unit (no violation)
            let stmt = node.CreateStmt;
            if stmt == () { return; }
            ",
            "CREATE INDEX idx ON t(id);",
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_script_returns_map_one_violation() {
        let violations = run_script(
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            if !stmt.concurrent {
                #{
                    operation: "INDEX without CONCURRENTLY",
                    problem: "locks table",
                    safe_alternative: "use CONCURRENTLY"
                }
            }
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "INDEX without CONCURRENTLY");
        assert_eq!(violations[0].problem, "locks table");
    }

    #[test]
    fn test_script_returns_array_multiple_violations() {
        let violations = run_script(
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            [
                #{ operation: "violation 1", problem: "p1", safe_alternative: "s1" },
                #{ operation: "violation 2", problem: "p2", safe_alternative: "s2" }
            ]
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].operation, "violation 1");
        assert_eq!(violations[1].operation, "violation 2");
    }

    #[test]
    fn test_script_invalid_return_type_no_crash() {
        // Returning a string instead of map — should produce an error violation
        let violations = run_script(
            r#"
            "not a valid return type"
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
    }

    #[test]
    fn test_script_infinite_loop_hits_max_operations() {
        // Engine's max_operations limit should kick in and surface as a SCRIPT ERROR
        let violations = run_script(
            r"
            loop { }
            ",
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(
            violations.len(),
            1,
            "expected 1 SCRIPT ERROR, got: {violations:?}"
        );
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
    }

    #[test]
    fn test_script_wrong_node_type_returns_unit() {
        // Script looks for CreateStmt but we give it an IndexStmt
        let violations = run_script(
            r#"
            let stmt = node.CreateStmt;
            if stmt == () { return; }
            #{ operation: "found", problem: "p", safe_alternative: "s" }
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_compilation_error_reported() {
        let engine = Arc::new(create_engine());
        let result = engine.compile("this is not valid rhai {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_custom_checks_from_directory() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();

        // Write a valid check script
        fs::write(
            dir.path().join("require_concurrent.rhai"),
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            if !stmt.concurrent {
                #{ operation: "custom", problem: "no concurrently", safe_alternative: "use it" }
            }
            "#,
        )
        .unwrap();

        // Write an invalid script
        fs::write(dir.path().join("broken.rhai"), "this is not valid {{{").unwrap();

        // Write a non-rhai file (should be ignored)
        fs::write(dir.path().join("notes.txt"), "not a script").unwrap();

        let config = crate::config::Config::default();
        let (checks, errors) = load_custom_checks(dir_path, &config);

        // One valid check loaded
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "require_concurrent");

        // One compilation error reported
        assert_eq!(errors.len(), 1);
        assert!(errors[0].file.contains("broken.rhai"));
    }

    #[test]
    fn test_empty_script_no_violations() {
        // An empty .rhai file evaluates to () — should produce no violations
        let violations = run_script("", "CREATE INDEX idx ON users(email);");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_map_with_missing_keys_produces_error_violation() {
        // Map missing "safe_alternative" — should produce an error violation
        let violations = run_script(
            r#"
            #{ operation: "op", problem: "p" }
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
        assert_eq!(
            violations[0].problem,
            "Custom check returned an invalid map: 'safe_alternative' is missing"
        );
    }

    #[test]
    fn test_map_with_misspelled_key_produces_error_violation() {
        // Unrecognized key "safe_alt" instead of "safe_alternative"
        let violations = run_script(
            r#"
            #{ operation: "op", problem: "p", safe_alt: "s" }
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
        assert_eq!(
            violations[0].problem,
            "Custom check returned an invalid map: 'safe_alternative' is missing"
        );
    }

    #[test]
    fn test_pg_constants_accessible_in_scripts() {
        let violations = run_script(
            r#"
            let stmt = node.DropStmt;
            if stmt == () { return; }
            if stmt.remove_type == pg::OBJECT_INDEX {
                #{ operation: "DROP INDEX", problem: "not concurrent", safe_alternative: "use CONCURRENTLY" }
            }
            "#,
            "DROP INDEX idx_users_email;",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "DROP INDEX");
    }

    #[test]
    fn test_config_postgres_version_accessible_in_scripts() {
        let config = crate::config::Config {
            postgres_version: Some(14),
            ..Default::default()
        };
        // Script skips violation when postgres_version >= 14
        let violations = run_script_with_config(
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            if config.postgres_version != () && config.postgres_version >= 14 { return; }
            #{ operation: "INDEX without CONCURRENTLY", problem: "locks table", safe_alternative: "use CONCURRENTLY" }
            "#,
            "CREATE INDEX idx ON users(email);",
            &config,
        );
        assert!(violations.is_empty());

        // Same script with pg 10 should produce a violation
        let config_old = crate::config::Config {
            postgres_version: Some(10),
            ..Default::default()
        };
        let violations = run_script_with_config(
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            if config.postgres_version != () && config.postgres_version >= 14 { return; }
            #{ operation: "INDEX without CONCURRENTLY", problem: "locks table", safe_alternative: "use CONCURRENTLY" }
            "#,
            "CREATE INDEX idx ON users(email);",
            &config_old,
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_pg_constants_no_match() {
        // Script checks for OBJECT_TABLE but SQL drops an index — should not match
        let violations = run_script(
            r#"
            let stmt = node.DropStmt;
            if stmt == () { return; }
            if stmt.remove_type == pg::OBJECT_TABLE {
                #{ operation: "DROP TABLE", problem: "dangerous", safe_alternative: "be careful" }
            }
            "#,
            "DROP INDEX idx_users_email;",
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_load_custom_checks_respects_disable() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();

        fs::write(dir.path().join("my_check.rhai"), r"return;").unwrap();

        let config = crate::config::Config {
            disable_checks: vec!["my_check".to_string()],
            ..Default::default()
        };

        let (checks, errors) = load_custom_checks(dir_path, &config);
        assert_eq!(checks.len(), 0);
        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn test_load_custom_checks_nonexistent_directory() {
        let dir = tempdir().expect("Failed to create temp dir");
        let missing = dir.path().join("does_not_exist");
        let dir_path = Utf8Path::from_path(&missing).unwrap();
        let config = crate::config::Config::default();
        let (checks, errors) = load_custom_checks(dir_path, &config);
        assert_eq!(checks.len(), 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("Failed to read directory"));
    }

    #[test]
    fn test_ctx_run_in_transaction_false_no_violation() {
        // CONCURRENTLY outside a transaction — no violation
        let ctx = crate::checks::MigrationContext {
            run_in_transaction: false,
            no_transaction_hint: "",
            ..crate::checks::MigrationContext::default()
        };
        let violations = run_script_with_ctx(
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            if stmt.concurrent && ctx.run_in_transaction {
                #{ operation: "CONCURRENTLY in transaction", problem: "will fail", safe_alternative: ctx.no_transaction_hint }
            }
            "#,
            "CREATE INDEX CONCURRENTLY idx ON users(email);",
            &crate::config::Config::default(),
            &ctx,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_ctx_run_in_transaction_true_produces_violation() {
        // CONCURRENTLY inside a transaction — should flag it
        let ctx = crate::checks::MigrationContext {
            run_in_transaction: true,
            no_transaction_hint: "Add -- diesel:no-transaction to the migration file.",
            ..crate::checks::MigrationContext::default()
        };
        let violations = run_script_with_ctx(
            r#"
            let stmt = node.IndexStmt;
            if stmt == () { return; }
            if stmt.concurrent && ctx.run_in_transaction {
                #{
                    operation: "CONCURRENTLY in transaction",
                    problem: "will fail",
                    safe_alternative: ctx.no_transaction_hint
                }
            }
            "#,
            "CREATE INDEX CONCURRENTLY idx ON users(email);",
            &crate::config::Config::default(),
            &ctx,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "CONCURRENTLY in transaction");
        assert!(
            violations[0]
                .safe_alternative
                .contains("diesel:no-transaction")
        );
    }

    #[test]
    fn test_load_custom_checks_unreadable_file() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();

        // A directory at the .rhai path always fails fs::read_to_string,
        // even under root — unlike chmod 0o000 which root can bypass.
        let script_path = dir.path().join("unreadable.rhai");
        fs::create_dir(&script_path).unwrap();

        let config = crate::config::Config::default();
        let (checks, errors) = load_custom_checks(dir_path, &config);

        assert_eq!(checks.len(), 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn test_load_custom_checks_rejects_symlink() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("linked.rhai");
        fs::write(&target, "return;").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let config = crate::config::Config::default();
        let (checks, errors) = load_custom_checks(dir_path, &config);

        assert_eq!(checks.len(), 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not a regular file"));
    }

    #[test]
    fn test_load_custom_checks_rejects_oversized_script() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        let script_path = dir.path().join("too_large.rhai");
        fs::write(
            &script_path,
            " ".repeat(usize::try_from(MAX_CUSTOM_CHECK_SOURCE_BYTES).unwrap() + 1),
        )
        .unwrap();

        let config = crate::config::Config::default();
        let (checks, errors) = load_custom_checks(dir_path, &config);

        assert!(checks.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0]
                .message
                .contains("Custom check script is larger than")
        );
    }

    #[test]
    fn test_load_custom_checks_rejects_too_many_scripts() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        for index in 0..=MAX_CUSTOM_CHECK_FILES {
            fs::write(dir.path().join(format!("check_{index}.rhai")), "return;").unwrap();
        }

        let config = crate::config::Config::default();
        let (_checks, errors) = load_custom_checks(dir_path, &config);

        assert!(errors.iter().any(|error| {
            error
                .message
                .contains("Custom checks directory has more than")
        }));
    }

    #[test]
    fn test_discover_custom_check_files_sorts_and_filters_entries() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        fs::write(dir.path().join("zeta.rhai"), "return;").unwrap();
        fs::write(dir.path().join("alpha.rhai"), "return;").unwrap();
        fs::write(dir.path().join("notes.txt"), "return;").unwrap();
        fs::create_dir(dir.path().join("nested.rhai")).unwrap();

        let (files, errors) = discover_custom_check_files(dir_path);

        let names: Vec<&str> = files
            .iter()
            .map(|file| file.path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, vec!["alpha.rhai", "zeta.rhai"]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not a regular file"));
    }

    #[test]
    fn test_process_custom_check_dir_entry_allows_non_rhai_entries() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        fs::write(dir.path().join("notes.txt"), "return;").unwrap();
        let entry = fs::read_dir(dir.path()).unwrap().next().unwrap();
        let mut files = Vec::new();
        let mut errors = Vec::new();

        assert!(process_custom_check_dir_entry(
            dir_path,
            0,
            entry,
            &mut files,
            &mut errors
        ));
        assert!(files.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn test_process_custom_check_dir_entry_stops_at_file_limit() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        fs::write(dir.path().join("extra.rhai"), "return;").unwrap();
        let entry = fs::read_dir(dir.path()).unwrap().next().unwrap();
        let mut files = (0..MAX_CUSTOM_CHECK_FILES)
            .map(|index| CustomCheckFile {
                path: PathBuf::from(format!("check_{index}.rhai")),
                stem: format!("check_{index}"),
            })
            .collect::<Vec<_>>();
        let mut errors = Vec::new();

        assert!(!process_custom_check_dir_entry(
            dir_path,
            0,
            entry,
            &mut files,
            &mut errors
        ));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("more than"));
    }

    #[test]
    fn test_parse_script_result_rejects_scalar() {
        let violations = parse_script_result("scalar_check", Dynamic::from(42_i64));

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: scalar_check");
        assert!(violations[0].problem.contains("expected (), map, or array"));
    }

    #[test]
    fn test_array_script_violations_filters_non_maps() {
        let mut valid = rhai::Map::new();
        valid.insert("operation".into(), Dynamic::from("op"));
        valid.insert("problem".into(), Dynamic::from("problem"));
        valid.insert("safe_alternative".into(), Dynamic::from("safe"));
        let result = Dynamic::from_array(vec![Dynamic::from(7_i64), Dynamic::from_map(valid)]);

        let violations = parse_script_result("array_check", result);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "op");
    }

    #[test]
    fn test_load_custom_checks_rejects_total_source_bytes() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_path = Utf8Path::from_path(dir.path()).unwrap();
        let script = format!(
            "let x = 1;{}",
            " ".repeat(usize::try_from(MAX_CUSTOM_CHECK_SOURCE_BYTES).unwrap() - 10)
        );
        for index in 0..33 {
            fs::write(dir.path().join(format!("check_{index}.rhai")), &script).unwrap();
        }

        let config = crate::config::Config::default();
        let (_checks, errors) = load_custom_checks(dir_path, &config);

        assert!(errors.iter().any(|error| {
            error
                .message
                .contains("Custom check scripts are larger than")
        }));
    }

    #[test]
    fn test_map_with_non_string_operation_field() {
        // operation is an integer, not a string — into_string() returns None,
        // so the match falls through to the error-violation arm in map_to_violation.
        let violations = run_script(
            r#"
            #{ operation: 42, problem: "p", safe_alternative: "s" }
            "#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
        assert_eq!(
            violations[0].problem,
            "Custom check returned an invalid map: 'operation' must be a string (got i64)"
        );
    }

    #[test]
    fn test_map_with_non_string_problem_field() {
        let violations = run_script(
            r#"#{ operation: "op", problem: 42, safe_alternative: "s" }"#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
        assert!(
            violations[0].problem.contains("'problem' must be a string"),
            "got: {}",
            violations[0].problem
        );
    }

    #[test]
    fn test_map_with_non_string_safe_alternative_field() {
        let violations = run_script(
            r#"#{ operation: "op", problem: "p", safe_alternative: false }"#,
            "CREATE INDEX idx ON users(email);",
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "SCRIPT ERROR: test_check");
        assert!(
            violations[0]
                .problem
                .contains("'safe_alternative' must be a string"),
            "got: {}",
            violations[0].problem
        );
    }

    fn make_test_check() -> CustomCheck {
        let engine = Arc::new(create_engine());
        let ast = engine.compile("()").expect("script should compile");
        CustomCheck {
            name: "test_check".to_string(),
            engine,
            ast,
            path: String::new(),
        }
    }

    #[test]
    fn test_internal_error_yields_script_error_violation() {
        let check = make_test_check();
        let violations = check.internal_error(&"boom");
        assert_eq!(violations.len(), 1);
        let v = &violations[0];
        assert_eq!(v.operation, "SCRIPT ERROR: test_check");
        assert_eq!(v.problem, "Error in custom check 'test_check': boom");
        assert_eq!(
            v.safe_alternative,
            "This is likely a diesel-guard bug. Please report it."
        );
    }

    #[test]
    fn test_script_runtime_error_yields_script_error_violation() {
        // Division by zero is a runtime error that does NOT contain "ErrorTerminated".
        // A broken script must not silently disable the safety check — it must surface
        // as a SCRIPT ERROR violation.
        let violations = run_script("1 / 0", "CREATE INDEX idx ON users(email);");
        assert_eq!(
            violations.len(),
            1,
            "expected 1 SCRIPT ERROR violation, got: {violations:?}"
        );
        let v = &violations[0];
        assert_eq!(v.operation, "SCRIPT ERROR: test_check");
        assert_eq!(
            v.problem,
            "Runtime error in custom check 'test_check': Division by zero: 1 / 0"
        );
        assert_eq!(
            v.safe_alternative,
            "Fix the custom check script to eliminate the runtime error."
        );
    }

    #[test]
    fn test_pg_alter_table_constraint_and_drop_constants_accessible() {
        // Verify one representative constant from each untested group:
        // AT_ADD_COLUMN (AlterTableType), CONSTR_PRIMARY (ConstrType), DROP_CASCADE (DropBehavior).
        let violations = run_script(
            r#"
            let at = pg::AT_ADD_COLUMN;
            let ct = pg::CONSTR_PRIMARY;
            let db = pg::DROP_CASCADE;
            if at == () || ct == () || db == () {
                return #{ operation: "MISSING CONSTANT", problem: "a pg constant was ()", safe_alternative: "" };
            }
            "#,
            "SELECT 1;",
        );
        assert!(
            violations.is_empty(),
            "All pg constants should be accessible, got: {violations:?}"
        );
    }

    #[test]
    fn test_describe_call_fn_debug() {
        let engine = Arc::new(create_engine());
        // Script with fn describe() AND body that references `node` (like a real check script).
        // Verifies that clone_functions_only() lets call_fn succeed even though the body
        // references the `node` variable that is only injected at check time.
        let script = r#"
fn describe() {
    "This check validates something important."
}
let stmt = node.IndexStmt;
if stmt == () { return; }
#{ operation: "MY OPERATION", problem: "my problem", safe_alternative: "my safe alternative" }
"#;
        let ast = engine.compile(script).expect("script should compile");
        let fns_ast = ast.clone_functions_only();
        let mut scope = rhai::Scope::new();
        let result = engine.call_fn::<rhai::Dynamic>(&mut scope, &fns_ast, "describe", ());
        let result = result.expect("call_fn on fns-only AST should succeed");
        assert_eq!(
            result.into_string().ok(),
            Some("This check validates something important.".to_string())
        );
    }

    #[test]
    fn test_describe_with_fn_describe_in_script() {
        let engine = Arc::new(create_engine());
        let script = r#"
fn describe() {
    "This check validates something important."
}
let stmt = node.IndexStmt;
if stmt == () { return; }
#{ operation: "MY OPERATION", problem: "my problem", safe_alternative: "my safe alternative" }
"#;
        let ast = engine.compile(script).expect("script should compile");
        let check = CustomCheck {
            name: "my_check".to_string(),
            engine,
            ast,
            path: "/path/my_check.rhai".to_string(),
        };

        assert_eq!(
            check.describe(),
            Some("This check validates something important.".to_string())
        );
    }

    #[test]
    fn test_describe_without_fn_describe_in_script_falls_back() {
        let engine = Arc::new(create_engine());
        let ast = engine.compile("()").expect("script should compile");
        let check = CustomCheck {
            name: "no_desc".to_string(),
            engine,
            ast,
            path: "/path/no_desc.rhai".to_string(),
        };

        assert_eq!(check.describe(), None);
    }

    #[test]
    fn test_custom_check_script_path_returns_path() {
        let engine = Arc::new(create_engine());
        let ast = engine.compile("()").expect("script should compile");
        let check = CustomCheck {
            name: "path_check".to_string(),
            engine,
            ast,
            path: "/checks/my_check.rhai".to_string(),
        };

        assert_eq!(check.script_path(), Some("/checks/my_check.rhai"));
    }
}
