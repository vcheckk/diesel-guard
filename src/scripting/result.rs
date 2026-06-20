use crate::violation::Violation;
use rhai::Dynamic;

/// Parse the return value of a Rhai script into violations.
///
/// Accepted return types:
/// - `()` — no violation
/// - `#{ operation: "...", problem: "...", safe_alternative: "..." }` — one violation
/// - Array of maps — multiple violations
pub(super) fn parse_script_result(check_name: &str, result: Dynamic) -> Vec<Violation> {
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

pub(super) fn single_script_violation(check_name: &str, result: Dynamic) -> Vec<Violation> {
    match map_to_violation(check_name, result) {
        Some(violation) => vec![violation],
        None => vec![],
    }
}

pub(super) fn array_script_violations(check_name: &str, result: Dynamic) -> Vec<Violation> {
    result
        .into_array()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| map_to_violation(check_name, value))
        .collect()
}

pub(super) fn invalid_script_result_violation(check_name: &str, result: &Dynamic) -> Violation {
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
pub(super) fn map_to_violation(check_name: &str, value: Dynamic) -> Option<Violation> {
    let map = value.try_cast::<rhai::Map>()?;
    violation_from_map_fields(&map).or_else(|| Some(invalid_map_violation(check_name, &map)))
}

pub(super) fn violation_from_map_fields(map: &rhai::Map) -> Option<Violation> {
    let operation = string_map_field(map, "operation");
    let problem = string_map_field(map, "problem");
    let safe_alternative = string_map_field(map, "safe_alternative");

    match (operation, problem, safe_alternative) {
        (Some(op), Some(prob), Some(alt)) => Some(Violation::new(op, prob, alt)),
        _ => None,
    }
}

pub(super) fn string_map_field(map: &rhai::Map, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|value| value.clone().into_string().ok())
}

pub(super) fn invalid_map_violation(check_name: &str, map: &rhai::Map) -> Violation {
    Violation::new(
        format!("SCRIPT ERROR: {check_name}"),
        format!(
            "Custom check returned an invalid map: {}",
            invalid_map_issues(map).join(", ")
        ),
        "Fix the custom check script to return all three required string keys.",
    )
}

pub(super) fn invalid_map_issues(map: &rhai::Map) -> Vec<String> {
    ["operation", "problem", "safe_alternative"]
        .into_iter()
        .filter_map(|key| invalid_map_issue(map, key))
        .collect()
}

pub(super) fn invalid_map_issue(map: &rhai::Map, key: &str) -> Option<String> {
    match map.get(key) {
        None => Some(format!("'{key}' is missing")),
        Some(value) if value.clone().into_string().is_err() => Some(format!(
            "'{key}' must be a string (got {})",
            value.type_name()
        )),
        _ => None,
    }
}
