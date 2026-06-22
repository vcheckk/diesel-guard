use super::{DIAGNOSTIC_SOURCE, DiagnosticEvent, file_uri_to_path};
use crate::error::{DieselGuardError, Result};
use crate::violation::Severity;
use crate::{SafetyChecker, ViolationList};
use lsp_types::{
    Diagnostic, DiagnosticSeverity, NumberOrString, Position, Range,
    TextDocumentContentChangeEvent, Uri,
};

pub(super) fn check_live_sql(
    checker: &SafetyChecker,
    uri: &Uri,
    text: &str,
) -> Result<(ViolationList, Vec<String>)> {
    file_uri_to_path(uri).map_or_else(
        || checker.check_sql_with_warnings(text),
        |path| checker.check_file_sql_with_warnings(&path, text),
    )
}

pub fn violations_to_diagnostics(text: &str, violations: &ViolationList) -> Vec<Diagnostic> {
    let lines = text.lines().collect::<Vec<_>>();
    violations
        .iter()
        .map(|(line, violation)| {
            Diagnostic::new(
                diagnostic_range(*line, &lines),
                Some(diagnostic_severity(violation.severity)),
                diagnostic_code(&violation.check_name),
                Some(DIAGNOSTIC_SOURCE.to_string()),
                diagnostic_message(&violation.problem, &violation.safe_alternative),
                None,
                None,
            )
        })
        .collect()
}

pub(super) fn diagnostic_range(line: usize, lines: &[&str]) -> Range {
    let zero_indexed_line = u32::try_from(line.saturating_sub(1)).unwrap_or(u32::MAX);
    let line_text = lines
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or_default();
    line_range(zero_indexed_line, line_text)
}

pub(super) fn diagnostic_severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
    }
}

pub(super) fn diagnostic_code(check_name: &str) -> Option<NumberOrString> {
    (!check_name.is_empty()).then(|| NumberOrString::String(check_name.to_string()))
}

pub(super) fn parse_error_event(
    uri: Uri,
    text: &str,
    err: &DieselGuardError,
    version: Option<i32>,
) -> DiagnosticEvent {
    let offset = match err {
        DieselGuardError::ParseError { span, .. } => {
            span.as_ref().map_or(0, miette::SourceSpan::offset)
        }
        _ => 0,
    };
    let position = byte_offset_to_position(text, offset);
    let range = Range {
        start: position,
        end: position,
    };
    DiagnosticEvent {
        uri,
        diagnostics: vec![Diagnostic::new(
            range,
            Some(DiagnosticSeverity::ERROR),
            Some(NumberOrString::String("ParseError".to_string())),
            Some(DIAGNOSTIC_SOURCE.to_string()),
            err.to_string(),
            None,
            None,
        )],
        version,
    }
}

pub(super) fn empty_event(uri: Uri, version: Option<i32>) -> DiagnosticEvent {
    DiagnosticEvent {
        uri,
        diagnostics: Vec::new(),
        version,
    }
}

pub(super) fn final_full_sync_text(changes: &[TextDocumentContentChangeEvent]) -> Option<&str> {
    changes
        .iter()
        .rev()
        .find(|change| change.range.is_none())
        .map(|change| change.text.as_str())
}

pub(super) fn line_range(line: u32, line_text: &str) -> Range {
    let end_character = line_text.encode_utf16().count();
    Range {
        start: Position { line, character: 0 },
        end: Position {
            line,
            character: u32::try_from(end_character).unwrap_or(u32::MAX),
        },
    }
}

pub(super) fn diagnostic_message(problem: &str, safe_alternative: &str) -> String {
    if safe_alternative.is_empty() {
        problem.to_string()
    } else {
        format!("{problem} Safe alternative: {safe_alternative}")
    }
}

pub(super) fn is_parse_error(err: &DieselGuardError) -> bool {
    matches!(err, DieselGuardError::ParseError { .. })
}

pub(super) fn byte_offset_to_position(text: &str, offset: usize) -> Position {
    let offset = clamped_byte_offset(text, offset);
    let mut line = 0_u32;
    let mut line_start = 0_usize;

    for (idx, ch) in text.char_indices() {
        if idx >= offset {
            break;
        }
        advance_position_for_char(ch, idx, &mut line, &mut line_start);
    }

    Position {
        line,
        character: utf16_character_offset(text, line_start, offset),
    }
}

pub(super) fn clamped_byte_offset(text: &str, offset: usize) -> usize {
    offset.min(text.len())
}

pub(super) fn advance_position_for_char(
    ch: char,
    idx: usize,
    line: &mut u32,
    line_start: &mut usize,
) {
    if ch == '\n' {
        *line = line.saturating_add(1);
        *line_start = idx + ch.len_utf8();
    }
}

pub(super) fn utf16_character_offset(text: &str, line_start: usize, offset: usize) -> u32 {
    u32::try_from(text[line_start..offset].encode_utf16().count()).unwrap_or(u32::MAX)
}
