/// PROJECT.md, "Two-stage semantic reasoning": a real, deterministic fact
/// -- never model-guessed -- that a tracked field's own value (or a simple
/// arithmetic expression derived from it) is displayed adjacent to a real,
/// resolved string literal, inside the same `operator<<` stream chain. The
/// real, confirmed case this exists for: Snake's own lives counter reaches
/// `FUN_14000205a` as `param_4`, used there only as `param_4 + -1`,
/// streamed immediately after `&DAT_14000e0c0`, which
/// `data_symbols::find_constructor_string_literals` already resolves to
/// `"Lives: "`. This asserts only the mechanically observable fact -- "a
/// value derived from this field is displayed under this label" -- never
/// the field's real meaning; that inference is `ProposeFieldSemanticRoleTask`'s
/// own job, with this as its strongest, independently-verifiable evidence.
use std::collections::HashMap;

use crate::forwarding_thunk::{parse_param_names, split_top_level_comma};
use crate::phantom_local::{find_calls, strip_casts_and_parens};
use crate::stack_object::FieldValueConsumer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayAssociation {
    /// The exact expression text found adjacent to the label (e.g.
    /// `"param_4 + -1"`) -- the tracked value itself, or a simple
    /// expression built from it, never claimed to be identical to the
    /// bare tracked identifier when it isn't.
    pub value_expr: String,
    /// The label's own decoded text (e.g. `"Lives: "`).
    pub label: String,
    /// The `DAT_*`/`PTR_*` symbol the label came from (e.g.
    /// `"DAT_14000e0c0"`), so a caller can cite exactly which resolved
    /// reference justified this.
    pub label_symbol: String,
    /// The function whose own body this association was found in (e.g.
    /// `"FUN_14000205a"`) -- the real sink, not the field's defining
    /// function.
    pub sink_function: String,
}

/// One `operator<<` call's own classified "value" argument (the second
/// argument to the free-function form, or the qualified member form --
/// both real, observed shapes, both always exactly two arguments: a
/// receiver/stream and a value).
enum StreamedValue<'a> {
    Tracked(&'a str),
    Literal { symbol: &'a str, label: &'a str },
    Other,
}

/// Every place `consumer`'s own body streams the field's own tracked
/// value (its own parameter, at `consumer.parameter_position`, or a
/// simple expression built from it) immediately adjacent -- in the same
/// ordered stream chain, filtered to only the meaningful entries, never
/// raw call-index adjacency -- to a real, resolved string literal from
/// `resolved_strings` (as `data_symbols::classify_data_symbols` already
/// produces, keyed by symbol name).
///
/// Raw Ghidra text renders C++ stream insertion (`operator<<`, the
/// genuine C++ idiom, not specific to this project) as `std::operator<<`
/// or the qualified member form
/// `std::basic_ostream<...>::operator<<` -- both contain `<`/`>`/`,`
/// characters `find_calls`'s own identifier scan was never built to
/// tokenize through (a real, confirmed bug this test caught: it silently
/// found zero calls at all against the exact real Snake text). Reuses
/// `render.rs`'s own already-correct, already-tested normalization
/// (`patch_known_idioms`, built earlier this session specifically to fix
/// this same shape for compilation) to convert both raw forms into the
/// plain `debura_stream_output(receiver, value)` call `find_calls` can
/// already tokenize, rather than re-implementing a template-aware call
/// scanner here.
pub fn find_display_associations(
    consumer: &FieldValueConsumer,
    resolved_strings: &HashMap<String, String>,
) -> Vec<DisplayAssociation> {
    let Some(brace_open) = consumer.callee_decompilation.find('{') else { return Vec::new() };
    let Some(params) = parse_param_names(&consumer.callee_decompilation[..brace_open + 1]) else {
        return Vec::new();
    };
    let Some(tracked_name) = params.get(consumer.parameter_position) else { return Vec::new() };

    let patched = crate::render::patch_known_idioms(&consumer.callee_decompilation);
    let mut sequence: Vec<StreamedValue> = Vec::new();
    for (name, args_text) in find_calls(&patched) {
        if name != "debura_stream_output" {
            continue;
        }
        let args = split_top_level_comma(args_text);
        let Some(value_arg) = args.get(1) else { continue };
        let value = strip_casts_and_parens(value_arg);

        if involves_identifier(value, tracked_name) {
            sequence.push(StreamedValue::Tracked(value));
            continue;
        }
        if let Some(symbol) = value.strip_prefix('&') {
            if let Some(label) = resolved_strings.get(symbol) {
                sequence.push(StreamedValue::Literal { symbol, label });
                continue;
            }
        }
        sequence.push(StreamedValue::Other);
    }

    // Only Tracked/Literal entries matter for adjacency -- an
    // intervening `Other` entry (a receiver, an unrelated value, a plain
    // `" - "`-shaped literal argument that isn't itself a resolved
    // symbol) doesn't break the real relationship between a value and
    // the nearest label actually explaining it.
    let meaningful: Vec<&StreamedValue> =
        sequence.iter().filter(|v| !matches!(v, StreamedValue::Other)).collect();

    let mut associations = Vec::new();
    for (i, entry) in meaningful.iter().enumerate() {
        let StreamedValue::Tracked(value_expr) = entry else { continue };
        let neighbor = meaningful.get(i.wrapping_sub(1)).filter(|_| i > 0).or_else(|| meaningful.get(i + 1));
        if let Some(StreamedValue::Literal { symbol, label }) = neighbor {
            associations.push(DisplayAssociation {
                value_expr: value_expr.to_string(),
                label: label.to_string(),
                label_symbol: symbol.to_string(),
                sink_function: consumer.callee_raw_name.clone(),
            });
        }
    }
    associations
}

/// Whether `expr` (already stripped of casts/parens) either *is*
/// `identifier` or contains it as a whole, boundary-delimited word --
/// the real shape a tracked value's own use looks like once an
/// arithmetic transform is applied (`"param_4 + -1"` still involves
/// `param_4`), not requiring exact textual equality.
fn involves_identifier(expr: &str, identifier: &str) -> bool {
    let mut rest = expr;
    while let Some(pos) = rest.find(identifier) {
        let before_ok = rest[..pos].chars().next_back().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let end = pos + identifier.len();
        let after_ok = rest[end..].chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if before_ok && after_ok {
            return true;
        }
        rest = &rest[end..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consumer(callee_raw_name: &str, parameter_position: usize, callee_decompilation: &str) -> FieldValueConsumer {
        FieldValueConsumer {
            callee_raw_name: callee_raw_name.to_string(),
            callee_decompilation: callee_decompilation.to_string(),
            parameter_position,
        }
    }

    fn resolved(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// The real, confirmed case: `FUN_14000205a` streams
    /// `"Score: " + param_3 + " - " + "Lives: " + (param_4 + -1)`. The
    /// tracked value (`param_4`, at parameter position 3) is used only
    /// as `param_4 + -1`, immediately after `&DAT_14000e0c0`, which
    /// resolves to `"Lives: "` -- must find exactly that association,
    /// not the unrelated `"Score: "` label two entries earlier.
    #[test]
    fn finds_the_real_lives_display_association() {
        let body = "undefined8 FUN_14000205a(undefined8 param_1,undefined8 param_2,int param_3,int param_4)\n\n{\n  basic_ostream *pbVar1;\n  \n  pbVar1 = std::operator<<(abStack_198,(basic_string *)&DAT_14000e0a0);\n  pbVar1 = std::basic_ostream<char,std::char_traits<char>>::operator<<((basic_ostream<char,std::char_traits<char>> *)pbVar1,param_3);\n  pbVar1 = std::operator<<(pbVar1,\" - \");\n  pbVar1 = std::operator<<(pbVar1,(basic_string *)&DAT_14000e0c0);\n  std::basic_ostream<char,std::char_traits<char>>::operator<<((basic_ostream<char,std::char_traits<char>> *)pbVar1,param_4 + -1);\n  return param_1;\n}";
        let c = consumer("FUN_14000205a", 3, body);
        let resolved_strings = resolved(&[("DAT_14000e0a0", "Score: "), ("DAT_14000e0c0", "Lives: ")]);

        let associations = find_display_associations(&c, &resolved_strings);

        assert_eq!(associations.len(), 1, "{associations:?}");
        assert_eq!(associations[0].value_expr, "param_4 + -1");
        assert_eq!(associations[0].label, "Lives: ");
        assert_eq!(associations[0].label_symbol, "DAT_14000e0c0");
        assert_eq!(associations[0].sink_function, "FUN_14000205a");
    }

    /// A tracked value with no resolved string anywhere nearby in the
    /// same chain must find nothing -- never a guessed association.
    #[test]
    fn a_value_with_no_adjacent_resolved_string_finds_no_association() {
        let body = "undefined8 FUN_1(undefined8 param_1,int param_2)\n\n{\n  basic_ostream *pbVar1;\n  \n  pbVar1 = std::operator<<(abStack_198,param_2);\n  return param_1;\n}";
        let c = consumer("FUN_1", 1, body);
        let resolved_strings: HashMap<String, String> = HashMap::new();

        assert!(find_display_associations(&c, &resolved_strings).is_empty());
    }
}
