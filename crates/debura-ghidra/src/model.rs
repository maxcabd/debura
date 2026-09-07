use serde::{Deserialize, Serialize};

/// A deterministic fact about one function, as observed by Ghidra.
///
/// Nothing here is a semantic claim (PROJECT.md S3.1) -- `name` is whatever
/// Ghidra assigned (e.g. `FUN_140271330`), not an inferred identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFact {
    pub address: String,
    pub name: String,
    pub size: u64,
    pub signature: String,
    pub calling_convention: String,
    pub callers: Vec<String>,
    pub callees: Vec<String>,
    pub decompilation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringFact {
    pub address: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFact {
    pub name: String,
    pub namespace: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFact {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefFact {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// The full set of deterministic observations extracted from one program
/// (PROJECT.md S21, M1). Raw material for M2's Observation/Evidence model --
/// this crate does not interpret any of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub program: String,
    pub functions: Vec<FunctionFact>,
    pub strings: Vec<StringFact>,
    pub imports: Vec<ImportFact>,
    pub exports: Vec<ExportFact>,
    pub xrefs: Vec<XrefFact>,
}
