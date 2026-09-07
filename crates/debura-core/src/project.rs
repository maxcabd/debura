use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::config::projects_dir;

/// Executable container format, detected from the binary's own header.
///
/// This is a deterministic observation (§21 of PROJECT.md) — it costs
/// nothing to compute and should never be guessed by a model.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Unknown,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinaryFormat::Pe => "PE",
            BinaryFormat::Elf => "ELF",
            BinaryFormat::MachO => "Mach-O",
            BinaryFormat::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// The persisted contents of a project's `state.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectState {
    pub id: String,
    pub binary_name: String,
    pub format: BinaryFormat,
    pub architecture: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A freshly created or reopened Debura project.
pub struct Project {
    pub id: Ulid,
    pub root: PathBuf,
    pub binary_name: String,
    pub format: BinaryFormat,
    pub architecture: String,
}

impl Project {
    /// Creates a new isolated project workspace for `binary_path` under
    /// `~/.debura/projects/<id>/` (see PROJECT.md §18) and initializes its
    /// `project.sqlite`.
    pub fn create(binary_path: &Path) -> anyhow::Result<Project> {
        anyhow::ensure!(
            binary_path.is_file(),
            "binary not found: {}",
            binary_path.display()
        );

        let bytes = fs::read(binary_path)?;
        let (format, architecture) = sniff(&bytes);

        let id = Ulid::new();
        let root = projects_dir().join(id.to_string());

        let binary_dir = root.join("binary");
        fs::create_dir_all(&binary_dir)?;
        fs::create_dir_all(root.join("ghidra/project"))?;
        fs::create_dir_all(root.join("artifacts/decomp"))?;
        fs::create_dir_all(root.join("artifacts/disassembly"))?;
        fs::create_dir_all(root.join("artifacts/cfg"))?;
        fs::create_dir_all(root.join("artifacts/traces"))?;
        fs::create_dir_all(root.join("summaries/subsystems"))?;
        fs::create_dir_all(root.join("recovered/include"))?;
        fs::create_dir_all(root.join("recovered/src"))?;

        let binary_name = binary_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "binary".to_string());

        fs::copy(binary_path, binary_dir.join(&binary_name))?;

        let state = ProjectState {
            id: id.to_string(),
            binary_name: binary_name.clone(),
            format,
            architecture: architecture.clone(),
            created_at: chrono::Utc::now(),
        };
        fs::write(
            root.join("state.json"),
            serde_json::to_string_pretty(&state)?,
        )?;

        debura_storage::init_project_db(&root.join("project.sqlite"))?;

        tracing::info!(project_id = %id, %binary_name, %format, %architecture, "created project");

        Ok(Project {
            id,
            root,
            binary_name,
            format,
            architecture,
        })
    }
}

fn sniff(bytes: &[u8]) -> (BinaryFormat, String) {
    match goblin::Object::parse(bytes) {
        Ok(goblin::Object::PE(pe)) => {
            let arch = match pe.header.coff_header.machine {
                0x8664 => "x86-64",
                0x14c => "x86",
                0xaa64 => "arm64",
                _ => "unknown",
            };
            (BinaryFormat::Pe, arch.to_string())
        }
        Ok(goblin::Object::Elf(elf)) => {
            let arch = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => "x86-64",
                goblin::elf::header::EM_386 => "x86",
                goblin::elf::header::EM_AARCH64 => "arm64",
                _ => "unknown",
            };
            (BinaryFormat::Elf, arch.to_string())
        }
        Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) => {
            let arch = match macho.header.cputype {
                goblin::mach::cputype::CPU_TYPE_X86_64 => "x86-64",
                goblin::mach::cputype::CPU_TYPE_ARM64 => "arm64",
                _ => "unknown",
            };
            (BinaryFormat::MachO, arch.to_string())
        }
        _ => (BinaryFormat::Unknown, "unknown".to_string()),
    }
}
