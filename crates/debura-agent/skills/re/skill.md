# Reverse Engineering Skill

Binary analysis and reverse engineering via MCP servers for Ghidra, IDA Pro, radare2, and angr.

## Trigger Conditions

- User asks to analyze binaries, disassemble code, decompile functions
- Questions about malware analysis, vulnerability research, CTF challenges
- Binary diffing, patch analysis, firmware extraction
- Symbol recovery, function identification, control flow analysis

## MCP Servers

### 1. GhidrAssistMCP (Ghidra - Free)
**Repository**: https://github.com/jtang613/GhidrAssistMCP
**Transport**: HTTP/SSE on port 8080

**Installation**:
```bash
# Download from releases page
# In Ghidra: File → Install Extensions → Add Extension
# Enable: File → Configure → Configure Plugins → GhidrAssistMCP
```

**31 Built-in Tools**:
| Category | Tools |
|----------|-------|
| Program Analysis | `get_program_info`, `list_functions`, `list_data`, `list_strings`, `list_imports`, `list_exports`, `list_segments` |
| Function Analysis | `get_function_info`, `decompile_function`, `disassemble_function`, `function_xrefs`, `search_functions` |
| Navigation | `get_current_address`, `xrefs_to`, `xrefs_from`, `get_current_function` |
| Modification | `rename_function`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`, `set_disassembly_comment` |
| Advanced | `auto_create_struct` |

### 2. LaurieWired/GhidraMCP (Popular Alternative)
**Repository**: https://github.com/LaurieWired/GhidraMCP
**Transport**: Python bridge to Ghidra

### 3. IDA Pro MCP Servers

**mrexodia/ida-pro-mcp** (Most active):
```bash
git clone https://github.com/mrexodia/ida-pro-mcp
cd ida-pro-mcp
pip install -e .
```

**MxIris-Reverse-Engineering/ida-mcp-server**:
```bash
git clone https://github.com/MxIris-Reverse-Engineering/ida-mcp-server
```

**fdrechsler/mcp-server-idapro**:
```bash
git clone https://github.com/fdrechsler/mcp-server-idapro
```

### 4. radare2-mcp (Official)
**Repository**: https://github.com/radareorg/radare2-mcp
**Transport**: stdio

```bash
# Install radare2 first
brew install radare2  # macOS
# or: apt install radare2  # Linux

git clone https://github.com/radareorg/radare2-mcp
cd radare2-mcp
pip install -e .
```

**MCP Config**:
```json
{
  "mcpServers": {
    "radare2": {
      "command": "r2-mcp",
      "args": []
    }
  }
}
```

### 5. rand-tech/pcm (Multi-tool)
**Repository**: https://github.com/rand-tech/pcm
MCP for reverse engineering combining multiple backends.

## Workflows

### Basic Binary Analysis
```
1. Load binary into Ghidra/IDA
2. Start MCP server
3. Query: "List all functions" → list_functions
4. Query: "Decompile main" → decompile_function
5. Query: "Find xrefs to this address" → xrefs_to
```

### Malware Analysis Pattern
```
1. get_program_info → Architecture, compiler, entry point
2. list_imports → Suspicious API calls (CreateRemoteThread, VirtualAlloc)
3. list_strings → C2 URLs, encryption keys, debug strings
4. search_functions "crypt" → Find encryption routines
5. decompile_function → Understand algorithm
6. auto_create_struct → Recover data structures
```

### Vulnerability Research
```
1. list_functions → Function list with sizes
2. search_functions "parse|read|copy" → Input handlers
3. decompile_function → Find buffer operations
4. xrefs_to → Trace data flow
5. set_decompiler_comment → Annotate findings
```

### CTF Binary Exploitation
```
1. get_program_info → Check protections (PIE, RELRO, canary)
2. list_functions → Find win/flag functions
3. decompile_function → Understand vulnerability
4. xrefs_from → Control flow analysis
5. list_segments → Memory layout for ROP
```

## CLI Quick Reference

### radare2 Commands
```bash
r2 binary                    # Open binary
aaa                          # Analyze all
afl                          # List functions
pdf @ main                   # Disassemble function
pdc @ main                   # Decompile (r2ghidra)
axt @ addr                   # Xrefs to
axf @ addr                   # Xrefs from
iz                           # List strings
ii                           # List imports
```

### Ghidra Headless
```bash
analyzeHeadless /tmp/project ProjectName \
  -import binary.exe \
  -postScript ExportDecompilation.java \
  -deleteProject
```

## Resources

- [Awesome Reverse Engineering](https://github.com/wtsxDev/reverse-engineering)
- [CTF Wiki - Reverse](https://ctf-wiki.org/reverse/)
- [Ghidra Scripting](https://ghidra.re/ghidra_docs/api/)
- [radare2 Book](https://book.rada.re/)

## Note on Debura's own agent

Debura's `AgentProvider` does not talk to any of the MCP servers above --
it drives Ghidra directly through headless Jython scripts
(`debura-ghidra`'s `analyze`/`reextract`) and reasons over the resulting
facts through a plain HTTP call to the model provider
(`debura-agent::openai`). This file is reference material on the wider
RE-tooling ecosystem, not a description of how Debura itself is wired.
