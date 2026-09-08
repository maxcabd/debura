# diff-run: differential execution tooling (M19 seed)

Ad-hoc gdb scripts used to compare an original binary against a Debura
recovered rebuild at runtime, checkpoint by checkpoint, to find the
*first* point of divergence rather than chasing the eventual crash
site. Written during the Snake M19 investigation (see PROJECT.md's M19
section for the full writeup and findings). Not yet a real `debura
diff-run` command -- these are the seed for building that.

## What's here

- `sdl_trace.gdb` -- breaks on every SDL/TTF entry point up through
  frame 1, logs function name + arguments (Windows x64 calling
  convention: rcx/rdx/r8/r9 + first stack arg) to a file, keeps running.
  Works against any exe (breaks by imported symbol name, not by
  Debura's recovered names), so the same script runs unmodified against
  both the original and the recovered binary.
- `dump_pixel_buffer.gdb` -- dumps the raw pixel buffer at the first
  `SDL_UpdateTexture` call to a binary file, for byte-level comparison
  via `cmp -l`.

## Exact commands used against Snake

Both binaries need `SDL2.dll`, `SDL2_ttf.dll`, and `Roboto-Regular.ttf`
alongside them (relative-path font load). The original ground-truth
binary lives at
`<debura-home>/projects/<project-id>/binary/snake_stripped.exe`; the
recovered one is built from
`<debura-home>/projects/<project-id>/recovered/{src,include}` (see
PROJECT.md's M18.3 notes for the build recipe -- MinGW g++, `-g -O0
-fpermissive`, linked against the SDL2/SDL2_ttf dev libs and
`-lmingw32 -lSDL2main -lSDL2 -lSDL2_ttf`).

```sh
# 1. Sanity check: does the original ever crash in this environment at all?
./snake_original.exe   # exit code 0 or keeps running; never segfaults

# 2. SDL call trace, one run per binary, same script:
sed 's/TRACEFILE/trace_original.log/'  sdl_trace.gdb > /tmp/trace_orig.gdb
sed 's/TRACEFILE/trace_recovered.log/' sdl_trace.gdb > /tmp/trace_rec.gdb
gdb -batch -x /tmp/trace_orig.gdb --args ./snake_original.exe &
sleep 8; kill -9 %1
gdb -batch -x /tmp/trace_rec.gdb --args ./snake_recovered.exe &
sleep 8; kill -9 %1

# align by call sequence and diff, ignoring gdb's own noise lines:
diff <(grep -v '^\[New Thread\|^No symbol\|^Breakpoint' trace_original.log) \
     <(grep -v '^\[New Thread\|^No symbol\|^Breakpoint' trace_recovered.log)

# 3. Pixel buffer diff at frame 1:
sed 's/OUTFILE/pixbuf_original.bin/'  dump_pixel_buffer.gdb > /tmp/dump_orig.gdb
sed 's/OUTFILE/pixbuf_recovered.bin/' dump_pixel_buffer.gdb > /tmp/dump_rec.gdb
gdb -batch -x /tmp/dump_orig.gdb --args ./snake_original.exe
gdb -batch -x /tmp/dump_rec.gdb  --args ./snake_recovered.exe
cmp -l pixbuf_original.bin pixbuf_recovered.bin | wc -l   # differing byte count
cmp -l pixbuf_original.bin pixbuf_recovered.bin | head    # first diffs

# 4. Stack alignment at a specific call site (Windows x64 ABI: rsp%16
#    must be 8 at function entry, since `call` just pushed an 8-byte
#    return address onto a 16-aligned stack):
gdb -batch -ex "set breakpoint pending on" -ex "break SDL_RenderPresent" \
    -ex run -ex "print/x ((long long)\$rsp) % 16" --args ./the.exe

# 5. Imported-DLL comparison (toolchain/CRT-split parity):
objdump -p snake_original.exe  | grep -A2 "DLL Name"
objdump -p snake_recovered.exe | grep -A2 "DLL Name"

# 6. Force a specific SDL render backend (isolates GPU/driver-specific
#    behavior from everything else):
SDL_RENDER_DRIVER=software ./the.exe
# confirm it actually took effect (don't trust the env var alone):
gdb -batch -ex "break Class_1400096e0.cpp:49" -ex run \
    -ex "print (int)SDL_GetRendererInfo((void*)lVar3, (void*)(\$rsp-512))" \
    -ex "print (char*)*(long long*)(\$rsp-512)" --args ./the.exe
# ($rsp-512 as scratch space for the output struct works because
#  SDL_RendererInfo's first field is `const char *name`, and the
#  breakpoint is stopped with nothing live below the current frame)
```

## What this found on Snake

See PROJECT.md's M19 section for the full narrative. Summary: the SDL
call trace caught a real missing call (`Screen::drawText`'s recovered
equivalent had been neutered to a no-op) within the first few lines of
output -- the original calls `SDL_RenderCopy` twice per frame, the
recovered build only once. After restoring it to match the real
original source exactly, frame-1 parity became complete across every
layer these scripts can check (call sequence, arguments, pixel buffer
content modulo RNG-driven food placement, stack alignment, DLL
imports) -- but a deterministic crash on the first `SDL_RenderPresent`
call remained. The failure is real and still unresolved; it lies below
what this generation of tooling can observe.

## What's still missing (next session should build this, not redo it by hand)

- A real comparison harness instead of manual `sed`/`diff` -- something
  that runs both binaries, aligns their traces automatically, and
  reports the first differing event with both sides' full context.
- Register/stack snapshots at matched call sites (not just arguments),
  diffed the same way.
- A path to see *inside* a shared system DLL's own call graph (SDL2.dll
  itself is identical for both processes here, so a real divergence
  that only manifests inside it implies something about process/thread
  state SDL reads internally -- TLS, heap state, etc. -- not the DLL's
  code). This needs either a stack-corruption detector (a real
  Application Verifier / page-heap run, which requires admin elevation
  we didn't have this session) or a way to snapshot/diff broader
  process state (all threads' stacks, TEB/PEB-adjacent data) at the
  matched checkpoint.
- Eventually: `debura diff-run original.exe recovered.exe` as a real
  CLI command, backed by `CallTrace{function, arguments, return_value}`
  and `StateSnapshot{checkpoint, registers, memory ranges, globals}`
  structures, so this stops being bespoke gdb scripts per investigation.
