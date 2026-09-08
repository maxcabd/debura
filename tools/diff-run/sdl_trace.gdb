# Differential-execution SDL call tracer (M19 seed tooling).
#
# Breaks on every SDL/TTF entry point in the "init through frame 1" path
# and logs function name + Windows x64 register/stack arguments (rcx,
# rdx, r8, r9, and the first stack-passed argument at rsp+0x28) to a
# log file, one line per call, without stopping execution. Works
# against ANY exe -- original or recovered -- since it breaks by
# imported-symbol name (resolved against whichever SDL2.dll/SDL2_ttf.dll
# is actually loaded), not against Debura's own recovered symbol names.
#
# Usage:
#   sed 's/TRACEFILE/my_trace.log/' sdl_trace.gdb > /tmp/run.gdb
#   gdb -batch -x /tmp/run.gdb --args ./the.exe
#   (run under a timeout/background job and kill it -- this traces
#   every matched call for the process's entire lifetime, which for a
#   render loop means one line per frame per breakpoint; a few seconds
#   is enough to cover initialization plus several frames)
#
# To compare two traces, align by call sequence (line number) and diff:
#   diff <(grep -v '^\[New Thread\|^No symbol\|^Breakpoint' trace_a.log) \
#        <(grep -v '^\[New Thread\|^No symbol\|^Breakpoint' trace_b.log)
#
# Extend this file with more `break ... / commands ... / end` blocks for
# any other entry point worth tracing (e.g. TTF_RenderText_Solid,
# SDL_CreateTextureFromSurface, SDL_DestroyTexture) -- same pattern.

set pagination off
set breakpoint pending on
set logging file TRACEFILE
set logging enabled on

break SDL_Init
commands
silent
printf "SDL_Init flags=0x%x\n", $rcx
continue
end

break SDL_CreateWindow
commands
silent
printf "SDL_CreateWindow title=%s x=0x%x y=0x%x w=%d\n", (char*)$rcx, (int)$rdx, (int)$r8, (int)$r9
continue
end

break TTF_Init
commands
silent
printf "TTF_Init\n"
continue
end

break TTF_OpenFont
commands
silent
printf "TTF_OpenFont file=%s ptsize=%d\n", (char*)$rcx, (int)$rdx
continue
end

break SDL_CreateRenderer
commands
silent
printf "SDL_CreateRenderer window=0x%llx index=%d flags=0x%x\n", (long long)$rcx, (int)$rdx, (int)$r8
continue
end

break SDL_CreateTexture
commands
silent
printf "SDL_CreateTexture renderer=0x%llx format=%u access=%d w=%d h=%d\n", (long long)$rcx, (unsigned)$rdx, (int)$r8, (int)$r9, *(int*)($rsp+0x28)
continue
end

break SDL_UpdateTexture
commands
silent
printf "SDL_UpdateTexture texture=0x%llx rect=0x%llx pixels=0x%llx pitch=%d\n", (long long)$rcx, (long long)$rdx, (long long)$r8, (int)$r9
continue
end

break SDL_RenderClear
commands
silent
printf "SDL_RenderClear renderer=0x%llx\n", (long long)$rcx
continue
end

break SDL_RenderCopy
commands
silent
printf "SDL_RenderCopy renderer=0x%llx texture=0x%llx srcrect=0x%llx dstrect=0x%llx\n", (long long)$rcx, (long long)$rdx, (long long)$r8, (long long)$r9
continue
end

break SDL_RenderPresent
commands
silent
printf "SDL_RenderPresent renderer=0x%llx\n", (long long)$rcx
continue
end

run
