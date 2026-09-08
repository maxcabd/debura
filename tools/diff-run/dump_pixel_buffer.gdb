# Dumps the raw pixel buffer passed to the first SDL_UpdateTexture call
# to a binary file, for byte-level comparison between an original and a
# recovered binary (M19 seed tooling).
#
# Assumes an 800x600, 4-bytes-per-pixel buffer (0x1d4c00 bytes) -- the
# Snake fixture's own dimensions. Adjust the size literal for a
# different binary/resolution.
#
# Usage:
#   sed 's/OUTFILE/pixbuf_a.bin/' dump_pixel_buffer.gdb > /tmp/dump.gdb
#   gdb -batch -x /tmp/dump.gdb --args ./the.exe
#
# Compare two dumps:
#   cmp -l pixbuf_a.bin pixbuf_b.bin | wc -l   # differing byte count
#   cmp -l pixbuf_a.bin pixbuf_b.bin | head    # first differing bytes
#
# A handful of small, non-adjacent differing regions is expected from
# any RNG-seeded game state (e.g. food/enemy placement) and is not
# itself evidence of a recovery bug -- compare the differing byte COUNT
# and LOCATIONS against what the game's own randomized elements would
# plausibly account for before concluding the buffers genuinely match.

set breakpoint pending on
break SDL_UpdateTexture
run
dump binary memory OUTFILE $r8 ($r8+0x1d4c00)
