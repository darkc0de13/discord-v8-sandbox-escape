# Discord Desktop V8 sandbox escape PoC

Proof-of-concept exploit chain for Discord Desktop on Windows (Electron /
V8), demonstrating an escape from the V8 sandbox in the renderer process.

## Affected versions

Confirmed working on Electron **42.11.1** (Discord Desktop 1.0.9257 /
1.0.9258, V8 14.8.178.38). On Electron 42.11.4 (1.0.9259) the initial
compiler bug no longer trains to the exploitable state, consistent with a
mitigation shipped in that patch release.

## Chain

1. **Turboshaft load-elimination miscompile** (bug class of
   crbug 554421904): a trained calling pattern makes the optimizer drop a
   store it must keep, yielding a corrupted JSArray and with it arbitrary
   read/write inside the V8 pointer-compression cage.
2. **Self-locating heap anchors**: a 128 MB marker whose slots encode
   their own addresses lets the payload find itself in the cage without
   any address leak; scan cursors persisted in sessionStorage survive
   renderer crashes.
3. **SFI/Script corruption** (bug class of crbug 554034656): three
   in-cage writes replace the Script source, point the wrapped-arguments
   slot at a 65,536-entry parameter-name list and set the SFI function
   kind to kWrapped. The lazy wrapped re-parse then stores 65,537
   parameters (65,536 names plus the receiver) into a 16-bit counter,
   which wraps to 1: the interpreter builds a frame for a one-parameter
   function while the compiled body still addresses parameters by their
   full index, and the Star bytecode writes a controlled tagged value to
   fp + 24 + 8*j for any j up to 65,535 - the native interpreter
   register file, outside the sandbox. Demonstrated as
   `fired:RET 65536,...,65550,2833485` (sixteen caller locals, fifteen
   intact, one reading the planted value).

The chain is fully natives-free (no `--allow-natives-syntax`, no V8 flags,
natural tier-up only) and runs as one autonomous payload injected at
document-start: from process launch to the out-of-cage write in ~97
seconds, deterministic and reproducible across runs.

## Files

- `payload.js` - the in-page payload (anchors, LLE machine, read/write
  primitives, corruption transport, spill stage).
- `exploit.js` - Node.js driver: launches the target with a CDP debugging
  port, injects the payload at document-start, advances the crash-resume
  scan cursor between reloads and reports stage-by-stage telemetry.

## Usage

```
node exploit.js [minutes=12] [cdp_port=9222]
```

Requires Windows x64, Node >= 18 and a Discord Desktop install in the
affected version range. The driver recycles renderer crashes (they are
part of the scan strategy), so expect the target window to reload several
times; the result string appears in the driver log.

## What separates this from code execution

Two things separate the demonstrated primitive from code execution:

- Value width. The written value is a tagged Smi: 32 controlled bits in
  the low half, zeros in the high half. A native 64-bit pointer does not
  fit in a single write. Both ways around it are mechanically available
  to the same primitive: it can write several parameters in one call, so
  adjacent serial writes compose a full 64-bit value, and it can read
  stack slots back, so a heap pointer already sitting on the stack can
  be located and reused.
- The return-address zone. Parameter indices 1-16 land on JS-observable
  caller locals (the demo zone); 18-20 hit frame metadata and crash on
  resume; 22 and beyond reach the saved frame pointer and the return
  address. This last zone was never exercised in the live client. The
  window map comes from a reference build, where index 65535 writes at
  fp + 0x80010, past the thread's 1 MB stack reservation, crashing
  inside the Star bytecode handler itself.

Given a chosen-offset repeatable write over the return-address zone plus
the stack read-back, what remains before control-flow hijack is
straightforward exploit engineering.

## Notes

- The demonstration stops at a JS-observable controlled write to a caller
  frame local on the native stack; no control-flow hijack stage is
  included.
- The renderer runs with `--no-sandbox --no-zygote`, so the V8 sandbox
  was the last memory-isolation boundary in the process at the time.
