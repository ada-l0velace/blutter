# B(l)utter
Flutter Mobile Application Reverse Engineering Tool by Compiling Dart AOT Runtime

Currently the application supports only Android libapp.so (arm64 only).
Also the application is currently work only against recent Dart versions.

For high priority missing features, see [TODO](#todo)


## Environment Setup
This application uses C++20 Formatting library. It requires very recent C++ compiler such as g++>=13, Clang>=16.

I recommend using Linux OS (only tested on Deiban sid/trixie) because it is easy to setup.

### Debian Unstable (gcc 13)
**_NOTE:_**
Use ONLY Debian/Ubuntu version that provides gcc>=13 from its own main repository.
Using ported gcc to old Debian/Ubuntu version does not work.

- Install build tools and depenencies
```
apt install python3-pyelftools python3-requests git cmake ninja-build \
    build-essential pkg-config libicu-dev libcapstone-dev
```

### Windows
- Install git and python 3
- Install latest Visual Studio with "Desktop development with C++" and "C++ CMake tools"
- Install required libraries (libcapstone and libicu4c)
```
python scripts\init_env_win.py
```
- Start "x64 Native Tools Command Prompt"

### macOS Sequoia
- Install XCode
- Install required tools
```
brew install cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests
```

### macOS Ventura and Sonoma (clang 16)
- Install XCode
- Install clang 16 and required tools
```
brew install llvm@16 cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests
```

## Usage
Extract "lib" directory from apk file
```
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```
The blutter.py will automatically detect the Dart version from the flutter engine and call executable of blutter to get the information from libapp.so.

If the blutter executable for required Dart version does not exists, the script will automatically checkout Dart source code and compiling it.

## Update
You can use ```git pull``` to update and run blutter.py with ```--rebuild``` option to force rebuild the executable
```
python3 blutter.py path/to/app/lib/arm64-v8a out_dir --rebuild
```

## Output files
- **asm/\*** libapp assemblies with symbols
- **blutter_frida.js** the frida script template for the target application
- **objs.txt** complete (nested) dump of Object from Object Pool
- **pp.txt** all Dart objects in Object Pool

On supported instructions-table snapshots, **asm/snapshot_code.asm** contains
the complete native payload inventory and **snapshot_calls.json** records calls,
jumps, and pool/thread references. Format 2 adds:

- `via_kind: "pool_code_entry"`: a pool load followed by an entry-field load
  from a typed Code object. `via_field_offset` identifies the tagged-pointer
  displacement; `snapshot_target` is the ELF VA from matched SDK metadata.
  `target` stays null because runtime patching has not been ruled out.
- `via_kind: "dispatch_table"`: an indexed load from the matched ARM64 dispatch
  register. `index_register` names the index at the load, scaled by eight;
  `via_offset` is the byte displacement. The callee remains unresolved.
- `register_constants`: known physical X-register bit patterns immediately
  before a call. `bits` is a hexadecimal string, including zero extension from
  W writes. `proof` lists producer instruction VAs. These observations do not
  establish argument counts, types, liveness, or stack arguments.

Facts stop at calls, branches, returns, and known incoming targets. Unknown
writes discard affected values, and constant proofs have a 64-producer bound.
Missing facts mean unknown, not absence of an argument or call.

Format 3 additionally exports `dispatch_table`, with the SDK's register bias,
normalized entries, null-error target, and original compressed stream location.
Dispatch edges contain a `dispatch` record: known signed index, physical table
index, resolution status, or an unresolved bitfield-plus-offset expression.
Arithmetic uses ARM64 register widths; facts are captured at the table load.
Known indices produce a `snapshot_target`, including explicit null-error entries.
The runtime may patch the table, so the ordinary indirect `target` stays null.

An extracted class-ID bitfield does not establish the receiver's class. Selector
rows can overlap in Dart's compressed table. Unknown indices remain unresolved;
the exporter does not enumerate an entire row as possible callees. A captured
index or extracted value can be queried explicitly:

```
python3 scripts/query_dispatch.py out_dir/snapshot_calls.json --site 0x1000 --index=-4
python3 scripts/query_dispatch.py out_dir/snapshot_calls.json --site 0x1000 --extracted-value 42
```

These are illustrative addresses/values. The query reports that supplied values
are observations from the caller; it does not modify the graph or validate them.

Focused validation requires a C++20 compiler, Capstone, and LLVM's `llvm-mc`:

```
python3 tests/runners/run_snapshot_annotations.py
python3 tests/runners/run_snapshot_annotations.py --memcheck
python3 scripts/check_snapshot_annotations.py path/to/libapp.so out_dir --log reader.log --vm-audit vm-audit.json
```

The first command uses ASan/UBSan (and leak checking on Linux); the second uses
ordinary binaries under Valgrind. The checker validates emitted facts against
original ELF instructions and separate exports. It does not independently prove
SDK layouts or runtime behavior.
For dispatch stream checks, collect `vm-audit.json` by setting
`BLUTTER_COVERAGE_AUDIT=vm-audit.json` when running the native reader. The checker
decodes the original root-unit stream and compares every entry; retained Code
entry points are cross-checked through the separate VM numerical audit. Deferred
unit dispatch updates are not validated by this checker.

Format 4 adds `static_dispatch`, a separate bounded analysis of the known normal
control flow. It propagates snapshot pool-object classes, typed allocation-stub
results, class-ID extraction, constants and register copies. Equality guards can
refine a class-ID value; a merge keeps a fact only when every incoming path
supports it. W comparisons do not invent the upper bits of an unknown X value.
Unknown calls discard register facts, while metadata-identified allocation calls
define their ABI result class. Unknown memory writes invalidate object/header
facts. Stack slots, implicit exception entries and interprocedural parameter
types are not analyzed. Payloads with unknown indirect jumps are skipped.

`receiver_metadata` exports the typed inputs and known entries.
`receiver_certificates` records block-entry invariants for payloads with a
resolution. The checker independently checks each incoming edge and original
instruction against those invariants; it does not repeat the native worklist
solver. Fact tuples are `[register, kind, value_hex, auxiliary_hex, origin_hex]`.
Kinds are 0 unknown, 1 exact word, 2 unsigned upper bound, 3 heap-object class,
4 header class bits, 5 pool address, 6 dispatch address, and 7 loaded dispatch
target, and 8 managed-stack address. The latter tracks ABI SP/FP aliases and
bounded frame offsets for store checks, without recovering stack-slot values.
Register numbers denote X registers. Certificates are normal-flow facts
under the matched ABI and snapshot metadata, not proofs about runtime patching.

The pass is limited to 16,384 instructions, 1,024 blocks, 1,000,000 transfer
steps per payload, and 128 supporting instruction addresses per fact. A limit
or unsupported indirect jump yields no new receiver resolution. No observations
from runtime traces are used as static inputs. Pool classes and allocation
contracts are cross-checked through separate VM audit fields.


## Directories
- **bin** contains blutter executables for each Dart version in "blutter_dartvm\<ver\>\_\<os\>\_\<arch\>" format
- **blutter** contains source code. need building against Dart VM library
- **build** contains building projects which can be deleted after finishing the build process
- **dartsdk** contains checkout of Dart Runtime which can be deleted after finishing the build process
- **external** contains 3rd party libraries for Windows only
- **packages** contains the static libraries of Dart Runtime
- **scripts** contains python scripts for getting/building Dart


## Generating Visual Studio Solution for Development
I use Visual Studio to delevlop Blutter on Windows. ```--vs-sln``` options can be used to generate a Visual Studio solution.
```
python blutter.py path\to\lib\arm64-v8a build\vs --vs-sln
```

## TODO
- More code analysis
  - Function arguments and return type
  - Some psuedo code for code pattern
- Generate better Frida script
  - More internal classes
  - Object modification
- Obfuscated app (still missing many functions)
- Reading iOS binary
- Input as apk or ipa
