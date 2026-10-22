# 📖 ropcatalog

`ropcatalog` is a post-extraction x86/x64 ROP gadget finder, semantic search engine, and bounded ROP-chain builder for exploit development. It consumes dumps from [rp++](https://github.com/0vercl0k/rp), [ROPgadget](https://github.com/JonathanSalwan/ROPgadget), and [Ropper](https://github.com/sashs/Ropper), then makes useful gadgets fast to find, compare, and reuse.

This is the semantic post-processing layer for gadget extractors, not another disassembler. `ropcatalog` filters unstable and bad-character addresses, removes duplicate gadgets per module, models side effects, and ranks candidates by exploit context. Use the interactive REPL while building an exploit, concise commands in shell pipelines, or the JSONL interface when a script or AI agent needs exact retrieval and a verifiable chain plan.

Built during an [OffSec](https://www.offsec.com/) journey, primarily for the [EXP-301](https://www.offsec.com/courses/exp-301/) and [EXP-401](https://www.offsec.com/courses/exp-401/) courses focused on Windows exploit development and ROP-chain construction.

## Why ropcatalog

- Query by exact instructions, regex, or exploit intent such as `pivot reg`, `copy rax`, `writeptr rcx`, and `syscall`.
- Keep bad characters, stack effects, memory writes, register clobbers, and control flow visible during selection.
- Format selected addresses for Python, C++, or JavaScript exploit code, including ASLR-relative expressions.
- Parse multiple modules once and save a reusable catalog for low-latency queries.
- Give scripts and agents bounded JSONL output, stable gadget IDs, rejection evidence, and deterministic artifacts.
- Synthesize register setup, arbitrary writes, indirect transitions, and ABI calls with explicit search limits.

`ropcatalog` does not scan binaries. Use your preferred gadget extractor, then pass its text output to `ropcatalog`.

## Try It

Install from GitHub with `uv`:

```shell
uv tool install git+https://github.com/n3rada/ropcatalog.git
```

Or run it once without installing:

```shell
uvx --from git+https://github.com/n3rada/ropcatalog.git ropcatalog --help
```

For a Windows rp++ dump, start the REPL with bad-character filtering and Python output:

```powershell
rp-win.exe -f "C:\target\libeay32IBM019.dll" --va=0 -r 5 > libeay32IBM019.txt
ropcatalog libeay32IBM019.txt -b '\x00\x09\x0a\x0b\x0c\x0d\x20' --offset --style python
```

On Linux, query ROPgadget output directly without an intermediate file:

```shell
ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 | ropcatalog --stdin-module libc.so.6 --address-kind rva --command 'pop rdi'
```

Add `--jsonl` and `--limit` when another process consumes the result:

```shell
ROPgadget --binary ./target | ropcatalog --stdin-module target --address-kind rva --query 'pop rdi ; ret' --jsonl --limit 5 | jq 'select(.status == "ok") | .gadgets[] | {id, address, raw}'
```

Ropper works through the same pipe:

```shell
ropper --file ./target --nocolor | ropcatalog --stdin-module target --address-kind rva --query 'pop rdi ; ret' --jsonl --limit 5
```

## Manual Exploit Development

Pass a file or a directory of extractor output to enter the REPL:

```shell
ropcatalog ./gadgets/ --offset --style python
```

Run `help` in the REPL for the complete command list. Common operations include:

| Goal | Commands | Example |
| --- | --- | --- |
| Exact, partial, or regex search | `?`, `/`, `.` | `? pop rax ; ret` |
| Memory displacement search | `memoff` | `memoff rbx+0x20` |
| Move or preserve a value | `copy`, `copyto`, `save`, `saveto` | `copyto r9` |
| Set or modify a register | `zero`, `neg`, `not`, `inc`, `dec`, `add`, `sub`, `swap` | `neg eax` |
| Read or write memory | `read`, `writereg`, `writeptr`, `writeimm`, `writebyte` | `writeptr rax` |
| Find stack operations | `push`, `pop`, `pushad`, `popad`, `ppr`, `pivot` | `pivot reg` |
| Find control transfers | `ret`, `jump`, `call`, `syscall`, `transition` | `call rax` |

Append `/v` to restrict semantic results to volatile registers. Append `/n` to include candidates rejected by normal stability filtering. Modifiers can appear in either order.

For a single shell-friendly operation, use `--command`:

```shell
ropcatalog target.txt --command 'pivot reg'
ropcatalog target.txt --command 'pop eax' --style python
```

The available output styles are `plain`, `python`, `cpp`, and `js`. With `--offset`, virtual addresses become base-relative expressions suitable for targets with ASLR:

```python
rop += pack("<L", ba__target + 0x10001000) # pop eax ; ret [target]
```

## Scripts And AI Agents

The machine interface is designed to avoid repeatedly loading a large gadget dump into context. Parse once, request only the fields needed for the current decision, and retain stable IDs for follow-up queries or chain changes.

### Batch Queries

`--batch` accepts one UTF-8 request per line. Plain lines are exact gadget queries. JSON objects support exact queries, semantic commands, constraints, fixed plans, synthesis, and stable-ID lookup:

```jsonl
pop rdi ; ret
{"id":"pivot","command":"pivot reg"}
{"id":"arg0","command":"pop rdi","constraints":{"preserve":["rsi","rdx"],"terminator":"ret","max_stack_delta":32,"forbid":["memory_write","unknown"]}}
```

```shell
ropcatalog target.txt --batch requests.jsonl --jsonl --limit 10
```

Each response reports the total match count, bounded results, selected ranking, and rejection counts. Rejected requests include relaxed alternatives when useful. Gadget records can contain source provenance, architecture, address kind, opcode bytes, register assignments, stack/control/memory effects, contextual cost, and copy-paste output.

Use `--fields` to reduce output volume:

```shell
ropcatalog target.ropcatalog --batch requests.jsonl --jsonl --fields id,module,address,raw,semantics
```

### Reusable Catalogs

Save extractor output in `ropcatalog.catalog.v1` format:

```shell
ROPgadget --binary ./target | ropcatalog --stdin-module target --address-kind rva --catalog-out target.ropcatalog
```

Use `--serve` when a long-running process needs many sequential requests. The catalog stays in memory and one flushed JSON response is emitted for each input line:

```shell
ropcatalog target.ropcatalog --serve --fields id,module,address,address_kind,raw,semantics
```

By default, `--jsonl` writes only JSONL to standard output and suppresses routine diagnostics. `--artifact-dir` writes module-named `.ropcatalog.jsonl` files instead of printing results. `--verbose` intentionally restores diagnostic text and cannot be combined with `--artifact-dir`.

```shell
ropcatalog target.txt --batch requests.jsonl --jsonl --artifact-dir artifacts
```

### Chain Synthesis

Use a `synthesize` request when the required result is a chain rather than an individual gadget. Declare register values, memory writes, a direct ABI call, or an indirect transition. Search limits keep work bounded and reproducible.

```jsonl
{"id":"protect","synthesize":{"profile":"windows-x64","call":{"module":"kernel32.dll","address":"0x12340","address_kind":"rva","arguments":["0x41410000","0x1000","0x40","0x41411000"]},"bases":{"kernel32.dll":"0x7ffb12340000"},"scratch":["0x41412000"],"search":{"beam_width":32,"max_depth":8,"max_nodes":5000,"per_effect":16},"emit":["python","pwntools"]}}
```

The result includes:

- ordered gadgets and stable IDs;
- register state before and after each gadget;
- chain words, stack frames, padding, relocations, and ABI stack requirements;
- satisfied postconditions, unresolved assumptions, and target-clobber information;
- cost vectors, rejected candidates, and non-dominated alternatives;
- mitigation issues for CET, CFG, KPTI, SMEP, and SMAP when requested.

Use `{"gadget_id":"<id>"}` to retrieve a previous gadget exactly. Resubmit a synthesis request with selected IDs in `locked` to preserve or replace individual choices without depending on result order.

`verify:"syntactic"` is the dependency-free default. `verify:"bytes"` optionally re-disassembles extractor opcode bytes with Capstone. `verify:"emulate"` optionally executes a fully resolved local chain with bounded Unicorn emulation and validates concrete register postconditions. If bytes, module bases, or concrete values are unavailable, the verification result states that limitation rather than claiming execution.

The synthesizer is conservative. It does not model every instruction or prove that a chain works in the complete target process. Review dynamic stack behavior, unresolved relocations, writable-memory assumptions, and mitigation-specific transitions before using emitted exploit code.

## Filtering And Ranking

Default stability filtering removes candidates that are normally unsuitable inside a chain:

- conditional or uncontrolled control transfers;
- interrupts, traps, halts, and privileged instructions;
- oversized `retn` stack adjustments;
- unmodelled instructions when forbidden by a constraint or by synthesis.

Bad-character filtering applies to each gadget address. Duplicate instruction sequences are removed per module unless `--all` is set. Semantic queries reject candidates that clobber requested values or violate stack, memory, terminator, architecture, or control-flow constraints.

Ranks are deterministic. They prefer shorter gadgets and lower stack, register, memory, control-flow, and uncertainty costs for the current goal. Pareto IDs expose candidates with side-effect tradeoffs that a single scalar rank would hide.

## CLI Reference

```text
ropcatalog [-h] [-b BAD_CHARACTERS] [-a] [-s {plain,python,js,cpp}] [-o]
           [-e ENCODING] [--address-kind {unknown,rva,va}]
           [-c COMMAND | -q QUERY | --batch PATH | --serve] [--jsonl]
           [--limit LIMIT] [--artifact-dir ARTIFACT_DIR]
           [--catalog-out CATALOG_OUT] [--stdin-module NAME]
           [--fields FIELD,...] [--capabilities] [--verbose] [paths ...]
```

| Argument | Description |
| --- | --- |
| `paths` | Extractor dumps, reusable catalogs, or directories. Use `-` for gadget input on standard input. |
| `-b`, `--bad-characters` | Exclude addresses containing specified bytes, for example `\x00\x0a\x0d`. |
| `-a`, `--all` | Disable per-module instruction uniqueness filtering. |
| `-s`, `--style` | Select `plain`, `python`, `js`, or `cpp` output. |
| `-o`, `--offset` | Emit base-relative addresses. Rejected for sources marked as `va`. |
| `-e`, `--encoding` | Force source encoding instead of auto-detection. |
| `--address-kind` | Mark extractor addresses as `unknown`, `rva`, or `va`. |
| `-c`, `--command` | Run one semantic command and exit. |
| `-q`, `--query` | Run one exact query and exit. Repeat for multiple queries. |
| `--batch` | Read plain or JSON requests from a file. Use `-` for request input on standard input. |
| `--serve` | Keep a file-backed catalog loaded and read JSON requests from standard input. |
| `--jsonl` | Emit one JSON response per query, suitable for `jq` and agent pipelines. |
| `--limit` | Bound returned gadgets while retaining total-match metadata. |
| `--artifact-dir` | Write JSONL results to `<module>.ropcatalog.jsonl` rather than standard output. |
| `--catalog-out` | Save a reusable parsed catalog and exit. |
| `--stdin-module` | Name an extractor source read from standard input. |
| `--fields` | Select fields in JSONL responses. |
| `--capabilities` | Print the complete machine-readable interface contract. |
| `--verbose` | Keep routine diagnostics in machine-readable modes. |

Input/output arguments that compete for standard input or produce incompatible output are rejected by `argparse`. In particular, standard input cannot carry both a gadget stream and `--batch -`, and `--catalog-out`, `--artifact-dir`, interactive mode, and `--serve` have separate output contracts.

## Development

```shell
uv run pytest
```

## License And Authorized Use

GPL-3.0-only. Use `ropcatalog` against binaries and systems you own or are authorized to assess, including private labs, CTFs, OffSec exam environments, and documented security engagements.
