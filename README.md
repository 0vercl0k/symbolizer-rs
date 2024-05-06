<div align='center'>
  <h1><code>symbolizer-rs</code></h1>
  <p>
    <strong>A fast execution trace symbolizer for Windows that runs on all major platforms and doesn't depend on any Microsoft libraries.</strong>
  </p>
  <p>
    <a href="https://crates.io/crates/symbolizer-rs"><img src="https://img.shields.io/crates/v/symbolizer-rs.svg" /></a>
    <img src='https://github.com/0vercl0k/symbolizer-rs/workflows/Builds/badge.svg'/>
  </p>
  <p>
    <img src='https://github.com/0vercl0k/symbolizer-rs/raw/main/pics/symbolizer-rs.webp'/>
  </p>
</div>

## Overview

[symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs) is the successor of [symbolizer](https://github.com/0vercl0k/symbolizer): it is faster, better and runs on all major platforms.

<p align='center'>
<img src='https://github.com/0vercl0k/symbolizer-rs/raw/main/pics/symbolizer-rs-symbolizer.webp'>
</p>

It doesn't depend on [dbgeng](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-api-overview) and download / parse PDB symbols on its own (thanks to the [pdb](https://github.com/getsentry/pdb) crate) unlike [symbolizer](https://github.com/0vercl0k/symbolizer) which was depending on Microsoft's [dbgeng](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-api-overview) for that.

<p align='center'>
<img src='https://github.com/0vercl0k/symbolizer-rs/raw/main/pics/symbolizer-rs-download.webp'>
</p>

[symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs) allows you to transform raw execution traces (`0xfffff8053b9ca5c0`) into symbolized ones (`nt!KiPageFault+0x0`). In order to be able to do this, it needs a kernel crash-dump that contains the lists of user / kernel modules available as well as their PE headers to extract the PDB information necessary to download them off Microsoft or any other symbol server. This tool was made originally to be paired with the [what the fuzz](https://github.com/0vercl0k/wtf) snapshot fuzzer but can be used by any similar tools.

Here is an example of a raw execution trace..:

```text
0xfffff8053b9ca5c0
0xfffff8053b9ca5c1
0xfffff8053b9ca5c8
0xfffff8053b9ca5d0
0xfffff8053b9ca5d4
0xfffff8053b9ca5d8
0xfffff8053b9ca5dc
0xfffff8053b9ca5e0
```

..transformed into a full symbolized trace:

```text
ntoskrnl.exe!KiPageFault+0x0
ntoskrnl.exe!KiPageFault+0x1
ntoskrnl.exe!KiPageFault+0x8
ntoskrnl.exe!KiPageFault+0x10
ntoskrnl.exe!KiPageFault+0x14
ntoskrnl.exe!KiPageFault+0x18
ntoskrnl.exe!KiPageFault+0x1c
ntoskrnl.exe!KiPageFault+0x20
```

Or into a `mod+offset` (*modoff*) trace to load it into [Lighthouse](https://github.com/gaasedelen/lighthouse) for code-coverage exploration:

```text
ntoskrnl.exe+0x1ca5c0
ntoskrnl.exe+0x1ca5c1
ntoskrnl.exe+0x1ca5c8
ntoskrnl.exe+0x1ca5d0
ntoskrnl.exe+0x1ca5d4
ntoskrnl.exe+0x1ca5d8
ntoskrnl.exe+0x1ca5dc
ntoskrnl.exe+0x1ca5e0
ntoskrnl.exe+0x1ca5e4
ntoskrnl.exe+0x1ca5e8
```

## Installation

- `cargo install symbolizer-rs`
- Build it yourself with by cloning the repository with `git clone https://github.com/0vercl0k/symbolizer-rs.git`, and build with `cargo build --release`.
- Prebuilts binaries available in the [Releases](https://github.com/0vercl0k/symbolizer-rs/releases/) section

### Batch mode

The batch mode is designed to symbolize an entire directory filled with execution traces. You can turn on batch mode by simply specifying a directory for the `--trace` command line option and an output directory for the `--output` option.

![Batch mode](https://github.com/0vercl0k/symbolizer-rs/raw/main/pics/batch.webp)

### Single file mode

As opposed to batch mode, you can symbolize a single trace file by specifying a trace file path via the `--trace` command line option.

![Single mode](https://github.com/0vercl0k/symbolizer-rs/raw/main/pics/single.webp)

## Usage

```text
A fast execution trace symbolizer for Windows.

Usage: symbolizer-rs.exe [OPTIONS] --trace <TRACE>

Options:
  -t, --trace <TRACE>
          Directory path full of traces or single input trace file

  -o, --output <OUTPUT>
          Output directory where to write symbolized traces, a path to an output file, or empty for the output to go on stdout

  -c, --crash-dump <CRASH_DUMP>
          Path to the crash-dump to load. If not specified, an attempt is made to find a 'state/mem.dmp' file in the same directory than the trace file

  -s, --skip <SKIP>
          Skip a number of lines

          [default: 0]

  -m, --max <MAX>
          The maximum amount of lines to process per file

          [default: 20000000]

      --style <STYLE>
          The symbolization style (mod+offset or mod!f+offset)

          [default: full]

          Possible values:
          - modoff: Module + offset style like `foo.dll+0x11`
          - full:   Full symbol style like `foo.dll!func+0x11`

      --overwrite
          Overwrite the output files if they exist

      --line-numbers
          Include line numbers in the symbolized output

      --symsrv <SYMSRV>
          Symbol servers to use to download PDBs; you can provide more than one

          [default: https://msdl.microsoft.com/download/symbols/]

      --sympath <SYMPATH>
          Specify a symbol path. If not specified, _NT_SYMBOL_PATH will be parsed if present

      --out-buffer-size <OUT_BUFFER_SIZE>
          The size in bytes of the buffer used to write data into the output files

          [default: 3145728]

      --in-buffer-size <IN_BUFFER_SIZE>
          The size in bytes of the buffer used to read data from the input files

          [default: 1048576]

  -h, --help
          Print help (see a summary with '-h')
```

## Authors

* Axel '[0vercl0k](https://twitter.com/0vercl0k)' Souchet

## Contributors

[ ![contributors-img](https://contrib.rocks/image?repo=0vercl0k/symbolizer-rs) ](https://github.com/0vercl0k/symbolizer-rs/graphs/contributors)
