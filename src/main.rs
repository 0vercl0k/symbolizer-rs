// Axel '0vercl0k' Souchet - February 19 2024
#![doc = include_str!("../README.md")]
use std::fs::File;
use std::io::{stdout, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use kdmp_parser::KernelDumpParser;
use symbolizer_rs::{HexAddressesIterator, Symbolizer};

/// Parse the `_NT_SYMBOL_PATH` environment variable to try the path of a symbol
/// cache.
fn sympath() -> Option<PathBuf> {
    let env = env::var("_NT_SYMBOL_PATH").ok()?;

    if !env.starts_with("srv*") {
        return None;
    }

    let sympath = env.strip_prefix("srv*").unwrap();
    let sympath = PathBuf::from(sympath.split('*').next().unwrap());

    if sympath.is_dir() {
        Some(sympath)
    } else {
        None
    }
}

/// The style of the symbols.
#[derive(Default, Debug, Clone, ValueEnum)]
enum SymbolStyle {
    /// Module + offset style like `foo.dll+0x11`.
    Modoff,
    /// Full symbol style like `foo.dll!func+0x11`.
    #[default]
    Full,
}

/// The command line arguments.
#[derive(Debug, Default, Parser)]
#[command(about = "A fast execution trace symbolizer for Windows.")]
struct CliArgs {
    /// Directory path full of traces or single input trace file.
    #[arg(short, long)]
    trace: PathBuf,
    /// Output directory where to write symbolized traces, a path to an output
    /// file, or empty for the output to go on stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Path to the crash-dump to load. If not specified, an attempt is made to
    /// find a 'state/mem.dmp' file in the same directory than the trace file.
    #[arg(short, long)]
    crash_dump: Option<PathBuf>,
    /// Skip a number of lines.
    #[arg(short, long, default_value_t = 0)]
    skip: usize,
    /// The maximum amount of lines to process per file.
    #[arg(short, long, default_value = "20000000")]
    max: Option<usize>,
    /// The symbolization style (mod+offset or mod!f+offset).
    #[arg(long, default_value = "full")]
    style: SymbolStyle,
    /// Overwrite the output files if they exist.
    #[arg(long, default_value_t = false)]
    overwrite: bool,
    /// Include line numbers in the symbolized output.
    #[arg(long, default_value_t = false)]
    line_numbers: bool,
    /// Symbol servers to use to download PDBs; you can provide more than one.
    #[arg(long, default_value = "https://msdl.microsoft.com/download/symbols/", action = ArgAction::Append)]
    symsrv: Vec<String>,
    /// Specify a symbol cache path. If not specified, _NT_SYMBOL_PATH will be
    /// parsed if present.
    #[arg(long)]
    symcache: Option<PathBuf>,
    /// The size in bytes of the buffer used to write data into the output
    /// files.
    #[arg(long, default_value_t = 3 * 1024 * 1024)]
    out_buffer_size: usize,
    /// The size in bytes of the buffer used to read data from the input files.
    #[arg(long, default_value_t = 1024 * 1024)]
    in_buffer_size: usize,
}

/// Create the output file from an input.
///
/// This logic was moved into a function to be able to handle the `--overwrite`
/// logic and to handle the case when `output` is a directory path and not a
/// file path. In that case, we will create a file with the same input file
/// name, but with a specific suffix.
fn get_output_file(args: &CliArgs, input: &Path, output: &Path) -> Result<File> {
    let output_path = if output.is_dir() {
        // If the output is a directory, then we'll create a file that has the same file
        // name as the input, but with a suffix.
        let path = input.with_extension("symbolized.txt");
        let filename = path.file_name().ok_or_else(|| anyhow!("no file name"))?;

        output.join(filename)
    } else {
        // If the output path is already a file path, then we'll use it as is.
        output.into()
    };

    // If the output exists, we'll want the user to tell us to overwrite those
    // files.
    if output_path.exists() && !args.overwrite {
        // If they don't we will bail.
        bail!(
            "{} already exists, run with --overwrite",
            output_path.display()
        );
    }

    // We can now create the output file!
    File::create(output_path.clone())
        .with_context(|| format!("failed to create output file {output_path:?}"))
}

/// Process an input file and symbolize every line.
fn symbolize_file(
    symbolizer: &mut Symbolizer,
    trace_path: impl AsRef<Path>,
    args: &CliArgs,
) -> Result<usize> {
    let trace_path = trace_path.as_ref();
    let input = File::open(trace_path)
        .with_context(|| format!("failed to open {}", trace_path.display()))?;

    let writer: Box<dyn Write> = match &args.output {
        Some(output) => Box::new(get_output_file(args, trace_path, output)?),
        None => Box::new(stdout()),
    };

    let mut output = BufWriter::with_capacity(args.out_buffer_size, writer);
    let mut line_number = 1 + args.skip;
    let mut lines_symbolized = 1;
    let max_line = args.max.unwrap_or(usize::MAX);
    let reader = BufReader::with_capacity(args.in_buffer_size, input);
    for addr in HexAddressesIterator::new(reader).skip(args.skip) {
        let addr = addr.with_context(|| {
            format!(
                "failed to get hex addr from l{line_number} of {}",
                trace_path.display()
            )
        })?;

        if args.line_numbers {
            let mut buffer = itoa::Buffer::new();
            output.write_all(&[b'l'])?;
            output.write_all(buffer.format(line_number).as_bytes())?;
            output.write_all(&[b':', b' '])?;
        }

        match args.style {
            SymbolStyle::Modoff => symbolizer.modoff(&mut output, addr),
            SymbolStyle::Full => symbolizer.full(&mut output, addr),
        }
        .with_context(|| {
            format!(
                "failed to symbolize l{line_number} of {}",
                trace_path.display()
            )
        })?;

        if lines_symbolized >= max_line {
            println!(
                "Hit maximum line limit {} for {}",
                max_line,
                trace_path.display()
            );
            break;
        }

        lines_symbolized += 1;
        line_number += 1;
    }

    // symbolizer.stats.done_file(lines_symbolized.try_into()?);

    Ok(lines_symbolized)
}

fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    env_logger::init();

    // Parse the CLI arguments.
    let args = CliArgs::parse();

    // Figure out the path to the crash-dump we will use. We will use the one
    // specified by the user, or we will try to find one ourselves.
    let crash_dump_path = if let Some(dump_path) = &args.crash_dump {
        dump_path.clone()
    } else {
        let wtf_base_path = args.trace.parent().expect("parent");
        let wtf_crash_dump_path = wtf_base_path.join("state").join("mem.dmp");
        if !wtf_crash_dump_path.is_file() {
            bail!("A dump file wasn't specified, and a wtf state directory wasn't found either in {wtf_base_path:?}. Please use --crash-dump.");
        }

        println!(
            "A dump file wasn't specified, but found {} so using it..",
            wtf_crash_dump_path.display()
        );

        wtf_crash_dump_path
    };

    // We need to parse the crash-dump to figure out where drivers / user-modules
    // are loaded at, and to read enough information out of the PE to download PDB
    // files ourselves.
    let parser = KernelDumpParser::new(&crash_dump_path).context("failed to create dump parser")?;

    // Figure out what is the symbol path we should be using. We will use the one
    // specified by the user, or will try to find one in the `_NT_SYMBOL_PATH`
    // environment variable if it is defined.
    let Some(symcache) = (match args.symcache.clone() {
        Some(symcache) => Some(symcache),
        None => sympath(),
    }) else {
        bail!("no sympath");
    };

    // All right, ready to create the symbolizer.
    let mut symbolizer = Symbolizer::new(symcache, parser, args.symsrv.clone())?;

    symbolizer.start_stopwatch();
    let paths = if args.trace.is_dir() {
        // If we received a path to a directory as input, then we will try to symbolize
        // every file inside that directory..
        let entries = fs::read_dir(&args.trace)?;

        entries
            .map(|e| e.map(|e| e.path()).context(""))
            .collect::<Result<Vec<_>>>()?
    } else {
        // .. or the user specified a path to a file in which case this is the file
        // we'll symbolize.
        vec![args.trace.clone()]
    };

    let total = paths.len();
    for (idx, path) in paths.into_iter().enumerate() {
        print!("\x1B[2K\r");
        symbolize_file(&mut symbolizer, &path, &args)?;
        print!("[{}/{total}] {} done", idx + 1, path.display());
        io::stdout().flush()?;
    }

    // Grab a few stats before exiting!
    let stats = symbolizer.stop_stopwatch();
    println!("\x1B[2K\r{stats}");

    Ok(())
}
