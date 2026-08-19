//! Key-generation benchmark for the experimental 2^32-epoch BLAKE3 scheme.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use leansig::{
    serialization::Serializable,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_blake3::lifetime_2_to_the_32::SIGTargetSumLifetime32Dim46Base8,
    },
};

type Scheme = SIGTargetSumLifetime32Dim46Base8;

struct Config {
    epochs: usize,
    runs: usize,
    output_prefix: Option<PathBuf>,
}

const fn usage() -> &'static str {
    r"Usage: keygen_lifetime32 --epochs <COUNT|2^EXPONENT> [--runs <COUNT>] [--output-prefix <PATH>]

Benchmarks key generation with the 2^32-lifetime, dimension-46, base-8
BLAKE3 scheme. Key-generation timing excludes serialization and file I/O.

The full run requires a second explicit opt-in:
  cargo run --release --bin keygen_lifetime32 -- \
    --epochs 2^32 --runs 1 --allow-full-lifetime \
    --output-prefix artifacts/leansig-blake3-2p32
"
}

fn parse_count(value: &str, name: &str) -> Result<usize, String> {
    let parsed = if let Some(exponent) = value.strip_prefix("2^") {
        let exponent = exponent
            .parse::<u32>()
            .map_err(|_| format!("invalid {name}: {value}"))?;
        1usize
            .checked_shl(exponent)
            .ok_or_else(|| format!("{name} does not fit usize: {value}"))?
    } else {
        value
            .parse::<usize>()
            .map_err(|_| format!("invalid {name}: {value}"))?
    };

    if parsed == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_args() -> Result<Option<Config>, String> {
    let mut args = env::args().skip(1);
    let mut epochs = None;
    let mut runs = 1;
    let mut output_prefix = None;
    let mut allow_full_lifetime = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--epochs" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--epochs requires a value".to_owned())?;
                epochs = Some(parse_count(&value, "epoch count")?);
            }
            "--runs" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--runs requires a value".to_owned())?;
                runs = parse_count(&value, "run count")?;
            }
            "--output-prefix" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output-prefix requires a value".to_owned())?;
                output_prefix = Some(PathBuf::from(value));
            }
            "--allow-full-lifetime" => allow_full_lifetime = true,
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    let epochs = epochs.ok_or_else(|| "--epochs is required".to_owned())?;
    if epochs as u64 > Scheme::LIFETIME {
        return Err(format!(
            "epoch count {epochs} exceeds the scheme lifetime {}",
            Scheme::LIFETIME
        ));
    }
    if output_prefix.is_some() && runs != 1 {
        return Err("--output-prefix requires --runs 1".to_owned());
    }
    if epochs as u64 == Scheme::LIFETIME && !allow_full_lifetime {
        return Err("a 2^32 run may take hours; pass --allow-full-lifetime to confirm".to_owned());
    }

    Ok(Some(Config {
        epochs,
        runs,
        output_prefix,
    }))
}

fn format_duration(duration: Duration) -> String {
    format!("{:.6}", duration.as_secs_f64())
}

fn write_key(prefix: &Path, public_key: &[u8], secret_key: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = prefix.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let public_path = prefix.with_extension("public.ssz");
    let secret_path = prefix.with_extension("secret.ssz");

    for path in [&public_path, &secret_path] {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("refusing to overwrite {}", path.display()),
            ));
        }
    }

    let mut secret_options = OpenOptions::new();
    secret_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        secret_options.mode(0o600);
    }
    secret_options.open(&secret_path)?.write_all(secret_key)?;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(public_path)?
        .write_all(public_key)?;
    Ok(())
}

fn run(config: Config) -> Result<(), String> {
    println!("scheme=blake3-l32-dim46-base8-target200");
    println!("lifetime={}", Scheme::LIFETIME);
    println!("requested_active_epochs={}", config.epochs);
    println!("keygen_runs={}", config.runs);

    let mut samples = Vec::with_capacity(config.runs);
    let mut last_keypair = None;
    for run in 0..config.runs {
        let mut rng = rand::rng();
        let started = Instant::now();
        let keypair = Scheme::key_gen(&mut rng, 0, config.epochs);
        let elapsed = started.elapsed();
        println!(
            "keygen_run_{}_seconds={}",
            run + 1,
            format_duration(elapsed)
        );
        samples.push(elapsed);
        last_keypair = Some(keypair);
    }

    let mean_seconds = samples.iter().map(Duration::as_secs_f64).sum::<f64>() / config.runs as f64;
    println!("keygen_mean_seconds={mean_seconds:.6}");

    let (public_key, secret_key) = last_keypair.expect("at least one key-generation run");
    let active = secret_key.get_activation_interval();
    let prepared = secret_key.get_prepared_interval();
    println!("actual_active_epoch_start={}", active.start);
    println!("actual_active_epochs={}", active.end - active.start);
    println!("prepared_epoch_start={}", prepared.start);
    println!("prepared_epochs={}", prepared.end - prepared.start);

    let serialization_started = Instant::now();
    let public_key_bytes = public_key.to_bytes();
    let secret_key_bytes = secret_key.to_bytes();
    println!(
        "serialization_seconds={}",
        format_duration(serialization_started.elapsed())
    );
    println!("public_key_bytes={}", public_key_bytes.len());
    println!("secret_key_bytes={}", secret_key_bytes.len());

    if let Some(prefix) = config.output_prefix {
        let write_started = Instant::now();
        write_key(&prefix, &public_key_bytes, &secret_key_bytes)
            .map_err(|error| format!("failed to write key files: {error}"))?;
        println!("write_seconds={}", format_duration(write_started.elapsed()));
        println!(
            "public_key_file={}",
            prefix.with_extension("public.ssz").display()
        );
        println!(
            "secret_key_file={}",
            prefix.with_extension("secret.ssz").display()
        );
    }

    Ok(())
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(None) => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Some(config)) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error}\n\n{}", usage());
            ExitCode::FAILURE
        }
    }
}
