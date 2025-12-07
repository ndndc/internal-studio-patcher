mod stagescan;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use clap::Parser;
use winreg::{enums::HKEY_CLASSES_ROOT, RegKey};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
}

fn patch(input: &PathBuf, output: &PathBuf) {
    let input_data = match fs::read(input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read input file {:?}: {}", input, e);
            std::process::exit(1);
        }
    };

    let now = Instant::now();
    stagescan::start(input_data, output);
    println!("Patched in {:?}", now.elapsed());
}

fn main() {
    let Cli { mut input, output } = Cli::parse();

    if input.is_none() {
        let path = match RegKey::predef(HKEY_CLASSES_ROOT)
            .open_subkey("roblox-studio")
            .and_then(|k| k.open_subkey("DefaultIcon"))
            .and_then(|k| k.get_value::<String, _>(""))
        {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Could not find Roblox Studio path in registry. Please provide --input manually.");
                std::process::exit(1);
            }
        };

        input = Some(PathBuf::from(path));
    }

    let input = input.as_ref().unwrap();
    if !input.exists() {
        eprintln!("Input file {:?} does not exist.", input);
        std::process::exit(1);
    }

    let output = output.unwrap_or_else(|| input.with_file_name("RobloxStudioBeta_INTERNAL.exe"));

    patch(input, &output);
}
