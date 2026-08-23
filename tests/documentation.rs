use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PLACEHOLDER_SYNOPSIS: &[&str] = &[
    "stallhunt [--duration DURATION] [--json] [--verbose] [--no-color]",
    "stallhunt hunt [--duration DURATION] [--json] [--verbose] [--no-color]",
    "stallhunt watch [--interval DURATION] [--count N] [--json] [--no-color]",
    "stallhunt record --output PATH [--duration DURATION] [--redact] [--force]",
    "stallhunt replay PATH [--json] [--verbose] [--no-color]",
    "stallhunt redact PATH --output PATH [--force]",
];

#[derive(Debug)]
struct Example {
    path: PathBuf,
    line: usize,
    command: String,
}

#[test]
fn concrete_documented_commands_parse() {
    let mut failures = Vec::new();
    let examples = documented_examples();

    assert!(
        !examples.is_empty(),
        "documentation scan found no CLI examples"
    );

    for example in examples {
        if example.command.starts_with("bottleneck ") {
            failures.push(format!(
                "{}:{}: stale executable command `{}`",
                example.path.display(),
                example.line,
                example.command
            ));
            continue;
        }

        let argv = shell_words_without_redirection(&example.command);
        let Some((program, arguments)) = argv.split_first() else {
            failures.push(format!(
                "{}:{}: could not read `{}`",
                example.path.display(),
                example.line,
                example.command
            ));
            continue;
        };
        if is_placeholder(arguments) {
            continue;
        }

        let output = match *program {
            "stallhunt" => Command::new(env!("CARGO_BIN_EXE_stallhunt"))
                .args(arguments)
                // Clap exits after parsing help, before collector or file I/O work.
                .arg("--help")
                .output()
                .expect("run documented command through CLI parser"),
            "cargo" => {
                let Some(subcommand) = arguments.first() else {
                    failures.push(format!(
                        "{}:{}: cargo example has no subcommand: `{}`",
                        example.path.display(),
                        example.line,
                        example.command
                    ));
                    continue;
                };
                Command::new("cargo")
                    .arg(subcommand)
                    .arg("--help")
                    .output()
                    .expect("run documented Cargo subcommand help")
            }
            "tools/measure-overhead.sh" => Command::new("bash")
                .args(["tools/measure-overhead.sh", "--help"])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .expect("run documented repository tool help"),
            _ => continue,
        };
        if !output.status.success() {
            failures.push(format!(
                "{}:{}: `{}` did not parse: {}",
                example.path.display(),
                example.line,
                example.command,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn placeholder_and_synopsis_argv_are_explicitly_inventoried() {
    assert_eq!(PLACEHOLDER_SYNOPSIS.len(), 6);
    for synopsis in PLACEHOLDER_SYNOPSIS {
        assert!(synopsis.starts_with("stallhunt "));
        assert!(synopsis.contains('[') || synopsis.contains(" PATH"));
    }
}

fn documented_examples() -> Vec<Example> {
    let mut paths = markdown_paths(Path::new(env!("CARGO_MANIFEST_DIR")));
    paths.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/stallhunt.1"));
    paths.sort();

    paths
        .into_iter()
        .flat_map(|path| examples_in(&path))
        .collect()
}

fn markdown_paths(root: &Path) -> Vec<PathBuf> {
    let output = Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(root)
        .output()
        .expect("list tracked Markdown documentation");
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("tracked Markdown paths should be UTF-8")
        .lines()
        .map(|path| root.join(path))
        .collect()
}

fn examples_in(path: &Path) -> Vec<Example> {
    let contents = fs::read_to_string(path).expect("read documentation file");
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            normalize_command(line).map(|command| Example {
                path: path.to_path_buf(),
                line: index + 1,
                command,
            })
        })
        .collect()
}

fn normalize_command(line: &str) -> Option<String> {
    let line = line.trim();
    let line = line.strip_prefix("$ ").unwrap_or(line);
    // The NAME stanza is prose (`stallhunt \- description`), not an example.
    if line.contains(r" \- ") {
        return None;
    }
    let line = line
        .replace(r"\-", "-")
        .replace(r"\fB", "")
        .replace(r"\fR", "");
    let command = if let Some(command) = line.strip_prefix("./target/release/stallhunt") {
        format!("stallhunt{command}")
    } else if line.starts_with("stallhunt")
        || line.starts_with("bottleneck ")
        || line.starts_with("cargo ")
        || line.starts_with("tools/measure-overhead.sh ")
    {
        line.to_owned()
    } else {
        return None;
    };

    // Roff synopsis lines are intentionally covered by PLACEHOLDER_SYNOPSIS.
    if command.starts_with(".B ") || command.starts_with(".BR ") {
        return None;
    }
    Some(command)
}

fn shell_words_without_redirection(command: &str) -> Vec<&str> {
    command
        .split_whitespace()
        .take_while(|word| !matches!(*word, ">" | ">>" | "|"))
        .collect()
}

fn is_placeholder(arguments: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        argument.contains('[')
            || argument.contains(']')
            || argument.contains('<')
            || argument.contains('>')
            || *argument == "PATH"
            || *argument == "DURATION"
            || *argument == "N"
            || *argument == "SHELL"
    })
}
