use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PLACEHOLDER_ARGV: &[&[&str]] = &[
    &["--duration", "100ms", "--json", "--verbose", "--no-color"],
    &[
        "hunt",
        "--duration",
        "100ms",
        "--json",
        "--verbose",
        "--no-color",
    ],
    &[
        "watch",
        "--interval",
        "100ms",
        "--count",
        "1",
        "--json",
        "--no-color",
    ],
    &["capabilities", "--json"],
    &["completions", "bash"],
    &[
        "record",
        "--output",
        "fixture.json",
        "--duration",
        "100ms",
        "--redact",
        "--force",
    ],
    &[
        "replay",
        "fixture.json",
        "--json",
        "--verbose",
        "--no-color",
    ],
    &[
        "redact",
        "fixture.json",
        "--output",
        "redacted.json",
        "--force",
    ],
    &["mcp", "--interval", "100ms", "--no-sampler"],
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
    let inventory_shapes = PLACEHOLDER_ARGV
        .iter()
        .map(|arguments| command_shape(arguments))
        .collect::<BTreeSet<_>>();

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
        let arguments = if is_placeholder(arguments) {
            let shape = command_shape(arguments);
            if !inventory_shapes.contains(&shape) {
                failures.push(format!(
                    "{}:{}: placeholder command shape `{shape}` is missing from PLACEHOLDER_ARGV: `{}`",
                    example.path.display(),
                    example.line,
                    example.command
                ));
            }
            materialize_placeholders(arguments)
        } else {
            arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect()
        };

        if let Some(failure) = validate_command(program, &arguments, &example) {
            failures.push(failure);
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn placeholder_and_synopsis_argv_are_explicitly_inventoried() {
    assert_eq!(PLACEHOLDER_ARGV.len(), 9);
    for arguments in PLACEHOLDER_ARGV {
        let example = Example {
            path: PathBuf::from("PLACEHOLDER_ARGV"),
            line: 0,
            command: format!("stallhunt {}", arguments.join(" ")),
        };
        assert!(
            validate_command(
                "stallhunt",
                &arguments
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>(),
                &example
            )
            .is_none(),
            "inventory entry did not parse: {}",
            example.command
        );
    }
}

#[test]
fn inline_legacy_commands_and_placeholder_typos_are_not_blind_spots() {
    assert_eq!(
        normalize_commands("Do not run `bottleneck capabilities` here.", false),
        vec!["bottleneck capabilities"]
    );
    assert!(
        normalize_commands("Legacy `bottleneck.recording` remains readable.", false).is_empty()
    );
    assert_eq!(
        normalize_commands("Try `stallhunt huunt --json`.", false),
        vec!["stallhunt huunt --json"]
    );
    assert_eq!(
        normalize_commands("bottleneck capabilties", true),
        vec!["bottleneck capabilties"]
    );
    assert_eq!(
        normalize_commands("cargo biuld --release", true),
        vec!["cargo biuld --release"]
    );
    assert!(normalize_commands("The binary printed `stallhunt 0.4.0`.", false).is_empty());

    let raw = ["hunt", "[--jsoon]"];
    let arguments = materialize_placeholders(&raw);
    let example = Example {
        path: PathBuf::from("inline-regression"),
        line: 1,
        command: "stallhunt hunt [--jsoon]".into(),
    };
    assert!(validate_command("stallhunt", &arguments, &example).is_some());
}

fn validate_command(program: &str, arguments: &[String], example: &Example) -> Option<String> {
    if program == "cargo" {
        return validate_cargo_arguments(arguments).err().map(|message| {
            format!(
                "{}:{}: `{}` did not parse: {message}",
                example.path.display(),
                example.line,
                example.command
            )
        });
    }
    let output = match program {
        "stallhunt" => Command::new(env!("CARGO_BIN_EXE_stallhunt"))
            .args(arguments)
            // Clap exits after parsing help, before collector or file I/O work.
            .arg("--help")
            .output()
            .expect("run documented command through CLI parser"),
        "tools/measure-overhead.sh" | "tools/check-tui-pty.sh" => Command::new("bash")
            .arg(program)
            .args(arguments)
            .arg("--help")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("run documented repository tool help"),
        _ => return None,
    };
    (!output.status.success()).then(|| {
        format!(
            "{}:{}: `{}` did not parse: {}",
            example.path.display(),
            example.line,
            example.command,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })
}

fn validate_cargo_arguments(arguments: &[String]) -> Result<(), String> {
    let Some((subcommand, arguments)) = arguments.split_first() else {
        return Err("missing Cargo subcommand".into());
    };
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let valid = match subcommand.as_str() {
        "build" => matches!(
            arguments.as_slice(),
            [] | ["--release", "--locked"] | ["--release", "--locked", "--offline"]
        ),
        "fmt" => matches!(arguments.as_slice(), ["--all", "--", "--check"]),
        "clippy" => matches!(
            arguments.as_slice(),
            [
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings"
            ] | [
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings"
            ]
        ),
        "install" => matches!(arguments.as_slice(), ["--path", "."]),
        "test" => matches!(
            arguments.as_slice(),
            ["--workspace", "--all-features"]
                | ["--locked", "--offline", "--workspace", "--all-features"]
                | ["--test", "cpu_acceptance", "--", "--ignored"]
                | ["--test", "io_acceptance", "--", "--ignored"]
                | [
                    "--locked",
                    "--offline",
                    "--test",
                    "io_acceptance",
                    "--",
                    "--ignored",
                    "--nocapture"
                ]
                | [
                    "--locked",
                    "--offline",
                    "--test",
                    "memory_acceptance",
                    "--",
                    "--ignored",
                    "--nocapture"
                ]
                | [
                    "--locked",
                    "--offline",
                    "--test",
                    "cgroup_acceptance",
                    "--",
                    "--ignored",
                    "--nocapture"
                ]
        ),
        "uninstall" => matches!(arguments.as_slice(), ["stallhunt"]),
        _ => return Err(format!("unrecognized Cargo subcommand `{subcommand}`")),
    };
    valid
        .then_some(())
        .ok_or_else(|| format!("unsupported documented arguments for `cargo {subcommand}`"))
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
    let mut in_code_fence = false;
    let mut examples = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_code_fence = !in_code_fence;
            continue;
        }
        examples.extend(
            normalize_commands(line, in_code_fence)
                .into_iter()
                .map(|command| Example {
                    path: path.to_path_buf(),
                    line: index + 1,
                    command,
                }),
        );
    }
    examples
}

fn normalize_commands(line: &str, in_code_fence: bool) -> Vec<String> {
    let is_shell_line = in_code_fence || line.trim_start().starts_with("$ ");
    let mut candidates = vec![(line, is_shell_line, is_shell_line)];
    candidates.extend(
        line.split('`')
            .enumerate()
            .filter_map(|(index, span)| (index % 2 == 1).then_some((span, true, false))),
    );
    let mut commands = candidates
        .into_iter()
        .filter_map(
            |(candidate, accept_unknown_product, accept_unknown_cargo)| {
                normalize_command(candidate, accept_unknown_product, accept_unknown_cargo)
            },
        )
        .collect::<Vec<_>>();
    commands.sort();
    commands.dedup();
    commands
}

fn normalize_command(
    line: &str,
    accept_unknown_product: bool,
    accept_unknown_cargo: bool,
) -> Option<String> {
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
    } else {
        line.to_owned()
    };

    // Roff synopsis lines are intentionally covered by PLACEHOLDER_SYNOPSIS.
    if command.starts_with(".B ") || command.starts_with(".BR ") {
        return None;
    }
    is_executable_command(&command, accept_unknown_product, accept_unknown_cargo).then_some(command)
}

fn is_executable_command(
    command: &str,
    accept_unknown_product: bool,
    accept_unknown_cargo: bool,
) -> bool {
    let mut words = command.split_whitespace();
    let Some(program) = words.next() else {
        return false;
    };
    let next = words.next();
    if program == "stallhunt" && next.is_some_and(is_version_number) {
        return false;
    }
    match program {
        "stallhunt" => {
            accept_unknown_product
                || next.is_none_or(|word| {
                    word.starts_with('-')
                        || word.starts_with('[')
                        || word == "|"
                        || matches!(
                            word,
                            "hunt"
                                | "watch"
                                | "capabilities"
                                | "record"
                                | "replay"
                                | "redact"
                                | "mcp"
                                | "completions"
                                | "version"
                        )
                })
        }
        "bottleneck" => {
            accept_unknown_product
                || next.is_some_and(|word| {
                    word.starts_with('-')
                        || matches!(
                            word,
                            "hunt" | "watch" | "capabilities" | "record" | "replay" | "redact"
                        )
                })
        }
        "cargo" => {
            accept_unknown_cargo
                || (command.split_whitespace().count() > 2
                    && next.is_some_and(|word| {
                        matches!(
                            word,
                            "build" | "clippy" | "fmt" | "install" | "test" | "uninstall"
                        )
                    }))
        }
        "tools/measure-overhead.sh" | "tools/check-tui-pty.sh" => true,
        _ => false,
    }
}

fn is_version_number(word: &str) -> bool {
    let mut parts = word.split('.');
    parts.clone().count() == 3
        && parts.all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
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

fn materialize_placeholders(arguments: &[&str]) -> Vec<String> {
    arguments
        .iter()
        .filter_map(|argument| {
            let argument = argument.trim_start_matches('[').trim_end_matches(']');
            if argument.is_empty() || argument == "..." {
                return None;
            }
            let placeholder = argument.trim_matches(['<', '>']).to_ascii_uppercase();
            Some(
                match placeholder.as_str() {
                    "PATH" => "fixture.json",
                    "DURATION" => "100ms",
                    "N" | "PID" => "1",
                    "SHELL" => "bash",
                    _ => argument,
                }
                .to_owned(),
            )
        })
        .collect()
}

fn command_shape(arguments: &[&str]) -> String {
    arguments
        .first()
        .filter(|argument| !argument.starts_with('-') && !argument.starts_with('['))
        .map_or_else(
            || "<implicit-hunt>".to_owned(),
            |argument| argument.trim_matches(['[', ']']).to_owned(),
        )
}
