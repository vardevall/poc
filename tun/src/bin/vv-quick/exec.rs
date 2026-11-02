//! Running a [`Cmd`]: the one small function that applies the plans.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::plan::Cmd;

/// Runs `cmd`; an error carries what it printed on its standard error.
pub fn run(cmd: &Cmd, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("+ {cmd}");
    }
    let mut child = Command::new(cmd.program)
        .args(&cmd.args)
        .stdin(if cmd.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {}", cmd.program))?;
    if let (Some(text), Some(mut stdin)) = (&cmd.stdin, child.stdin.take()) {
        stdin.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{} failed: {}",
            cmd.to_string().lines().next().unwrap_or(cmd.program),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Runs `cmd` and returns whether it succeeded, saying nothing.
pub fn run_quiet(cmd: &Cmd) -> bool {
    Command::new(cmd.program)
        .args(&cmd.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// What `program args` prints on its standard output, if it succeeds.
pub fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_runs_and_its_failure_carries_the_message() {
        run(&Cmd::new("true", [] as [&str; 0]), false).unwrap();
        let e = run(&Cmd::new("sh", ["-c", "echo no good >&2; exit 3"]), false).unwrap_err();
        assert!(e.to_string().contains("no good"), "{e}");
        assert!(run(&Cmd::new("vv-no-such-program", [] as [&str; 0]), false).is_err());
    }

    #[test]
    fn input_reaches_the_command() {
        let mut c = Cmd::new("sh", ["-c", "test \"$(cat)\" = hello"]);
        c.stdin = Some("hello".into());
        run(&c, false).unwrap();
        assert!(!run_quiet(&Cmd::new("false", [] as [&str; 0])));
    }

    #[test]
    fn output_is_trimmed() {
        assert_eq!(output("echo", &["  x "]).as_deref(), Some("x"));
        assert_eq!(output("false", &[]), None);
    }
}
