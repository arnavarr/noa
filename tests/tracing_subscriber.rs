//! Tests de subproceso para el subscriber de `tracing` instalado en `noa::main()`.
//!
//! `try_init()` instala un subscriber GLOBAL de proceso; no es unit-testeable in-process
//! (colisionaría con el subscriber de otros tests). Por eso estos tests lanzan el binario
//! como subproceso vía `CARGO_BIN_EXE_noa` (solo disponible en tests de integración, no en
//! unit tests). Ver spec `docs/superpowers/specs/2026-07-09-tracing-subscriber-design.md` §4.

use std::process::{Command, ExitStatus, Output};

/// Lanza `noa` con argv vacío (cae en el brazo `usage:`/`ExitCode::FAILURE`, rápido y sin red)
/// y el `RUST_LOG` dado (`Some` para fijarlo, `None` para eliminarlo del env del hijo).
/// Devuelve stdout/stderr en pipes SEPARADOS (nunca `2>&1`: D1 depende de la separación).
fn run_noa_with_rust_log(rust_log: Option<&str>) -> (ExitStatus, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_noa"));
    match rust_log {
        Some(value) => {
            cmd.env("RUST_LOG", value);
        }
        None => {
            cmd.env_remove("RUST_LOG");
        }
    }
    let Output {
        status,
        stdout,
        stderr,
    } = cmd.output().expect("failed to spawn noa subprocess");
    (
        status,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// T1: `RUST_LOG=debug` hace emitir la línea de arranque a stderr, nunca a stdout.
/// Caza (a) ausencia total de subscriber (1er assert) y (b) `.with_writer` mutado a stdout,
/// el default de `fmt()` (2º assert) — el pin D1.
#[test]
fn rust_log_debug_emits_startup_line_on_stderr_not_stdout() {
    let (_status, stdout, stderr) = run_noa_with_rust_log(Some("debug"));
    assert!(
        stderr.contains("noa iniciando"),
        "stderr debería contener la línea de arranque; stderr={stderr:?}"
    );
    assert!(
        !stdout.contains("noa iniciando"),
        "stdout NO debería contener la línea de arranque; stdout={stdout:?}"
    );
}

/// T2: sin `RUST_LOG`, el default `WARN` filtra la línea de arranque (`debug`) ⇒ silencio.
/// Pin de D2 + evidencia de que el filtro está realmente cableado (no solo "no rompe").
#[test]
fn no_rust_log_is_silent_at_startup() {
    let (_status, _stdout, stderr) = run_noa_with_rust_log(None);
    assert!(
        !stderr.contains("noa iniciando"),
        "stderr no debería contener la línea de arranque sin RUST_LOG; stderr={stderr:?}"
    );
}

/// T3: un `RUST_LOG` con nivel inválido no aborta el proceso (from_env_lossy, no from_env).
/// El código de salida debe ser el normal del brazo `usage:` (1), no un panic-abort (101).
#[test]
fn invalid_rust_log_does_not_abort_startup() {
    let (status, _stdout, _stderr) = run_noa_with_rust_log(Some("noa=notalevel"));
    assert_eq!(
        status.code(),
        Some(1),
        "RUST_LOG inválido no debe abortar (panic); status={status:?}"
    );
}
