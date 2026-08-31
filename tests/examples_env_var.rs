//! Regression test for the examples' TLS-verification env var name.
//!
//! The examples must read `MISP_VERIFYCERT`, the same env var name used by
//! `tests/integration_tests.rs` and by CI (see `.github/workflows/ci.yml`).
//! A prior version of the examples read a different name (`MISP_SSL_VERIFY`),
//! which meant setting the documented `MISP_VERIFYCERT=false` to skip TLS
//! verification silently had no effect in the examples and certificate
//! verification stayed on.

use std::fs;
use std::path::Path;

#[test]
fn examples_use_misp_verifycert_env_var() {
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut checked = 0;

    for entry in fs::read_dir(&examples_dir).expect("read examples dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let contents = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("failed to read {}: {e}", path.display());
        });

        if !contents.contains("std::env::var(\"MISP_URL\")") {
            // Not a MISP-connecting example; skip.
            continue;
        }
        checked += 1;

        assert!(
            !contents.contains("MISP_SSL_VERIFY"),
            "{} still reads the stale MISP_SSL_VERIFY env var; \
             examples must use MISP_VERIFYCERT like the integration tests and CI do",
            path.display()
        );
        assert!(
            contents.contains("MISP_VERIFYCERT"),
            "{} does not read MISP_VERIFYCERT for TLS verification control",
            path.display()
        );
    }

    assert!(
        checked >= 8,
        "expected at least 8 MISP-connecting examples, found {checked}"
    );
}
