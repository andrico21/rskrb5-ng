use core::{cell::Cell, error};
use std::{
    env, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{Config, Error, LibDefaults, MAX_INCLUDE_BYTES, MAX_INCLUDE_DEPTH, MAX_INCLUDE_FILES};

thread_local! {
    /// Suffix lines visited by include lookahead, isolated per test thread.
    pub(super) static LOOKAHEAD_SCANS: Cell<usize> = const { Cell::new(0) };
}

/// Include runs scan their suffix at most once while resolving a pending scalar.
#[test]
fn include_lookahead_work_is_linear() -> Result<(), Box<dyn error::Error>> {
    let directory = fixture_dir("linear-lookahead")?;
    let child = directory.join("empty.conf");
    fs::write(&child, "")?;
    let directive = format!("include {}\n", child.display());
    for prefix in ["[libdefaults]\n", "[libdefaults]\ndefault_realm =\n"] {
        let mut input = prefix.to_owned();
        input.push_str(&directive.repeat(MAX_INCLUDE_FILES));
        input.push_str(&"# comment\n".repeat(4096));
        assert!(input.len() < MAX_INCLUDE_BYTES);
        LOOKAHEAD_SCANS.with(|count| count.set(0));
        drop(Config::parse(&input)?);
        LOOKAHEAD_SCANS.with(|count| {
            assert!(
                count.get() <= input.lines().count(),
                "suffix scans {} exceed source lines {}",
                count.get(),
                input.lines().count()
            );
        });
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// The marker the parent sets when it re-executes this binary as a probe, so
/// a normal run leaves the probe test inert.
const PROBE_MARKER: &str = "RSKRB5_ENV_FREE_PROBE";
/// Every probe line carries this prefix, so the parent can ignore the test
/// harness's own output.
const PROBE_PREFIX: &str = "rskrb5-probe:";
/// This probe test's name in this binary, for the child's `--exact`.
const PROBE_TEST: &str = "configuration::fork_tests::env_free_fields_probe_child";
/// The hostile `UID` the parent gives the child.
const HOSTILE_UID: &str = "4242";
/// The hostile `HOME` the parent gives the child.
const HOSTILE_HOME: &str = "/attacker/home";

/// The unexpanded identity template every default constructor preserves.
const ENV_FREE_CLIENT_KEYTAB: &str = "/usr/local/var/krb5/user/%{euid}/client.keytab";

/// The environment-free constructor's fields, and - as the control - the
/// environment-reading constructor's, printed for the parent to assert on.
#[test]
fn env_free_fields_probe_child() -> Result<(), Box<dyn error::Error>> {
    assert_eq!(
        super::parse_supported_enctype_ids(&["rc4-hmac".to_owned()], false),
        [23_i32]
    );
    if env::var_os(PROBE_MARKER).is_none() {
        return Ok(());
    }
    let config = Config::new();
    let defaults = LibDefaults::new();
    let parsed = Config::parse("[libdefaults]\n")?;
    let reading = LibDefaults::from_env();
    let mut stdout = io::stdout().lock();
    for (name, keytab, k5login) in [
        (
            "config",
            &config.libdefaults.default_client_keytab_name,
            &config.libdefaults.k5login_directory,
        ),
        (
            "defaults",
            &defaults.default_client_keytab_name,
            &defaults.k5login_directory,
        ),
        (
            "parsed",
            &parsed.libdefaults.default_client_keytab_name,
            &parsed.libdefaults.k5login_directory,
        ),
        (
            "reading",
            &reading.default_client_keytab_name,
            &reading.k5login_directory,
        ),
    ] {
        writeln!(stdout, "{PROBE_PREFIX}{name}_client_keytab={keytab}")?;
        writeln!(stdout, "{PROBE_PREFIX}{name}_k5login={k5login}")?;
    }
    Ok(())
}

/// Run this binary as a child with a hostile `UID`/`HOME` - a child process,
/// never this one's environment - and return the probe lines it
/// printed.
fn hostile_env_probe() -> Result<Vec<String>, Box<dyn error::Error>> {
    let executable = env::current_exe()?;
    let output = Command::new(executable)
        .args(["--exact", PROBE_TEST, "--nocapture"])
        .env_clear()
        .env(PROBE_MARKER, "1")
        .env("UID", HOSTILE_UID)
        .env("HOME", HOSTILE_HOME)
        .output()?;
    assert!(
        output.status.success(),
        "the probe child must exit 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix(PROBE_PREFIX))
        .map(str::to_owned)
        .collect())
}

/// The value of one probe line, or an error naming the line the child did
/// not print.
fn probe_field(lines: &[String], key: &str) -> Result<String, Box<dyn error::Error>> {
    lines
        .iter()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('=').map(str::to_owned))
        .ok_or_else(|| format!("the probe must print {key}: {lines:?}").into())
}

/// The control, asserted by every test below: the child's environment really
/// is hostile, so `LibDefaults::from_env` in that child follows it. Without this,
/// an inert probe would make the env-free assertions pass for the wrong
/// reason.
fn assert_the_child_environment_is_hostile(lines: &[String]) -> Result<(), Box<dyn error::Error>> {
    assert_eq!(
        probe_field(lines, "reading_client_keytab")?,
        ENV_FREE_CLIENT_KEYTAB,
        "even the opt-in constructor must preserve the identity template"
    );
    assert_eq!(probe_field(lines, "reading_k5login")?, HOSTILE_HOME);
    Ok(())
}

/// `Config::new` reads neither `UID` nor `HOME`: hostile values
/// in the process environment leave both derived fields at their
/// deterministic non-env values.
#[test]
fn env_free_config_constructor_does_not_read_uid_or_home() -> Result<(), Box<dyn error::Error>> {
    let lines = hostile_env_probe()?;
    assert_the_child_environment_is_hostile(&lines)?;
    assert_eq!(
        probe_field(&lines, "config_client_keytab")?,
        ENV_FREE_CLIENT_KEYTAB,
        "the config preserves its unexpanded process-identity template"
    );
    assert_eq!(probe_field(&lines, "config_k5login")?, "");
    Ok(())
}

/// The same for the `LibDefaults` constructor the two env-free config
/// constructors share.
#[test]
fn env_free_libdefaults_constructor_does_not_read_uid_or_home() -> Result<(), Box<dyn error::Error>>
{
    let lines = hostile_env_probe()?;
    assert_the_child_environment_is_hostile(&lines)?;
    assert_eq!(
        probe_field(&lines, "defaults_client_keytab")?,
        ENV_FREE_CLIENT_KEYTAB
    );
    assert_eq!(probe_field(&lines, "defaults_k5login")?, "");
    Ok(())
}

/// Ordinary parsing preserves deterministic defaults under hostile ambient input.
#[test]
fn parse_does_not_read_uid_or_home() -> Result<(), Box<dyn error::Error>> {
    let lines = hostile_env_probe()?;
    assert_the_child_environment_is_hostile(&lines)?;
    assert_eq!(
        probe_field(&lines, "parsed_client_keytab")?,
        ENV_FREE_CLIENT_KEYTAB
    );
    assert_eq!(probe_field(&lines, "parsed_k5login")?, "");
    Ok(())
}

/// A fresh directory for one fixture tree, unique per process and call.
fn fixture_dir(name: &str) -> Result<PathBuf, Box<dyn error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = env::temp_dir().join(format!(
        "rskrb5-config-include-{name}-{}-{nanos}",
        process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Write `contents` to `dir/name`.
fn write_file(dir: &Path, name: &str, contents: &str) -> Result<(), Box<dyn error::Error>> {
    fs::write(dir.join(name), contents)?;
    Ok(())
}

/// Write `contents` to `dir/name` and return the path it wrote.
fn write_fixture(dir: &Path, name: &str, contents: &str) -> Result<PathBuf, Box<dyn error::Error>> {
    let path = dir.join(name);
    fs::write(&path, contents)?;
    Ok(path)
}

/// Remove a fixture tree. Cleanup never fails a test: a tree that cannot be
/// removed is left in the temporary directory.
fn remove_fixture(dir: &Path) {
    fs::remove_dir_all(dir).unwrap_or_default();
}

/// The error a load that must be refused returned, or a test failure saying
/// what was expected when it loaded instead.
fn refusal(loaded: Result<Config, Error>, expected: &str) -> Result<Error, Box<dyn error::Error>> {
    loaded.err().ok_or_else(|| expected.into())
}

/// Included scalar values precede values written after the directive site.
#[test]
fn include_file_splices_settings_at_directive_site() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("splice")?;
    let fragment = write_fixture(
        &dir,
        "fragment.conf",
        "[libdefaults]\n default_realm = FRAGMENT.EXAMPLE\n\
         [realms]\n FRAGMENT.EXAMPLE = {\n  kdc = kdc.fragment.example:88\n }\n",
    )?;
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!(
            "include {}\n[libdefaults]\n default_realm = PARENT.EXAMPLE\n",
            fragment.display()
        ),
    )?;

    let config = Config::load(&root)?;
    remove_fixture(&dir);

    assert!(
        config.realm("FRAGMENT.EXAMPLE").is_some(),
        "the fragment's realm is spliced into the configuration"
    );
    assert_eq!(
        config.libdefaults.default_realm, "FRAGMENT.EXAMPLE",
        "the first setting is in the included fragment"
    );
    Ok(())
}

/// `includedir` applies MIT's filename filter - a `.conf` name or a
/// name made only of alphanumerics, dashes and underscores, never a dotfile -
/// and reads the accepted names in alphanumeric order.
///
/// The order assertion is the `default_realm` one: two accepted names set it,
/// and the one that sorts first wins. The filter assertion is the empty realm
/// list: only the two rejected names carry a `[realms]` section, so a realm
/// appearing at all would mean one of them was read.
#[test]
fn includedir_filters_names_like_mit_and_sorts_alphanumerically()
-> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("filter")?;
    let fragments = dir.join("fragments");
    fs::create_dir_all(&fragments)?;
    write_file(
        &fragments,
        "10-first.conf",
        "[libdefaults]\n default_realm = FIRST.EXAMPLE\n",
    )?;
    write_file(
        &fragments,
        "20-flag",
        "[libdefaults]\n udp_preference_limit = 1\n",
    )?;
    write_file(
        &fragments,
        "30-last.conf",
        "[libdefaults]\n default_realm = LAST.EXAMPLE\n",
    )?;
    write_file(
        &fragments,
        "40-dotfile-suffix.bak",
        "[realms]\n REJECTED.EXAMPLE = {\n  kdc = kdc.rejected.example:88\n }\n",
    )?;
    write_file(
        &fragments,
        ".50-hidden.conf",
        "[realms]\n HIDDEN.EXAMPLE = {\n  kdc = kdc.hidden.example:88\n }\n",
    )?;
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("includedir {}\n", fragments.display()),
    )?;

    let config = Config::load(&root)?;
    remove_fixture(&dir);

    assert_eq!(
        config.libdefaults.default_realm, "FIRST.EXAMPLE",
        "the accepted names are read in byte order, so the first one wins"
    );
    assert_eq!(config.libdefaults.udp_preference_limit, 1_i32);
    assert!(
        config.realms.is_empty(),
        "a `.bak` name and a dotfile are not included: {:?}",
        config.realms
    );
    Ok(())
}

/// An include chain that returns to a file it is already reading is a
/// named cycle error, not unbounded recursion.
///
/// `a.conf` is the file the caller loaded, so it is on the open chain from
/// the start: the chain returns to it, and that is the file the error
/// names. Before the root was tracked the parser read `a.conf` a second time
/// and detected the cycle one level further down, at `b.conf`.
#[test]
fn include_cycle_is_a_named_error() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("cycle")?;
    let second = write_fixture(&dir, "b.conf", "")?;
    let first = write_fixture(&dir, "a.conf", &format!("include {}\n", second.display()))?;
    fs::write(&second, format!("include {}\n", first.display()))?;

    let error = refusal(Config::load(&first), "a cycle is refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(&error, Error::IncludeCycle { path } if path == &first),
        "the cycle names the file it returned to, which is already being read: {error:?}"
    );
    Ok(())
}

/// Nesting past [`MAX_INCLUDE_DEPTH`] is a named error carrying the
/// depth it reached and the limit.
#[test]
fn include_depth_limit_is_named() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("depth")?;
    let paths = (1..=10_u8)
        .map(|level| write_fixture(&dir, &format!("level{level}.conf"), ""))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, path) in paths.iter().enumerate() {
        let next = paths.get(index.saturating_add(1));
        let contents = next.map_or_else(String::new, |target| {
            format!("include {}\n", target.display())
        });
        fs::write(path, contents)?;
    }
    let first = paths.first().ok_or("the chain has ten files")?;

    let error = refusal(Config::load(first), "a chain past the limit is refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(
            error,
            Error::IncludeTooDeep {
                depth: 9,
                limit: MAX_INCLUDE_DEPTH
            }
        ),
        "eight levels of include are read; the ninth is past the limit of {MAX_INCLUDE_DEPTH}: {error:?}"
    );
    Ok(())
}

/// More included files than [`MAX_INCLUDE_FILES`] is a named error.
#[test]
fn include_file_count_limit_is_named() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("count")?;
    let fragments = dir.join("fragments");
    fs::create_dir_all(&fragments)?;
    for index in 0..=MAX_INCLUDE_FILES {
        write_file(
            &fragments,
            &format!("f{index:02}.conf"),
            "[libdefaults]\n default_realm = COUNT.EXAMPLE\n",
        )?;
    }
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("includedir {}\n", fragments.display()),
    )?;

    let error = refusal(Config::load(&root), "too many included files are refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(
            error,
            Error::IncludeTooMany {
                count: 257,
                limit: MAX_INCLUDE_FILES
            }
        ),
        "the 257th file is past the limit of {MAX_INCLUDE_FILES}: {error:?}"
    );
    Ok(())
}

/// An `includedir` with more accepted names than the file cap is refused while
/// the directory is scanned: its first entry cannot be read, and the cap is
/// still what is reported, so no file was opened.
#[test]
fn includedir_past_the_file_cap_is_refused_before_any_file_is_read()
-> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("count-early")?;
    let fragments = dir.join("fragments");
    fs::create_dir_all(fragments.join("f00.conf"))?;
    for index in 1..=MAX_INCLUDE_FILES {
        write_file(&fragments, &format!("f{index:02}.conf"), "[libdefaults]\n")?;
    }
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("includedir {}\n", fragments.display()),
    )?;

    let error = refusal(Config::load(&root), "too many accepted names are refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(
            error,
            Error::IncludeTooMany {
                count: _,
                limit: MAX_INCLUDE_FILES
            }
        ),
        "the cap is reported before the unreadable first entry is opened: {error:?}"
    );
    Ok(())
}

/// `includedir` matches names as bytes, like MIT's `valid_name`: a `.conf`
/// name that is not UTF-8 is included. Linux only, because some filesystems
/// refuse such names.
#[cfg(target_os = "linux")]
#[test]
fn includedir_matches_names_as_bytes_like_mit() -> Result<(), Box<dyn error::Error>> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

    let dir = fixture_dir("byte-names")?;
    let fragments = dir.join("fragments");
    fs::create_dir_all(&fragments)?;
    let name = OsStr::from_bytes(b"\xff-realm.conf");
    fs::write(
        fragments.join(name),
        "[libdefaults]\n default_realm = BYTES.EXAMPLE\n",
    )?;
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("includedir {}\n", fragments.display()),
    )?;

    let config = Config::load(&root)?;
    remove_fixture(&dir);

    assert_eq!(config.libdefaults.default_realm, "BYTES.EXAMPLE");
    Ok(())
}

/// Included bytes past [`MAX_INCLUDE_BYTES`] are a named error - and the
/// oversize file is refused rather than read into memory whole.
#[test]
fn include_total_byte_limit_is_named() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("bytes")?;
    let oversize = write_fixture(
        &dir,
        "big.conf",
        &format!(
            "#{}\n[libdefaults]\n default_realm = BIG.EXAMPLE\n",
            "x".repeat(MAX_INCLUDE_BYTES)
        ),
    )?;
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("include {}\n", oversize.display()),
    )?;

    let error = refusal(Config::load(&root), "an oversize include is refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(
            error,
            Error::IncludeTooLarge {
                bytes: 0x0040_0001,
                limit: MAX_INCLUDE_BYTES
            }
        ),
        "the read stops one byte past the limit of {MAX_INCLUDE_BYTES}: {error:?}"
    );
    Ok(())
}

/// An `include` naming a file that cannot be read is a named error
/// carrying the path - MIT's `PROF_FAIL_INCLUDE_FILE`, never a silent skip.
#[test]
fn unreadable_include_file_is_named() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("unreadable-file")?;
    let missing = dir.join("missing.conf");
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("include {}\n", missing.display()),
    )?;

    let error = refusal(Config::load(&root), "a missing include is refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(&error, Error::IncludeFile { path, source } if path == &missing && source.kind() == io::ErrorKind::NotFound),
        "the error names the file the directive named: {error:?}"
    );
    Ok(())
}

/// An `includedir` naming a directory that cannot be listed is a named
/// error - MIT's `PROF_FAIL_INCLUDE_DIR`.
#[test]
fn unreadable_includedir_is_named() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("unreadable-dir")?;
    let missing = dir.join("missing-dir");
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("includedir {}\n", missing.display()),
    )?;

    let error = refusal(Config::load(&root), "a missing includedir is refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(&error, Error::IncludeDir { path, source } if path == &missing && source.kind() == io::ErrorKind::NotFound),
        "the error names the directory the directive named: {error:?}"
    );
    Ok(())
}

/// A `KRB5_CONFIG` path list keeps MIT's order with an include in it -
/// files are read in list order, each file's includes are expanded where the
/// directive sits, and the first scalar value wins.
#[test]
fn krb5_config_path_list_preserves_mit_order_with_includes() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("path-list")?;
    let fragment = write_fixture(
        &dir,
        "fragment.conf",
        "[libdefaults]\n default_realm = INCLUDE.EXAMPLE\n\
         [realms]\n INCLUDE.EXAMPLE = {\n  kdc = kdc.include.example:88\n }\n",
    )?;
    let first = write_fixture(
        &dir,
        "first.conf",
        &format!(
            "include {}\n[libdefaults]\n udp_preference_limit = 1\n",
            fragment.display()
        ),
    )?;
    let second = write_fixture(
        &dir,
        "second.conf",
        "[libdefaults]\n default_realm = SECOND.EXAMPLE\n udp_preference_limit = 2\n",
    )?;

    let config = Config::load_paths([first, second])?;
    remove_fixture(&dir);

    assert_eq!(
        config.libdefaults.default_realm, "INCLUDE.EXAMPLE",
        "the included fragment provides the first value"
    );
    assert_eq!(
        config.libdefaults.udp_preference_limit, 1_i32,
        "the first root provides the first preference value"
    );
    assert!(
        config.realm("INCLUDE.EXAMPLE").is_some(),
        "the include inside the first file was expanded at its directive site"
    );
    Ok(())
}

/// A root file that includes itself is a cycle, and the root is what
/// the cycle returns to - so the root is on the open stack before its own
/// directives expand.
///
/// The chain is seven files long on purpose: the root is reached again while
/// the parser is already eight levels down, which is the deepest include the
/// limit allows. Without the root on the open stack the recursion runs one
/// level past [`MAX_INCLUDE_DEPTH`] and is named as merely deep.
#[test]
fn a_root_file_including_itself_is_a_cycle() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("root-self")?;
    let root = write_fixture(&dir, "krb5.conf", "")?;
    let chain = (1..=7_u8)
        .map(|level| write_fixture(&dir, &format!("level{level}.conf"), ""))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, path) in chain.iter().enumerate() {
        let next = chain.get(index.saturating_add(1)).unwrap_or(&root);
        fs::write(path, format!("include {}\n", next.display()))?;
    }
    let first = chain.first().ok_or("the chain has seven files")?;
    fs::write(&root, format!("include {}\n", first.display()))?;

    let error = refusal(
        Config::load(&root),
        "a root that includes itself is refused",
    )?;
    remove_fixture(&dir);

    assert!(
        matches!(&error, Error::IncludeCycle { path } if path == &root),
        "the root file is already being read, so returning to it is a cycle: {error:?}"
    );
    Ok(())
}

/// Re-including a completed root is not an active-chain cycle.
#[test]
fn a_completed_path_list_root_can_be_reincluded() -> Result<(), Box<dyn error::Error>> {
    let dir = fixture_dir("path-list-root")?;
    let first = write_fixture(
        &dir,
        "first.conf",
        "[libdefaults]\n default_realm = FIRST.EXAMPLE\n",
    )?;
    let second = write_fixture(
        &dir,
        "second.conf",
        &format!("include {}\n", first.display()),
    )?;

    let config = Config::load_paths([&first, &second])?;
    remove_fixture(&dir);

    assert_eq!(config.libdefaults.default_realm, "FIRST.EXAMPLE");
    Ok(())
}

/// An `includedir` reached again through a symlink while its files
/// are being expanded is a cycle, named at the path the directive spelled -
/// the canonical directories being expanded are tracked, so the chain is
/// named rather than merely deep.
///
/// `top/up` is `top` itself, and the directive that names it sits at the
/// eighth include level. The ninth edge fails the depth cap first; the same
/// cycle at the eighth edge is still named.
#[cfg(target_family = "unix")]
#[test]
fn a_symlinked_includedir_cycle_is_named() -> Result<(), Box<dyn error::Error>> {
    use std::os::unix::fs::symlink;

    let dir = fixture_dir("symlinked-dir")?;
    let top = dir.join("top");
    fs::create_dir_all(&top)?;
    symlink(&top, top.join("up"))?;
    write_file(
        &top,
        "00.conf",
        "[libdefaults]\n udp_preference_limit = 1\n",
    )?;
    let chain: Vec<PathBuf> = (1..=7_u8)
        .map(|level| top.join(format!("tmp{level}.conf")))
        .collect();
    let last = chain.last().ok_or("the chain has seven files")?;
    fs::write(last, format!("includedir {}\n", top.join("up").display()))?;
    for (path, next) in chain.iter().zip(chain.iter().skip(1)).rev() {
        fs::write(path, format!("include {}\n", next.display()))?;
    }
    let first = chain.first().ok_or("the chain has seven files")?;
    write_file(&top, "10.conf", &format!("include {}\n", first.display()))?;
    let cycle = top.join("up");
    let root = write_fixture(
        &dir,
        "krb5.conf",
        &format!("includedir {}\n", top.display()),
    )?;

    let error = refusal(Config::load(&root), "the symlinked cycle is refused")?;
    let earlier = chain.get(5).ok_or("the chain has a sixth file")?;
    fs::write(earlier, format!("includedir {}\n", cycle.display()))?;
    let within_limit = refusal(Config::load(&root), "the shallower cycle is refused")?;
    remove_fixture(&dir);

    assert!(
        matches!(error, Error::IncludeTooDeep { depth: 9, limit: 8 }),
        "the ninth edge is rejected before resolving the directory"
    );
    assert!(
        matches!(&within_limit, Error::IncludeCycle { path } if path == &cycle),
        "the symlink names the directory that is already being read: {within_limit:?}"
    );
    Ok(())
}
