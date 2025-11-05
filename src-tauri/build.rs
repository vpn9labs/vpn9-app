use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if should_build_daemon() {
        println!("cargo:rerun-if-changed=../vpn9-daemon/Cargo.toml");
        println!("cargo:rerun-if-changed=../vpn9-daemon/src");
        build_vpn9_daemon();
    }

    tauri_build::build()
}

fn should_build_daemon() -> bool {
    matches!(env::var("PROFILE").as_deref(), Ok("release"))
        && matches!(env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("linux"))
}

fn build_vpn9_daemon() {
    let target = env::var("TARGET").unwrap_or_else(|_| env::consts::ARCH.to_string());
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().expect("workspace root not found");

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));

    let mut cmd = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()));
    let daemon_target_dir = target_dir.parent().map(|parent| {
        let dir_name = target_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "target".to_string());
        parent.join(format!("{}-vpn9-daemon", dir_name))
    }).unwrap_or_else(|| target_dir.join("vpn9-daemon"));
    cmd.current_dir(workspace_root)
        .args([
            "build",
            "--package",
            "vpn9-daemon",
            "--bin",
            "vpn9-daemon",
            "--release",
            "--target",
            &target,
        ])
        .arg("--target-dir")
        .arg(&daemon_target_dir);

    let status = cmd
        .status()
        .expect("failed to invoke cargo to build vpn9-daemon");
    if !status.success() {
        panic!("cargo build -p vpn9-daemon failed");
    }

    let exe_suffix = env::consts::EXE_SUFFIX;
    let source = daemon_target_dir
        .join(&target)
        .join("release")
        .join(format!("vpn9-daemon{}", exe_suffix));
    let destination = target_dir
        .join("release")
        .join(format!("vpn9-daemon{}", exe_suffix));

    if !source.exists() {
        panic!(
            "vpn9-daemon binary not found after build at {}",
            source.display()
        );
    }

    std::fs::create_dir_all(
        destination
            .parent()
            .expect("vpn9-daemon destination parent missing"),
    )
    .expect("failed to create target/release directory");

    std::fs::copy(&source, &destination)
        .unwrap_or_else(|err| panic!("failed to copy vpn9-daemon binary: {err}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&destination)
            .expect("failed to read vpn9-daemon metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&destination, permissions)
            .expect("failed to set vpn9-daemon permissions");
    }
}
