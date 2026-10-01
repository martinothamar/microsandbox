//! WAL and POSIX-lock regression coverage in independent processes.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use microsandbox_db::pool::DbPools;
use sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::identity::DatabaseIdentity;
use super::registry::ControlSessions;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_PATH: &str = "MSB_CATALOG_IDENTITY_CHILD_PATH";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn open(path: &Path) -> DbPools {
    DbPools::open(path, 2, TIMEOUT, TIMEOUT).await.unwrap()
}

async fn close(pools: DbPools) {
    pools.read().inner().close_by_ref().await.unwrap();
    pools.write().inner().close_by_ref().await.unwrap();
}

async fn run_child(path: &Path) {
    let output = tokio::time::timeout(
        TIMEOUT,
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::control::catalog_tests::catalog_identity_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD_PATH, path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("catalog child deadline")
    .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("catalog child verified"));
}

fn wal_identity(path: &Path) -> [(u64, u64); 2] {
    ["-wal", "-shm"].map(|suffix| {
        let metadata = std::fs::metadata(format!("{}{suffix}", path.display())).unwrap();
        (metadata.dev(), metadata.ino())
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn catalog_identity_preserves_locks_and_wal_across_binding_and_teardown() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("catalog.db");
    let host = open(&path).await;
    host.write()
        .execute_unprepared(
            "CREATE TABLE identity_writes (value INTEGER); INSERT INTO identity_writes VALUES (1)",
        )
        .await
        .unwrap();
    let original_wal = wal_identity(&path);
    let registry = ControlSessions::default();
    // Exercise the actual backend binding path, including simultaneous retries.
    let bindings = (0..8).map(|_| registry.bind_database(&path));
    for result in futures::future::join_all(bindings).await {
        result.unwrap();
    }
    let identity = registry.database().unwrap();
    for _ in 0..8 {
        identity.verify().unwrap();
    }
    run_child(&path).await;
    assert_eq!(
        wal_identity(&path),
        original_wal,
        "runtime close must retain the host WAL generation"
    );

    // A second backend and capture can disappear while existing pool clones and
    // control owners still use the catalog. Every close must remain SQLite-owned.
    let second = ControlSessions::default();
    second.bind_database(&path).await.unwrap();
    drop(second);
    drop(registry);
    drop(identity);
    let transient = DatabaseIdentity::capture(&path).await.unwrap();
    drop(transient);
    // SQLite's worker closes asynchronously; run another process after teardown.
    run_child(&path).await;
    assert_eq!(wal_identity(&path), original_wal);

    host.write()
        .execute_unprepared("INSERT INTO identity_writes VALUES (3)")
        .await
        .unwrap();
    let fresh = open(&path).await;
    let row = fresh
        .read()
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT count(*) AS count, sum(value) AS total FROM identity_writes",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get_by_index::<i64>(0).unwrap(), 4);
    assert_eq!(row.try_get_by_index::<i64>(1).unwrap(), 8);
    let row = fresh
        .read()
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA integrity_check",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "ok");
    close(fresh).await;
    close(host).await;
    // Raw reads are safe only after the last SQLite user has closed.
    assert_eq!(&std::fs::read(&path).unwrap()[..16], b"SQLite format 3\0");
    assert!(!path.with_extension("db-wal").exists());
    assert!(!path.with_extension("db-shm").exists());
    let reopened = open(&path).await;
    let row = reopened
        .read()
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA quick_check",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "ok");
    close(reopened).await;
}

#[tokio::test]
#[ignore = "subprocess helper, invoked by the catalog identity regression"]
async fn catalog_identity_child() {
    let path = std::env::var(CHILD_PATH).expect("only invoke through run_child");
    // Ask the kernel about the parent's main-file lock before opening SQLite.
    // This fails even when newer SQLite defenses happen to mask WAL corruption.
    let file = File::open(&path).unwrap();
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_start = 0x4000_0002; // SQLite SHARED_FIRST
    lock.l_len = 510; // SQLite SHARED_SIZE
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) },
        0
    );
    assert_eq!(
        lock.l_type,
        libc::F_RDLCK as libc::c_short,
        "SDK discarded the host's SQLite locks"
    );
    assert_ne!(lock.l_pid, std::process::id() as i32);
    drop(file);
    let runtime = open(Path::new(&path)).await;
    runtime
        .write()
        .execute_unprepared("INSERT INTO identity_writes VALUES (2)")
        .await
        .unwrap();
    runtime
        .read()
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT count(*) FROM identity_writes",
        ))
        .await
        .unwrap()
        .unwrap();
    close(runtime).await;
    println!("catalog child verified");
}

#[tokio::test]
#[ignore = "requires macOS virtualization or Linux KVM, Internet access, MSB_PATH and MSB_LIBKRUNFW_PATH"]
async fn live_catalog_identity_survives_runtime_stop_restart_and_stall() {
    use std::sync::Arc;

    use futures::FutureExt;
    use microsandbox_control_client::GetCapabilities;

    // macOS socket paths cannot accommodate its default long temp directory.
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let local = Arc::new(
        crate::backend::LocalBackend::builder()
            .home(directory.path())
            .build()
            .await
            .unwrap(),
    );
    let backend: Arc<dyn crate::backend::Backend> = local.clone();
    crate::backend::with_backend(backend, async {
        let name = "catalog-identity-live";
        let result = std::panic::AssertUnwindSafe(async {
            let mut sandbox = crate::Sandbox::builder(name)
                .image("mirror.gcr.io/library/alpine:3.22")
                .cpus(1)
                .memory(256)
                .create()
                .await
                .unwrap();
            sandbox
                .exec("sh", ["-c", "printf catalog-marker > /root/catalog-marker"])
                .await
                .unwrap();
            for _ in 0..3 {
                let session = local.control_session(name).await.unwrap().unwrap();
                session.request(&GetCapabilities).await.unwrap();
                sandbox.stop().await.unwrap();
                local.control_sessions.database().unwrap().verify().unwrap();
                sandbox = crate::Sandbox::get(name)
                    .await
                    .unwrap()
                    .start_detached()
                    .await
                    .unwrap();
                let output = sandbox.exec("cat", ["/root/catalog-marker"]).await.unwrap();
                assert!(output.status().success);
                assert_eq!(output.stdout().unwrap(), "catalog-marker");
            }
            let session = local.control_session(name).await.unwrap().unwrap();
            let pid = session.entry.key.pid;
            assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
            // Always resume this disposable runtime, including on test failure.
            struct Resume(i32);
            impl Drop for Resume {
                fn drop(&mut self) {
                    unsafe {
                        libc::kill(self.0, libc::SIGCONT);
                    }
                }
            }
            let resume = Resume(pid);
            for _ in 0..60 {
                local.control_sessions.database().unwrap().verify().unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            drop(resume);
            session.request(&GetCapabilities).await.unwrap();
            let output = sandbox.exec("cat", ["/root/catalog-marker"]).await.unwrap();
            assert_eq!(output.stdout().unwrap(), "catalog-marker");
            sandbox.pause().await.unwrap();
            local.control_sessions.database().unwrap().verify().unwrap();
            sandbox.resume().await.unwrap();
            sandbox.stop().await.unwrap();
            let row = local
                .db()
                .await
                .unwrap()
                .read()
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "PRAGMA integrity_check",
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "ok");
        })
        .catch_unwind()
        .await;
        // Separate supported lifecycle cleanup even when an assertion fails.
        if let Ok(handle) = crate::Sandbox::get(name).await {
            let _ = handle.stop().await;
            crate::Sandbox::remove(name).await.unwrap();
        }
        result.unwrap();
    })
    .await;
}
