//! Run on a Linux KVM or Apple Silicon macOS host with:
//! `cargo test --test mediated_egress_e2e -- --ignored --nocapture`.
//! Set `SMOLVM_E2E_BIN` to a signed binary on macOS when needed.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod vm {
    use serde_json::{json, Value};
    use smolvm_protocol::mediated_egress::{Decision, FlowPrelude};
    use std::error::Error;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn check(ok: bool, message: impl Into<String>) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(message.into()))
        }
    }

    fn free_port() -> io::Result<u16> {
        Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port())
    }

    struct Broker {
        addr: SocketAddr,
        flows: Arc<Mutex<Vec<FlowPrelude>>>,
        errors: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Broker {
        fn start(token: [u8; 32]) -> io::Result<Self> {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let addr = listener.local_addr()?;
            let flows = Arc::new(Mutex::new(Vec::new()));
            let errors = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (worker_flows, worker_errors, worker_stop) =
                (flows.clone(), errors.clone(), stop.clone());
            let worker = thread::spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let result = (|| -> io::Result<()> {
                                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                                let flow = FlowPrelude::read_from(&mut stream, &token)?;
                                check(
                                    flow.destination == "1.1.1.1:443".parse().unwrap(),
                                    format!("unexpected broker destination: {}", flow.destination),
                                )?;
                                worker_flows.lock().unwrap().push(flow);
                                Decision::Redirect.write_to(&mut stream)?;
                                stream.write_all(b"broker-ok\n")
                            })();
                            if let Err(error) = result {
                                worker_errors.lock().unwrap().push(error.to_string());
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            worker_errors.lock().unwrap().push(error.to_string());
                            break;
                        }
                    }
                }
            });
            Ok(Self {
                addr,
                flows,
                errors,
                stop,
                worker: Some(worker),
            })
        }

        fn stop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(worker) = self.worker.take() {
                worker.join().expect("broker thread panicked");
            }
        }
    }

    impl Drop for Broker {
        fn drop(&mut self) {
            self.stop();
        }
    }

    struct Server {
        child: Child,
        _root: tempfile::TempDir,
        base: String,
        agent: ureq::Agent,
    }

    impl Server {
        fn start() -> TestResult<Self> {
            let host_home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset")?);
            let default_rootfs = if cfg!(target_os = "macos") {
                host_home.join("Library/Application Support/smolvm/agent-rootfs")
            } else {
                host_home.join(".local/share/smolvm/agent-rootfs")
            };
            let rootfs = std::env::var_os("SMOLVM_AGENT_ROOTFS")
                .map(PathBuf::from)
                .unwrap_or(default_rootfs);
            check(
                rootfs.is_dir(),
                format!("agent rootfs missing: {}", rootfs.display()),
            )?;
            let binary = std::env::var_os("SMOLVM_E2E_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_smolvm")));
            let root = tempfile::Builder::new().prefix("sme-").tempdir_in("/tmp")?;
            let api_port = free_port()?;
            let rollout_port = free_port()?;
            let log_path = root.path().join("server.log");
            let log = File::create(&log_path)?;
            let mut command = Command::new(binary);
            command
                .args(["serve", "start", "-l", &format!("127.0.0.1:{api_port}")])
                .env("XDG_CACHE_HOME", root.path().join("cache"))
                .env("XDG_DATA_HOME", root.path().join("data"))
                .env("XDG_CONFIG_HOME", root.path().join("config"))
                // The local direct-flow probe dials the gateway's CGNAT address.
                .env("SMOLVM_EGRESS_FLOOR", "metadata")
                .env("SMOLVM_GUEST_ROLLOUT_HOST_PORT", rollout_port.to_string())
                .env("SMOLVM_AGENT_ROOTFS", rootfs)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log));
            if cfg!(target_os = "macos") {
                command.env("HOME", root.path());
            }
            let child = command.spawn()?;
            let mut server = Self {
                child,
                _root: root,
                base: format!("http://127.0.0.1:{api_port}/api/v1/machines"),
                agent: ureq::AgentBuilder::new()
                    .timeout(Duration::from_secs(60))
                    .build(),
            };
            let health = format!("http://127.0.0.1:{api_port}/health");
            let probe = ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(200))
                .build();
            for _ in 0..100 {
                if server.child.try_wait()?.is_some() {
                    return Err(format!(
                        "API server exited before readiness: {}",
                        fs::read_to_string(log_path).unwrap_or_default()
                    )
                    .into());
                }
                if probe.get(&health).call().is_ok() {
                    return Ok(server);
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err("API server did not become ready".into())
        }

        fn api(&self, method: &str, path: &str, body: Option<&Value>) -> TestResult<(u16, Value)> {
            let url = format!("{}{}", self.base, path);
            let request = self
                .agent
                .request(method, &url)
                .set("Content-Type", "application/json");
            let response = match body {
                Some(body) => request.send_string(&body.to_string()),
                None => request.call(),
            };
            let response = match response {
                Ok(response) | Err(ureq::Error::Status(_, response)) => response,
                Err(error) => return Err(error.into()),
            };
            let status = response.status();
            let text = response.into_string()?;
            let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
            Ok((status, body))
        }

        fn expect_status(
            &self,
            method: &str,
            path: &str,
            body: Option<&Value>,
            want: u16,
        ) -> TestResult {
            let (status, response) = self.api(method, path, body)?;
            check(
                status == want,
                format!("{method} {path}: wanted {want}, got {status}: {response}"),
            )?;
            Ok(())
        }

        fn exec(&self, name: &str, command: Value) -> TestResult<Value> {
            let (status, response) = self.api(
                "POST",
                &format!("/{name}/exec"),
                Some(&json!({"command": command})),
            )?;
            check(
                status == 200,
                format!("exec in {name} returned {status}: {response}"),
            )?;
            Ok(response)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let cleanup = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(2))
                .build();
            for name in ["child", "source"] {
                for (method, suffix) in [("POST", "/stop"), ("DELETE", "")] {
                    let _ = cleanup
                        .request(method, &format!("{}/{name}{suffix}", self.base))
                        .call();
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn accept_direct(listener: TcpListener) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut first = [0; 6];
                    stream.read_exact(&mut first)?;
                    check(
                        first == *b"direct",
                        format!("unexpected direct payload: {first:?}"),
                    )?;
                    return stream.write_all(b"direct-ok\n");
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn run() -> TestResult {
        if cfg!(target_os = "linux") {
            check(
                PathBuf::from("/dev/kvm").exists(),
                "this test requires /dev/kvm",
            )?;
        }
        let mut token = [0u8; 32];
        getrandom::fill(&mut token)?;
        let mut broker = Broker::start(token)?;
        let direct_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let direct_port = direct_listener.local_addr()?.port();
        let server = Server::start()?;

        server.expect_status("POST", "", Some(&json!({
            "name": "invalid-rule", "egressRules": [{"transport": "tcp", "cidr": "bad-cidr", "action": "allow"}]
        })), 400)?;
        server.expect_status("POST", "", Some(&json!({
            "name": "tsi-rule", "networkBackend": "tsi", "egressRules": [{"transport": "tcp", "action": "deny"}]
        })), 400)?;
        server.expect_status("POST", "", Some(&json!({
            "name": "source", "network": true, "allowedCidrs": ["1.1.1.1/32"],
            "egressRules": [
                {"transport": "tcp", "cidr": "1.1.1.1/32", "ports": {"start": 80, "end": 80}, "action": "deny"},
                {"transport": "tcp", "cidr": "1.1.1.1/32", "ports": {"start": 443, "end": 443}, "action": "redirect"},
                {"transport": "tcp", "cidr": "1.1.1.1/32", "ports": {"start": 8443, "end": 8443}, "action": "allow"},
                {"transport": "tcp", "cidr": "100.96.0.1/32", "ports": {"start": direct_port, "end": direct_port}, "action": "allow"},
                {"transport": "udp", "cidr": "1.1.1.1/32", "ports": {"start": 124, "end": 124}, "action": "allow"}
            ]
        })), 200)?;
        server.expect_status("POST", "/source/start", None, 400)?;
        server.expect_status("POST", "/source/start?branchable=true", Some(&json!({
            "egressInterceptor": {"address": broker.addr.to_string(), "token": hex::encode(token), "mediated": true}
        })), 200)?;

        for name in ["source", "child"] {
            if name == "child" {
                server.expect_status(
                    "POST",
                    "/source/branches",
                    Some(&json!({"name": "child"})),
                    200,
                )?;
            }
            let response = server.exec(
                name,
                json!(["sh", "-c", "printf hello | nc -w 2 1.1.1.1 443"]),
            )?;
            check(
                response["exitCode"] == 0 && response["stdout"] == "broker-ok\n",
                format!("{name} redirect failed: {response}"),
            )?;
        }
        let flows = broker.flows.lock().unwrap().clone();
        check(
            flows.len() == 2,
            format!("wanted two broker flows: {flows:?}"),
        )?;
        let broker_errors = broker.errors.lock().unwrap().clone();
        check(
            broker_errors.is_empty(),
            format!("broker errors: {broker_errors:?}"),
        )?;
        check(
            flows[0].machine_id != flows[1].machine_id && flows[1].parent_id == flows[0].machine_id,
            format!("branch identity is wrong: {flows:?}"),
        )?;
        check(
            flows.iter().all(|flow| flow.initial_bytes == b"hello"),
            format!("first payload missing: {flows:?}"),
        )?;

        let _ = server.exec(
            "source",
            json!(["sh", "-c", "printf deny | nc -w 1 1.1.1.1 80"]),
        )?;
        let direct_worker = thread::spawn(move || accept_direct(direct_listener));
        let response = server.exec(
            "source",
            json!([
                "sh",
                "-c",
                format!("printf direct | nc -w 2 100.96.0.1 {direct_port}")
            ]),
        )?;
        check(
            response["exitCode"] == 0 && response["stdout"] == "direct-ok\n",
            format!("direct relay failed: {response}"),
        )?;
        direct_worker
            .join()
            .expect("direct server thread panicked")?;
        check(
            broker.flows.lock().unwrap().len() == 2,
            "static allow unexpectedly reached broker",
        )?;

        let _ = server.exec(
            "source",
            json!(["sh", "-c", "printf udp | nc -u -w 1 1.1.1.1 123"]),
        )?;
        let _ = server.exec(
            "source",
            json!(["sh", "-c", "printf udp | nc -u -w 1 1.1.1.1 124"]),
        )?;
        let _ = server.exec("source", json!(["ping", "-c", "1", "-W", "1", "1.1.1.1"]))?;

        let (status, audit) = server.api("GET", "/source/mediation-events", None)?;
        check(status == 200, format!("audit returned {status}: {audit}"))?;
        let events = audit["events"].as_array().ok_or("missing audit events")?;
        let has = |transport: &str, action: &str, reason: Option<&str>| {
            events.iter().any(|event| {
                event["transport"].as_str() == Some(transport)
                    && event["action"].as_str() == Some(action)
                    && reason.is_none_or(|reason| event["reason"].as_str() == Some(reason))
            })
        };
        check(
            has("tcp", "redirect", Some("broker_decision")),
            format!("missing redirect: {audit}"),
        )?;
        check(
            has("udp", "deny", None) && has("icmp", "deny", None),
            format!("missing protocol denial: {audit}"),
        )?;
        check(
            has("tcp", "allow", Some("static_rule")) && has("udp", "allow", Some("local_policy")),
            format!("missing static allow: {audit}"),
        )?;
        check(
            events.iter().any(|event| {
                event["transport"] == "tcp"
                    && event["action"] == "deny"
                    && event["destination"] == "to 1.1.1.1:80"
            }),
            format!("missing TCP denial: {audit}"),
        )?;
        check(
            events
                .iter()
                .any(|event| event["machineId"] == hex::encode(flows[0].machine_id)),
            format!("missing host identity in audit: {audit}"),
        )?;

        server.expect_status("POST", "/child/stop", None, 200)?;
        server.expect_status("DELETE", "/child", None, 200)?;
        broker.stop();
        let _ = server.exec(
            "source",
            json!(["sh", "-c", "printf hello | nc -w 2 1.1.1.1 443"]),
        )?;
        let (_, audit) = server.api("GET", "/source/mediation-events", None)?;
        check(
            audit["events"].as_array().is_some_and(|events| {
                events.iter().any(|event| {
                    event["transport"] == "tcp"
                        && event["action"] == "deny"
                        && event["reason"] == "broker_unavailable"
                })
            }),
            format!("missing fail-closed event: {audit}"),
        )?;
        server.expect_status("POST", "/source/stop", None, 200)?;
        server.expect_status("POST", "/source/start", None, 400)?;
        Ok(())
    }

    #[test]
    #[ignore = "requires a Linux KVM or Apple Silicon macOS host with an installed agent rootfs"]
    fn mediated_egress_vm_end_to_end() {
        run().unwrap();
    }
}
