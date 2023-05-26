use aya::maps::perf::PerfBufferError;
use aya::maps::AsyncPerfEventArray;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use procfs::net::TcpState;
use procfs::process::{all_processes, FDTarget};
use snitchrs_common::SnitchrsEvent;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp3s0")]
    iface: String,
}

// todo: there is probably a better way to do this, the code works so I will keep it for now.
fn find_process_by_port(port_to_find: u16) -> Result<Option<i32>, anyhow::Error> {
    // get all processes
    let all_procs = all_processes()?;

    // build up a map between socket inodes and processes:
    let mut map = std::collections::HashMap::new();
    for process in all_procs {
        let process = process?;
        if let Ok(fds) = process.fd() {
            for fd in fds {
                if let FDTarget::Socket(inode) = fd?.target {
                    map.insert(inode, process.pid());
                }
            }
        }
    }

    // get the tcp table
    let tcp = procfs::net::tcp()?;
    let tcp6 = procfs::net::tcp6()?;

    for entry in tcp.into_iter().chain(tcp6) {
        if entry.local_address.port() == port_to_find && entry.state == TcpState::Listen {
            if let Some(pid) = map.remove(&entry.inode) {
                return Ok(Some(pid));
            }
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/snitchrs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/snitchrs"
    ))?;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let mut bpf_w = Pin::new(Box::new(bpf));
    let program: &mut SchedClassifier = bpf_w.program_mut("snitchrs").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;
    let program: &mut SchedClassifier =
        bpf_w.program_mut("snitchrs_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf_w.take_map("EVENT_QUEUE").unwrap())?;
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();

    for cpu_id in cpus {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, None)?;

        // process each perf buffer in a separate task
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SnitchrsEvent;
                    let snitchrs_event = unsafe { ptr.read_unaligned() };
                    info!(
                        "snitchr event: {}",
                        snitcher_to_string(&snitchrs_event).unwrap()
                    );
                }
            }

            Ok::<_, anyhow::Error>(())
        });
    }

    info!("Waiting for Ctrl-C...");

    signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c event");

    eprintln!("Exiting...");

    Ok(())
}

fn ip_string(ip: u32) -> String {
    let ipv4_addr = Ipv4Addr::from(ip);
    ipv4_addr.to_string()
}

fn snitcher_to_string(snitcher: &SnitchrsEvent) -> Result<String, anyhow::Error> {
    Ok(match snitcher {
        SnitchrsEvent::Connect {
            ip,
            remote_port,
            local_port,
        } => {
            format!(
                "Connect to ip = {} on port {} from port {}",
                ip_string(*ip),
                local_port,
                remote_port,
            )
        }
        SnitchrsEvent::Disconnect {
            ip,
            remote_port,
            local_port,
        } => {
            format!(
                "Disconnect from ip = {} on port {} from port {}",
                ip_string(*ip),
                local_port,
                remote_port,
            )
        }
        SnitchrsEvent::IngressTraffic {
            ip,
            payload_size,
            local_port,
            remote_port,
        } => {
            format!(
                "Ingress from ip = {} on port {}, to local port: {} with payload size = {}",
                ip_string(*ip),
                remote_port,
                local_port,
                payload_size,
            )
        }
        SnitchrsEvent::EgressTraffic {
            ip,
            remote_port,
            local_port,
            payload_size,
        } => {
            format!(
                "Egress to ip = {} on port {}, from local port: {} with payload size = {}",
                ip_string(*ip),
                local_port,
                remote_port,
                payload_size,
            )
        }
    })
}
