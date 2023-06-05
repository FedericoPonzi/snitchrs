#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum SnitchrsDirection {
    Ingress,
    Egress,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub enum SnitchrsEvent {
    Connect {
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        direction: SnitchrsDirection,
    },
    Traffic {
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
        direction: SnitchrsDirection,
    },
    Disconnect {
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        direction: SnitchrsDirection,
    },
    ConnectFunc {
        destination_ip: u32,
        pid: u32,
        destination_port: u16,
        padd: u16, // just used for padding, otherwise the load will complain. See point #10: https://docs.cilium.io/en/v1.7/bpf/
    },
}
impl SnitchrsEvent {
    #[inline]
    pub fn new_connect(
        remote_ip: u32,
        local_port: u16,
        remote_port: u16,
        direction: SnitchrsDirection,
    ) -> Self {
        Self::Connect {
            remote_ip,
            local_port,
            remote_port,
            direction,
        }
    }

    #[inline]
    pub fn new_disconnect(
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        direction: SnitchrsDirection,
    ) -> Self {
        Self::Disconnect {
            remote_ip,
            remote_port,
            local_port,
            direction,
        }
    }
    #[inline]
    pub fn new_traffic(
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
        direction: SnitchrsDirection,
    ) -> Self {
        Self::Traffic {
            remote_ip,
            remote_port,
            local_port,
            payload_size,
            direction,
        }
    }
    #[inline]
    pub fn new_connect_func(destination_ip: u32, destination_port: u16, pid: u32) -> Self {
        Self::ConnectFunc {
            destination_ip,
            destination_port,
            pid,
            padd: 0,
        }
    }
}

#[cfg(feature = "user")]
mod userspace {
    use super::*;
    unsafe impl Pod for SnitchrsEvent {}
}
