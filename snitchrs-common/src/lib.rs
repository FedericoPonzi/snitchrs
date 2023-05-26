#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

use core::fmt;

#[derive(Copy, Clone)]
#[repr(C)]
pub enum SnitchrsEvent {
    Connect {
        ip: u32,
        local_port: u16,
        remote_port: u16,
    },
    IngressTraffic {
        ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
    },
    EgressTraffic {
        ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
    },
    Disconnect {
        ip: u32,
        remote_port: u16,
        local_port: u16,
    },
}
impl SnitchrsEvent {
    #[inline]
    pub fn new_connect(ip: u32, local_port: u16, remote_port: u16) -> Self {
        Self::Connect {
            ip,
            local_port,
            remote_port,
        }
    }

    #[inline]
    pub fn new_disconnect(ip: u32, remote_port: u16, local_port: u16) -> Self {
        Self::Disconnect {
            ip,
            remote_port,
            local_port,
        }
    }
    #[inline]
    pub fn new_ingress_traffic(
        ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
    ) -> Self {
        Self::IngressTraffic {
            ip,
            remote_port,
            local_port,
            payload_size,
        }
    }
    #[inline]
    pub fn new_egress_traffic(
        ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
    ) -> Self {
        Self::EgressTraffic {
            ip,
            remote_port,
            local_port,
            payload_size,
        }
    }
    pub fn get_ip(&self) -> u32 {
        match self {
            Self::Connect { ip, .. } => *ip,
            Self::Disconnect { ip, .. } => *ip,
            Self::IngressTraffic { ip, .. } => *ip,
            Self::EgressTraffic { ip, .. } => *ip,
        }
    }
}

#[cfg(feature = "user")]
mod userspace {
    use super::*;
    unsafe impl Pod for SnitchrsEvent {}
}
