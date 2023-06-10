#![no_std]
#![feature(strict_provenance)]
#![no_main]

mod bindings_linux_in;
mod maps;
mod snitchrs_classifier;
mod snitchrs_syscall_accept;
mod snitchrs_syscall_connect;

pub use snitchrs_classifier::*;
pub use snitchrs_syscall_accept::*;
pub use snitchrs_syscall_connect::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
