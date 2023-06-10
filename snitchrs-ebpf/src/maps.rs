use aya_bpf::macros::map;
use aya_bpf::maps::PerfEventArray;
use snitchrs_common::SnitchrsEvent;

#[map]
pub static EVENT_QUEUE: PerfEventArray<SnitchrsEvent> = PerfEventArray::with_max_entries(0, 0);
