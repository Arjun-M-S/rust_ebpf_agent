#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,         // DAY 1: Who ran it?
    pub cmd: [u8; 16],    // The command
    pub pcomm: [u8; 16],  // DAY 2: What spawned it?
}