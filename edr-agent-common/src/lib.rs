#![no_std]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,     // We added this field
    pub cmd: [u8; 16],
}