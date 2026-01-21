#![no_std]

// We use `cfg_attr` to say: 
// "Only derive Serialize and Deserialize IF the 'user' feature is enabled."
#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub cmd: [u8; 16],
}