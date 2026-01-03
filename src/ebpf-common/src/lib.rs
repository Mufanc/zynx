#![no_std]

#[repr(C)]
pub enum Message {
    PathMatches(i32, [u8; 128]),
    NameMatches(i32, [u8; 16]),
    ZygoteFork(i32),
}
