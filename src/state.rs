use rand::{thread_rng, Rng};
use std::num::Wrapping;
use std::time;

pub struct State {
    pub last_ack: Option<time::Instant>,
    pub last_connect: Option<time::Instant>,
    pub last_echo: Option<time::Instant>,
    pub xmit_seq: Wrapping<u16>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            last_ack: None,
            last_connect: None,
            last_echo: None,
            xmit_seq: Wrapping(thread_rng().next_u32() as u16),
        }
    }
}

impl State {
    pub fn next_seq(&mut self) -> u16 {
        self.xmit_seq += Wrapping(1u16);
        self.xmit_seq.0
    }

    pub fn gen_id(&mut self) -> u32 {
        thread_rng().next_u32()
    }
}
