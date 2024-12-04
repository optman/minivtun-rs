use rand::{thread_rng, RngCore};
use std::time;

pub struct State {
    pub last_rebind: Option<time::Instant>,
    pub last_ack: Option<time::Instant>,
    pub last_connect: Option<time::Instant>,
    pub last_echo: Option<time::Instant>,
    pub last_rx: Option<time::Instant>,
    pub xmit_seq: u16,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            last_rebind: None,
            last_ack: None,
            last_connect: None,
            last_echo: None,
            last_rx: None,
            xmit_seq: thread_rng().next_u32() as u16,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

impl State {
    pub fn next_seq(&mut self) -> u16 {
        self.xmit_seq.wrapping_add(1)
    }

    pub fn gen_id(&mut self) -> u32 {
        thread_rng().next_u32()
    }
}
