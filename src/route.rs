use ipnet::IpNet;
use log::{debug, info};
use rand::{thread_rng, Rng};
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::num::Wrapping;
use std::rc::Rc;
use std::time::{Duration, Instant};

use std::collections::{hash_map::Entry, HashMap};

const RECYCLE_VA_TIMEOUT: Duration = Duration::from_secs(47);

#[derive(Clone)]
pub struct RealAddr {
    pub addr: SocketAddr,
    pub last_recv: Instant,
    pub xmit_seq: Wrapping<u16>,
}

impl RealAddr {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr: addr,
            last_recv: Instant::now(),
            xmit_seq: Wrapping(thread_rng().next_u32() as u16),
        }
    }

    pub fn next_seq(&mut self) -> u16 {
        self.xmit_seq += Wrapping(1u16);
        self.xmit_seq.0
    }
}

#[derive(Clone)]
pub struct RefRA(Rc<RefCell<RealAddr>>);

impl RefRA {
    pub fn new(addr: &SocketAddr) -> Self {
        RefRA(Rc::new(RefCell::new(RealAddr::new(*addr))))
    }

    pub fn recv(&self) {
        self.0.borrow_mut().last_recv = Instant::now();
    }

    pub fn last_recv(&self) -> Instant {
        self.0.borrow().last_recv
    }

    pub fn addr(&self) -> SocketAddr {
        self.0.borrow().addr
    }

    pub fn next_seq(&self) -> u16 {
        self.0.borrow_mut().next_seq()
    }
}

#[derive(Clone)]
pub struct VirtualAddr {
    pub va: IpAddr,
    pub ra: RefRA,
    pub last_recv: Instant,
}

impl VirtualAddr {
    pub fn new(va: IpAddr, ra: RefRA) -> Self {
        Self {
            va: va,
            ra: ra,
            last_recv: Instant::now(),
        }
    }
}

#[derive(Default)]
pub struct RouteTable {
    ra_map: HashMap<SocketAddr, RefRA>,
    va_map: HashMap<IpAddr, VirtualAddr>,
    vt_routes: Vec<(IpNet, IpAddr)>,
}

impl RouteTable {
    pub fn add_route(&mut self, net: &IpNet, gw: &IpAddr) {
        self.vt_routes.push((*net, *gw));
    }

    pub fn get_va(&self, va: &IpAddr) -> Option<VirtualAddr> {
        self.va_map.get(va).map(|v| v.clone())
    }

    pub fn get_ra(&mut self, addr: &SocketAddr) -> Option<RefRA> {
        self.ra_map.get(addr).map(|v| v.clone())
    }

    pub fn get_or_add_ra(&mut self, addr: &SocketAddr) -> RefRA {
        self.ra_map
            .entry(*addr)
            .and_modify(|v| v.recv())
            .or_insert_with(|| {
                info!("New client [{:?}]", addr);
                RefRA::new(addr)
            })
            .clone()
    }

    pub fn add_or_update_va(&mut self, va: &IpAddr, ra: &RefRA) -> Option<VirtualAddr> {
        if va.is_unspecified() {
            return None;
        }

        let mut va = self
            .va_map
            .entry(*va)
            .and_modify(|v| v.last_recv = Instant::now())
            .or_insert_with(|| {
                info!("New vip [{:?}] at [{:?}]", va, ra.addr());
                VirtualAddr::new(*va, ra.clone())
            });
        if va.ra.addr() != ra.addr() {
            info!("Change vip [{:?}] to [{:?}]", va.va, ra.addr());
            va.ra = ra.clone();
        }

        Some(va.clone())
    }

    pub fn get_route(&mut self, va: &IpAddr) -> Option<VirtualAddr> {
        self.va_map
            .get(&va)
            .map(|va| va.clone())
            .or_else(|| self.get_rt_route(va))
    }

    pub fn get_and_update_route(&mut self, va: &IpAddr, addr: &SocketAddr) -> Option<SocketAddr> {
        let ra = match self.get_ra(addr) {
            Some(ra) => ra,
            None => {
                debug!("an orphan packet");
                return None;
            }
        };

        match self.va_map.entry(*va).and_modify(|v| {
            v.last_recv = Instant::now();
            if v.ra.addr() == *addr {
                v.ra.recv();
            } else {
                info!("Change vip [{:?}] to [{:?}]", va, ra.addr());
                v.ra = ra;
            }
        }) {
            Entry::Occupied(va) => Some(va.get().ra.addr()),
            _ => self.get_rt_route(va).map(|va| va.ra.addr()),
        }
    }

    pub fn get_rt_route(&mut self, va: &IpAddr) -> Option<VirtualAddr> {
        let mut gw_ra: Option<RefRA> = None;
        for (net, gw) in &self.vt_routes {
            if net.contains(va) {
                gw_ra = self.get_va(gw).map(|va| va.ra);
                if gw_ra.is_some() {
                    break;
                }
            }
        }

        gw_ra.and_then(|ra| self.add_or_update_va(va, &ra))
    }

    pub fn prune(&mut self) {
        let now = Instant::now();
        self.va_map.retain(|_, v| {
            if now.duration_since(v.last_recv) > RECYCLE_VA_TIMEOUT {
                info!("Recycle vip [{:?}] at [{:}]", v.va, v.ra.addr());
                return false;
            } else {
                return true;
            }
        });
        self.ra_map.retain(|_, v| {
            if now.duration_since(v.last_recv()) > RECYCLE_VA_TIMEOUT {
                info!("Recycle client [{:?}]", v.addr());
                return false;
            } else {
                return true;
            }
        });
    }
}
