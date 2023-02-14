use ipnet::IpNet;
use log::info;
use rand::{thread_rng, Rng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::num::Wrapping;
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RealAddr {
    pub addr: SocketAddr,
    pub last_recv: Instant,
    pub xmit_seq: Wrapping<u16>,
}

impl RealAddr {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
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
            va,
            ra,
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

    pub fn get_or_add_ra(&mut self, addr: &SocketAddr) -> &RefRA {
        self.ra_map
            .entry(*addr)
            .and_modify(|v| v.recv())
            .or_insert_with(|| {
                info!("New client [{:?}]", addr);
                RefRA::new(addr)
            })
    }

    pub fn add_or_update_va(&mut self, va: &IpAddr, ra: RefRA) -> Option<&VirtualAddr> {
        if va.is_unspecified() {
            return None;
        }

        let va = self
            .va_map
            .entry(*va)
            .and_modify(|v| {
                v.last_recv = Instant::now();
                if v.ra.addr() != ra.addr() {
                    info!("Change vip [{:?}] to [{:?}]", va, ra.addr());
                    v.ra = ra.clone();
                }
            })
            .or_insert_with(|| {
                info!("New vip [{:?}] at [{:?}]", va, ra.addr());
                VirtualAddr::new(*va, ra)
            });

        Some(va)
    }

    pub fn get_route(&mut self, va: &IpAddr) -> Option<&VirtualAddr> {
        //https://github.com/rust-lang/rfcs/blob/master/text/2094-nll.md#problem-case-3-conditional-control-flow-across-functions
        if self.va_map.contains_key(va) {
            return self.va_map.get(va);
        }

        self.get_rt_route(va)
    }

    pub fn update_va(&mut self, va: &IpAddr, addr: &SocketAddr) -> bool {
        let Self { va_map, ra_map, .. } = self;
        if let Some(v) = va_map.get_mut(va) {
            v.last_recv = Instant::now();
            if v.ra.addr() == *addr {
                v.ra.recv();
            } else if let Some(ra) = ra_map.get(addr) {
                info!("Change vip [{:?}] to [{:?}]", va, ra.addr());
                v.ra = ra.clone();
            } else {
                return false;
            }
            true
        } else {
            false
        }
    }

    pub fn get_rt_route(&mut self, va: &IpAddr) -> Option<&VirtualAddr> {
        let mut gw_ra: Option<RefRA> = None;
        for (net, gw) in &self.vt_routes {
            if net.contains(va) {
                gw_ra = self.va_map.get(gw).map(|va| va.ra.clone());
                if gw_ra.is_some() {
                    break;
                }
            }
        }

        gw_ra.and_then(move |ra| self.add_or_update_va(va, ra))
    }

    pub fn prune(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.va_map.retain(|_, v| {
            if now.duration_since(v.last_recv) > timeout {
                info!("Recycle vip [{:?}] at [{:}]", v.va, v.ra.addr());
                false
            } else {
                true
            }
        });
        self.ra_map.retain(|_, v| {
            if now.duration_since(v.last_recv()) > timeout {
                info!("Recycle client [{:?}]", v.addr());
                false
            } else {
                true
            }
        });
    }
}

impl Display for RouteTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "clients:")?;
        let mut cs = self.va_map.values().collect::<Vec<_>>();
        cs.sort_by(|a, b| a.va.partial_cmp(&b.va).unwrap());
        for v in cs {
            writeln!(
                f,
                "{:} @ {:}, last recv {:.1?}",
                v.va,
                v.ra.addr(),
                v.last_recv.elapsed()
            )?;
        }
        writeln!(f, "routes:")?;
        for r in &self.vt_routes {
            writeln!(f, "{:} -> {:}", r.0, r.1)?;
        }
        Ok(())
    }
}
