use std::error::Error;
use std::mem;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{cmp::max, io, ptr};

extern crate libc;

type Result = std::result::Result<(), Box<dyn Error>>;

pub trait Reactor {
    fn socket_fd(&self) -> RawFd;
    fn keepalive(&mut self) -> Result;
    fn tunnel_recv(&mut self) -> Result;
    fn network_recv(&mut self) -> Result;
    fn handle_control_connection(&mut self, _fd: RawFd);
}

pub fn poll<T: Reactor>(
    tun_fd: RawFd,
    control_fd: Option<RawFd>,
    mut reactor: T,
    should_stop: Option<Arc<AtomicBool>>,
) -> Result {
    let mut fd_set = unsafe { MaybeUninit::assume_init(MaybeUninit::<libc::fd_set>::uninit()) };

    while !should_stop
        .as_ref()
        .map_or(false, |stop| stop.load(Ordering::Relaxed))
    {
        let socket_fd = reactor.socket_fd();
        let control_fd = control_fd.unwrap_or(0);

        let nfds = max(max(tun_fd, socket_fd), control_fd) + 1;

        unsafe {
            libc::FD_ZERO(&mut fd_set);
            libc::FD_SET(tun_fd, &mut fd_set);
            libc::FD_SET(socket_fd, &mut fd_set);
            if control_fd != 0 {
                libc::FD_SET(control_fd, &mut fd_set);
            }
        }

        let mut timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        if -1
            == unsafe {
                libc::select(
                    nfds,
                    &mut fd_set,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut timeout,
                )
            }
        {
            Err(io::Error::last_os_error())?;
        }

        reactor.keepalive()?;

        if unsafe { libc::FD_ISSET(tun_fd, &fd_set) } {
            reactor.tunnel_recv()?
        }

        if unsafe { libc::FD_ISSET(socket_fd, &fd_set) } {
            reactor.network_recv()?
        }

        if control_fd != 0 && unsafe { libc::FD_ISSET(control_fd, &fd_set) } {
            let mut storage: libc::sockaddr_un = unsafe { mem::zeroed() };
            let mut len = mem::size_of_val(&storage) as libc::socklen_t;
            let fd =
                unsafe { libc::accept(control_fd, &mut storage as *mut _ as *mut _, &mut len) };
            if fd > 0 {
                reactor.handle_control_connection(fd);
            }
        }
    }

    Ok(())
}
