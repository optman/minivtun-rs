use std::error::Error;
use std::os::unix::io::RawFd;
use std::{io, mem, ptr};

extern crate libc;

type Result = std::result::Result<(), Box<dyn Error>>;

pub trait Reactor {
    fn keepalive(&mut self) -> Result;
    fn tunnel_recv(&mut self) -> Result;
    fn network_recv(&mut self) -> Result;
}

pub fn poll<T: Reactor>(tun_fd: RawFd, socket_fd: RawFd, mut reactor: T) -> Result {
    let nfds = match tun_fd > socket_fd {
        true => tun_fd,
        false => socket_fd,
    } + 1;

    let mut fd_set: libc::fd_set = unsafe { mem::MaybeUninit::uninit().assume_init() };

    loop {
        unsafe {
            libc::FD_ZERO(&mut fd_set);
            libc::FD_SET(tun_fd, &mut fd_set);
            libc::FD_SET(socket_fd, &mut fd_set);
        }

        let mut timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        match unsafe {
            libc::select(
                nfds,
                &mut fd_set,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut timeout,
            )
        } {
            -1 => Err(io::Error::last_os_error())?,
            _ => {}
        }

        reactor.keepalive()?;

        if unsafe { libc::FD_ISSET(tun_fd, &fd_set) } {
            reactor.tunnel_recv()?
        }

        if unsafe { libc::FD_ISSET(socket_fd, &fd_set) } {
            reactor.network_recv()?
        }
    }
}
