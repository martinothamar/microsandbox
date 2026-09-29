//! The parts of `dns_sd.h` (exported by libSystem) the macOS resolver
//! uses, and an owned query.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::os::fd::RawFd;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice;

use super::answers::{Collector, Reply};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// More replies follow in the same batch (`kDNSServiceFlagsMoreComing`).
pub(super) const FLAGS_MORE_COMING: DNSServiceFlags = 0x1;

/// The reply adds a record rather than removing one (`kDNSServiceFlagsAdd`).
pub(super) const FLAGS_ADD: DNSServiceFlags = 0x2;

/// Deliver CNAMEs and negative answers (`kDNSServiceFlagsReturnIntermediates`).
/// Without it, a query for a name that does not exist never completes.
const FLAGS_RETURN_INTERMEDIATES: DNSServiceFlags = 0x1000;

/// Query on every interface, as the system resolver chooses
/// (`kDNSServiceInterfaceIndexAny`).
const INTERFACE_INDEX_ANY: u32 = 0;

pub(super) const ERR_NO_ERROR: DNSServiceErrorType = 0;
pub(super) const ERR_NO_SUCH_NAME: DNSServiceErrorType = -65538;
pub(super) const ERR_NO_SUCH_RECORD: DNSServiceErrorType = -65554;
const ERR_SERVICE_NOT_RUNNING: DNSServiceErrorType = -65563;
const ERR_DEFUNCT_CONNECTION: DNSServiceErrorType = -65569;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type DNSServiceRef = *mut c_void;
pub(super) type DNSServiceFlags = u32;
pub(super) type DNSServiceErrorType = i32;

type DNSServiceQueryRecordReply = unsafe extern "C" fn(
    sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32,
    error_code: DNSServiceErrorType,
    fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    ttl: u32,
    context: *mut c_void,
);

/// One `DNSServiceQueryRecord` operation and the collector its replies
/// feed. Dropping it cancels the query.
pub(super) struct ActiveQuery {
    sd_ref: DNSServiceRef,
    /// Owned by this query. Every access, from the reply callback or from
    /// [`Self::collector`], goes through this pointer, and the callback only
    /// runs inside [`Self::process`], which takes `&mut self`.
    collector: *mut Collector,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ActiveQuery {
    /// Start querying `name` (in `dns_sd` presentation format) for records
    /// of `rrtype` and `rrclass`.
    pub(super) fn start(
        name: &CStr,
        rrtype: u16,
        rrclass: u16,
        collector: Collector,
    ) -> io::Result<Self> {
        let collector = Box::into_raw(Box::new(collector));
        let mut sd_ref = ptr::null_mut();
        // SAFETY: `name` is NUL-terminated, `sd_ref` is a valid out pointer,
        // and `collector` stays allocated until this query is deallocated.
        let status = unsafe {
            DNSServiceQueryRecord(
                &mut sd_ref,
                FLAGS_RETURN_INTERMEDIATES,
                INTERFACE_INDEX_ANY,
                name.as_ptr(),
                rrtype,
                rrclass,
                query_reply,
                collector.cast(),
            )
        };
        if status != ERR_NO_ERROR {
            // SAFETY: the call failed, so dns_sd never saw the pointer and
            // the callback will not run.
            drop(unsafe { Box::from_raw(collector) });
            return Err(service_error(status));
        }
        Ok(Self { sd_ref, collector })
    }

    /// The socket that becomes readable when mDNSResponder has replies.
    pub(super) fn socket(&self) -> io::Result<RawFd> {
        // SAFETY: `sd_ref` is a live query reference.
        match unsafe { DNSServiceRefSockFD(self.sd_ref) } {
            -1 => Err(io::Error::other(
                "macOS DNS service returned no socket for the query",
            )),
            fd => Ok(fd),
        }
    }

    /// Read every reply queued on the socket and pass it to the collector.
    /// Blocks until a whole reply has arrived.
    pub(super) fn process(&mut self) -> io::Result<()> {
        // SAFETY: `sd_ref` is a live query reference that no other thread
        // uses; the callback it invokes only touches `self.collector`.
        match unsafe { DNSServiceProcessResult(self.sd_ref) } {
            ERR_NO_ERROR => Ok(()),
            status => Err(service_error(status)),
        }
    }

    /// The collector that replies have been fed into.
    pub(super) fn collector(&mut self) -> &mut Collector {
        // SAFETY: the collector is owned by this query and the callback does
        // not run while `self` is mutably borrowed here.
        unsafe { &mut *self.collector }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ActiveQuery {
    fn drop(&mut self) {
        // SAFETY: deallocation cancels the query and closes its socket, after
        // which the callback can no longer run and the collector can be freed.
        unsafe {
            DNSServiceRefDeallocate(self.sd_ref);
            drop(Box::from_raw(self.collector));
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Describe a `DNSServiceErrorType` returned by the service.
pub(super) fn service_error(status: DNSServiceErrorType) -> io::Error {
    match status {
        ERR_SERVICE_NOT_RUNNING => {
            io::Error::new(io::ErrorKind::NotConnected, "mDNSResponder is not running")
        }
        ERR_DEFUNCT_CONNECTION => io::Error::new(
            io::ErrorKind::ConnectionReset,
            "connection to mDNSResponder was closed",
        ),
        status => io::Error::other(format!("macOS DNS service error {status}")),
    }
}

/// `DNSServiceQueryRecordReply` for [`ActiveQuery`].
unsafe extern "C" fn query_reply(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    _interface_index: u32,
    error_code: DNSServiceErrorType,
    fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    ttl: u32,
    context: *mut c_void,
) {
    // SAFETY: `context` is the collector pointer registered by
    // `ActiveQuery::start`, alive for as long as the query.
    let collector = unsafe { &mut *context.cast::<Collector>() };
    let fullname = if fullname.is_null() {
        &[][..]
    } else {
        // SAFETY: dns_sd passes a NUL-terminated name valid for this call.
        unsafe { CStr::from_ptr(fullname) }.to_bytes()
    };
    let rdata = if rdata.is_null() {
        &[][..]
    } else {
        // SAFETY: dns_sd passes `rdlen` bytes of rdata valid for this call.
        unsafe { slice::from_raw_parts(rdata.cast::<u8>(), usize::from(rdlen)) }
    };
    let reply = Reply {
        flags,
        error_code,
        fullname,
        rrtype,
        rrclass,
        rdata,
        ttl,
    };
    // A panic must not unwind into C, which would abort the process. The
    // collector only ends up with a failure that ends the query.
    if panic::catch_unwind(AssertUnwindSafe(|| collector.accept(reply))).is_err() {
        collector.fail(io::Error::other(
            "decoding a macOS DNS service reply panicked",
        ));
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Foreign
//--------------------------------------------------------------------------------------------------

unsafe extern "C" {
    fn DNSServiceQueryRecord(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        callback: DNSServiceQueryRecordReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> c_int;

    fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;

    fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hickory_net::proto::rr::RecordType;

    use super::*;

    /// Invoke the reply callback the way dns_sd does, with `collector` as
    /// the context.
    fn deliver(
        collector: &mut Collector,
        error_code: DNSServiceErrorType,
        fullname: Option<&CStr>,
        rrtype: RecordType,
        rdata: Option<&[u8]>,
    ) {
        let (rdata_ptr, rdlen) = rdata.map_or((ptr::null(), 0), |rdata| {
            (rdata.as_ptr().cast(), u16::try_from(rdata.len()).unwrap())
        });
        // SAFETY: the pointers are valid for the call and `context` is a
        // live collector, as dns_sd guarantees for a real reply.
        unsafe {
            query_reply(
                ptr::null_mut(),
                FLAGS_ADD,
                0,
                error_code,
                fullname.map_or(ptr::null(), CStr::as_ptr),
                u16::from(rrtype),
                1,
                rdlen,
                rdata_ptr,
                60,
                ptr::from_mut(collector).cast(),
            );
        }
    }

    #[test]
    fn callback_feeds_the_registered_collector() {
        let mut collector = Collector::new(RecordType::A);
        deliver(
            &mut collector,
            ERR_NO_ERROR,
            Some(c"example.com."),
            RecordType::A,
            Some(&[192, 0, 2, 1]),
        );
        assert_eq!(collector.finish().unwrap().unwrap().len(), 1);
    }

    #[test]
    fn callback_tolerates_null_name_and_rdata() {
        let mut collector = Collector::new(RecordType::A);
        deliver(
            &mut collector,
            ERR_NO_SUCH_RECORD,
            None,
            RecordType::A,
            None,
        );
        assert!(collector.finish().unwrap().unwrap().is_empty());

        let mut collector = Collector::new(RecordType::A);
        deliver(
            &mut collector,
            ERR_NO_ERROR,
            Some(c"example.com."),
            RecordType::A,
            None,
        );
        assert_eq!(
            collector.finish().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
