// libccp rust bindings
include!(concat!(env!("OUT_DIR"), "/libccp.rs"));

use super::ConnectionObj;

pub extern "C" fn set_cwnd(_dp: *mut ccp_datapath, conn: *mut ccp_connection, cwnd: u32) {
    // get the impl ConnectionObj
    let mut conn: Box<ConnectionObj> = unsafe {
        use std::mem;
        let conn = mem::transmute((*conn).impl_);
        Box::from_raw(conn)
    };

    conn.0.set_cwnd(cwnd);

    // "leak" the Box because *mut ccp::ccp_datapath still owns it
    Box::leak(conn);
}

pub extern "C" fn set_rate_abs(_dp: *mut ccp_datapath, conn: *mut ccp_connection, rate: u32) {
    // get the impl ConnectionObj
    let mut conn: Box<ConnectionObj> = unsafe {
        use std::mem;
        let conn = mem::transmute((*conn).impl_);
        Box::from_raw(conn)
    };

    conn.0.set_rate_abs(rate);

    // "leak" the Box because *mut ccp::ccp_datapath still owns it
    Box::leak(conn);
}

pub extern "C" fn set_rate_rel(_dp: *mut ccp_datapath, conn: *mut ccp_connection, rate: u32) {
    // do nothing, this method is deprecated
}

pub extern "C" fn now() -> u64 {
    time::precise_time_ns()
}

pub extern "C" fn since_usecs(then: u64) -> u64 {
    time::precise_time_ns() - then
}

pub extern "C" fn after_usecs(usecs: u64) -> u64 {
    time::precise_time_ns() + usecs * 1_000
}
