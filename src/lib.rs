//! Rust bindings for [libccp](https://github.com/ccp-project/libccp).
//! This crate is useful for writing CCP datapaths in Rust.
//!
//! Users need to implement two traits: `Datapath` and `CongestionOps`.
//! `Datapath` implements not specific to a single connection.
//! `CongestionOps` implements connection-level events.

// Made necessary by use of `mashup!`.
// https://github.com/dtolnay/mashup/issues/19
// Need +22 recursion_limit per struct field.
// The longest struct in this crate is `Primitives` with 15 fields, so
// we need recursion_limit >= 330 + some large constant.
// So we pick 512.
#![recursion_limit = "512"]

/// Bindgen-generated libccp bindings.
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
mod ccp;

extern crate failure;
use failure::bail;
#[macro_use]
extern crate mashup;
extern crate time;

pub trait Datapath {
    /// How should libccp communicate with the CCP congestion control algorithm?
    fn send_msg(&mut self, msg: &[u8]);
}

struct DatapathObj(Box<Datapath>);

/// When the datapath receives an IPC message from the congestion
/// control algorithm, call this function to tell libccp about it.
pub fn recv_msg(msg: &mut [u8]) -> Result<(), failure::Error> {
    let buf_len = msg.len();
    let ok = unsafe {
        ccp::ccp_read_msg(
            msg.as_mut_ptr() as *mut std::os::raw::c_char,
            buf_len as i32,
        )
    };

    if ok < 0 {
        bail!("ccp_read_msg failed with {:?}", ok);
    }

    Ok(())
}

/// Initialize libccp and pass it an implementation of `Datapath` functionality.
pub fn init_with_datapath<T: Datapath + 'static>(dp: T) -> Result<(), failure::Error> {
    // need 2 levels of Box so we can avoid passing a fat pointer down
    let dp = Box::new(DatapathObj(Box::new(dp)));
    let mut dp = ccp::ccp_datapath {
        set_cwnd: Some(ccp::set_cwnd),
        set_rate_abs: Some(ccp::set_rate_abs),
        set_rate_rel: Some(ccp::set_rate_rel),
        time_zero: time::precise_time_ns(),
        now: Some(ccp::now),
        since_usecs: Some(ccp::since_usecs),
        after_usecs: Some(ccp::after_usecs),
        send_msg: Some(ccp::send_msg),
        impl_: Box::into_raw(dp) as *mut std::os::raw::c_void,
    };

    let ok = unsafe { ccp::ccp_init(&mut dp) };
    if ok < 0 {
        bail!("Could not initialize ccp datapath");
    }

    Ok(())
}

/// Call this function only if you will no longer use libccp.
/// It will de-allocate libccp's internal state.
pub fn deinit() {
    unsafe { ccp::ccp_free() }
}

pub trait CongestionOps {
    fn set_cwnd(&mut self, cwnd: u32);
    fn set_rate_abs(&mut self, rate: u32);
}

struct ConnectionObj(Box<CongestionOps>);

macro_rules! setters {
    ( $s:ident => $($x: ident : $t: ty),+ ) => {
        mashup! { $(
            m["fname" $x] = with_ $x;
        )* }

        m! {
        impl $s { $(
            pub fn "fname" $x (mut self, val: $t) -> Self { (self.0).$x = val; self }
        )*
	}
	}
    };
}

mod flow_info;
mod primitives;

pub use crate::flow_info::FlowInfo;
pub use crate::primitives::Primitives;

pub struct Connection(*mut ccp::ccp_connection);

impl Connection {
    /// Call this function when a connection starts.
    pub fn start(conn: Box<CongestionOps>, flow_info: FlowInfo) -> Result<Self, failure::Error> {
        let conn_obj = Box::new(ConnectionObj(conn));
        let conn = unsafe {
            ccp::ccp_connection_start(
                Box::into_raw(conn_obj) as *mut std::os::raw::c_void,
                &mut flow_info.get_dp_info(),
            )
        };

        if conn.is_null() {
            bail!("Could not initialize connection");
        }

        Ok(Connection(conn))
    }

    /// Call this function when a connection ends.
    pub fn end(self) {
        unsafe {
            let index = (*(self.0)).index;
            ccp::ccp_connection_free(index);
        }
    }

    /// Inform libccp of new measurements.
    pub fn load_primitives(&mut self, prims: Primitives) {
        unsafe {
            (*(self.0)).prims = prims.0;
        }
    }

    pub fn primitives(&self) -> Primitives {
        let pr = unsafe { &(*(self.0)).prims };
        pr.into()
    }

    /// Tell libccp to invoke. This will run the congestion control's datapath program,
    /// and potentially result in calls to the `CongestionOps` callbacks.
    /// Therefore, ensure that when you call this function, you are not holding locks that
    /// the `CongestionOps` functionality tries to acquire - this will deadlock.
    pub fn invoke(&mut self) -> Result<(), failure::Error> {
        let ok = unsafe { ccp::ccp_invoke(self.0) };

        if ok < 0 {
            bail!("CCP Invoke error: {:?}", ok);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // mock implementation
    struct Dp {
        expected_msgs: Vec<Option<Vec<u8>>>,
    }

    impl Datapath for Dp {
        fn send_msg(&mut self, msg: &[u8]) {
            let expected_send_msg: Vec<u8> = self.expected_msgs.pop().unwrap().unwrap();
            println!(
                "this message: {:?}, remaining messsages: {:?}",
                expected_send_msg, self.expected_msgs
            );
            assert_eq!(msg, &expected_send_msg[..msg.len()]);
        }
    }

    struct Cn {
        curr_cwnd: u32,
        curr_rate: u32,
    }

    impl CongestionOps for Cn {
        fn set_cwnd(&mut self, cwnd: u32) {
            self.curr_cwnd = cwnd;
        }

        fn set_rate_abs(&mut self, rate: u32) {
            self.curr_rate = rate;
        }
    }

    fn make_dp(expected_msgs: Vec<Option<Vec<u8>>>) {
        let dp = Dp { expected_msgs };
        init_with_datapath(dp).unwrap();
    }

    fn free_dp() {
        deinit()
    }

    fn make_conn() -> Connection {
        let cn = Cn {
            curr_cwnd: 0,
            curr_rate: 0,
        };

        let fi = FlowInfo::default()
            .with_init_cwnd(100)
            .with_mss(10)
            .with_four_tuple(1, 2, 3, 4);

        Connection::start(Box::new(cn), fi).unwrap()
    }

    #[test]
    fn basic() {
        let basic_prog_uid = 4;

        #[rustfmt::skip]
        make_dp(vec![
            Some(vec![ //  close msg
                0x01, 0,
                16, 0,
                0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            Some(vec![ // report msg
                0x01, 0x00,                                     // type 
                0x18, 0x00,                                     // len
                0x01, 0x00, 0x00, 0x00,                         // sockid
                basic_prog_uid, 0x00, 0x00, 0x00,               // program_uid
                0x01, 0x00, 0x00, 0x00,                         // num_fields
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fields
            ]),
            Some(vec![ // create msg
                0x00,0x00,
                0x20,0x00,
                0x01,0x00,0x00,0x00,
                0x64,0x00,0x00,0x00,
                0x0a,0x00,0x00,0x00,
                0x01,0x00,0x00,0x00,
                0x02,0x00,0x00,0x00,
                0x03,0x00,0x00,0x00,
                0x04,0x00,0x00,0x00,
            ]),
        ]);

        let mut c = make_conn();

        #[rustfmt::skip]
        let mut install_basic = vec![
            2, 0,                                           // INSTALL                                                     
            116, 0,                                         // length = 0x74 = 116
            1, 0, 0, 0,                                     // sock_id = 1                                                 
            basic_prog_uid, 0, 0, 0,                        // program_uid
            1, 0, 0, 0,                                     // num_events = 1                                              
            5, 0, 0, 0,                                     // num_instrs = 5                                              
            1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, // event { flag-idx=1, num-flag=1, body-idx=2, num-body=3 }
            2, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 1, 0, 0, 0, 0, // (def (volatile Report.foo 0))
            1, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, // (when true
            0, 7, 0, 0, 0, 0, 5, 0, 0, 0, 0, 1, 1, 0, 0, 0, //      ----------------(+ Report.foo 1)
            1, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 7, 0, 0, 0, 0, //     (bind Report.foo ^^^^^^^^^^^^^^^^)
            1, 2, 2, 0, 0, 0, 2, 2, 0, 0, 0, 1, 1, 0, 0, 0, //     (bind __shouldReport true)
        ];

        #[rustfmt::skip]
        let mut changeprog_msg = vec![
            4, 0,                                           // type
            12, 0,                                          // length 
            1, 0, 0, 0,                                     // sock id
            basic_prog_uid, 0, 0, 0,                        // program_uid
            0, 0, 0, 0,                                     // extra fields
        ];

        recv_msg(&mut install_basic).unwrap();
        recv_msg(&mut changeprog_msg).unwrap();
        c.invoke();

        c.end();
        free_dp();
        return;
    }
}
