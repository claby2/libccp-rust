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

/// Datapath-wide functionality.
/// ```
/// struct Dp(std::os::unix::net::UnixDatagram);
/// impl libccp::DatapathOps for Dp {
///     fn send_msg(&mut self, msg: &[u8]) {
///         self.0.send(msg).unwrap_or_else(|_| (0));
///     }
/// }
/// ```
pub trait DatapathOps {
    /// How should libccp communicate with the CCP congestion control algorithm?
    /// An `impl Datapath` should contain some IPC strategy, and transmit `msg` via that.
    fn send_msg(&mut self, msg: &[u8]);
}

struct DatapathObj(Box<DatapathOps>);

pub struct Datapath(i8);

impl Datapath {
    /// When the datapath receives an IPC message from the congestion
    /// control algorithm, call this function to tell libccp about it.
    pub fn recv_msg(&mut self, msg: &mut [u8]) -> Result<(), failure::Error> {
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
}

/// Initialize libccp and pass it an implementation of `Datapath` functionality.
pub fn init_with_datapath<T: DatapathOps + 'static>(dp: T) -> Result<Datapath, failure::Error> {
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
    match ok {
        i if i >= 0 => (),    // ok
        -1 => unreachable!(), // ccp_init checks that we didn't pass null function pointers in with `dp`, but we didn't
        -2 => bail!("Cannot initialize libccp twice"),
        -3 | -4 | -5 => bail!("Could not alloc"),
        i if i < -5 => unreachable!(), // ccp_init only returns error codes -1 | -2 | -3 | -4 | -5
        _ => unreachable!(), // because rust can't figure out that (i < -5 | -5 | -4 | -3 | -2 | -1 | i >= 0) is exhaustive
    };

    Ok(Datapath(0))
}

/// Call this function only if you will no longer use libccp.
/// It will de-allocate libccp's internal state.
pub fn deinit(_: Datapath) {
    unsafe { ccp::ccp_free() }
}

/// Implement this trait on the type that holds
/// per-connection state.
/// ```
/// struct Cn {
///     curr_cwnd: u32,
///     curr_rate: u32,
/// }
///
/// impl libccp::CongestionOps for Cn {
///     fn set_cwnd(&mut self, cwnd: u32) {
///         self.curr_cwnd = cwnd;
///     }
///
///     fn set_rate_abs(&mut self, rate: u32) {
///         self.curr_rate = rate;
///     }
/// }
/// ```
pub trait CongestionOps {
    fn set_cwnd(&mut self, cwnd: u32);
    fn set_rate_abs(&mut self, rate: u32);
}

impl CongestionOps {
    fn downcast_mut<T: CongestionOps>(&mut self) -> &mut T {
        unsafe { &mut *(self as *mut Self as *mut T) }
    }
}

struct ConnectionObj(Box<dyn CongestionOps>);

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

pub struct Connection<T: CongestionOps + 'static>(
    *mut ccp::ccp_connection,
    Box<ConnectionObj>,
    std::marker::PhantomData<T>,
);

impl<T: CongestionOps + 'static> Connection<T> {
    /// Call this function when a connection starts.
    /// `conn: impl CongestionOps` represents per-connection state,
    /// and how to mutate it in response to changing congestion windows
    /// or rates.
    /// You *must* call `init_with_datapath` *before* this. To enforce this,
    /// you must pass in a token, `DatapathInitialized`, which only that function
    /// can give you.
    pub fn start(token: &Datapath, conn: T, flow_info: FlowInfo) -> Result<Self, failure::Error> {
        if token.0 != 0 {
            bail!("Must initialize datapath (init_with_datapath) before Connection::start");
        }

        let conn_obj = Box::new(ConnectionObj(Box::new(conn) as Box<dyn CongestionOps>));
        let ops_raw_pointer = Box::into_raw(conn_obj);
        let conn_obj = unsafe { Box::from_raw(ops_raw_pointer.clone()) };
        let conn = unsafe {
            ccp::ccp_connection_start(
                Box::into_raw(conn_obj) as *mut std::os::raw::c_void,
                &mut flow_info.get_dp_info(),
            )
        };

        if conn.is_null() {
            bail!("Could not initialize connection");
        }

        Ok(Connection(
            conn,
            unsafe { Box::from_raw(ops_raw_pointer) },
            Default::default(),
        ))
    }

    /// Get a mutable reference to the T: impl CongestionOps
    /// that was passed in at the beginning.
    pub fn conn_state(&mut self) -> &mut T {
        let y = &mut *(self.1);
        y.0.downcast_mut::<T>()
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

    /// Call this function when a connection ends.
    pub fn end(self) {
        unsafe {
            let index = (*(self.0)).index;
            ccp::ccp_connection_free(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // mock implementation
    struct Dp {
        expected_msgs: Vec<Option<Vec<u8>>>,
    }

    impl DatapathOps for Dp {
        fn send_msg(&mut self, msg: &[u8]) {
            if self.expected_msgs.is_empty() {
                return;
            }

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

    fn make_dp(expected_msgs: Vec<Option<Vec<u8>>>) -> Datapath {
        let dp = Dp { expected_msgs };
        init_with_datapath(dp).unwrap()
    }

    fn free_dp(d: Datapath) {
        deinit(d)
    }

    fn make_conn(d: &Datapath) -> Connection<Cn> {
        let cn = Cn {
            curr_cwnd: 19,
            curr_rate: 89,
        };

        let fi = FlowInfo::default()
            .with_init_cwnd(100)
            .with_mss(10)
            .with_four_tuple(1, 2, 3, 4);

        let mut c = Connection::start(d, cn, fi).unwrap();
        assert_eq!(c.conn_state().curr_cwnd, 19);
        c
    }

    #[test]
    fn basic() {
        let basic_prog_uid = 4;

        #[rustfmt::skip]
        let mut dp = make_dp(vec![
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

        let mut c = make_conn(&dp);

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

        dp.recv_msg(&mut install_basic).unwrap();
        dp.recv_msg(&mut changeprog_msg).unwrap();
        c.invoke().unwrap();

        c.end();
        free_dp(dp);
        return;
    }
}
