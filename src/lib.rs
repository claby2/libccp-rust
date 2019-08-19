//! Rust bindings for [libccp](https://github.com/ccp-project/libccp).
//! This crate is useful for writing CCP datapaths in Rust.
//!
//! Users need to implement two traits: `Datapath` and `CongestionOps`.
//! `Datapath` implements not specific to a single connection.
//! `CongestionOps` implements connection-level events.

/// Bindgen-generated libccp bindings.
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
mod ccp;

extern crate failure;
use failure::bail;
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

    /// How should libccp log messages?
    /// By default, silently drop them.
    fn log(&self, _level: ccp::ccp_log_level, _msg: &str) {}
}

struct DatapathObj(Box<dyn DatapathOps>);

/// Represents datapath functionality.
/// libccp state is freed when this is dropped.
pub struct Datapath(i8);

impl Datapath {
    /// Initialize libccp and pass it an implementation of `Datapath` functionality.
    pub fn init<T: DatapathOps + 'static>(dp: T) -> Result<Self, failure::Error> {
        // need 2 levels of Box so we can avoid passing a fat pointer down
        let dp = Box::new(DatapathObj(Box::new(dp)));
        let mut dp = ccp::ccp_datapath {
            set_cwnd: Some(ccp::set_cwnd),
            set_rate_abs: Some(ccp::set_rate_abs),
            time_zero: time::precise_time_ns(),
            now: Some(ccp::now),
            since_usecs: Some(ccp::since_usecs),
            after_usecs: Some(ccp::after_usecs),
            send_msg: Some(ccp::send_msg),
            log: Some(ccp::log),
            state: std::ptr::null_mut(),
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

    /// When the datapath receives an IPC message from the congestion
    /// control algorithm, call this function to tell libccp about it.
    pub fn recv_msg(&self, msg: &mut [u8]) -> Result<(), failure::Error> {
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

impl Drop for Datapath {
    fn drop(&mut self) {
        unsafe { ccp::ccp_free() }
    }
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

impl dyn CongestionOps {
    fn downcast<T: CongestionOps>(&self) -> &T {
        unsafe { &*(self as *const Self as *const T) }
    }

    fn downcast_mut<T: CongestionOps>(&mut self) -> &mut T {
        unsafe { &mut *(self as *mut Self as *mut T) }
    }
}

struct ConnectionObj(Box<dyn CongestionOps>);

macro_rules! setters {
    ( $s:ident => $($x: ident : $t: ty),+ ) => {
        paste::item! { impl $s { $(
            pub fn [<with_ $x>] (mut self, val: $t) -> Self { (self.0).$x = val; self }
        )*
	} }
    };
}

mod flow_info;
mod primitives;

pub use crate::flow_info::FlowInfo;
pub use crate::primitives::Primitives;

/// An individual Connection.
/// Connections cannot outlive the `Datapath` they belong to, since they contain
/// a pointer to memory that is freed when `Datapath` is dropped.
/// So, their lifetime is `'dp` from the `&'dp Datapath`.
///
/// You can regain access to the `impl CongestionOps` by dereferencing `Connection`
/// ```
/// struct Dp();
/// impl libccp::DatapathOps for Dp {
///     fn send_msg(&mut self, _: &[u8]) { /* ___ */ }
/// }
/// struct Cn(u32);
/// impl libccp::CongestionOps for Cn {
///     fn set_cwnd(&mut self, cwnd: u32) { /* ___ */ }   
///     fn set_rate_abs(&mut self, cwnd: u32) { /* ___ */ }   
/// }
/// fn main() {
///     let d = libccp::Datapath::init(Dp()).unwrap();
///     let mut c = libccp::Connection::start(&d, Cn(0), libccp::FlowInfo::default()).unwrap();
///     c.load_primitives(libccp::Primitives::default());
///     c.0 = 1;
/// }
/// ```
pub struct Connection<'dp, T: CongestionOps + 'static>(
    *mut ccp::ccp_connection,
    Box<ConnectionObj>,
    &'dp Datapath,
    std::marker::PhantomData<T>,
);

impl<'dp, T: CongestionOps + 'static> Connection<'dp, T> {
    /// Call this function when a connection starts.
    /// `conn: impl CongestionOps` represents per-connection state,
    /// and how to mutate it in response to changing congestion windows
    /// or rates.
    pub fn start(
        token: &'dp Datapath,
        conn: T,
        flow_info: FlowInfo,
    ) -> Result<Self, failure::Error> {
        if token.0 != 0 {
            unreachable!();
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
            token,
            Default::default(),
        ))
    }

    /// Inform libccp of new measurements.
    pub fn load_primitives(&mut self, prims: Primitives) {
        unsafe {
            (*(self.0)).prims = prims.0;
        }
    }

    pub fn primitives(&self, _token: &Datapath) -> Primitives {
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

unsafe impl<'dp, T: CongestionOps> Send for Connection<'dp, T> {}

impl<'dp, T: CongestionOps> Drop for Connection<'dp, T> {
    fn drop(&mut self) {
        unsafe {
            let index = (*(self.0)).index;
            ccp::ccp_connection_free(index);
        }
    }
}

impl<'dp, T: CongestionOps> std::ops::Deref for Connection<'dp, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        let y = &*(self.1);
        y.0.downcast::<T>()
    }
}

impl<'dp, T: CongestionOps> std::ops::DerefMut for Connection<'dp, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let y = &mut *(self.1);
        y.0.downcast_mut::<T>()
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
        Datapath::init(dp).unwrap()
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

        let c = Connection::start(d, cn, fi).unwrap();
        assert_eq!(c.curr_cwnd, 19);
        c
    }

    use lazy_static::lazy_static;
    use std::sync::Mutex;

    lazy_static! {
        static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn primitives() {
        let _l = TEST_MUTEX.lock().unwrap();

        let prims_prog_uid = 5;

        #[rustfmt::skip]
        let dp = make_dp(vec![
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
                prims_prog_uid, 0x00, 0x00, 0x00,               // program_uid
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
        let mut install_prims = vec![
            2, 0,                                           // INSTALL                                                     
            116, 0,                                         // length = 0x74 = 116
            1, 0, 0, 0,                                     // sock_id = 1                                                 
            prims_prog_uid, 0, 0, 0,                        // program_uid
            1, 0, 0, 0,                                     // num_events = 1                                              
            5, 0, 0, 0,                                     // num_instrs = 5                                              
            1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, // event { flag-idx=1, num-flag=1, body-idx=2, num-body=3 }
            2, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 1, 0, 0, 0, 0, // (def (volatile Report.foo 0))
            1, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, // (when true
            0, 7, 0, 0, 0, 0, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, //      ----------------(+ Report.foo Ack.bytes_acked)
            1, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 7, 0, 0, 0, 0, //     (bind Report.foo ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^)
            1, 2, 2, 0, 0, 0, 2, 2, 0, 0, 0, 1, 1, 0, 0, 0, //     (bind __shouldReport true)
        ];

        #[rustfmt::skip]
        let mut changeprog_msg = vec![
            4, 0,                                           // type
            12, 0,                                          // length 
            1, 0, 0, 0,                                     // sock id
            prims_prog_uid, 0, 0, 0,                        // program_uid
            0, 0, 0, 0,                                     // extra fields
        ];

        dp.recv_msg(&mut install_prims).unwrap();
        dp.recv_msg(&mut changeprog_msg).unwrap();

        c.load_primitives(
            Primitives::default()
                .with_bytes_acked(1)
                .with_rtt_sample_us(100),
        );
        c.invoke().unwrap();
    }

    #[test]
    fn primitives_multiple() {
        let _l = TEST_MUTEX.lock().unwrap();

        let prims_prog_uid = 5;

        #[rustfmt::skip]
        let close = 
            Some(vec![ //  close msg
                0x01, 0,
                16, 0,
                0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]);

        #[rustfmt::skip]
        let report = 
            Some(vec![ // report msg
                0x01, 0x00,                                     // type 
                0x18, 0x00,                                     // len
                0x01, 0x00, 0x00, 0x00,                         // sockid
                prims_prog_uid, 0x00, 0x00, 0x00,               // program_uid
                0x01, 0x00, 0x00, 0x00,                         // num_fields
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fields
            ]);

        #[rustfmt::skip]
        let create = 
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
            ]);

        let mut msgs = vec![close];

        // 4 reports
        msgs.push(report.clone());
        msgs.push(report.clone());
        msgs.push(report.clone());
        msgs.push(report);

        msgs.push(create);

        let dp = make_dp(msgs);
        let mut c = make_conn(&dp);

        #[rustfmt::skip]
        let mut install_prims = vec![
            2, 0,                                           // INSTALL                                                     
            116, 0,                                         // length = 0x74 = 116
            1, 0, 0, 0,                                     // sock_id = 1                                                 
            prims_prog_uid, 0, 0, 0,                        // program_uid
            1, 0, 0, 0,                                     // num_events = 1                                              
            5, 0, 0, 0,                                     // num_instrs = 5                                              
            1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, // event { flag-idx=1, num-flag=1, body-idx=2, num-body=3 }
            2, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 1, 0, 0, 0, 0, // (def (volatile Report.foo 0))
            1, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 1, 0, 0, 0, // (when true
            0, 7, 0, 0, 0, 0, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, //      ----------------(+ Report.foo Ack.bytes_acked)
            1, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 7, 0, 0, 0, 0, //     (bind Report.foo ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^)
            1, 2, 2, 0, 0, 0, 2, 2, 0, 0, 0, 1, 1, 0, 0, 0, //     (bind __shouldReport true)
        ];

        #[rustfmt::skip]
        let mut changeprog_msg = vec![
            4, 0,                                           // type
            12, 0,                                          // length 
            1, 0, 0, 0,                                     // sock id
            prims_prog_uid, 0, 0, 0,                        // program_uid
            0, 0, 0, 0,                                     // extra fields
        ];

        dp.recv_msg(&mut install_prims).unwrap();
        dp.recv_msg(&mut changeprog_msg).unwrap();

        // 4 invokes
        for _ in 0..4 {
            c.load_primitives(
                Primitives::default()
                    .with_bytes_acked(1)
                    .with_rtt_sample_us(100),
            );
            c.invoke().unwrap();
        }
    }

    #[test]
    fn basic() {
        let _l = TEST_MUTEX.lock().unwrap();

        let basic_prog_uid = 4;

        #[rustfmt::skip]
        let dp = make_dp(vec![
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
    }
}
