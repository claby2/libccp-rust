//! Rust bindings for [libccp](https://github.com/ccp-project/libccp).
//! This crate is useful for writing CCP datapaths in Rust.

/// Bindgen-generated libccp bindings.
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(unused)]
mod ccp;

extern crate failure;
use failure::bail;
extern crate time;

pub trait Datapath {
    fn send_msg(&mut self, msg: &[u8]);
}

struct DatapathObj(Box<Datapath>);

extern "C" fn bundler_send_msg(
    dp: *mut ccp::ccp_datapath,
    _conn: *mut ccp::ccp_connection,
    msg: *mut ::std::os::raw::c_char,
    msg_size: ::std::os::raw::c_int,
) -> std::os::raw::c_int {
    // get the impl CcpDatapath
    let mut dp: Box<DatapathObj> = unsafe {
        use std::mem;
        let dp = mem::transmute((*dp).impl_);
        Box::from_raw(dp)
    };

    // construct the slice
    use std::slice;
    let buf = unsafe { slice::from_raw_parts(msg as *mut u8, msg_size as usize) };

    // send the message using the provided impl
    dp.0.send_msg(buf);

    // "leak" the Box because *mut ccp::ccp_datapath still owns it
    Box::leak(dp);

    return 0;
}

pub trait CongestionOps {
    fn set_cwnd(&mut self, cwnd: u32);
    fn set_rate_abs(&mut self, rate: u32);
    fn set_rate_rel(&mut self, rate: u32);
}

struct ConnectionObj(Box<CongestionOps>);

extern "C" fn bundler_set_cwnd(
    _dp: *mut ccp::ccp_datapath,
    conn: *mut ccp::ccp_connection,
    cwnd: u32,
) {
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

extern "C" fn bundler_set_rate_abs(
    _dp: *mut ccp::ccp_datapath,
    conn: *mut ccp::ccp_connection,
    rate: u32,
) {
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

extern "C" fn bundler_set_rate_rel(
    _dp: *mut ccp::ccp_datapath,
    conn: *mut ccp::ccp_connection,
    rate: u32,
) {
    // get the impl ConnectionObj
    let mut conn: Box<ConnectionObj> = unsafe {
        use std::mem;
        let conn = mem::transmute((*conn).impl_);
        Box::from_raw(conn)
    };

    conn.0.set_rate_rel(rate);

    // "leak" the Box because *mut ccp::ccp_datapath still owns it
    Box::leak(conn);
}

extern "C" fn bundler_now() -> u64 {
    time::precise_time_ns()
}

extern "C" fn bundler_since_usecs(then: u64) -> u64 {
    time::precise_time_ns() - then
}

extern "C" fn bundler_after_usecs(usecs: u64) -> u64 {
    time::precise_time_ns() + usecs * 1_000
}

pub fn init_with_datapath<T: Datapath + 'static>(dp: T) -> Result<(), failure::Error> {
    // need 2 levels of Box so we can avoid passing a fat pointer down
    let dp = Box::new(DatapathObj(Box::new(dp)));
    let mut dp = ccp::ccp_datapath {
        set_cwnd: Some(bundler_set_cwnd),
        set_rate_abs: Some(bundler_set_rate_abs),
        set_rate_rel: Some(bundler_set_rate_rel),
        time_zero: time::precise_time_ns(),
        now: Some(bundler_now),
        since_usecs: Some(bundler_since_usecs),
        after_usecs: Some(bundler_after_usecs),
        send_msg: Some(bundler_send_msg),
        impl_: Box::into_raw(dp) as *mut std::os::raw::c_void,
    };

    let ok = unsafe { ccp::ccp_init(&mut dp) };
    if ok < 0 {
        bail!("Could not initialize ccp datapath");
    }

    Ok(())
}

pub fn deinit() {
    unsafe { ccp::ccp_free() }
}

pub struct FlowInfo(ccp::ccp_datapath_info);

impl Default for FlowInfo {
    fn default() -> Self {
        FlowInfo(ccp::ccp_datapath_info {
            init_cwnd: 10,
            mss: 1460,
            src_ip: 0,
            src_port: 0,
            dst_ip: 0,
            dst_port: 0,
            congAlg: [0i8; 64],
        })
    }
}

impl FlowInfo {
    pub fn with_init_cwnd(mut self, init_cwnd: u32) -> Self {
        self.0.init_cwnd = init_cwnd;
        self
    }

    pub fn with_mss(mut self, mss: u32) -> Self {
        self.0.mss = mss;
        self
    }

    pub fn with_src(mut self, src: u32) -> Self {
        self.0.src_ip = src;
        self
    }

    pub fn with_src_port(mut self, src: u32) -> Self {
        self.0.src_port = src;
        self
    }

    pub fn with_dst(mut self, dst: u32) -> Self {
        self.0.dst_ip = dst;
        self
    }

    pub fn with_dst_port(mut self, dst: u32) -> Self {
        self.0.dst_port = dst;
        self
    }

    pub fn with_four_tuple(self, src_ip: u32, src_port: u32, dst_ip: u32, dst_port: u32) -> Self {
        self.with_src(src_ip)
            .with_src_port(src_port)
            .with_dst(dst_ip)
            .with_dst_port(dst_port)
    }

    fn get_dp_info(&self) -> ccp::ccp_datapath_info {
        ccp::ccp_datapath_info {
            init_cwnd: self.0.init_cwnd,
            mss: self.0.mss,
            src_ip: self.0.src_ip,
            src_port: self.0.src_port,
            dst_ip: self.0.dst_ip,
            dst_port: self.0.dst_port,
            congAlg: self.0.congAlg,
        }
    }
}

pub struct Primitives(ccp::ccp_primitives);

impl Default for Primitives {
    fn default() -> Self {
        Primitives(ccp::ccp_primitives {
            bytes_acked: 0,
            packets_acked: 0,
            bytes_misordered: 0,
            packets_misordered: 0,
            ecn_bytes: 0,
            ecn_packets: 0,
            lost_pkts_sample: 0,
            was_timeout: false,
            rtt_sample_us: 0,
            rate_outgoing: 0,
            rate_incoming: 0,
            bytes_in_flight: 0,
            packets_in_flight: 0,
            snd_cwnd: 0,
            snd_rate: 0,
            bytes_pending: 0,
        })
    }
}

impl Primitives {
    pub fn with_bytes_acked(mut self, bytes_acked: u32) -> Self {
        self.0.bytes_acked = bytes_acked;
        self
    }

    pub fn with_bytes_misordered(mut self, bytes_misordered: u32) -> Self {
        self.0.bytes_misordered = bytes_misordered;
        self
    }

    pub fn with_rate(mut self, rate_outgoing: u64, rate_incoming: u64) -> Self {
        self.0.rate_outgoing = rate_outgoing;
        self.0.rate_incoming = rate_incoming;
        self
    }
}

pub struct Connection(*mut ccp::ccp_connection);

impl Connection {
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

    pub fn end(self) {
        unsafe {
            let index = (*(self.0)).index;
            ccp::ccp_connection_free(index);
        }
    }

    pub fn load_primitives(&mut self, prims: Primitives) {
        unsafe {
            (*(self.0)).prims.bytes_acked = prims.0.bytes_acked;
            (*(self.0)).prims.packets_acked = prims.0.packets_acked;
            (*(self.0)).prims.bytes_misordered = prims.0.bytes_misordered;
            (*(self.0)).prims.packets_misordered = prims.0.packets_misordered;
            (*(self.0)).prims.ecn_bytes = prims.0.ecn_bytes;
            (*(self.0)).prims.ecn_packets = prims.0.ecn_packets;
            (*(self.0)).prims.lost_pkts_sample = prims.0.lost_pkts_sample;
            (*(self.0)).prims.was_timeout = prims.0.was_timeout;
            (*(self.0)).prims.rtt_sample_us = prims.0.rtt_sample_us;
            (*(self.0)).prims.rate_outgoing = prims.0.rate_outgoing;
            (*(self.0)).prims.rate_incoming = prims.0.rate_incoming;
            (*(self.0)).prims.bytes_in_flight = prims.0.bytes_in_flight;
            (*(self.0)).prims.packets_in_flight = prims.0.packets_in_flight;
            (*(self.0)).prims.snd_cwnd = prims.0.snd_cwnd;
            (*(self.0)).prims.snd_rate = prims.0.snd_rate;
            (*(self.0)).prims.bytes_pending = prims.0.bytes_pending;
        }
    }

    pub fn invoke(&mut self) {
        unsafe {
            ccp::ccp_invoke(self.0);
        }
    }
}

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

        fn set_rate_rel(&mut self, _rate: u32) {
            unimplemented!()
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
