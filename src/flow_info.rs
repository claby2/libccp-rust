use super::ccp;

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

setters!(FlowInfo => 
    init_cwnd: u32,
    mss: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u32,
    dst_port: u32
);

impl FlowInfo {
    pub fn with_four_tuple(self, src_ip: u32, src_port: u32, dst_ip: u32, dst_port: u32) -> Self {
        self.with_src_ip(src_ip)
            .with_src_port(src_port)
            .with_dst_ip(dst_ip)
            .with_dst_port(dst_port)
    }

    pub(crate) fn get_dp_info(&self) -> ccp::ccp_datapath_info {
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
