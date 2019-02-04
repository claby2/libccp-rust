use super::ccp;

pub struct Primitives(pub ccp::ccp_primitives);

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

impl From<&ccp::ccp_primitives> for Primitives {
    fn from(f: &ccp::ccp_primitives) -> Self {
        // TODO get bindgen to #[derive(Clone)]
        Primitives(ccp::ccp_primitives {
            bytes_acked: f.bytes_acked,
            packets_acked: f.packets_acked,
            bytes_misordered: f.bytes_misordered,
            packets_misordered: f.packets_misordered,
            ecn_bytes: f.ecn_bytes,
            ecn_packets: f.ecn_packets,
            lost_pkts_sample: f.lost_pkts_sample,
            was_timeout: f.was_timeout,
            rtt_sample_us: f.rtt_sample_us,
            rate_outgoing: f.rate_outgoing,
            rate_incoming: f.rate_incoming,
            bytes_in_flight: f.bytes_in_flight,
            packets_in_flight: f.packets_in_flight,
            snd_cwnd: f.snd_cwnd,
            snd_rate: f.snd_rate,
            bytes_pending: f.bytes_pending,
        })
    }
}

setters!(Primitives =>
    bytes_acked: u32,
    packets_acked: u32,
    bytes_misordered: u32,
    packets_misordered: u32,
    ecn_bytes: u32,
    ecn_packets: u32,
    lost_pkts_sample: u32,
    was_timeout: bool,
    rtt_sample_us: u64,
    rate_outgoing: u64,
    rate_incoming: u64,
    bytes_in_flight: u32,
    packets_in_flight: u32,
    snd_cwnd: u32,
    snd_rate: u64,
    bytes_pending: u32
);
