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
