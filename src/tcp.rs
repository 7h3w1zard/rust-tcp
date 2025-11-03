use std::io::{self, Write};

pub enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            Self::SynRcvd => false,
            Self::Estab | Self::FinWait1 | Self::FinWait2 | Self::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcph: etherparse::TcpHeader,
}

///      Send Sequence Space (RFC 793 S3.2 F4)
/// ```
///                1         2          3          4
///           ----------|----------|----------|----------
///                  SND.UNA    SND.NXT    SND.UNA
///                                       +SND.WND
///
///      1 - old sequence numbers which have been acknowledged
///      2 - sequence numbers of unacknowledged data
///      3 - sequence numbers allowed for new data transmission
///      4 - future sequence numbers which are not yet allowed
/// ```
pub struct SendSequenceSpace {
    /// - send unacknowledged
    una: u32,
    /// - send next
    nxt: u32,
    /// - send window
    wnd: u16,
    /// - send urgent pointer
    up: bool,
    /// - segment sequence number used for last window update
    wl1: usize,
    /// - segment acknowledgment number used for last window update
    wl2: usize,
    /// - initial send sequence number
    iss: u32,
}

///     Receive Sequence Space (RFC 793 S3.2 F5)
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
///     1 - old sequence numbers which have been acknowledged
///     2 - sequence numbers allowed for new reception
///     3 - future sequence numbers which are not yet allowed
/// ```
pub struct ReceiveSequenceSpace {
    /// - receive next
    nxt: u32,
    /// - receive window
    wnd: u16,
    /// - receive urgent pointer
    up: bool,
    /// - initial received sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: ReceiveSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            tcph: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
        };

        // need to start establishing a connection
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        c.tcph.syn = true;
        c.tcph.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcph.sequence_number = self.send.nxt;
        self.tcph.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.tcph.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );
        self.ip.set_payload_len(size - self.ip.header_len() as usize);

        // the kernel does this for us
        self.tcph.checksum = self.tcph
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");
        // eprintln!("got ip header:\n{:02x?}", iph);
        // eprintln!("got tcp header:\n{:02x?}", tcph);

        // write out the headers

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcph.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcph.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcph.syn = false;
        }
        if self.tcph.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcph.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcph.rst = true;
        // TODO: fix seq num
        self.tcph.sequence_number = 0;
        self.tcph.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)

        //
        // valid segment check. Ok if it acks at least one byte, which means that at least one
        // of the following is true:
        //
        //   RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //   RCV.NXT =< SEG.SEQ+SEQ.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                return Ok(());
            }
        }
        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO: if _not_ acceptable, send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
            return Ok(());
        }

        // acceptable ack check
        //  SND.UNA < SEQ.ACK =< SND.NXT
        // remember wrapping!
        //
        
        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (SYN).
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEQ.ACK><CTL=RST>
            }
        }


        // // expect to get an ACK for our SYN
        // if !tcph.ack() {
        //     return Ok(());
        // }
        // // must have ACKed our SYN, since we detected at least one acked byte,
        // // and we have only sent one byte (SYN).
        // self.state = State::Estab;
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            // todo!()
            assert!(data.is_empty());

            if let State::Estab = self.state {    
                // now let's terminate the connection!
                // TODO: needs to be stored in the retransmission queue.
                self.tcph.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed!
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection!
                    self.tcph.fin = false;
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        std::cmp::Ordering::Equal => return false,
        std::cmp::Ordering::Less => {
            // we have:
            //    0 |-------------S------X--------------------| (wraparond)
            //
            // X is between S and E (S < X < E) in these cases:
            //
            //    0 |-------------S------X---E----------------| (wraparond)
            //
            //    0 |---------E---S------X--------------------| (wraparond)
            //
            // but *not* in these cases
            //
            //    0 |-------------S--E---X--------------------| (wraparond)
            //
            //    0 |-------------|------X--------------------| (wraparond)
            //                    ^-S+E
            //
            //    0 |-------------S------|--------------------| (wraparond)
            //                       X+E-^
            //
            // or, in other words, iff !(S <= E <= X)
            if end >= start && end <= x {
                return false;
            }
        }
        std::cmp::Ordering::Greater => {
            // we have the opposite:
            //    0 |-------------X------S--------------------| (wraparond)
            //
            // X is between S and E (S < X < E) *only* in these case:
            //
            //    0 |-------------X--E---S--------------------| (wraparond)
            //
            // but *not* in these cases
            //
            //    0 |-------------X------S---E----------------| (wraparond)
            //
            //    0 |---------У---X------S--------------------| (wraparond)
            //
            //    0 |-------------|------S--------------------| (wraparond)
            //                    ^-X+E
            //
            //    0 |-------------X------|--------------------| (wraparond)
            //                       S+E-^
            //
            // or, in other words, iff S < E < X
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }
    true
}
// eprintln!(
//     "{}:{} → {}:{} {}b of tcp",
//     iph.source_addr(),
//     tcph.source_port(),
//     iph.destination_addr(),
//     tcph.destination_port(),
//     data.len(),
// );
