#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    Unimplemented,
    Io(String),
    Protocol(String),
    InvalidConfig(String),
}

pub trait Transport {
    fn type_name(&self) -> &'static str;
    fn connect(&mut self) -> Result<(), TransportError>;
    fn checkin(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn send_result(&mut self, data: &[u8]) -> Result<(), TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyTransport {
        pub last_sent: Vec<u8>,
        pub next_recv: Vec<u8>,
        pub connected: bool,
    }

    impl DummyTransport {
        fn new(next_recv: Vec<u8>) -> Self {
            Self {
                last_sent: Vec::new(),
                next_recv,
                connected: false,
            }
        }
    }

    impl Transport for DummyTransport {
        fn type_name(&self) -> &'static str {
            "dummy"
        }

        fn connect(&mut self) -> Result<(), TransportError> {
            self.connected = true;
            Ok(())
        }

        fn checkin(&mut self, _request: &[u8]) -> Result<Vec<u8>, TransportError> {
            Ok(std::mem::take(&mut self.next_recv))
        }

        fn send_result(&mut self, data: &[u8]) -> Result<(), TransportError> {
            self.last_sent = data.to_vec();
            Ok(())
        }
    }

    #[test]
    fn dummy_transport_roundtrip() {
        let mut t = DummyTransport::new(vec![1, 2, 3]);
        t.connect().unwrap();
        assert!(t.connected);
        let r = t.checkin(&[]).unwrap();
        assert_eq!(r, vec![1, 2, 3]);
        t.send_result(b"ok").unwrap();
        assert_eq!(t.last_sent, b"ok");
    }
}
