use crate::agent::core::config::AgentConfig;
use crate::agent::core::sleep::jittered_sleep_ms;
use crate::agent::transport::traits::{Transport, TransportError};
use rand::Rng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    Transport(TransportError),
}

impl From<TransportError> for RuntimeError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

pub trait TaskDispatcher {
    fn dispatch(&mut self, bytes: Vec<u8>) -> Result<Option<Vec<u8>>, RuntimeError>;

    fn checkin_request(&mut self) -> Vec<u8> {
        Vec::new()
    }

    fn update_config(&mut self, _cfg: &mut AgentConfig) {}
}

/// Loop principal del agente (beaconing).
///
/// PASOS A IMPLEMENTAR:
/// 1. Conectar el transporte (transport.connect())
/// 2. Loop infinito con contador de iteraciones:
///    a. Obtener request de checkin del dispatcher
///    b. Enviar checkin y recibir datos (transport.checkin)
///    c. Si hay datos entrantes, hacer dispatch y enviar resultado
///    d. Actualizar configuración del dispatcher
///    e. Calcular sleep con jitter y dormir
/// 3. Salir si se alcanza max_iterations (para tests)
pub fn run_loop<T: Transport, D: TaskDispatcher, R: Rng>(
    transport: &mut T,
    dispatcher: &mut D,
    cfg: &mut AgentConfig,
    rng: &mut R,
    max_iterations: Option<u64>,
) -> Result<(), RuntimeError> {
    /*
    ============================================================
    WORKSHOP: Implementar el loop principal del agente
    ============================================================
    
    Estructura:
    1. transport.connect()? - conectar al C2
    2. let mut iter: u64 = 0;
    3. loop {
        - Verificar max_iterations para salir en tests
        - iter += 1;
        - let req = dispatcher.checkin_request();
        - let inbound = transport.checkin(&req)?;
        - if !inbound.is_empty() {
            if let Some(out) = dispatcher.dispatch(inbound)? {
                transport.send_result(&out)?;
            }
        }
        - dispatcher.update_config(cfg);
        - let sleep_ms = jittered_sleep_ms(cfg.sleep.as_millis() as u64, cfg.jitter_pct, rng);
        - std::thread::sleep(Duration::from_millis(sleep_ms));
    }
    ============================================================
    */
    todo!("Implementar run_loop con beaconing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    struct OnceDispatcher {
        pub called: bool,
    }

    impl TaskDispatcher for OnceDispatcher {
        fn dispatch(&mut self, bytes: Vec<u8>) -> Result<Option<Vec<u8>>, RuntimeError> {
            self.called = true;
            Ok(Some(bytes))
        }
    }

    struct LoopbackTransport {
        pub connected: bool,
        pub next: Vec<u8>,
        pub sent: Vec<u8>,
    }

    impl Transport for LoopbackTransport {
        fn type_name(&self) -> &'static str {
            "loopback"
        }

        fn connect(&mut self) -> Result<(), TransportError> {
            self.connected = true;
            Ok(())
        }

        fn checkin(&mut self, _request: &[u8]) -> Result<Vec<u8>, TransportError> {
            Ok(std::mem::take(&mut self.next))
        }

        fn send_result(&mut self, data: &[u8]) -> Result<(), TransportError> {
            self.sent = data.to_vec();
            Ok(())
        }
    }

    #[test]
    fn run_loop_dispatches_and_sends() {
        let mut cfg = AgentConfig::new("http://127.0.0.1:8080/register".to_string());
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let mut t = LoopbackTransport {
            connected: false,
            next: vec![9, 9],
            sent: Vec::new(),
        };
        let mut d = OnceDispatcher { called: false };

        run_loop(&mut t, &mut d, &mut cfg, &mut rng, Some(1)).unwrap();

        assert!(t.connected);
        assert!(d.called);
        assert_eq!(t.sent, vec![9, 9]);
    }
}
