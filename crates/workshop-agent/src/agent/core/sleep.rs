use rand::Rng;

/// Calcula el tiempo de sleep con jitter aplicado.
///
/// El jitter es un porcentaje que define la variación aleatoria del sleep.
/// Por ejemplo, con base_ms=1000 y jitter_pct=10:
/// - El sleep estará entre 900ms y 1100ms
///
/// PASOS A IMPLEMENTAR:
/// 1. Si jitter_pct es 0, retornar base_ms directamente
/// 2. Calcular el rango: span = base_ms * jitter_pct / 100
/// 3. low = base_ms - span, high = base_ms + span
/// 4. Retornar un valor aleatorio entre low y high usando rng.gen_range()
pub fn jittered_sleep_ms<R: Rng + ?Sized>(base_ms: u64, jitter_pct: u8, rng: &mut R) -> u64 {
    /*
    ============================================================
    WORKSHOP: Implementar sleep con jitter
    ============================================================
    
    El jitter permite variar el tiempo de beaconing para evitar
    detección por patrones de tiempo fijos.
    
    Fórmula:
    - j = jitter_pct.min(100) as u64
    - span = base_ms * j / 100
    - low = base_ms - span
    - high = base_ms + span
    - rng.gen_range(low..=high)
    
    Ejemplo: base_ms=5000, jitter_pct=20
    - span = 5000 * 20 / 100 = 1000
    - low = 4000, high = 6000
    - sleep aleatorio entre 4s y 6s
    ============================================================
    */
    todo!("Implementar jittered_sleep_ms")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn jitter_0_is_exact() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        assert_eq!(jittered_sleep_ms(1000, 0, &mut rng), 1000);
    }

    #[test]
    fn jitter_bounds_respected() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let v = jittered_sleep_ms(1000, 10, &mut rng);
        assert!((900..=1100).contains(&v));
    }
}
