use rand::Rng;

pub fn jittered_sleep_ms<R: Rng + ?Sized>(base_ms: u64, jitter_pct: u8, rng: &mut R) -> u64 {
    let j = jitter_pct.min(100) as u64;
    if j == 0 {
        return base_ms;
    }
    let span = base_ms.saturating_mul(j) / 100;
    let low = base_ms.saturating_sub(span);
    let high = base_ms.saturating_add(span);
    if high <= low {
        return base_ms;
    }
    rng.gen_range(low..=high)
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
