use core::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub url: String,
    pub sleep: Duration,
    pub jitter_pct: u8,
}

impl AgentConfig {
    pub fn new(url: String) -> Self {
        Self {
            url,
            sleep: Duration::from_millis(300),
            jitter_pct: 0,
        }
    }

    pub fn normalized_url(&self) -> String {
        normalize_url(&self.url)
    }
}

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
