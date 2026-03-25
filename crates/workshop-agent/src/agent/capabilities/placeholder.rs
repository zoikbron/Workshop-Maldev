#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceholderCapability;

impl PlaceholderCapability {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_constructs() {
        let _ = PlaceholderCapability::new();
    }
}
