use gloves::types::SecretValue;

fn main() {
    let secret = SecretValue::new(b"abc".to_vec());
    let _ = format!("{secret:?}");
}
