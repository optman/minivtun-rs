#[derive(Default, Clone)]
pub struct RndzConfig {
    pub server: String,
    pub local_id: String,
    pub remote_id: Option<String>,
}
