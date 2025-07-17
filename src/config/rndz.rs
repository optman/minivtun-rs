#[derive(Default, Clone)]
pub struct Config {
    pub servers: Vec<String>,
    pub local_id: String,
    pub remote_id: Option<String>,
}
