#[path = "../private_storage/hidden.rs"]
mod hidden;
mod bridge;
#[derive(Debug)]
pub struct Outer { value: bridge::Storage }
