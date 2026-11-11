#[path = "../private_storage/hidden.rs"]
mod hidden;
use hidden::Hidden as Storage;
#[derive(Debug)]
pub struct Outer {
    value: Storage,
}
