use codama::Codama;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let codama = Codama::load(Path::new("./program/src"))?;
    let json_idl: String = codama.get_json_idl()?;
    fs::write("./idl.json", json_idl)?;
    Ok(())
}
