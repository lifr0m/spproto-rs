fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = spproto::generate_key_pair();
    let public_key = spproto::get_public_key(key_pair.as_ref())?;

    std::fs::write("key_pair", key_pair)?;
    std::fs::write("public_key", public_key)?;
    
    Ok(())
}
