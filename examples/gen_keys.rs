fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = spproto::keys::generate_signing_key();
    let verifying_key = spproto::keys::get_verifying_key(signing_key);

    std::fs::write("signing_key", signing_key)?;
    std::fs::write("verifying_key", verifying_key)?;
    
    Ok(())
}
