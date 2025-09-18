fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = spproto::generate_signing_key();
    let verifying_key = spproto::get_verifying_key(signing_key);

    std::fs::write("signing_key", signing_key)?;
    std::fs::write("verifying_key", verifying_key)?;
    
    Ok(())
}
