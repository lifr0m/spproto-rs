use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = std::fs::read("signing_key")?
        .try_into()
        .expect("signing key has wrong size");
    let verifying_key = std::fs::read("verifying_key")?
        .try_into()
        .expect("verifying key has wrong size");
    
    let stream = TcpStream::connect("localhost:59350").await?;
    let mut proto = spproto::auth::auth(stream, signing_key, verifying_key).await?;
    
    proto.send(b"hello server").await?;
    let response = proto.receive().await?;
    println!("server responded: {}", String::from_utf8(response)?);
    
    Ok(())
}
