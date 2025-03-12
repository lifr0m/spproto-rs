use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = std::fs::read("key_pair_2")?;
    let peer_public_key = std::fs::read("public_key")?;
    
    let stream = TcpStream::connect("localhost:59350").await?;
    let mut proto = spproto::auth(stream, key_pair, peer_public_key).await?;
    
    proto.send(b"hello server").await?;
    let response = proto.receive().await?;
    println!("server responded: {}", String::from_utf8(response)?);
    
    Ok(())
}
