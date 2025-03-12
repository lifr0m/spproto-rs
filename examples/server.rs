use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = std::fs::read("key_pair")?;
    let peer_public_key = std::fs::read("public_key_2")?;

    let listener = TcpListener::bind("localhost:59350").await?;
    
    loop {
        let (stream, _) = listener.accept().await?;
        let mut proto = spproto::auth(
            stream, key_pair.clone(), peer_public_key.clone()
        ).await?;

        proto.send(b"hello client").await?;
        let response = proto.receive().await?;
        println!("client responded: {}", String::from_utf8(response)?);
    }
}
