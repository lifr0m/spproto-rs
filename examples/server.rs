use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = std::fs::read("signing_key")?;
    let verifying_key = std::fs::read("verifying_key")?;

    let listener = TcpListener::bind("localhost:59350").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let mut proto = spproto::auth(stream, &signing_key, &verifying_key).await?;

        proto.send(b"hello client").await?;
        let response = proto.receive().await?;
        println!("client responded: {}", String::from_utf8(response)?);
    }
}
