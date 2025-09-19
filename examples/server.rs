use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = std::fs::read("signing_key")?
        .try_into()
        .expect("signing key has wrong size");
    let verifying_key = std::fs::read("verifying_key")?
        .try_into()
        .expect("verifying key has wrong size");

    let listener = TcpListener::bind("localhost:59350").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let mut proto = spproto::auth::auth(stream, signing_key, verifying_key).await?;

        proto.send(b"hello client").await?;
        let response = proto.receive().await?;
        println!("client responded: {}", String::from_utf8(response)?);
    }
}
