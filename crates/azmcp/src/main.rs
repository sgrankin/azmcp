fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
        .ok();
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next().as_deref(), arguments.next()) {
        (Some(argument), None) if argument == "--worker" => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(azmcp::worker::run_stdio())
        }
        (None, None) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(azmcp::run_stdio()),
        _ => anyhow::bail!("usage: azmcp [--worker]"),
    }
}
