mod listener;
mod operator;
mod tasking;

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let state = tasking::AppState::new();

    let addr = args.bind.parse().expect("invalid bind address");

    operator::run(state.clone(), Some(addr)).await;
}
