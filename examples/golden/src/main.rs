use clap::Parser;
use commonware_golden::cli::Cli;
use commonware_runtime::{
    tokio::{self, telemetry::Logging},
    Metrics, Runner,
};

fn main() {
    let cli = Cli::parse();
    let config = tokio::Config::new()
        .with_worker_threads(cli.worker_threads)
        .with_tcp_nodelay(Some(true))
        .with_catch_panics(false);
    let runner = tokio::Runner::new(config);
    runner.start(|context| async move {
        // Initialize telemetry.
        tokio::telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: cli.log_level,
                json: false,
            },
            None,
            None,
        );

        cli.run(context).await
    });
}
