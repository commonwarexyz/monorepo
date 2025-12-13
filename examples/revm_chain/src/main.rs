use clap::{value_parser, Arg, Command};
use commonware_revm_chain::{simulate, SimConfig};

fn main() -> anyhow::Result<()> {
    let matches = Command::new("commonware-revm-chain")
        .about("threshold-simplex + EVM execution example (scaffold)")
        .arg(
            Arg::new("nodes")
                .long("nodes")
                .required(false)
                .default_value("4")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("blocks")
                .long("blocks")
                .required(false)
                .default_value("3")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("seed")
                .long("seed")
                .required(false)
                .default_value("1")
                .value_parser(value_parser!(u64)),
        )
        .get_matches();

    let nodes = *matches.get_one::<usize>("nodes").expect("defaulted");
    let blocks = *matches.get_one::<u64>("blocks").expect("defaulted");
    let seed = *matches.get_one::<u64>("seed").expect("defaulted");

    let outcome = simulate(SimConfig { nodes, blocks, seed })?;
    println!("scaffold complete: head={:?}", outcome.head);
    Ok(())
}

