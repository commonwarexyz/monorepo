use clap::{value_parser, Arg, Command};
use commonware_cryptography::bls12381::{
    dkg::ops,
    primitives::{group::Element, poly},
};
use commonware_utils::{hex, quorum};
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    // Parse arguments
    let matches = Command::new("dealer")
        .about("generate threshold secret")
        .arg(
            Arg::new("seed")
                .long("seed")
                .required(true)
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("n")
                .long("n")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .get_matches();

    // Parse args
    let seed = *matches.get_one::<u64>("seed").expect("seed is required");
    let n = *matches.get_one::<u32>("n").expect("n is required");
    let t = quorum(n).expect("unable to compute threshold");

    // Generate secret
    let mut rng = StdRng::seed_from_u64(seed);
    let (public, shares) = ops::generate_shares_from(&mut rng, None, n, t);

    // Log secret
    println!("polynomial: {}", hex(&public.serialize()));
    let public = poly::public(&public);
    println!("public: {}", hex(&public.serialize()));
    for (index, share) in shares.iter().enumerate() {
        println!("share-{}: {}", index, hex(&share.serialize()));
    }
}
