use clap::{value_parser, Arg, Command};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{group::Element, poly},
    },
    Ed25519, Scheme,
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
            Arg::new("participants")
                .long("participants")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("All participants (arbiter and contributors)"),
        )
        .get_matches();

    // Parse args
    let seed = *matches.get_one::<u64>("seed").expect("seed is required");
    let mut validators = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.clone().next().is_none() {
        panic!("Please provide at least one participant");
    }
    for peer in participants {
        let verifier = Ed25519::from_seed(peer).public_key();
        validators.push((peer, verifier));
    }
    validators.sort_by(|(_, a), (_, b)| a.cmp(b));
    let n = validators.len() as u32;
    let t = quorum(n).expect("unable to compute threshold");

    // Generate secret
    let mut rng = StdRng::seed_from_u64(seed);
    let (public, shares) = ops::generate_shares(&mut rng, None, n, t);

    // Log secret
    println!("polynomial: {}", hex(&public.serialize()));
    let public = poly::public(&public);
    println!("public: {}", hex(&public.serialize()));
    for share in shares {
        let validator = validators[share.index as usize].0;
        println!(
            "share (index={} validator={}): {}",
            share.index,
            validator,
            hex(&share.serialize())
        );
    }
}
