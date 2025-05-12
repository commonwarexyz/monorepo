use clap::{value_parser, Arg, Command};
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{poly, variant::MinSig},
    },
    Ed25519, Signer,
};
use commonware_utils::{hex, quorum};
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    // Setup parsing
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

    // Parse arguments
    let seed = *matches.get_one::<u64>("seed").expect("seed is required");
    let mut validators = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    for peer in participants {
        let verifier = Ed25519::from_seed(peer).public_key();
        validators.push((peer, verifier));
    }
    validators.sort_by(|(_, a), (_, b)| a.cmp(b));
    let n = validators.len() as u32;
    let t = quorum(n);

    // Generate secret
    let mut rng = StdRng::seed_from_u64(seed);
    let (public, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

    // Log secret
    println!("polynomial: {}", hex(&public.encode()));
    println!("public: {}", poly::public::<MinSig>(&public));
    for share in shares {
        let validator = validators[share.index as usize].0;
        println!("validator={}: {}", validator, share,);
    }
}
