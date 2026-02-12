// -*- mode: Bluespec; -*-

// Option type utilities
module option {
    type Option[a] =
        | Some(a)
        | None

    pure def is_some(opt: Option[a]): bool = {
        match opt {
            | Some(_) => true
            | None => false
        }
    }

    pure def is_none(opt: Option[a]): bool = {
        match opt {
            | Some(_) => false
            | None => true
        }
    }

    pure def unwrap(opt: Option[a]): a = {
        match opt {
            | Some(x) => x
            | None => ???  // Error: unwrap on None
        }
    }

    pure def unwrap_or(opt: Option[a], default: a): a = {
        match opt {
            | Some(x) => x
            | None => default
        }
    }

    pure def map_option(opt: Option[a], f: a => b): Option[b] = {
        match opt {
            | Some(x) => Some(f(x))
            | None => None
        }
    }

    pure def flat_map(opt: Option[a], f: a => Option[b]): Option[b] = {
        match opt {
            | Some(x) => f(x)
            | None => None
        }
    }
}
