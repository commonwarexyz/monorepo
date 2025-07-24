// -*- mode: Bluespec; -*-

// a typical option type, defined as a sum type in Quint
module option {
    /// A polymorphic option type
    type Option[a] =
        | Some(a)
        | None

    /// is `opt` of the shape `Some(...)`
    pure def is_some(opt: Option[a]): bool = {
        match (opt) {
            | Some(_) => true
            | None => false
        }
    }

    // is `opt` of the shape `None`
    pure def is_none(opt: Option[a]): bool = {
        not(is_some(opt))
    }

    // get `a` when `opt` is `Some(a)`; otherwise, get `default`
    pure def unwrap_or(opt: Option[a], default: a): a = {
        match (opt) {
            | Some(value) => value
            | None => default
        }
    }

    // If is Some(e), test whether `pred(e)` holds true.
    // If None, return false.
    def option_has(opt: Option[a], pred: a => bool): bool = {
        match (opt) {
            | None => false
            | Some(e) => pred(e)
        }
    }

    // return Some(mapper(e)) if opt is Some(e); otherwise None
    def option_map(opt: Option[a], mapper: a => b): Option[b] = {
        match (opt) {
            | None => None
            | Some(e) => Some(mapper(e))
        }
    }
}