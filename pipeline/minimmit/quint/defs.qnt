// -*- mode: Bluespec; -*-

// Pure definitions
module defs {
    // The maximum of two integers
    pure def max(x: int, y: int): int = {
        if (x > y) x else y
    }

    pure def last(v: List[a]): a = {
        v[v.length() - 1]
    }
}
