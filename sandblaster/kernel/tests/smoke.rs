use sandblaster_kernel::api::*;
use sandblaster_kernel::value::*;

fn budget() -> Budget {
    Budget { steps: 10_000_000 }
}

#[test]
fn smoke_list_len() {
    let mut env = Env::new();
    let src = r#"
inductive List (T : Type) { | Nil | Cons(head : T, tail : List(T)) }
def[prelude] seq::len : (T : Type) -> (l : List(T)) -> Int :=
  fun (T : Type) (l : List(T)) => match l : List(T) as _ return Int with
    | Nil => 0int
    | Cons(h, t) => #iadd(1int, rec(T, t))
  end
  structural 1
def[lemma] three : Eq(Int, seq::len U8 (Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Nil[U8])))), 3int) := refl(Int, 3int)
"#;
    env.load_core(src, &mut budget()).unwrap();
    let t = env.parse_term(&[], "seq::len U8 (Cons[U8](1u8, Nil[U8]))").unwrap();
    let v = env.eval(&VEnv::default(), sandblaster_kernel::term::Lvl(0), &t, &mut budget()).unwrap();
    let q = env.quote(sandblaster_kernel::term::Lvl(0), &v, false);
    assert_eq!(env.print_term(&[], &q), "1int");
}
