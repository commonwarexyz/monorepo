use super::*;
use syn::parse_quote;

fn error(input: DeriveInput, kind: Kind, message: &str) {
    let error = expand(input, kind).expect_err("derive should reject this input");
    assert!(error.to_string().contains(message), "{error}");
}

#[test]
fn rejects_invalid_attribute_placement_and_duplicates() {
    for input in [
        parse_quote!(
            #[codec(cfg = &())]
            struct Item;
        ),
        parse_quote!(
            struct Item(#[codec(tag = 0)] u8);
        ),
        parse_quote!(
            enum Item {
                #[codec(encode_size = 1)]
                A,
            }
        ),
        parse_quote!(
            struct Item(#[read_cfg(())] u8);
        ),
        parse_quote!(
            #[codec(unknown = 1)]
            struct Item;
        ),
        parse_quote!(
            #[codec()]
            struct Item;
        ),
    ] {
        assert!(expand(input, Kind::Write).is_err());
    }
    error(
        parse_quote!(
            #[read_cfg(())]
            #[codec(read_cfg = ())]
            struct Item;
        ),
        Kind::Read,
        "duplicate `read_cfg`",
    );
    error(
        parse_quote!(
            #[encode_size(0)]
            #[codec(encode_size = 0)]
            struct Item;
        ),
        Kind::EncodeSize,
        "duplicate `encode_size`",
    );
    error(
        parse_quote!(
            struct Item(#[codec(cfg = &(), cfg = &())] u8);
        ),
        Kind::Read,
        "duplicate `cfg`",
    );
    error(
        parse_quote!(
            enum Item {
                #[codec(tag = 1, tag = 2)]
                A,
            }
        ),
        Kind::Write,
        "duplicate `tag`",
    );
}

#[test]
fn validates_enum_tags_and_shape() {
    for tag in [quote!(256), quote!(-1), quote!(1 + 1), quote!("1")] {
        let input = syn::parse2(quote!(
            enum Item {
                #[codec(tag = #tag)]
                A,
            }
        ))
        .unwrap();
        assert!(expand(input, Kind::Write).is_err());
    }
    error(
        parse_quote!(
            enum Item {
                #[codec(tag = 1)]
                A,
                B,
            }
        ),
        Kind::Write,
        "duplicate codec enum tag",
    );
    error(
        parse_quote!(
            enum Item {}
        ),
        Kind::Read,
        "1 through 256",
    );
    error(parse_quote!(union Item { a: u8 }), Kind::Read, "unions");
    let variants = (0..256).map(|i| format_ident!("V{i}"));
    let input = syn::parse2(quote!(enum Item { #(#variants),* })).unwrap();
    assert!(expand(input, Kind::Write).is_ok());
    let variants = (0..257).map(|i| format_ident!("V{i}"));
    let input = syn::parse2(quote!(enum Item { #(#variants),* })).unwrap();
    error(input, Kind::Read, "1 through 256");
    assert!(
        expand(
            parse_quote!(
                enum Item {
                    #[codec(tag = 0xff)]
                    A,
                    B,
                }
            ),
            Kind::Write
        )
        .is_ok()
    );
}

#[test]
fn custom_encoding_requires_size_only_when_deriving_size() {
    let input: DeriveInput = parse_quote!(
        struct Item(#[codec(encode_with = custom)] u8);
    );
    assert!(expand(input.clone(), Kind::Write).is_ok());
    error(
        input.clone(),
        Kind::EncodeSize,
        "requires a field or container encode_size",
    );
    error(
        input.clone(),
        Kind::Encode,
        "requires a field or container encode_size",
    );
    error(input, Kind::FixedSize, "does not support custom encoding");
    for input in [
        parse_quote!(
            struct Item(#[codec(encode_with = custom, encode_size = 3)] u8);
        ),
        parse_quote!(
            #[encode_size(3)]
            struct Item(#[codec(encode_with = custom)] u8);
        ),
    ] {
        let input: DeriveInput = input;
        assert!(expand(input.clone(), Kind::Encode).is_ok());
        error(input, Kind::FixedSize, "does not support custom encoding");
    }
}

#[test]
fn expansions_parse_for_all_shapes_and_generics() {
    for input in [
        parse_quote!(
            struct Item;
        ),
        parse_quote!(
            struct Item();
        ),
        parse_quote!(
            struct Item {}
        ),
        parse_quote!(
            struct Item<'a, T, const N: usize>(&'a T, [u8; N])
            where
                T: Clone;
        ),
        parse_quote!(
            struct Item<T> {
                buf: T,
                cfg: T,
                value: T,
                __codec_field_0: T,
            }
        ),
        parse_quote!(
            enum Item<T> {
                Unit,
                Tuple(T),
                Named { value: T },
            }
        ),
    ] {
        let input: DeriveInput = input;
        for kind in [
            Kind::Write,
            Kind::Read,
            Kind::EncodeSize,
            Kind::FixedSize,
            Kind::Encode,
        ] {
            let tokens = expand(input.clone(), kind).unwrap();
            syn::parse2::<syn::File>(tokens).expect("generated impls should be valid syntax");
        }
    }
}

#[test]
fn bound_attributes_validate_placement_and_duplicates() {
    for name in [
        "read_bounds",
        "write_bounds",
        "encode_size_bounds",
        "fixed_size_bounds",
    ] {
        let name = format_ident!("{name}");
        for bounds in [quote!(), quote!(T: Clone, T: Send,)] {
            let input: DeriveInput = syn::parse2(quote!(
                #[codec(#name(#bounds))]
                struct Item<T>(T);
            ))
            .unwrap();
            for kind in [
                Kind::Read,
                Kind::Write,
                Kind::EncodeSize,
                Kind::FixedSize,
                Kind::Encode,
            ] {
                let tokens = expand(input.clone(), kind).unwrap();
                syn::parse2::<syn::File>(tokens).unwrap();
            }
        }
        let input = syn::parse2(quote!(
            #[codec(#name())]
            #[codec(#name(T: Clone))]
            struct Item<T>(T);
        ))
        .unwrap();
        error(input, Kind::Read, &format!("duplicate `{name}`"));
        for input in [
            quote!(
                struct Item<T>(#[codec(#name())] T);
            ),
            quote!(
                enum Item {
                    #[codec(#name())]
                    A,
                }
            ),
        ] {
            error(syn::parse2(input).unwrap(), Kind::Read, "wrong position");
        }
    }
}

#[test]
fn read_hooks_validate_placement_and_duplicates() {
    error(
        parse_quote!(
            struct Item(#[codec(read_with = f, read_with = g)] u8);
        ),
        Kind::Read,
        "duplicate `read_with`",
    );
    error(
        parse_quote!(
            #[codec(invalid_tag = f, invalid_tag = g)]
            enum Item {
                A,
            }
        ),
        Kind::Read,
        "duplicate `invalid_tag`",
    );
    for input in [
        quote!(
            #[codec(read_with = f)]
            struct Item;
        ),
        quote!(
            enum Item {
                #[codec(read_with = f)]
                A,
            }
        ),
        quote!(
            struct Item(#[codec(invalid_tag = f)] u8);
        ),
        quote!(
            enum Item {
                #[codec(invalid_tag = f)]
                A,
            }
        ),
    ] {
        error(syn::parse2(input).unwrap(), Kind::Read, "wrong position");
    }
    for kind in [
        Kind::Read,
        Kind::Write,
        Kind::EncodeSize,
        Kind::FixedSize,
        Kind::Encode,
    ] {
        error(
            parse_quote!(
                #[codec(invalid_tag = f)]
                struct Item;
            ),
            kind,
            "requires an enum",
        );
    }
    for hook in [
        quote!(custom),
        quote!(|buf, cfg| custom(buf, cfg)),
        quote!({ custom(buf, cfg) }),
    ] {
        let input = syn::parse2(quote!(
            struct Item(#[codec(cfg = &(), read_with = #hook)] u8);
        ))
        .unwrap();
        syn::parse2::<syn::File>(expand(input, Kind::Read).unwrap()).unwrap();
    }
    for hook in [
        quote!(custom),
        quote!(|tag| custom(tag)),
        quote!({ custom(tag) }),
    ] {
        let input = syn::parse2(quote!(
            #[codec(invalid_tag = #hook)]
            enum Item {
                A,
            }
        ))
        .unwrap();
        syn::parse2::<syn::File>(expand(input, Kind::Read).unwrap()).unwrap();
    }
}
