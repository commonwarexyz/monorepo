//! Recognition of scoped `#[rustfmt::skip]` attributes.

use syn::{Attribute, Expr, ForeignItem, ImplItem, Item, Meta, PathArguments, Stmt, TraitItem};

pub(crate) fn item(item: &Item) -> bool {
    match item {
        Item::Const(item) => attributes(&item.attrs),
        Item::Enum(item) => attributes(&item.attrs),
        Item::ExternCrate(item) => attributes(&item.attrs),
        Item::Fn(item) => attributes(&item.attrs),
        Item::ForeignMod(item) => attributes(&item.attrs),
        Item::Impl(item) => attributes(&item.attrs),
        Item::Macro(item) => attributes(&item.attrs),
        Item::Mod(item) => attributes(&item.attrs),
        Item::Static(item) => attributes(&item.attrs),
        Item::Struct(item) => attributes(&item.attrs),
        Item::Trait(item) => attributes(&item.attrs),
        Item::TraitAlias(item) => attributes(&item.attrs),
        Item::Type(item) => attributes(&item.attrs),
        Item::Union(item) => attributes(&item.attrs),
        Item::Use(item) => attributes(&item.attrs),
        Item::Verbatim(_) => false,
        _ => false,
    }
}

pub(crate) fn impl_item(item: &ImplItem) -> bool {
    match item {
        ImplItem::Const(item) => attributes(&item.attrs),
        ImplItem::Fn(item) => attributes(&item.attrs),
        ImplItem::Type(item) => attributes(&item.attrs),
        ImplItem::Macro(item) => attributes(&item.attrs),
        ImplItem::Verbatim(_) => false,
        _ => false,
    }
}

pub(crate) fn trait_item(item: &TraitItem) -> bool {
    match item {
        TraitItem::Const(item) => attributes(&item.attrs),
        TraitItem::Fn(item) => attributes(&item.attrs),
        TraitItem::Type(item) => attributes(&item.attrs),
        TraitItem::Macro(item) => attributes(&item.attrs),
        TraitItem::Verbatim(_) => false,
        _ => false,
    }
}

pub(crate) fn foreign_item(item: &ForeignItem) -> bool {
    match item {
        ForeignItem::Fn(item) => attributes(&item.attrs),
        ForeignItem::Static(item) => attributes(&item.attrs),
        ForeignItem::Type(item) => attributes(&item.attrs),
        ForeignItem::Macro(item) => attributes(&item.attrs),
        ForeignItem::Verbatim(_) => false,
        _ => false,
    }
}

pub(crate) fn statement(statement: &Stmt) -> bool {
    match statement {
        Stmt::Local(local) => attributes(&local.attrs),
        Stmt::Item(item) => self::item(item),
        Stmt::Expr(expression, _) => self::expression(expression),
        Stmt::Macro(statement) => attributes(&statement.attrs),
    }
}

pub(crate) fn expression(expression: &Expr) -> bool {
    match expression {
        Expr::Array(node) => attributes(&node.attrs),
        Expr::Assign(node) => attributes(&node.attrs),
        Expr::Async(node) => attributes(&node.attrs),
        Expr::Await(node) => attributes(&node.attrs),
        Expr::Binary(node) => attributes(&node.attrs),
        Expr::Block(node) => attributes(&node.attrs),
        Expr::Break(node) => attributes(&node.attrs),
        Expr::Call(node) => attributes(&node.attrs),
        Expr::Cast(node) => attributes(&node.attrs),
        Expr::Closure(node) => attributes(&node.attrs),
        Expr::Const(node) => attributes(&node.attrs),
        Expr::Continue(node) => attributes(&node.attrs),
        Expr::Field(node) => attributes(&node.attrs),
        Expr::ForLoop(node) => attributes(&node.attrs),
        Expr::Group(node) => attributes(&node.attrs),
        Expr::If(node) => attributes(&node.attrs),
        Expr::Index(node) => attributes(&node.attrs),
        Expr::Infer(node) => attributes(&node.attrs),
        Expr::Let(node) => attributes(&node.attrs),
        Expr::Lit(node) => attributes(&node.attrs),
        Expr::Loop(node) => attributes(&node.attrs),
        Expr::Macro(node) => attributes(&node.attrs),
        Expr::Match(node) => attributes(&node.attrs),
        Expr::MethodCall(node) => attributes(&node.attrs),
        Expr::Paren(node) => attributes(&node.attrs),
        Expr::Path(node) => attributes(&node.attrs),
        Expr::Range(node) => attributes(&node.attrs),
        Expr::RawAddr(node) => attributes(&node.attrs),
        Expr::Reference(node) => attributes(&node.attrs),
        Expr::Repeat(node) => attributes(&node.attrs),
        Expr::Return(node) => attributes(&node.attrs),
        Expr::Struct(node) => attributes(&node.attrs),
        Expr::Try(node) => attributes(&node.attrs),
        Expr::TryBlock(node) => attributes(&node.attrs),
        Expr::Tuple(node) => attributes(&node.attrs),
        Expr::Unary(node) => attributes(&node.attrs),
        Expr::Unsafe(node) => attributes(&node.attrs),
        Expr::Verbatim(_) => false,
        Expr::While(node) => attributes(&node.attrs),
        Expr::Yield(node) => attributes(&node.attrs),
        _ => false,
    }
}

fn attributes(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let Meta::Path(path) = &attribute.meta else {
            return false;
        };
        if path.leading_colon.is_some() || path.segments.len() != 2 {
            return false;
        }
        let mut segments = path.segments.iter();
        let rustfmt = segments.next().expect("path has two segments");
        let skip = segments.next().expect("path has two segments");
        rustfmt.ident == "rustfmt"
            && skip.ident == "skip"
            && matches!(rustfmt.arguments, PathArguments::None)
            && matches!(skip.arguments, PathArguments::None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_exact_skip_path() {
        for (source, expected) in [
            ("#[rustfmt::skip] fn example() {}", true),
            ("#[rustfmtx::skip] fn example() {}", false),
            ("#[rustfmt::skip::extra] fn example() {}", false),
            ("#[rustfmt::skip(reason)] fn example() {}", false),
        ] {
            let item: Item = syn::parse_str(source).expect("item should parse");
            assert_eq!(self::item(&item), expected, "{source}");
        }
    }
}
