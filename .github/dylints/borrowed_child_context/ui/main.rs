struct Context;

impl Context {
    fn child(&self, _: &'static str) -> Self {
        Self
    }
}

struct Holder {
    context: Context,
}

fn takes_context(_: &Context) {}

fn takes_context_mut(_: &mut Context) {}

#[rustfmt::skip]
fn main() {
    let context = Context;
    let child = context.child("bound");
    takes_context(&child);
    takes_context(&context);

    takes_context(&context.child("direct"));
    takes_context(
        &context
            .child("multiline"),
    );

    let holder = Holder { context: Context };
    takes_context(&holder.context.child("field"));

    let mut context = Context;
    takes_context_mut(&mut context.child("mutable"));
}
