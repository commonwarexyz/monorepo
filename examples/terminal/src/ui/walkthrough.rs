use crossterm::style::{Color, Stylize};
use std::{fmt::Display, io::IsTerminal as _};

fn accent(text: &str) -> String {
    if std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb")
    {
        text.with(Color::Cyan).bold().to_string()
    } else {
        text.to_owned()
    }
}

pub(super) fn banner() {
    println!("\n  {}", accent("BAJILLION / PAYMENT WALKTHROUGH"));
    println!("  Wallets  ->  Operator  ->  Validators  ->  Settlement\n");
}

pub(super) fn step(number: u8, title: &str, description: &str) {
    println!("\n  {}", accent(&format!("[{number}/5] {title}")));
    println!("  {description}\n");
}

pub(super) fn event(label: &str, message: impl Display) {
    println!("  {label:>11}  {message}");
}
