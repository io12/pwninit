use std::fmt::Display;

use colored::Colorize;

pub trait Warn {
    fn warn(self, msg: &str);
}

pub trait WarnResult {
    fn warn(self, msg: &str);
}

impl<T, E: Warn> WarnResult for Result<T, E> {
    fn warn(self, msg: &str) {
        if let Err(error) = self {
            error.warn(msg)
        }
    }
}

impl<T: Display> Warn for T {
    fn warn(self, msg: &str) {
        eprintln!("{}", format!("warning: {}: {}", msg, self).magenta().bold())
    }
}
