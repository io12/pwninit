use std::fmt::Display;

use colored::Colorize;

pub trait Warn {
    fn warn(self);
}

pub trait WarnResult {
    fn warn(self);
}

impl<T, E: Warn> WarnResult for Result<T, E> {
    fn warn(self) {
        if let Err(error) = self {
            error.warn()
        }
    }
}

impl<T: Display> Warn for T {
    fn warn(self) {
        eprintln!("{}", format!("warning: {}", self).magenta().bold())
    }
}
