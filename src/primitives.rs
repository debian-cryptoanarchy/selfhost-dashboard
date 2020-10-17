use core::fmt::{Display, Debug};
use core::borrow::Borrow;

pub trait Stringly: AsRef<str> + Borrow<str> + Display + Debug + Into<String> + crate::marker::StableData {}

impl<T> Stringly for T where T: AsRef<str> + Borrow<str> + Display + Debug + Into<String> + crate::marker::StableData {}
