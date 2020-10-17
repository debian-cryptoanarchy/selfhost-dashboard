/// Marker trait that ensures references returned from `Deref::deref()`, `DerefMut::deref_mut()`,
/// `AsRef<<Self as Deref>::Target>::as_ref()`, `AsMut<<Self as Deref>::Target>::as_mut()`,
/// `Borrow<<Self as Deref>::Target>::borrow()`, `BorrowMut<<Self as Deref>::Target>::borrow_mut()`
/// always point to the same data. (But the pointer doesn't need to have stable address.)
pub trait StableData {}

use std::rc::Rc;
use std::sync::Arc;
use std::borrow::Cow;

// We believe types from `std` satisfy the condition
impl<T: ?Sized> StableData for &'_ T {}
impl StableData for String {}
impl<T: ToOwned + ?Sized> StableData for Cow<'_, T> {}
impl<T: ?Sized> StableData for Box<T> {}
impl<T: ?Sized> StableData for Rc<T> {}
impl<T: ?Sized> StableData for Arc<T> {}
impl<T> StableData for Vec<T> {}
