//! concurrent tests for hashkit.
//! See TESTING.md for the Santh testing standard.

#[path = "concurrent/determinism.rs"]
mod determinism;
#[path = "concurrent/stress.rs"]
mod stress;
