//! property tests for hashkit.
//! See TESTING.md for the Santh testing standard.

#[path = "property/blake3.rs"]
mod blake3;
#[path = "property/invariants.rs"]
mod invariants;
#[path = "property/large_fuzz.rs"]
mod large_fuzz;
