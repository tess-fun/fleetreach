/// Non-generic, exported, and actually called by the bin — codegen'd, so it has
/// a graph node.
pub fn safe(n: u32) -> u32 {
    n.wrapping_add(1)
}

/// Exported but generic, so it is codegen'd only when instantiated. The bin never
/// calls it, so no monomorphization exists anywhere in the closure and the mono
/// collector produces no node. The driver still records it as a generic def, the
/// positive evidence that lets reach return a sound `NotReachable`.
pub fn vulnerable_generic<T: Into<u64>>(x: T) -> u64 {
    x.into()
}
