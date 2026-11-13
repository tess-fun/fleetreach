//! A stack large enough for the file being read.
//!
//! `oxc_parser` and the AST walk recurse once per level of nesting, and so do the Python
//! reader's call and attribute chains. A hostile file inside the 2 MiB cap can nest a million
//! levels deep (`((((...`, `a=a=a=...`, `() => () => ...`), which overflows any thread's stack
//! and aborts the whole process: a panic handler never sees it. So each read runs on its own
//! thread with a stack sized from the file. The size is a bound, not a guess: every level of
//! nesting costs at most [`Cost::opener`] bytes of stack when it opens with `(`, `[` or `{`,
//! and at most [`Cost::byte`] bytes per source byte otherwise, whatever the lexer makes of
//! strings, regexes and templates. Counting brackets without lexing can only count too many.
//!
//! The costs were measured on the worst shapes found (`examples/srcattack.rs`), separately for
//! optimized and debug builds, and carry a margin of one and a half. Real files need far less:
//! of 231,223 installed JavaScript files, the largest bound is 706 MiB before the margin, the
//! median under 1 MiB, so the largest asks for about 1.1 GiB. Only the address range is
//! reserved; pages are used as deep as the parse goes. A file whose bound passes
//! [`MAX_STACK`] is not read, like one over the size cap.

/// No read gets a larger stack: a file needing more is not read.
pub(crate) const MAX_STACK: u64 = 2 << 30;

/// Room for everything around the parse.
const BASE: u64 = 16 << 20;

/// Stack bytes one level of nesting can cost.
pub(crate) struct Cost {
    /// Per `(`, `[` or `{`: the worst is nested arrow functions, about 1,170 bytes a level in
    /// an optimized build and 4,100 in a debug one.
    pub opener: u64,
    /// Per other byte: the worst is chained assignment (`a=a=a=`), about 290 bytes per
    /// source byte optimized and 1,420 debug.
    pub byte: u64,
}

/// JavaScript and TypeScript through `oxc_parser` and the walk.
pub(crate) const JS: Cost = if cfg!(debug_assertions) {
    Cost {
        opener: 4_500,
        byte: 1_500,
    }
} else {
    Cost {
        opener: 1_300,
        byte: 300,
    }
};

/// The Python reader: only chains of calls and attributes recurse (about 56 bytes per
/// source byte optimized, 204 debug); brackets do not.
pub(crate) const PYTHON: Cost = if cfg!(debug_assertions) {
    Cost {
        opener: 300,
        byte: 300,
    }
} else {
    Cost {
        opener: 64,
        byte: 64,
    }
};

/// The stack a read of `src` may need, or `None` past [`MAX_STACK`].
pub(crate) fn needed(src: &str, cost: &Cost) -> Option<usize> {
    let bytes = src.as_bytes();
    let openers = bytes
        .iter()
        .filter(|b| matches!(b, b'(' | b'[' | b'{'))
        .count() as u64;
    let rest = bytes.len() as u64 - openers;
    let bound = openers
        .saturating_mul(cost.opener)
        .saturating_add(rest.saturating_mul(cost.byte));
    let size = bound.saturating_add(bound / 2).saturating_add(BASE);
    (size <= MAX_STACK)
        .then(|| usize::try_from(size).ok())
        .flatten()
}

/// Run `read` on a thread with the stack `src` needs. `None` when the file needs more than
/// [`MAX_STACK`], the thread cannot be made, or `read` panics.
pub(crate) fn on_own_stack<T: Send>(
    src: &str,
    cost: &Cost,
    read: impl FnOnce() -> T + Send,
) -> Option<T> {
    let size = needed(src, cost)?;
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("fleetreach-parse".to_string())
            .stack_size(size)
            .spawn_scoped(scope, read)
            .ok()?
            .join()
            .ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_file_asks_for_little_more_than_the_base() {
        let need = needed("const a = f(1);\n", &JS).unwrap_or(usize::MAX);
        assert!(need < (BASE as usize) + (1 << 20), "{need}");
    }

    #[test]
    fn a_file_needing_more_than_the_cap_is_not_read() {
        let src = "(".repeat(2 << 20);
        assert_eq!(needed(&src, &JS), None);
        assert_eq!(on_own_stack(&src, &JS, || 1), None);
    }
}
