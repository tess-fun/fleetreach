//! The parts of a class file a call graph needs, with names interned.

use std::collections::HashMap;

/// An interned string.
pub type Sym = u32;

/// Interned strings: class names in slash form, method names, descriptors.
#[derive(Debug, Default, Clone)]
pub struct Interner {
    ids: HashMap<Box<str>, Sym>,
    names: Vec<Box<str>>,
}

impl Interner {
    pub fn intern(&mut self, s: &str) -> Sym {
        if let Some(&id) = self.ids.get(s) {
            return id;
        }
        let id = Sym::try_from(self.names.len()).unwrap_or(Sym::MAX);
        self.names.push(s.into());
        self.ids.insert(s.into(), id);
        id
    }

    /// The id of a string already seen.
    #[must_use]
    pub fn get(&self, s: &str) -> Option<Sym> {
        self.ids.get(s).copied()
    }

    #[must_use]
    pub fn name(&self, id: Sym) -> &str {
        self.names.get(id as usize).map_or("", |n| n)
    }
}

/// Whose code a class is. Every non-private method of the service's own code is an entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    App,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// `invokestatic`: resolved up the superclasses.
    Static,
    /// `invokespecial`: resolved up the superclasses, no dispatch.
    Special,
    /// `invokevirtual` and `invokeinterface`: every concrete subtype's resolution.
    Virtual,
}

/// What a method body does that matters to the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Call {
        kind: CallKind,
        class: Sym,
        name: Sym,
        desc: Sym,
    },
    /// `new`: the class is instantiated and initialized.
    New(Sym),
    /// A static field access: the class is initialized.
    Touch(Sym),
    /// A constant string, which may name a class.
    Text(Sym),
    /// A class constant, which reflection can instantiate.
    ClassConst(Sym),
    /// An `invokedynamic` this crate cannot resolve (not a lambda or string concatenation).
    OpenDynamic,
}

#[derive(Debug, Clone, Default)]
pub struct Method {
    pub name: Sym,
    pub desc: Sym,
    pub is_static: bool,
    pub is_abstract: bool,
    pub is_private: bool,
    pub ops: Vec<Op>,
    /// Annotation types, slash form.
    pub annotations: Vec<Sym>,
    /// Class names the annotations' elements give, as class literals or strings.
    pub annotation_refs: Vec<Sym>,
}

#[derive(Debug, Clone)]
pub struct Class {
    pub name: Sym,
    pub superclass: Option<Sym>,
    pub interfaces: Vec<Sym>,
    pub is_interface: bool,
    pub is_abstract: bool,
    pub role: Role,
    pub methods: Vec<Method>,
    pub annotations: Vec<Sym>,
    pub annotation_refs: Vec<Sym>,
}
