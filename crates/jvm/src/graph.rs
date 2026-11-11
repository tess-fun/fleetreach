//! A rapid type analysis call graph, walked from a service's entry points: a virtual call
//! lands only on classes the graph has seen an instance of, or that something makes by name.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::classpath::ClassPath;
use crate::model::{CallKind, Class, Method, Op, Role, Sym};

/// A method, as indices into [`ClassPath::classes`] and that class's `methods`.
type Id = (u32, u32);

/// Annotations that make a framework call into a class, slash form. Annotation types
/// meta-annotated with one of these count too, so `@RestController` and an app's own
/// stereotypes need no entry here as long as the annotation's class is on the class path.
const ENTRY_ANNOTATIONS: &[&str] = &[
    "org/springframework/stereotype/Component",
    "org/springframework/stereotype/Controller",
    "org/springframework/stereotype/Service",
    "org/springframework/stereotype/Repository",
    "org/springframework/context/annotation/Configuration",
    "org/springframework/context/annotation/Bean",
    "org/springframework/boot/autoconfigure/SpringBootApplication",
    "org/springframework/boot/autoconfigure/AutoConfiguration",
    "org/springframework/web/bind/annotation/RestController",
    "org/springframework/web/bind/annotation/ControllerAdvice",
    "org/springframework/web/bind/annotation/RequestMapping",
    "org/springframework/web/bind/annotation/GetMapping",
    "org/springframework/web/bind/annotation/PostMapping",
    "org/springframework/web/bind/annotation/PutMapping",
    "org/springframework/web/bind/annotation/PatchMapping",
    "org/springframework/web/bind/annotation/DeleteMapping",
    "org/springframework/web/bind/annotation/ResponseBody",
    "org/springframework/web/bind/annotation/ExceptionHandler",
    "org/springframework/web/bind/annotation/ModelAttribute",
    "org/springframework/web/bind/annotation/InitBinder",
    "org/springframework/messaging/handler/annotation/MessageMapping",
    "org/springframework/graphql/data/method/annotation/SchemaMapping",
    "org/springframework/boot/actuate/endpoint/annotation/ReadOperation",
    "org/springframework/boot/actuate/endpoint/annotation/WriteOperation",
    "org/springframework/boot/actuate/endpoint/annotation/DeleteOperation",
    "org/aspectj/lang/annotation/Around",
    "org/aspectj/lang/annotation/Before",
    "org/aspectj/lang/annotation/After",
    "org/aspectj/lang/annotation/AfterReturning",
    "org/aspectj/lang/annotation/AfterThrowing",
    "org/springframework/scheduling/annotation/Scheduled",
    "org/springframework/context/event/EventListener",
    "org/springframework/beans/factory/annotation/Autowired",
    "org/springframework/jms/annotation/JmsListener",
    "org/springframework/kafka/annotation/KafkaListener",
    "org/springframework/amqp/rabbit/annotation/RabbitListener",
    "org/springframework/security/oauth2/provider/endpoint/FrameworkEndpoint",
    "com/google/inject/Inject",
    "com/google/inject/Provides",
    "org/apache/camel/Converter",
    "org/apache/camel/FallbackConverter",
    "org/osgi/service/component/annotations/Component",
    "org/osgi/service/component/annotations/Activate",
    "org/osgi/service/component/annotations/Deactivate",
    "org/osgi/service/component/annotations/Modified",
    "org/apache/felix/scr/annotations/Component",
    "org/apache/felix/scr/annotations/Activate",
    "org/apache/felix/scr/annotations/Deactivate",
    "org/apache/felix/scr/annotations/Modified",
    // Jenkins finds what these mark through an index: `@Initializer`, `@Terminator`, `@Extension`.
    "org/jvnet/hudson/annotation_indexer/Indexed",
    "net/java/sezpoz/Indexable",
];

/// The same annotations under both Java EE package roots.
const EE_ANNOTATIONS: &[&str] = &[
    "ws/rs/Path",
    "ws/rs/GET",
    "ws/rs/POST",
    "ws/rs/PUT",
    "ws/rs/DELETE",
    "ws/rs/PATCH",
    "ws/rs/HEAD",
    "ws/rs/OPTIONS",
    "ws/rs/ext/Provider",
    "jws/WebService",
    "servlet/annotation/WebServlet",
    "servlet/annotation/WebFilter",
    "servlet/annotation/WebListener",
    "websocket/server/ServerEndpoint",
    "inject/Inject",
    "inject/Named",
    "inject/Singleton",
    "annotation/ManagedBean",
    "annotation/PostConstruct",
    "enterprise/context/ApplicationScoped",
    "enterprise/context/RequestScoped",
    "enterprise/context/SessionScoped",
    "enterprise/context/Dependent",
    "ejb/Stateless",
    "ejb/Stateful",
    "ejb/Singleton",
    "ejb/MessageDriven",
    "faces/bean/ManagedBean",
    "faces/convert/FacesConverter",
    "faces/validator/FacesValidator",
    "faces/component/FacesComponent",
    // JAXB makes the bound classes itself while it reads a document.
    "xml/bind/annotation/XmlRootElement",
    "xml/bind/annotation/XmlType",
    "xml/bind/annotation/XmlRegistry",
];

/// EE annotations on a class whose every public method is called from outside the service.
const EE_ENDPOINTS: &[&str] = &[
    "ws/rs/Path",
    "ws/rs/ext/Provider",
    "ejb/Stateless",
    "ejb/Stateful",
    "ejb/Singleton",
    "ejb/MessageDriven",
    "jws/WebService",
];

/// Name endings of classes generated at build time and loaded by building the name at run time:
/// JBoss Logging's message classes, and Undertow's request parser.
const GENERATED: &[&str] = &["_$logger", "_$bundle", "$$generated"];

/// Name starts of the same: Groovy's `dgm$N` method classes, which `dgminfo` lists by number.
const GENERATED_PREFIXES: &[&str] = &["org/codehaus/groovy/runtime/dgm$"];

/// Classes only runtime-generated proxies call.
const CALLED_BY_PROXIES: &[&str] = &[
    "org/springframework/cglib/proxy/MethodProxy",
    "net/sf/cglib/proxy/MethodProxy",
];

/// Types runtime-generated proxies call into, so they count as outside the graph: a repository
/// interface's `findAll` lands on `SimpleJpaRepository` by matching the name.
const PROXY_CALLBACKS: &[&str] = &[
    "org/springframework/cglib/proxy/Callback",
    "net/sf/cglib/proxy/Callback",
    "org/springframework/data/repository/Repository",
];

/// `Object` methods the JDK calls on anything: `HashMap` on a key, `StringBuilder` on a value.
const OBJECT_METHODS: &[&str] = &["hashCode", "equals", "toString"];

/// Annotation packages whose method annotations make a serializer call the method on any
/// instance, whatever its name: Jackson's `@JsonAnyGetter`, `@JsonValue`, `@JsonAnySetter`.
const SERIALIZER_ANNOTATIONS: &[&str] = &[
    "com/fasterxml/jackson/annotation/",
    "com/fasterxml/jackson/databind/annotation/",
    "org/codehaus/jackson/annotate/",
];

/// JDK types that declare no method a callback could override.
const MARKERS: &[&str] = &[
    "java/lang/Object",
    "java/io/Serializable",
    "java/lang/Cloneable",
    "java/util/RandomAccess",
    "java/util/EventListener",
    "java/lang/annotation/Annotation",
    "java/lang/Record",
];

/// Packages the JDK or a container implements. A jar on the class path can carry these types
/// (`xml-apis` ships `DefaultHandler`), but the parser or server calling into a subclass is
/// still outside the graph.
const PLATFORM: &[&str] = &[
    "java/",
    "javax/",
    "jakarta/",
    "org/xml/sax/",
    "org/w3c/dom/",
    "org/ietf/jgss/",
    "org/omg/",
];

/// Private methods `ObjectInputStream` and `ObjectOutputStream` call on a serializable class.
const SERIALIZATION_HOOKS: &[&str] = &[
    "readObject",
    "writeObject",
    "readObjectNoData",
    "readResolve",
    "writeReplace",
];

/// Calls that take a class or member from data a constant does not give.
const REFLECTION: &[(&str, &str)] = &[
    ("java/lang/Class", "forName"),
    ("java/lang/Class", "newInstance"),
    ("java/lang/ClassLoader", "loadClass"),
    ("java/lang/reflect/Method", "invoke"),
    ("java/lang/reflect/Constructor", "newInstance"),
    ("java/lang/reflect/Proxy", "newProxyInstance"),
    ("java/lang/invoke/MethodHandle", "invoke"),
    ("java/lang/invoke/MethodHandle", "invokeExact"),
    ("java/lang/invoke/MethodHandle", "invokeWithArguments"),
];

/// Why a method is in the graph with no caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// A non-private method of the service's own code.
    AppCode,
    /// `Main-Class` or `Start-Class`.
    Manifest,
    /// An annotated class nested in one the service makes.
    Nested,
    /// Generated code calls it, or code that builds its name loads it.
    Generated,
    /// Carries, or its class carries, an annotation frameworks act on.
    Annotation(String),
    /// Named by another class's annotation.
    AnnotationRef(String),
    /// Named in this resource.
    Resource(String),
}

/// How a method got into the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Via {
    Root(Root),
    /// Called, instantiated or initialized from another method, or run by code this graph
    /// does not hold (the JDK) on an instance made there.
    Call(Id),
}

/// One step of a witness, entry point first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub class: String,
    pub method: String,
    pub descriptor: String,
}

/// A path to a method: why the first step is an entry point, then each step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub root: Root,
    pub steps: Vec<Step>,
}

/// The graph, reached methods with how each was reached.
#[derive(Debug)]
pub struct Analysis<'a> {
    cp: &'a ClassPath,
    reached: HashMap<Id, Via>,
    /// Entry points found. None means the inputs held no service to analyze.
    pub roots: usize,
    /// Reached methods that call reflection on data no constant gives, as `class.method`.
    pub open_reflection: Vec<String>,
    /// Reached `invokedynamic` sites with an unknown bootstrap method.
    pub open_dynamic: usize,
}

struct Walk<'a> {
    cp: &'a ClassPath,
    /// A type to every class declaring it as superclass or interface, unknown types included.
    subtypes: HashMap<Sym, Vec<u32>>,
    /// Per type, the virtual calls seen on it, each with its first caller.
    sites: HashMap<Sym, HashMap<(Sym, Sym), Id>>,
    reached: HashMap<Id, Via>,
    queue: VecDeque<Id>,
    instantiated: HashSet<u32>,
    initialized: HashSet<u32>,
    entered: HashSet<u32>,
    entry_types: HashSet<Sym>,
    endpoints: HashSet<Sym>,
    callbacks: HashSet<Sym>,
    /// Annotated classes by the class they are nested in.
    nested: HashMap<Sym, Vec<u32>>,
    /// Classes by their package, slash form with the trailing slash.
    packages: HashMap<String, Vec<u32>>,
    /// Classes by the last segment of their name.
    simple: HashMap<String, Vec<u32>>,
    clinit: Option<Sym>,
    init: Option<Sym>,
    object: Option<Sym>,
    serializable: Option<Sym>,
    reflection: HashSet<(Sym, Sym)>,
    markers: HashSet<Sym>,
    open_reflection: Vec<String>,
    open_dynamic: usize,
    roots: usize,
}

/// Build the graph from every entry point.
#[must_use]
pub fn analyze(cp: &ClassPath) -> Analysis<'_> {
    let mut walk = Walk::new(cp);
    walk.seed();
    walk.run();
    Analysis {
        cp,
        reached: walk.reached,
        roots: walk.roots,
        open_reflection: walk.open_reflection,
        open_dynamic: walk.open_dynamic,
    }
}

impl<'a> Walk<'a> {
    fn new(cp: &'a ClassPath) -> Self {
        let mut subtypes: HashMap<Sym, Vec<u32>> = HashMap::new();
        for (i, c) in cp.classes.iter().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            for parent in c.superclass.iter().chain(&c.interfaces) {
                subtypes.entry(*parent).or_default().push(i);
            }
        }
        let mut entry_types: HashSet<Sym> = ENTRY_ANNOTATIONS
            .iter()
            .filter_map(|n| cp.names.get(n))
            .collect();
        for root in ["javax", "jakarta"] {
            entry_types.extend(
                EE_ANNOTATIONS
                    .iter()
                    .filter_map(|n| cp.names.get(&format!("{root}/{n}"))),
            );
        }
        // Any `Inject` counts: libraries shade Guice (Elasticsearch's own copy, for one).
        for c in &cp.classes {
            for s in c
                .methods
                .iter()
                .flat_map(|m| &m.annotations)
                .chain(&c.annotations)
            {
                if cp.names.name(*s).ends_with("/inject/Inject") {
                    entry_types.insert(*s);
                }
            }
        }
        // Annotations carrying an entry annotation, to a fixed point.
        loop {
            let before = entry_types.len();
            for c in &cp.classes {
                if !entry_types.contains(&c.name)
                    && c.is_interface
                    && c.annotations.iter().any(|a| entry_types.contains(a))
                {
                    entry_types.insert(c.name);
                }
            }
            if entry_types.len() == before {
                break;
            }
        }
        let endpoints = ["javax", "jakarta"]
            .iter()
            .flat_map(|root| EE_ENDPOINTS.iter().map(move |n| format!("{root}/{n}")))
            .filter_map(|n| cp.names.get(&n))
            .collect();
        let mut nested: HashMap<Sym, Vec<u32>> = HashMap::new();
        for (i, c) in cp.classes.iter().enumerate() {
            let name = cp.names.name(c.name);
            // Field annotations count: a Log4j plugin's `Builder` carries `@PluginBuilderAttribute`
            // on its fields only, and that annotation names the visitor that fills them.
            if c.annotations.is_empty() && c.annotation_refs.is_empty() {
                continue;
            }
            if let Some(outer) = name.rfind('$').and_then(|d| cp.names.get(&name[..d])) {
                nested
                    .entry(outer)
                    .or_default()
                    .push(u32::try_from(i).unwrap_or(u32::MAX));
            }
        }
        let mut packages: HashMap<String, Vec<u32>> = HashMap::new();
        let mut simple: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, c) in cp.classes.iter().enumerate() {
            let name = cp.names.name(c.name);
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if let Some(slash) = name.rfind('/') {
                packages
                    .entry(name[..=slash].to_string())
                    .or_default()
                    .push(i);
                simple
                    .entry(name[slash + 1..].to_string())
                    .or_default()
                    .push(i);
            }
        }
        Walk {
            cp,
            endpoints,
            packages,
            simple,
            callbacks: PROXY_CALLBACKS
                .iter()
                .filter_map(|n| cp.names.get(n))
                .collect(),
            nested,
            subtypes,
            sites: HashMap::new(),
            reached: HashMap::new(),
            queue: VecDeque::new(),
            instantiated: HashSet::new(),
            initialized: HashSet::new(),
            entered: HashSet::new(),
            entry_types,
            clinit: cp.names.get("<clinit>"),
            init: cp.names.get("<init>"),
            object: cp.names.get("java/lang/Object"),
            serializable: cp.names.get("java/io/Serializable"),
            reflection: REFLECTION
                .iter()
                .filter_map(|(c, m)| Some((cp.names.get(c)?, cp.names.get(m)?)))
                .collect(),
            markers: MARKERS.iter().filter_map(|n| cp.names.get(n)).collect(),
            open_reflection: Vec::new(),
            open_dynamic: 0,
            roots: 0,
        }
    }

    fn class(&self, i: u32) -> &'a Class {
        &self.cp.classes[i as usize]
    }

    fn index(&self, name: Sym) -> Option<u32> {
        self.cp
            .by_name
            .get(&name)
            .and_then(|i| u32::try_from(*i).ok())
    }

    fn reach(&mut self, id: Id, via: Via) {
        if let std::collections::hash_map::Entry::Vacant(slot) = self.reached.entry(id) {
            slot.insert(via);
            self.queue.push_back(id);
        }
    }

    fn root(&mut self, id: Id, root: Root) {
        self.roots += 1;
        self.reach(id, Via::Root(root));
    }

    fn seed(&mut self) {
        let cp = self.cp;
        for name in CALLED_BY_PROXIES {
            if let Some(i) = cp.names.get(name).and_then(|s| self.index(s)) {
                self.enter(i, &Root::Generated);
            }
        }
        for (i, c) in cp.classes.iter().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if c.role == Role::App {
                self.enter(i, &Root::AppCode);
                continue;
            }
            let name = cp.names.name(c.name);
            if GENERATED.iter().any(|e| name.ends_with(e))
                || GENERATED_PREFIXES.iter().any(|p| name.starts_with(p))
            {
                self.drive(i, &Via::Root(Root::Generated));
            }
            if let Some(a) = c.annotations.iter().find(|a| self.entry_types.contains(a)) {
                let label = Root::Annotation(cp.names.name(*a).to_string());
                if c.annotations.iter().any(|a| self.endpoints.contains(a)) {
                    self.enter(i, &label);
                } else {
                    self.drive(i, &Via::Root(label.clone()));
                }
            }
            for (j, m) in c.methods.iter().enumerate() {
                if let Some(a) = m.annotations.iter().find(|a| self.entry_types.contains(a)) {
                    let label = Root::Annotation(cp.names.name(*a).to_string());
                    // A method a framework calls runs on an instance the framework made.
                    self.drive(i, &Via::Root(label.clone()));
                    self.root((i, u32::try_from(j).unwrap_or(u32::MAX)), label);
                }
            }
        }
        for (name, origin) in &cp.named_in_resources {
            if let Some(i) = self.named(name) {
                self.drive(i, &Via::Root(Root::Resource(origin.clone())));
            }
        }
        for name in &cp.main_classes {
            if let Some(i) = self.named(name) {
                self.enter(i, &Root::Manifest);
            }
        }
    }

    fn named(&self, name: &str) -> Option<u32> {
        self.cp
            .class_named(name)
            .and_then(|i| u32::try_from(i).ok())
    }

    /// The service's own class: every non-private method it has or inherits is an entry point.
    fn enter(&mut self, class: u32, why: &Root) {
        let mut next = Some(class);
        while let Some(i) = next {
            let c = self.class(i);
            for (j, m) in c.methods.iter().enumerate() {
                if !m.is_private && !m.is_abstract {
                    self.root((i, u32::try_from(j).unwrap_or(u32::MAX)), why.clone());
                }
            }
            next = c.superclass.and_then(|s| self.index(s));
        }
        self.drive(class, &Via::Root(why.clone()));
    }

    /// A class something makes by name: its constructors run, an instance exists for virtual
    /// calls to land on, its static methods can be called reflectively, and whatever its
    /// annotations name is made too, through annotations on annotations:
    /// `@ConditionalOnProperty` carries `@Conditional(OnPropertyCondition.class)`.
    fn drive(&mut self, class: u32, via: &Via) {
        if !self.entered.insert(class) {
            return;
        }
        if matches!(via, Via::Root(_)) {
            self.roots += 1;
        }
        self.make(class, via);
        self.initialize(class, via);
        self.statics(class, via);
        let c = self.class(class);
        let label = self.cp.names.name(c.name).to_string();
        let refs = c
            .annotation_refs
            .iter()
            .chain(c.methods.iter().flat_map(|m| &m.annotation_refs));
        let types = c
            .annotations
            .iter()
            .chain(c.methods.iter().flat_map(|m| &m.annotations));
        let named = Via::Root(Root::AnnotationRef(label));
        for r in refs.chain(types) {
            if let Some(i) = self.index(*r) {
                self.drive(i, &named);
            }
        }
    }

    /// An instance made outside the code this graph sees: its constructors ran.
    fn make(&mut self, class: u32, via: &Via) {
        let c = self.class(class);
        for (j, m) in c.methods.iter().enumerate() {
            if Some(m.name) == self.init {
                self.reach((class, u32::try_from(j).unwrap_or(u32::MAX)), via.clone());
            }
        }
        self.mark_instantiated(class, via);
    }

    /// Code holding a class by name can call its static methods reflectively.
    fn statics(&mut self, class: u32, via: &Via) {
        let c = self.class(class);
        for (j, m) in c.methods.iter().enumerate() {
            if m.is_static && !m.is_private && Some(m.name) != self.clinit {
                self.reach((class, u32::try_from(j).unwrap_or(u32::MAX)), via.clone());
            }
        }
    }

    /// `<clinit>` of a class, its superclasses and its interfaces. An interface's runs only for
    /// a static field or a default method, but a static field read through a subclass names the
    /// subclass, so all of them count.
    fn initialize(&mut self, class: u32, via: &Via) {
        let mut stack = vec![class];
        while let Some(i) = stack.pop() {
            if !self.initialized.insert(i) {
                continue;
            }
            let c = self.class(i);
            if let Some(j) = c.methods.iter().position(|m| Some(m.name) == self.clinit) {
                self.reach((i, u32::try_from(j).unwrap_or(u32::MAX)), via.clone());
            }
            let parents = c.superclass.iter().chain(&c.interfaces);
            stack.extend(parents.filter_map(|p| self.index(*p)));
        }
    }

    /// An instance exists. Code outside this graph can call whatever it inherits from a type
    /// outside this graph, so those methods are reached: `resolveClass` from the JDK's
    /// `ObjectInputStream`, `run` from an executor, `compare` from a sort.
    fn mark_instantiated(&mut self, class: u32, via: &Via) {
        if !self.instantiated.insert(class) {
            return;
        }
        self.dispatch_new_instance(class);
        // Spring reads the annotated classes nested in a configuration or a nested condition.
        if let Some(nested) = self.nested.get(&self.class(class).name) {
            for i in nested.clone() {
                self.drive(i, &Via::Root(Root::Nested));
            }
        }
        // Jackson reads the annotations of what it handles: `@JsonDeserialize(using = ...)` on
        // the class, a superclass or a field makes the named deserializer.
        let mut next = Some(class);
        while let Some(i) = next {
            let c = self.class(i);
            let names = &self.cp.names;
            let jackson = c
                .annotations
                .iter()
                .chain(&c.annotation_refs)
                .chain(c.methods.iter().flat_map(|m| &m.annotations))
                .any(|a| {
                    let a = names.name(*a);
                    SERIALIZER_ANNOTATIONS.iter().any(|p| a.starts_with(p))
                });
            if jackson {
                let refs: Vec<Sym> = c
                    .annotation_refs
                    .iter()
                    .chain(c.methods.iter().flat_map(|m| &m.annotation_refs))
                    .copied()
                    .collect();
                let label = Via::Root(Root::AnnotationRef(names.name(c.name).to_string()));
                for r in refs {
                    if let Some(j) = self.index(r) {
                        self.drive(j, &label);
                    }
                }
            }
            next = c.superclass.and_then(|s| self.index(s));
        }
        let mut seen = HashSet::new();
        let outside = self.has_outside_type(class, &mut seen);
        let mut seen = HashSet::new();
        // A parent outside the graph may be serializable too (`HashMap`).
        let serial = outside || self.is_serializable(class, &mut seen);
        let mut next = Some(class);
        while let Some(i) = next {
            let c = self.class(i);
            for (j, m) in c.methods.iter().enumerate() {
                let special = Some(m.name) == self.init || Some(m.name) == self.clinit;
                let callback = outside && !m.is_private && !m.is_static && !m.is_abstract;
                let hook = serial
                    && !m.is_static
                    && !m.is_abstract
                    && SERIALIZATION_HOOKS.contains(&self.cp.names.name(m.name));
                if !special && (callback || hook || self.called_on_any_instance(m)) {
                    self.reach((i, u32::try_from(j).unwrap_or(u32::MAX)), via.clone());
                }
            }
            next = c.superclass.and_then(|s| self.index(s));
        }
    }

    fn has_outside_type(&self, class: u32, seen: &mut HashSet<u32>) -> bool {
        if !seen.insert(class) {
            return false;
        }
        let c = self.class(class);
        c.superclass
            .iter()
            .chain(&c.interfaces)
            .any(|p| match self.index(*p) {
                Some(_) if self.callbacks.contains(p) => true,
                Some(_) if self.is_platform(*p) && !self.markers.contains(p) => true,
                Some(i) => self.has_outside_type(i, seen),
                None => !self.markers.contains(p) && Some(*p) != self.object,
            })
    }

    fn is_platform(&self, name: Sym) -> bool {
        let name = self.cp.names.name(name);
        PLATFORM.iter().any(|p| name.starts_with(p))
    }

    fn is_serializable(&self, class: u32, seen: &mut HashSet<u32>) -> bool {
        if !seen.insert(class) {
            return false;
        }
        let c = self.class(class);
        c.superclass.iter().chain(&c.interfaces).any(|p| {
            Some(*p) == self.serializable
                || self
                    .index(*p)
                    .is_some_and(|i| self.is_serializable(i, seen))
        })
    }

    /// Whether code outside the graph can call this method on any instance: a framework setting
    /// or reading a bean property, or the JDK hashing a key.
    fn called_on_any_instance(&self, m: &Method) -> bool {
        if m.is_private || m.is_static || m.is_abstract {
            return false;
        }
        let name = self.cp.names.name(m.name);
        let property = |prefix: &str| {
            name.strip_prefix(prefix)
                .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_uppercase()))
        };
        let serialized = m.annotations.iter().any(|a| {
            let a = self.cp.names.name(*a);
            SERIALIZER_ANNOTATIONS.iter().any(|p| a.starts_with(p))
        });
        // Utility code clones any `Cloneable` reflectively: XStream's `Cloneables`, commons-lang's
        // `ObjectUtils.clone`.
        // The collector runs `finalize`.
        OBJECT_METHODS.contains(&name)
            || name == "clone"
            || name == "finalize"
            || property("get")
            || property("set")
            || property("is")
            || serialized
    }

    /// What `name desc` resolves to on `class`: up the superclasses, then the default methods of
    /// the interfaces. Every default counts, since a sub-interface can override another.
    fn resolve(&self, class: u32, name: Sym, desc: Sym) -> Vec<Id> {
        let mut next = Some(class);
        while let Some(i) = next {
            let c = self.class(i);
            if let Some(j) = c
                .methods
                .iter()
                .position(|m| m.name == name && m.desc == desc && !m.is_abstract)
            {
                return vec![(i, u32::try_from(j).unwrap_or(u32::MAX))];
            }
            next = c.superclass.and_then(|s| self.index(s));
        }
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        self.default_methods(class, name, desc, &mut seen, &mut found);
        found
    }

    fn default_methods(
        &self,
        class: u32,
        name: Sym,
        desc: Sym,
        seen: &mut HashSet<u32>,
        found: &mut Vec<Id>,
    ) {
        if !seen.insert(class) {
            return;
        }
        let c = self.class(class);
        for parent in c.interfaces.iter().chain(&c.superclass) {
            let Some(i) = self.index(*parent) else {
                continue;
            };
            let p = self.class(i);
            if p.is_interface {
                if let Some(j) = p
                    .methods
                    .iter()
                    .position(|m| m.name == name && m.desc == desc && !m.is_abstract)
                {
                    found.push((i, u32::try_from(j).unwrap_or(u32::MAX)));
                }
            }
            self.default_methods(i, name, desc, seen, found);
        }
    }

    /// Every call seen so far on a type of this new instance can now land on it.
    fn dispatch_new_instance(&mut self, class: u32) {
        let c = self.class(class);
        if c.is_interface || c.is_abstract {
            return;
        }
        let mut types = vec![c.name];
        let mut seen: HashSet<Sym> = HashSet::new();
        while let Some(t) = types.pop() {
            if !seen.insert(t) {
                continue;
            }
            if let Some(i) = self.index(t) {
                let p = self.class(i);
                types.extend(p.superclass.iter().chain(&p.interfaces));
            }
            let Some(calls) = self.sites.get(&t) else {
                continue;
            };
            let found: Vec<(Id, Id)> = calls
                .iter()
                .flat_map(|((name, desc), from)| {
                    let found = self.resolve(class, *name, *desc);
                    found.into_iter().map(|target| (target, *from))
                })
                .collect();
            for (target, from) in found {
                self.reach(target, Via::Call(from));
            }
        }
    }

    /// A virtual call: it lands on every instance of a subtype made so far, and
    /// [`Self::dispatch_new_instance`] covers the ones made later.
    fn virtual_call(&mut self, class: Sym, name: Sym, desc: Sym, from: Id) {
        let calls = self.sites.entry(class).or_default();
        if calls.contains_key(&(name, desc)) {
            return;
        }
        calls.insert((name, desc), from);
        // A repository proxy forwards a call on `OwnerRepository` to the implementation of the
        // interface declaring the method, which is no subtype of `OwnerRepository`.
        if let Some(i) = self.index(class) {
            let c = self.class(i);
            if c.is_interface {
                for parent in &c.interfaces {
                    self.virtual_call(*parent, name, desc, from);
                }
            }
        }
        let mut seen = HashSet::new();
        let mut stack: Vec<u32> = self.subtypes.get(&class).cloned().unwrap_or_default();
        stack.extend(self.index(class));
        let mut found = Vec::new();
        while let Some(i) = stack.pop() {
            if !seen.insert(i) {
                continue;
            }
            let c = self.class(i);
            if let Some(subs) = self.subtypes.get(&c.name) {
                stack.extend(subs);
            }
            if self.instantiated.contains(&i) && !c.is_interface && !c.is_abstract {
                found.extend(self.resolve(i, name, desc));
            }
        }
        // Whatever the call is written against can exist with no instance this graph saw: a
        // deserializer makes a field's class, a lambda or a proxy stands in for an interface.
        if let Some(i) = self.index(class) {
            found.extend(self.resolve(i, name, desc));
        }
        for target in found {
            self.reach(target, Via::Call(from));
        }
    }

    fn run(&mut self) {
        while let Some(id) = self.queue.pop_front() {
            let c = self.class(id.0);
            let m = &c.methods[id.1 as usize];
            let mut opened = false;
            for op in &m.ops {
                match *op {
                    Op::Call {
                        kind,
                        class,
                        name,
                        desc,
                    } => {
                        if self.reflection.contains(&(class, name)) {
                            opened = true;
                        }
                        match kind {
                            CallKind::Virtual => {
                                self.virtual_call(class, name, desc, id);
                            }
                            CallKind::Static | CallKind::Special => {
                                if let Some(i) = self.index(class) {
                                    for target in self.resolve(i, name, desc) {
                                        self.reach(target, Via::Call(id));
                                    }
                                    if kind == CallKind::Static {
                                        self.initialize(i, &Via::Call(id));
                                    }
                                }
                            }
                        }
                    }
                    Op::New(class) => {
                        if let Some(i) = self.index(class) {
                            self.mark_instantiated(i, &Via::Call(id));
                            self.initialize(i, &Via::Call(id));
                        }
                    }
                    Op::Touch(class) => {
                        if let Some(i) = self.index(class) {
                            self.initialize(i, &Via::Call(id));
                        }
                    }
                    Op::Text(class) | Op::ClassConst(class) => {
                        if let Some(i) = self.index(class) {
                            self.drive(i, &Via::Call(id));
                        }
                        // A package name ending in a dot is the start of names built at run time:
                        // Bouncy Castle's provider loads `digest.` + `SHA1` + `$Mappings`.
                        let name = self.cp.names.name(class);
                        if let Some(classes) = self.packages.get(name).cloned() {
                            for i in classes {
                                self.drive(i, &Via::Call(id));
                            }
                        }
                        // One starting with a dot is the end of one: jnr-ffi loads its own
                        // package name + `.jffi.Provider`.
                        if name.starts_with('/') {
                            let last = name.rsplit('/').next().unwrap_or_default();
                            let classes = self.simple.get(last).cloned().unwrap_or_default();
                            for i in classes {
                                if self.cp.names.name(self.class(i).name).ends_with(name) {
                                    self.drive(i, &Via::Call(id));
                                }
                            }
                        }
                    }
                    Op::OpenDynamic => self.open_dynamic += 1,
                }
            }
            if opened {
                let names = &self.cp.names;
                self.open_reflection.push(format!(
                    "{}.{}",
                    names.name(c.name).replace('/', "."),
                    names.name(m.name)
                ));
            }
        }
        self.open_reflection.sort_unstable();
    }
}

impl Analysis<'_> {
    /// Whether the class is on the class path at all.
    #[must_use]
    pub fn has_class(&self, class: &str) -> bool {
        self.index(class).is_some()
    }

    fn index(&self, class: &str) -> Option<usize> {
        let sym = self.cp.names.get(&class.replace('.', "/"))?;
        self.cp.by_name.get(&sym).copied()
    }

    /// The methods of `class` called `method` (with this descriptor, if given).
    fn matching(&self, class: &str, method: &str, descriptor: Option<&str>) -> Vec<Id> {
        let Some(i) = self.index(class) else {
            return Vec::new();
        };
        let names = &self.cp.names;
        self.cp.classes[i]
            .methods
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                names.name(m.name) == method && descriptor.is_none_or(|d| names.name(m.desc) == d)
            })
            .map(|(j, _)| {
                (
                    u32::try_from(i).unwrap_or(u32::MAX),
                    u32::try_from(j).unwrap_or(u32::MAX),
                )
            })
            .collect()
    }

    /// Whether such a method exists on the class path.
    #[must_use]
    pub fn has_method(&self, class: &str, method: &str, descriptor: Option<&str>) -> bool {
        !self.matching(class, method, descriptor).is_empty()
    }

    /// A path to the method, if the graph reaches it.
    #[must_use]
    pub fn witness(&self, class: &str, method: &str, descriptor: Option<&str>) -> Option<Witness> {
        let id = self
            .matching(class, method, descriptor)
            .into_iter()
            .find(|id| self.reached.contains_key(id))?;
        let mut steps = Vec::new();
        let mut seen = HashSet::new();
        let mut at = id;
        loop {
            steps.push(self.step(at));
            if !seen.insert(at) {
                return None;
            }
            match self.reached.get(&at)? {
                Via::Root(root) => {
                    steps.reverse();
                    return Some(Witness {
                        root: root.clone(),
                        steps,
                    });
                }
                Via::Call(from) => at = *from,
            }
        }
    }

    fn step(&self, id: Id) -> Step {
        let names = &self.cp.names;
        let c = &self.cp.classes[id.0 as usize];
        let m = &c.methods[id.1 as usize];
        Step {
            class: names.name(c.name).replace('/', "."),
            method: names.name(m.name).to_string(),
            descriptor: names.name(m.desc).to_string(),
        }
    }

    /// The dotted names of classes with a reached method.
    #[must_use]
    pub fn reached_classes(&self) -> std::collections::BTreeSet<String> {
        self.reached.keys().map(|id| self.step(*id).class).collect()
    }

    /// Every reached method as `class.name:descriptor`, with the class in slashes.
    #[must_use]
    pub fn reached_methods(&self) -> std::collections::BTreeSet<String> {
        self.reached
            .keys()
            .map(|(class, method)| {
                let c = &self.cp.classes[*class as usize];
                let m = &c.methods[*method as usize];
                let names = &self.cp.names;
                format!(
                    "{}.{}:{}",
                    names.name(c.name),
                    names.name(m.name),
                    names.name(m.desc)
                )
            })
            .collect()
    }

    /// How many methods the class path holds.
    #[must_use]
    pub fn methods(&self) -> usize {
        self.cp.classes.iter().map(|c| c.methods.len()).sum()
    }

    /// How many methods the graph reached.
    #[must_use]
    pub fn reached(&self) -> usize {
        self.reached.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::Role;

    #[derive(Default)]
    struct Fixture {
        cp: ClassPath,
    }

    impl Fixture {
        fn sym(&mut self, s: &str) -> Sym {
            self.cp.names.intern(s)
        }

        fn method(&mut self, name: &str, ops: Vec<Op>) -> Method {
            Method {
                name: self.sym(name),
                desc: self.sym("()V"),
                ops,
                ..Method::default()
            }
        }

        fn call(&mut self, kind: CallKind, class: &str, name: &str) -> Op {
            Op::Call {
                kind,
                class: self.sym(class),
                name: self.sym(name),
                desc: self.sym("()V"),
            }
        }

        fn class(&mut self, name: &str, parents: &[&str], role: Role, methods: Vec<Method>) {
            let class = Class {
                name: self.sym(name),
                superclass: None,
                interfaces: parents.iter().map(|p| self.sym(p)).collect(),
                is_interface: false,
                is_abstract: false,
                role,
                methods,
                annotations: Vec::new(),
                annotation_refs: Vec::new(),
            };
            self.cp.by_name.insert(class.name, self.cp.classes.len());
            self.cp.classes.push(class);
        }
    }

    #[test]
    fn app_code_reaches_a_dependency_through_an_interface() {
        let mut f = Fixture::default();
        let call = f.call(CallKind::Virtual, "lib/Api", "run");
        let main = f.method("main", vec![call]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let run = f.method("run", vec![]);
        f.class("lib/Impl", &["lib/Api"], Role::Dependency, vec![run]);
        let impl_class = f.sym("lib/Impl");
        f.cp.classes[0].methods[0]
            .ops
            .insert(0, Op::New(impl_class));
        let unused = f.method("unused", vec![]);
        f.class("lib/Other", &[], Role::Dependency, vec![unused]);
        let a = analyze(&f.cp);
        let w = a.witness("lib.Impl", "run", None).unwrap();
        assert_eq!(w.root, Root::AppCode);
        assert_eq!(w.steps.len(), 2);
        assert!(a.witness("lib.Other", "unused", None).is_none());
        assert!(a.has_method("lib.Other", "unused", None));
    }

    #[test]
    fn a_class_named_in_a_resource_is_driven() {
        let mut f = Fixture::default();
        let sink = f.method("<init>", vec![]);
        f.class("lib/Plugin", &[], Role::Dependency, vec![sink]);
        f.cp.named_in_resources
            .insert("lib.Plugin".into(), "web.xml".into());
        let a = analyze(&f.cp);
        let w = a.witness("lib.Plugin", "<init>", None).unwrap();
        assert_eq!(w.root, Root::Resource("web.xml".into()));
    }

    #[test]
    fn an_annotation_meta_annotated_with_an_entry_annotation_counts() {
        let mut f = Fixture::default();
        let component = f.sym("org/springframework/stereotype/Component");
        f.class("lib/Stereotype", &[], Role::Dependency, vec![]);
        f.cp.classes[0].is_interface = true;
        f.cp.classes[0].annotations.push(component);
        let stereotype = f.sym("lib/Stereotype");
        let init = f.method("<init>", vec![]);
        f.class("lib/Handler", &[], Role::Dependency, vec![init]);
        f.cp.classes[1].annotations.push(stereotype);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Handler", "<init>", None).is_some());
    }

    #[test]
    fn a_class_an_annotation_names_is_driven() {
        let mut f = Fixture::default();
        let component = f.sym("org/springframework/stereotype/Component");
        let target = f.sym("lib/Imported");
        let m = f.method("m", vec![]);
        f.class("lib/Config", &[], Role::Dependency, vec![m]);
        f.cp.classes[0].annotations.push(component);
        f.cp.classes[0].annotation_refs.push(target);
        let sink = f.method("<init>", vec![]);
        f.class("lib/Imported", &[], Role::Dependency, vec![sink]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Imported", "<init>", None).is_some());
    }

    #[test]
    fn what_an_annotation_on_an_annotation_names_is_driven() {
        let mut f = Fixture::default();
        let component = f.sym("org/springframework/stereotype/Component");
        let conditional = f.sym("lib/Conditional");
        let check = f.sym("lib/Check");
        let m = f.method("m", vec![]);
        f.class("lib/Config", &[], Role::Dependency, vec![m]);
        f.cp.classes[0].annotations.extend([component, conditional]);
        f.class("lib/Conditional", &[], Role::Dependency, vec![]);
        f.cp.classes[1].is_interface = true;
        f.cp.classes[1].annotation_refs.push(check);
        let init = f.method("<init>", vec![]);
        f.class("lib/Check", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Check", "<init>", None).is_some());
    }

    #[test]
    fn a_method_marked_by_an_indexed_annotation_is_an_entry() {
        let mut f = Fixture::default();
        let indexed = f.sym("org/jvnet/hudson/annotation_indexer/Indexed");
        let initializer = f.sym("hudson/init/Initializer");
        f.class("hudson/init/Initializer", &[], Role::Dependency, vec![]);
        f.cp.classes[0].is_interface = true;
        f.cp.classes[0].annotations.push(indexed);
        let mut init = f.method("init", vec![]);
        init.annotations.push(initializer);
        f.class("lib/Uptime", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Uptime", "init", None).is_some());
    }

    #[test]
    fn a_jaxb_bean_and_a_groovy_method_class_are_made() {
        let mut f = Fixture::default();
        let bound = f.sym("jakarta/xml/bind/annotation/XmlType");
        let init = f.method("<init>", vec![]);
        f.class("lib/SignatureType", &[], Role::Dependency, vec![init]);
        f.cp.classes[0].annotations.push(bound);
        let init = f.method("<init>", vec![]);
        f.class(
            "org/codehaus/groovy/runtime/dgm$243",
            &[],
            Role::Dependency,
            vec![init],
        );
        let init = f.method("<init>", vec![]);
        f.class("lib/Unused", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.SignatureType", "<init>", None).is_some());
        assert!(a
            .witness("org.codehaus.groovy.runtime.dgm$243", "<init>", None)
            .is_some());
        assert!(a.witness("lib.Unused", "<init>", None).is_none());
    }

    #[test]
    fn a_nested_class_with_annotated_fields_is_driven() {
        let mut f = Fixture::default();
        let init = f.method("<init>", vec![]);
        f.class("lib/Plugin", &[], Role::Dependency, vec![init]);
        f.cp.named_in_resources
            .insert("lib.Plugin".to_string(), "Log4j2Plugins.dat".to_string());
        let attribute = f.sym("lib/Attribute");
        f.class("lib/Plugin$Builder", &[], Role::Dependency, vec![]);
        f.cp.classes[1].annotation_refs.push(attribute);
        let visitor = f.sym("lib/Visitor");
        f.class("lib/Attribute", &[], Role::Dependency, vec![]);
        f.cp.classes[2].is_interface = true;
        f.cp.classes[2].annotation_refs.push(visitor);
        let init = f.method("<init>", vec![]);
        f.class("lib/Visitor", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Visitor", "<init>", None).is_some());
    }

    #[test]
    fn a_nested_class_can_be_named_with_dots() {
        let mut f = Fixture::default();
        let init = f.method("<init>", vec![]);
        f.class("lib/Outer$Factory", &[], Role::Dependency, vec![init]);
        f.cp.named_in_resources
            .insert("lib.Outer.Factory".to_string(), "x.factories".to_string());
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Outer$Factory", "<init>", None).is_some());
    }

    #[test]
    fn a_virtual_call_skips_a_subtype_nothing_made() {
        let mut f = Fixture::default();
        let base = f.sym("lib/Base");
        let made = f.sym("lib/Made");
        let call = f.call(CallKind::Virtual, "lib/Base", "run");
        let main = f.method("main", vec![Op::New(made), call]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let run = f.method("run", vec![]);
        f.class("lib/Base", &[], Role::Dependency, vec![run]);
        for name in ["lib/Made", "lib/Unmade"] {
            let run = f.method("run", vec![]);
            f.class(name, &[], Role::Dependency, vec![run]);
            let last = f.cp.classes.len() - 1;
            f.cp.classes[last].superclass = Some(base);
        }
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Made", "run", None).is_some());
        assert!(a.witness("lib.Unmade", "run", None).is_none());
        // Written against the class itself: a deserializer may have made it.
        assert!(a.witness("lib.Base", "run", None).is_some());
    }

    #[test]
    fn the_jdk_can_call_back_into_an_instance_of_its_subclass() {
        let mut f = Fixture::default();
        let target = f.sym("lib/Stream");
        let main = f.method("main", vec![Op::New(target)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let resolve = f.method("resolveClass", vec![]);
        f.class(
            "lib/Stream",
            &["java/io/ObjectInputStream"],
            Role::Dependency,
            vec![resolve],
        );
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Stream", "resolveClass", None).is_some());
    }

    #[test]
    fn serializable_alone_is_no_callback() {
        let mut f = Fixture::default();
        let target = f.sym("lib/Data");
        f.sym("java/io/Serializable");
        let main = f.method("main", vec![Op::New(target)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let sink = f.method("sink", vec![]);
        f.class(
            "lib/Data",
            &["java/io/Serializable"],
            Role::Dependency,
            vec![sink],
        );
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Data", "sink", None).is_none());
    }

    #[test]
    fn the_jdk_calls_the_private_serialization_hooks() {
        let mut f = Fixture::default();
        let target = f.sym("lib/Item");
        f.sym("java/io/Serializable");
        let main = f.method("main", vec![Op::New(target)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let mut read = f.method("readObject", vec![]);
        read.is_private = true;
        let mut other = f.method("helper", vec![]);
        other.is_private = true;
        f.class(
            "lib/Item",
            &["java/io/Serializable"],
            Role::Dependency,
            vec![read, other],
        );
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Item", "readObject", None).is_some());
        assert!(a.witness("lib.Item", "helper", None).is_none());
    }

    #[test]
    fn a_platform_type_a_jar_ships_is_still_outside() {
        let mut f = Fixture::default();
        let target = f.sym("lib/Recorder");
        let main = f.method("main", vec![Op::New(target)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let empty = f.method("startElement", vec![]);
        f.class(
            "org/xml/sax/helpers/DefaultHandler",
            &[],
            Role::Dependency,
            vec![empty],
        );
        let handler = f.sym("org/xml/sax/helpers/DefaultHandler");
        let start = f.method("startElement", vec![]);
        f.class("lib/Recorder", &[], Role::Dependency, vec![start]);
        f.cp.classes[2].superclass = Some(handler);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Recorder", "startElement", None).is_some());
    }

    #[test]
    fn a_method_a_framework_calls_by_annotation_is_an_entry_point() {
        let mut f = Fixture::default();
        let converter = f.sym("org/apache/camel/Converter");
        let activate = f.sym("org/apache/felix/scr/annotations/Activate");
        let mut convert = f.method("toSource", vec![]);
        convert.annotations.push(converter);
        f.class("lib/XmlConverter", &[], Role::Dependency, vec![convert]);
        let mut start = f.method("activate", vec![]);
        start.annotations.push(activate);
        f.class("lib/Service", &[], Role::Dependency, vec![start]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.XmlConverter", "toSource", None).is_some());
        assert!(a.witness("lib.Service", "activate", None).is_some());
    }

    #[test]
    fn a_string_naming_a_class_makes_an_instance() {
        let mut f = Fixture::default();
        let name = f.sym("lib/Loaded");
        let main = f.method("main", vec![Op::Text(name)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let init = f.method("<init>", vec![]);
        f.class("lib/Loaded", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Loaded", "<init>", None).is_some());
    }

    #[test]
    fn a_package_name_string_makes_the_package_classes() {
        let mut f = Fixture::default();
        let package = f.sym("lib/digest/");
        let main = f.method("main", vec![Op::Text(package)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let init = f.method("<init>", vec![]);
        f.class(
            "lib/digest/SHA1$Mappings",
            &[],
            Role::Dependency,
            vec![init],
        );
        let init = f.method("<init>", vec![]);
        f.class("lib/digest/sub/Other", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a
            .witness("lib.digest.SHA1$Mappings", "<init>", None)
            .is_some());
        assert!(a.witness("lib.digest.sub.Other", "<init>", None).is_none());
    }

    #[test]
    fn a_string_starting_with_a_dot_makes_the_classes_it_ends() {
        let mut f = Fixture::default();
        let tail = f.sym("/jffi/Provider");
        let main = f.method("main", vec![Op::Text(tail)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let init = f.method("<init>", vec![]);
        f.class("lib/ffi/jffi/Provider", &[], Role::Dependency, vec![init]);
        let init = f.method("<init>", vec![]);
        f.class("lib/ffi/other/Provider", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.ffi.jffi.Provider", "<init>", None).is_some());
        assert!(a
            .witness("lib.ffi.other.Provider", "<init>", None)
            .is_none());
    }

    #[test]
    fn a_property_accessor_or_object_method_runs_on_any_instance() {
        let mut f = Fixture::default();
        let made = f.sym("lib/Bean");
        let main = f.method("main", vec![Op::New(made)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let methods =
            ["setPort", "hashCode", "clone", "finalize", "settle"].map(|n| f.method(n, vec![]));
        f.class("lib/Bean", &[], Role::Dependency, methods.to_vec());
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Bean", "setPort", None).is_some());
        assert!(a.witness("lib.Bean", "hashCode", None).is_some());
        assert!(a.witness("lib.Bean", "clone", None).is_some());
        assert!(a.witness("lib.Bean", "finalize", None).is_some());
        assert!(a.witness("lib.Bean", "settle", None).is_none());
    }

    #[test]
    fn a_deserializer_a_made_class_names_is_made() {
        let mut f = Fixture::default();
        let made = f.sym("lib/Headers");
        let main = f.method("main", vec![Op::New(made)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let using = f.sym("com/fasterxml/jackson/databind/annotation/JsonDeserialize");
        let deserializer = f.sym("lib/HeadersDeserializer");
        let init = f.method("<init>", vec![]);
        f.class("lib/Headers", &[], Role::Dependency, vec![init]);
        f.cp.classes[1].annotations.push(using);
        f.cp.classes[1].annotation_refs.push(deserializer);
        let init = f.method("<init>", vec![]);
        f.class("lib/HeadersDeserializer", &[], Role::Dependency, vec![init]);
        let a = analyze(&f.cp);
        assert!(a
            .witness("lib.HeadersDeserializer", "<init>", None)
            .is_some());
    }

    #[test]
    fn a_jackson_annotated_method_runs_on_any_instance() {
        let mut f = Fixture::default();
        let made = f.sym("lib/Jwt");
        let main = f.method("main", vec![Op::New(made)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let any = f.sym("com/fasterxml/jackson/annotation/JsonAnyGetter");
        let mut getter = f.method("anyGetter", vec![]);
        getter.annotations.push(any);
        let other = f.method("otherClaims", vec![]);
        f.class("lib/Jwt", &[], Role::Dependency, vec![getter, other]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Jwt", "anyGetter", None).is_some());
        assert!(a.witness("lib.Jwt", "otherClaims", None).is_none());
    }

    #[test]
    fn a_proxy_callback_runs_with_no_call_in_the_graph() {
        let mut f = Fixture::default();
        let made = f.sym("lib/Interceptor");
        let main = f.method("main", vec![Op::New(made)]);
        f.class("app/Main", &[], Role::App, vec![main]);
        f.class(
            "org/springframework/cglib/proxy/Callback",
            &[],
            Role::Dependency,
            vec![],
        );
        f.cp.classes[1].is_interface = true;
        let intercept = f.method("intercept", vec![]);
        f.class(
            "lib/Interceptor",
            &["org/springframework/cglib/proxy/Callback"],
            Role::Dependency,
            vec![intercept],
        );
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Interceptor", "intercept", None).is_some());
    }

    #[test]
    fn a_call_on_an_interface_also_lands_on_implementations_of_its_parents() {
        let mut f = Fixture::default();
        let made = f.sym("lib/Simple");
        let call = f.call(CallKind::Virtual, "app/Owners", "find");
        let main = f.method("main", vec![Op::New(made), call]);
        f.class("app/Main", &[], Role::App, vec![main]);
        f.class("app/Owners", &["lib/Crud"], Role::App, vec![]);
        f.cp.classes[1].is_interface = true;
        f.class("lib/Crud", &[], Role::Dependency, vec![]);
        f.cp.classes[2].is_interface = true;
        let find = f.method("find", vec![]);
        f.class("lib/Simple", &["lib/Crud"], Role::Dependency, vec![find]);
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Simple", "find", None).is_some());
    }

    #[test]
    fn a_default_method_overridden_in_a_sub_interface_is_found() {
        let mut f = Fixture::default();
        let made = f.sym("lib/Impl");
        let call = f.call(CallKind::Virtual, "lib/Base", "depth");
        let main = f.method("main", vec![Op::New(made), call]);
        f.class("app/Main", &[], Role::App, vec![main]);
        for (name, parents) in [("lib/Base", vec![]), ("lib/Sub", vec!["lib/Base"])] {
            let depth = f.method("depth", vec![]);
            f.class(name, &parents, Role::Dependency, vec![depth]);
            let last = f.cp.classes.len() - 1;
            f.cp.classes[last].is_interface = true;
        }
        f.class(
            "lib/Impl",
            &["lib/Base", "lib/Sub"],
            Role::Dependency,
            vec![],
        );
        let a = analyze(&f.cp);
        assert!(a.witness("lib.Sub", "depth", None).is_some());
    }

    #[test]
    fn open_reflection_is_counted() {
        let mut f = Fixture::default();
        f.sym("java/lang/Class");
        f.sym("forName");
        let call = f.call(CallKind::Static, "java/lang/Class", "forName");
        let main = f.method("main", vec![call]);
        f.class("app/Main", &[], Role::App, vec![main]);
        let a = analyze(&f.cp);
        assert_eq!(a.open_reflection, vec!["app.Main.main".to_string()]);
    }

    #[test]
    fn no_inputs_means_no_entry_points() {
        let cp = ClassPath::default();
        assert_eq!(analyze(&cp).roots, 0);
    }
}
