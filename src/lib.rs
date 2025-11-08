// structly/src/lib.rs

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyModule, PyString, PyTuple};
use pyo3::{Bound, PyObject};

use ahash::{AHashSet, AHasher};
use aho_corasick::{AhoCorasick, MatchKind};
use memchr::memchr_iter;
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use regex::bytes as rebytes;
use std::hash::Hasher;

// ============================
// Config models (generic)
// ============================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    First,
    All,
}

#[derive(Clone)]
struct FieldOptions {
    mode: Mode,        // "first" or "all"
    unique: bool,      // dedup values for this field
    return_list: bool, // if true, always return list even in "first" mode
}

#[derive(Clone)]
struct Field {
    name: String,
    opts: FieldOptions,
}

#[derive(Clone)]
struct InlineDelims {
    table: [bool; 256],
}

impl InlineDelims {
    #[inline]
    fn new(bytes: &[u8]) -> Self {
        let mut table = [false; 256];
        for &b in bytes {
            table[b as usize] = true;
        }
        Self { table }
    }

    #[inline]
    fn contains(&self, b: u8) -> bool {
        self.table[b as usize]
    }
}

#[derive(Clone)]
enum FieldLayout {
    LineAnchored,
    Inline { delims: InlineDelims },
}

impl FieldLayout {
    const DEFAULT_INLINE_DELIMS: &'static [u8] = b" \t,;|";

    #[inline]
    fn accepts_match(&self, start: usize) -> bool {
        match self {
            FieldLayout::LineAnchored => start == 0,
            FieldLayout::Inline { .. } => true,
        }
    }

    #[inline]
    fn value_end(&self, bytes: &[u8], mut start: usize, line_end: usize) -> usize {
        match self {
            FieldLayout::LineAnchored => line_end,
            FieldLayout::Inline { delims } => {
                while start < line_end {
                    if delims.contains(bytes[start]) {
                        break;
                    }
                    start += 1;
                }
                start
            }
        }
    }

    #[inline]
    fn is_line_anchored(&self) -> bool {
        matches!(self, FieldLayout::LineAnchored)
    }

    fn from_py_args(field_layout: &str, inline_value_delimiters: Option<&str>) -> PyResult<Self> {
        if field_layout.eq_ignore_ascii_case("line") {
            return Ok(FieldLayout::LineAnchored);
        }
        if field_layout.eq_ignore_ascii_case("inline") {
            let delims_bytes = inline_value_delimiters.unwrap_or_else(|| {
                std::str::from_utf8(FieldLayout::DEFAULT_INLINE_DELIMS).unwrap()
            });
            let delims = InlineDelims::new(delims_bytes.as_bytes());
            return Ok(FieldLayout::Inline { delims });
        }
        Err(PyValueError::new_err(format!(
            "Invalid field_layout '{}'. Expected 'line' or 'inline'",
            field_layout
        )))
    }
}

// A compiled "starts-with" pattern
#[derive(Clone)]
struct SwRoute {
    field_idx: usize,
}

// A compiled regex pattern
#[derive(Clone)]
struct ReRoute {
    field_idx: usize,
    has_val_group: bool, // true if the regex defines (?P<val>...)
}

// ============================
// Utility helpers
// ============================

#[inline]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r')
}

#[inline]
fn trim(bytes: &[u8], mut s: usize, mut e: usize) -> (usize, usize) {
    // Early exits for already-trimmed ranges
    if s >= e {
        return (s, e);
    }
    let left_needs = matches!(bytes[s], b' ' | b'\t' | b'\r');
    let right_needs = matches!(bytes[e - 1], b' ' | b'\t' | b'\r');
    if !left_needs && !right_needs {
        return (s, e);
    }
    while s < e && is_space(bytes[s]) {
        s += 1;
    }
    while e > s && is_space(bytes[e - 1]) {
        e -= 1;
    }
    (s, e)
}

#[inline]
fn trim_quotes(bytes: &[u8], mut s: usize, mut e: usize) -> (usize, usize) {
    if e <= s + 1 {
        return (s, e);
    }
    let start_byte = bytes[s];
    if (start_byte == b'"' || start_byte == b'\'') && bytes[e - 1] == start_byte {
        s += 1;
        e -= 1;
    }
    (s, e)
}

#[inline]
fn hash_bytes(b: &[u8]) -> u64 {
    let mut h = AHasher::default();
    h.write(b);
    h.finish()
}

#[inline]
fn line_ranges(bytes: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    // yields [start,end) of each line, stripping CR from CRLF
    let mut start = 0usize;
    memchr_iter(b'\n', bytes)
        .map(move |nl| {
            let mut end = nl;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            let ret = (start, end);
            start = nl + 1;
            ret
        })
        .chain(std::iter::once((start, bytes.len())))
}

// When converting byte ranges (from regex::bytes / AC) back to Python strings,
// ensure we only slice on UTF-8 boundaries; otherwise safely revalidate/repair.
// Fast path is zero-cost when boundaries align.
#[inline]
fn py_str_from_range<'py>(py: Python<'py>, text: &str, s: usize, e: usize) -> Bound<'py, PyString> {
    if text.is_char_boundary(s) && text.is_char_boundary(e) {
        return PyString::new_bound(py, &text[s..e]);
    }
    let bytes = &text.as_bytes()[s..e];
    match std::str::from_utf8(bytes) {
        Ok(valid) => PyString::new_bound(py, valid),
        Err(_) => {
            // extremely rare path for partially-cut UTF-8 when using bytes regexes
            let cow = String::from_utf8_lossy(bytes);
            PyString::new_bound(py, &cow)
        }
    }
}

// ============================
// Parallelism mode (cached)
// ============================

#[derive(Clone, Copy)]
enum RayonMode {
    Never,
    Always,
    Auto,
}

#[inline]
fn rayon_mode() -> RayonMode {
    static ENV: OnceCell<RayonMode> = OnceCell::new();
    *ENV.get_or_init(|| match std::env::var("STRUCTLY_RAYON") {
        Ok(s) if s.eq_ignore_ascii_case("never") => RayonMode::Never,
        Ok(s) if s.eq_ignore_ascii_case("always") => RayonMode::Always,
        _ => RayonMode::Auto,
    })
}

// Per-field accumulation (ranges into the doc text)
#[derive(Default)]
struct FieldState {
    values: Vec<(usize, usize)>,
    // Use (hash, len) to make accidental collisions vanishingly unlikely while
    // avoiding expensive slice comparisons.
    seen: Option<AHashSet<(u64, u32)>>, // only allocated if unique
    first_done: bool,                   // for Mode::First (and not return_list)
}

// ============================
// Parser
// ============================

#[pyclass]
struct Parser {
    // fields in insertion order
    fields: Vec<Field>,

    // starts-with index across all fields
    ac: Option<AhoCorasick>,
    sw_routes: Vec<SwRoute>, // index aligned with ac patterns

    // regex index across all fields
    re_set: Option<rebytes::RegexSet>,
    re_list: Vec<rebytes::Regex>,
    re_routes: Vec<ReRoute>, // index aligned with re_list

    // Fast decisions
    only_first_scalars: bool, // all requested fields are Mode::First && return_list==false
    layout: FieldLayout,
}

impl Parser {
    fn compile(_py: Python<'_>, config: &Bound<PyAny>, layout: FieldLayout) -> PyResult<Self> {
        let dict = config.downcast::<PyDict>()?;

        let mut fields = Vec::<Field>::with_capacity(dict.len());

        // Temporary structures for patterns gathered from config
        // sw_patterns: AC patterns; each entry corresponds to a sw_routes entry
        let mut sw_patterns: Vec<Vec<u8>> = Vec::new();
        let mut sw_routes: Vec<SwRoute> = Vec::new();

        // re_patterns: list of regex strings; parallel to re_routes
        let mut re_patterns: Vec<String> = Vec::new();
        let mut re_routes: Vec<ReRoute> = Vec::new();

        // Parse config
        for (k_obj, v_obj) in dict.iter() {
            let name: String = k_obj.extract()?;

            // Patterns + options
            let (patterns, mode, unique, return_list) =
                if let Ok(list) = v_obj.extract::<Vec<String>>() {
                    (list, Mode::First, false, false)
                } else {
                    let d = v_obj.downcast::<PyDict>().map_err(|_| {
                        PyValueError::new_err(format!(
                            "Field '{}' must be a dict or list of patterns",
                            name
                        ))
                    })?;

                    let patterns_any = d.get_item("patterns")?.ok_or_else(|| {
                        PyValueError::new_err(format!("Missing 'patterns' for field '{}'", name))
                    })?;
                    let patterns: Vec<String> = patterns_any.extract()?;

                    let mode = match d.get_item("mode")? {
                        Some(x) => {
                            let s: String = x.extract()?;
                            if s.eq_ignore_ascii_case("all") {
                                Mode::All
                            } else {
                                Mode::First
                            }
                        }
                        None => Mode::First,
                    };
                    let unique = d
                        .get_item("unique")?
                        .map(|x| x.extract::<bool>())
                        .transpose()?
                        .unwrap_or(false);
                    let return_list = match d.get_item("return")? {
                        Some(x) => {
                            let s: String = x.extract()?;
                            s.eq_ignore_ascii_case("list")
                        }
                        None => false,
                    };
                    (patterns, mode, unique, return_list)
                };

            let field_idx = fields.len();

            // collect patterns
            for p in patterns {
                if let Some(rest) = p.strip_prefix("sw:") {
                    sw_patterns.push(rest.as_bytes().to_vec());
                    sw_routes.push(SwRoute { field_idx });
                } else if let Some(rest) = p.strip_prefix("r:") {
                    re_patterns.push(rest.to_string());
                    re_routes.push(ReRoute {
                        field_idx,
                        has_val_group: false,
                    });
                } else {
                    // default to starts-with
                    sw_patterns.push(p.into_bytes());
                    sw_routes.push(SwRoute { field_idx });
                }
            }

            fields.push(Field {
                name,
                opts: FieldOptions {
                    mode,
                    unique,
                    return_list,
                },
            });
        }

        // Compile AC for starts-with
        let ac = if sw_patterns.is_empty() {
            None
        } else {
            let match_kind = match layout {
                FieldLayout::LineAnchored => MatchKind::LeftmostLongest,
                FieldLayout::Inline { .. } => MatchKind::Standard,
            };
            let ac = AhoCorasick::builder()
                .match_kind(match_kind)
                .build(&sw_patterns)
                .map_err(|e| PyValueError::new_err(format!("Failed to build Aho-Corasick: {e}")))?;
            Some(ac)
        };

        // Compile RegexSet + individual Regexes for captures
        let (re_set, re_list) = if re_patterns.is_empty() {
            (None, Vec::new())
        } else {
            let set = rebytes::RegexSet::new(&re_patterns)
                .map_err(|e| PyValueError::new_err(format!("RegexSet compile error: {e}")))?;
            let mut regs = Vec::with_capacity(re_patterns.len());
            for pat in &re_patterns {
                let re = rebytes::Regex::new(pat)
                    .map_err(|e| PyValueError::new_err(format!("Invalid regex '{pat}': {e}")))?;
                regs.push(re);
            }
            (Some(set), regs)
        };

        // Fill has_val_group flag
        for (i, route) in re_routes.iter_mut().enumerate() {
            if let Some(re) = re_list.get(i) {
                let has_val = re.capture_names().flatten().any(|name| name == "val");
                route.has_val_group = has_val;
            }
        }

        // Early-exit condition: only-first scalars?
        let only_first_scalars = fields
            .iter()
            .all(|f| f.opts.mode == Mode::First && !f.opts.return_list);

        Ok(Self {
            fields,
            ac,
            sw_routes,
            re_set,
            re_list,
            re_routes,
            only_first_scalars,
            layout,
        })
    }

    #[inline]
    fn parse_ranges(&self, text: &str) -> Vec<Vec<(usize, usize)>> {
        let bytes = text.as_bytes();
        let n_fields = self.fields.len();

        // Initialize per-field state
        let mut states: Vec<FieldState> = self
            .fields
            .iter()
            .map(|f| FieldState {
                values: Vec::new(),
                seen: if f.opts.unique {
                    Some(AHashSet::with_capacity(8))
                } else {
                    None
                },
                first_done: false,
            })
            .collect();

        let mut first_remaining = if self.only_first_scalars { n_fields } else { 0 };

        'lines: for (ls, le) in line_ranges(bytes) {
            if ls >= le {
                continue;
            }
            let line = &bytes[ls..le];

            // 1) starts-with (AC), anchored at start-of-line
            if let Some(ac) = &self.ac {
                let mut stop_lines = false;
                for m in ac.find_iter(line) {
                    if !self.layout.accepts_match(m.start()) {
                        continue;
                    }
                    let ridx = m.pattern();
                    let route = &self.sw_routes[ridx];
                    let fidx = route.field_idx;

                    let field = &self.fields[fidx];
                    let st = &mut states[fidx];
                    if field.opts.mode == Mode::First && !field.opts.return_list && st.first_done {
                        if self.layout.is_line_anchored() {
                            break;
                        }
                        continue;
                    }

                    let value_start = ls + m.end();
                    if value_start >= le {
                        if self.layout.is_line_anchored() {
                            break;
                        }
                        continue;
                    }
                    let value_end = self.layout.value_end(bytes, value_start, le);
                    if value_start >= value_end {
                        if self.layout.is_line_anchored() {
                            break;
                        }
                        continue;
                    }

                    if self.push_value(
                        bytes,
                        st,
                        field,
                        value_start,
                        value_end,
                        &mut first_remaining,
                    ) {
                        if self.only_first_scalars && first_remaining == 0 {
                            stop_lines = true;
                            break;
                        }
                        if self.layout.is_line_anchored() {
                            break;
                        }
                        continue;
                    }

                    if self.layout.is_line_anchored() {
                        break;
                    }
                }
                if stop_lines {
                    break 'lines;
                }
            }

            // 2) regex set across all regex patterns
            if let Some(set) = &self.re_set {
                let matches = set.matches(line);
                if matches.matched_any() {
                    let mut stop_all = false;
                    'regexes: for idx in matches.into_iter() {
                        let route = &self.re_routes[idx];
                        let fidx = route.field_idx;
                        let field = &self.fields[fidx];
                        let st = &mut states[fidx];

                        if field.opts.mode == Mode::First
                            && !field.opts.return_list
                            && st.first_done
                        {
                            continue;
                        }

                        let re = &self.re_list[idx];

                        if route.has_val_group {
                            for caps in re.captures_iter(line) {
                                if let Some(mv) = caps.name("val") {
                                    if self.push_value(
                                        bytes,
                                        st,
                                        field,
                                        ls + mv.start(),
                                        ls + mv.end(),
                                        &mut first_remaining,
                                    ) {
                                        if self.only_first_scalars && first_remaining == 0 {
                                            stop_all = true;
                                            break 'regexes;
                                        }
                                        continue 'regexes;
                                    }
                                } else if let Some(m0) = caps.get(0) {
                                    if self.push_value(
                                        bytes,
                                        st,
                                        field,
                                        ls + m0.end(),
                                        le,
                                        &mut first_remaining,
                                    ) {
                                        if self.only_first_scalars && first_remaining == 0 {
                                            stop_all = true;
                                            break 'regexes;
                                        }
                                        continue 'regexes;
                                    }
                                }
                            }
                        } else {
                            for m0 in re.find_iter(line) {
                                if self.push_value(
                                    bytes,
                                    st,
                                    field,
                                    ls + m0.end(),
                                    le,
                                    &mut first_remaining,
                                ) {
                                    if self.only_first_scalars && first_remaining == 0 {
                                        stop_all = true;
                                        break 'regexes;
                                    }
                                    continue 'regexes;
                                }
                            }
                        }
                    }
                    if stop_all {
                        break 'lines;
                    }
                }
            }
        }

        // Normalize: for First+scalar fields keep only the first
        for (i, f) in self.fields.iter().enumerate() {
            if f.opts.mode == Mode::First && !f.opts.return_list && states[i].values.len() > 1 {
                states[i].values.truncate(1);
            }
        }

        states.into_iter().map(|s| s.values).collect()
    }

    #[inline]
    fn push_value(
        &self,
        bytes: &[u8],
        st: &mut FieldState,
        field: &Field,
        raw_start: usize,
        raw_end: usize,
        first_remaining: &mut usize,
    ) -> bool {
        let (mut s, mut e) = trim(bytes, raw_start, raw_end);
        if s >= e {
            return false;
        }
        (s, e) = trim_quotes(bytes, s, e);
        if s >= e {
            return false;
        }

        if let Some(seen) = &mut st.seen {
            let hv = hash_bytes(&bytes[s..e]);
            let key = (hv, (e - s) as u32);
            if !seen.insert(key) {
                let duplicate = st
                    .values
                    .iter()
                    .any(|&(ss, ee)| ee - ss == e - s && bytes[ss..ee] == bytes[s..e]);
                if duplicate {
                    return false;
                }
            }
        }

        st.values.push((s, e));

        if field.opts.mode == Mode::First && !field.opts.return_list {
            if !st.first_done {
                st.first_done = true;
                if self.only_first_scalars && *first_remaining > 0 {
                    *first_remaining -= 1;
                }
            }
            return true;
        }
        false
    }

    fn build_dict(
        &self,
        py: Python<'_>,
        text: &str,
        ranges: &[Vec<(usize, usize)>],
    ) -> PyResult<PyObject> {
        let out = PyDict::new_bound(py);
        for (i, field) in self.fields.iter().enumerate() {
            // Intern per-call (cheap) – avoids storing non-Clone Py<PyString>
            let key = PyString::intern_bound(py, &field.name);
            let rr = &ranges[i];
            if field.opts.return_list || field.opts.mode == Mode::All {
                let mut vals = Vec::<PyObject>::with_capacity(rr.len());
                for &(s, e) in rr {
                    vals.push(py_str_from_range(py, text, s, e).into_py(py));
                }
                let pylist = PyList::new_bound(py, vals);
                out.set_item(key, pylist)?;
            } else if let Some((s, e)) = rr.get(0) {
                out.set_item(key, py_str_from_range(py, text, *s, *e))?;
            } else {
                out.set_item(key, py.None())?;
            }
        }
        Ok(out.into())
    }

    fn build_tuple(
        &self,
        py: Python<'_>,
        text: &str,
        ranges: &[Vec<(usize, usize)>],
    ) -> PyResult<PyObject> {
        let mut items = Vec::<PyObject>::with_capacity(self.fields.len());
        for (i, field) in self.fields.iter().enumerate() {
            let rr = &ranges[i];
            if field.opts.return_list || field.opts.mode == Mode::All {
                let mut vals = Vec::<PyObject>::with_capacity(rr.len());
                for &(s, e) in rr {
                    vals.push(py_str_from_range(py, text, s, e).into_py(py));
                }
                items.push(PyList::new_bound(py, vals).into_py(py));
            } else if let Some((s, e)) = rr.get(0) {
                items.push(py_str_from_range(py, text, *s, *e).into_py(py));
            } else {
                items.push(py.None());
            }
        }
        Ok(PyTuple::new_bound(py, items).into())
    }
}

// ============================
// PyO3 methods
// ============================

#[pymethods]
impl Parser {
    #[new]
    #[pyo3(signature = (config, *, field_layout="line", inline_value_delimiters=None))]
    fn new(
        py: Python<'_>,
        config: Bound<PyAny>,
        field_layout: &str,
        inline_value_delimiters: Option<&str>,
    ) -> PyResult<Self> {
        let layout = FieldLayout::from_py_args(field_layout, inline_value_delimiters)?;
        Parser::compile(py, &config, layout)
    }

    #[pyo3(text_signature = "(self)")]
    fn field_names(&self, py: Python<'_>) -> PyResult<PyObject> {
        let names: Vec<_> = self
            .fields
            .iter()
            .map(|f| PyString::intern_bound(py, &f.name))
            .collect();
        Ok(PyTuple::new_bound(py, names).into())
    }

    #[pyo3(text_signature = "(self, text)")]
    fn parse(&self, py: Python<'_>, text: &str) -> PyResult<PyObject> {
        let ranges = py.allow_threads(|| self.parse_ranges(text));
        self.build_dict(py, text, &ranges)
    }

    #[pyo3(text_signature = "(self, text)")]
    fn parse_tuple(&self, py: Python<'_>, text: &str) -> PyResult<PyObject> {
        let ranges = py.allow_threads(|| self.parse_ranges(text));
        self.build_tuple(py, text, &ranges)
    }

    #[pyo3(text_signature = "(self, texts)")]
    fn parse_many(&self, py: Python<'_>, texts: Vec<String>) -> PyResult<Vec<PyObject>> {
        // Parallel across docs if STRUCTLY_RAYON != "never"
        let use_par = match rayon_mode() {
            RayonMode::Never => false,
            RayonMode::Always => true,
            RayonMode::Auto => true, // auto → parallel across docs is nearly always beneficial
        };

        // Process in chunks to keep peak memory bounded for very large inputs.
        const CHUNK: usize = 512;

        let mut out = Vec::with_capacity(texts.len());

        let mut i = 0;
        while i < texts.len() {
            let end = (i + CHUNK).min(texts.len());
            let chunk = &texts[i..end];

            let ranges_chunk: Vec<Vec<Vec<(usize, usize)>>> = py.allow_threads(|| {
                if use_par {
                    chunk.par_iter().map(|t| self.parse_ranges(t)).collect()
                } else {
                    chunk.iter().map(|t| self.parse_ranges(t)).collect()
                }
            });

            // Build Python objects immediately so ranges can be dropped before next chunk.
            for (t, ranges) in chunk.iter().zip(ranges_chunk.into_iter()) {
                out.push(self.build_dict(py, t, &ranges)?);
            }

            i = end;
        }

        Ok(out)
    }
}

// Back-compat one-shot (compiles config each call)
#[pyfunction]
#[pyo3(text_signature = "(text, config)")]
fn parse(py: Python<'_>, text: &str, config: Bound<PyAny>) -> PyResult<PyObject> {
    let p = Parser::compile(py, &config, FieldLayout::LineAnchored)?;
    p.parse(py, text)
}

#[pyfunction]
#[pyo3(text_signature = "(text, config)")]
fn iter_field_items(py: Python<'_>, text: &str, config: Bound<PyAny>) -> PyResult<PyObject> {
    let p = Parser::compile(py, &config, FieldLayout::LineAnchored)?;
    let dict_obj = p.parse(py, text)?;
    let dict = dict_obj.downcast_bound::<PyDict>(py)?;
    let mut items = Vec::<(String, PyObject)>::with_capacity(dict.len());
    for (k, v) in dict.iter() {
        items.push((k.extract::<String>()?, v.to_object(py)));
    }
    Ok(items.into_py(py))
}

#[pymodule]
fn _structly(_py: Python<'_>, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Parser>()?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_function(wrap_pyfunction!(iter_field_items, m)?)?;
    Ok(())
}
