//! Checks that the Rust signatures match the hand-written `include/vardevall.h`.

use std::collections::BTreeSet;

fn strip_comments(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find("/*") {
        out.push_str(&rest[..i]);
        rest = match rest[i..].find("*/") {
            Some(j) => &rest[i + j + 2..],
            None => "",
        };
    }
    out.push_str(rest);
    out.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ")
}

fn squeeze(s: &str) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    s.replace(" *", "*").replace("* ", "*")
}

fn drop_param_name(p: &str) -> String {
    let p = squeeze(p);
    let end = p
        .trim_end_matches(|c: char| c.is_alphanumeric() || c == '_')
        .len();
    let (head, tail) = p.split_at(end);
    if head.is_empty() || tail.is_empty() || !head.ends_with(['*', ' ']) {
        return p;
    }
    squeeze(head)
}

fn normalise(decl: &str) -> String {
    let decl = decl.trim();
    let close = decl.rfind(')').expect("declaration without parameter list");
    let mut depth = 0;
    let mut open = 0;
    for (i, c) in decl[..=close].char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    open = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let params: Vec<String> = decl[open + 1..close]
        .split(',')
        .map(drop_param_name)
        .filter(|p| !p.is_empty())
        .collect();
    format!("{}({})", squeeze(&decl[..open]), params.join(","))
}

fn declarations(src: &str) -> BTreeSet<String> {
    strip_comments(src)
        .split(';')
        .map(str::trim)
        .filter(|d| d.contains('('))
        .map(|d| {
            let d = d
                .strip_prefix("typedef ")
                .map_or(d.to_owned(), |t| format!("typedef {t}"));
            normalise(&d)
        })
        .collect()
}

#[test]
fn header_matches_rust_signatures() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let mut out = Vec::new();
    cbindgen::Builder::new()
        .with_crate(dir)
        .with_config(cbindgen::Config::from_file(format!("{dir}/cbindgen.toml")).unwrap())
        .generate()
        .expect("cbindgen")
        .write(&mut out);
    let generated = declarations(&String::from_utf8(out).unwrap());
    let written = declarations(
        &std::fs::read_to_string(format!("{dir}/../apple/include/vardevall.h")).unwrap(),
    );
    assert_eq!(
        written, generated,
        "include/vardevall.h differs from the Rust signatures"
    );
}
