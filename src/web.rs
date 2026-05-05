use std::collections::HashMap;

use crate::fingerprint::WeightedFeature;

#[derive(Debug, Clone)]
pub struct WebFeatureOptions {
    pub include_bigrams: bool,
    pub include_length_bucket: bool,
    pub drop_stop_words: bool,
    pub drop_numeric_tokens: bool,
    pub stem_tokens: bool,
}

impl Default for WebFeatureOptions {
    fn default() -> Self {
        Self {
            include_bigrams: true,
            include_length_bucket: true,
            drop_stop_words: true,
            drop_numeric_tokens: true,
            stem_tokens: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WebFeatureExtractor {
    options: WebFeatureOptions,
}

impl WebFeatureExtractor {
    pub fn new(options: WebFeatureOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &WebFeatureOptions {
        &self.options
    }

    pub fn text_from_html(&self, html: &str) -> String {
        decode_html_entities(&strip_html(html))
    }

    pub fn extract_from_html(&self, html: &str) -> Vec<WeightedFeature> {
        let text = self.text_from_html(html);
        self.extract_from_text(&text)
    }

    pub fn extract_from_text(&self, text: &str) -> Vec<WeightedFeature> {
        let tokens = self.tokenize(text);
        let mut weights: HashMap<String, u32> = HashMap::new();

        for token in &tokens {
            *weights.entry(format!("term:{token}")).or_insert(0) += 3;
        }

        if self.options.include_bigrams {
            for pair in tokens.windows(2) {
                *weights
                    .entry(format!("phrase:{} {}", pair[0], pair[1]))
                    .or_insert(0) += 2;
            }
        }

        if self.options.include_length_bucket {
            *weights
                .entry(format!("len:{}", length_bucket(tokens.len())))
                .or_insert(0) += 4;
        }

        let mut features: Vec<_> = weights
            .into_iter()
            .map(|(key, weight)| WeightedFeature::new(key, weight))
            .collect();
        features.sort_by(|a, b| a.key.cmp(&b.key));
        features
    }

    pub fn tokenize(&self, text: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();

        for ch in text.chars() {
            if ch.is_alphanumeric() {
                current.extend(ch.to_lowercase());
            } else {
                self.push_token(&mut current, &mut tokens);
            }
        }
        self.push_token(&mut current, &mut tokens);

        tokens
    }

    fn push_token(&self, current: &mut String, tokens: &mut Vec<String>) {
        if current.is_empty() {
            return;
        }

        let raw = std::mem::take(current);
        if self.options.drop_numeric_tokens && raw.chars().all(|ch| ch.is_ascii_digit()) {
            return;
        }
        if self.options.drop_stop_words && is_stop_word(&raw) {
            return;
        }

        let token = if self.options.stem_tokens {
            stem(&raw)
        } else {
            raw
        };

        if token.len() >= 2 {
            tokens.push(token);
        }
    }
}

fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut pos = 0usize;
    let lower: Vec<u8> = html.as_bytes().iter().map(u8::to_ascii_lowercase).collect();
    let bytes = html.as_bytes();

    while pos < html.len() {
        if lower[pos..].starts_with(b"<!--") {
            if let Some(end) = find_bytes(&lower[pos + 4..], b"-->") {
                pos += 4 + end + 3;
            } else {
                break;
            }
            out.push(' ');
            continue;
        }

        if bytes[pos] == b'<' {
            let Some(end_rel) = html[pos..].find('>') else {
                break;
            };
            let end = pos + end_rel;
            let inside = String::from_utf8_lossy(&lower[pos + 1..end]);
            let tag = tag_name(&inside);
            let closing = inside.trim_start().starts_with('/');

            if !closing && should_skip_tag(&tag) {
                let close_pat = format!("</{tag}");
                if let Some(close_start_rel) = find_bytes(&lower[end + 1..], close_pat.as_bytes()) {
                    let close_start = end + 1 + close_start_rel;
                    if let Some(close_end_rel) = find_bytes(&lower[close_start..], b">") {
                        pos = close_start + close_end_rel + 1;
                    } else {
                        break;
                    }
                } else {
                    pos = end + 1;
                }
                out.push(' ');
                continue;
            }

            if is_boundary_tag(&tag) || inside.trim_end().ends_with('/') {
                out.push(' ');
            }
            pos = end + 1;
            continue;
        }

        let ch = html[pos..].chars().next().expect("valid char boundary");
        out.push(ch);
        pos += ch.len_utf8();
    }

    out
}

fn tag_name(inside: impl AsRef<str>) -> String {
    let inside = inside.as_ref();
    let trimmed = inside.trim_start().trim_start_matches('/');
    trimmed
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn should_skip_tag(tag: &str) -> bool {
    matches!(
        tag,
        "script"
            | "style"
            | "noscript"
            | "template"
            | "svg"
            | "head"
            | "nav"
            | "footer"
            | "aside"
            | "form"
            | "iframe"
    )
}

fn is_boundary_tag(tag: &str) -> bool {
    matches!(
        tag,
        "address"
            | "article"
            | "br"
            | "div"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "li"
            | "main"
            | "p"
            | "section"
            | "td"
            | "th"
            | "tr"
            | "ul"
            | "ol"
    )
}

fn decode_html_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' {
            out.push(ch);
            continue;
        }

        let mut entity = String::new();
        while let Some(next) = chars.peek().copied() {
            chars.next();
            if next == ';' {
                break;
            }
            if entity.len() > 16 {
                break;
            }
            entity.push(next);
        }

        match decode_entity(&entity) {
            Some(decoded) => out.push(decoded),
            None => {
                out.push('&');
                out.push_str(&entity);
                out.push(';');
            }
        }
    }

    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ if entity.starts_with("#x") || entity.starts_with("#X") => {
            u32::from_str_radix(&entity[2..], 16)
                .ok()
                .and_then(char::from_u32)
        }
        _ if entity.starts_with('#') => entity[1..].parse::<u32>().ok().and_then(char::from_u32),
        _ => None,
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_stop_word(token: &str) -> bool {
    matches!(
        token,
        "a" | "an"
            | "and"
            | "are"
            | "as"
            | "at"
            | "be"
            | "by"
            | "for"
            | "from"
            | "has"
            | "have"
            | "in"
            | "is"
            | "it"
            | "its"
            | "of"
            | "on"
            | "or"
            | "that"
            | "the"
            | "this"
            | "to"
            | "was"
            | "were"
            | "will"
            | "with"
    )
}

fn stem(token: &str) -> String {
    let len = token.len();
    if len > 6 && token.ends_with("ingly") {
        return token[..len - 5].to_string();
    }
    if len > 5 && token.ends_with("ing") {
        return token[..len - 3].to_string();
    }
    if len > 5 && token.ends_with("edly") {
        return token[..len - 4].to_string();
    }
    if len > 4 && token.ends_with("ed") {
        return token[..len - 2].to_string();
    }
    if len > 4 && token.ends_with("ies") {
        return format!("{}y", &token[..len - 3]);
    }
    if len > 5
        && (token.ends_with("sses")
            || token.ends_with("ches")
            || token.ends_with("shes")
            || token.ends_with("xes")
            || token.ends_with("zes"))
    {
        return token[..len - 2].to_string();
    }
    if len > 4 && token.ends_with('s') {
        return token[..len - 1].to_string();
    }
    token.to_string()
}

fn length_bucket(len: usize) -> &'static str {
    match len {
        0 => "empty",
        1..=15 => "tiny",
        16..=63 => "short",
        64..=255 => "medium",
        256..=1023 => "long",
        _ => "huge",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_html_boilerplate_and_decodes_entities() {
        let extractor = WebFeatureExtractor::default();
        let text = extractor.text_from_html(
            r#"
            <html>
              <head><title>hidden title</title></head>
              <body>
                <!-- hidden comment -->
                <nav>hidden navigation</nav>
                <main><h1>Visible &amp; useful</h1><p>Text&nbsp;here.</p></main>
                <script>hiddenCode()</script>
                <style>.hidden { color: red }</style>
              </body>
            </html>
            "#,
        );

        assert!(text.contains("Visible & useful"));
        assert!(text.contains("Text here"));
        assert!(!text.contains("hidden title"));
        assert!(!text.contains("hidden navigation"));
        assert!(!text.contains("hiddenCode"));
    }

    #[test]
    fn strips_html_with_unicode_text_before_tags() {
        let extractor = WebFeatureExtractor::default();
        let text = extractor.text_from_html("İstanbul <script>hidden</script><main>café</main>");

        assert!(text.contains("İstanbul"));
        assert!(text.contains("café"));
        assert!(!text.contains("hidden"));
    }

    #[test]
    fn tokenizes_normalizes_and_filters_web_text() {
        let extractor = WebFeatureExtractor::default();
        let tokens =
            extractor.tokenize("The crawlers were RUNNING on pages 123 and indexed pages.");

        assert!(!tokens.contains(&"the".to_string()));
        assert!(!tokens.contains(&"123".to_string()));
        assert!(tokens.contains(&"crawler".to_string()));
        assert!(tokens.contains(&"runn".to_string()));
        assert!(tokens.contains(&"page".to_string()));
    }

    #[test]
    fn extraction_adds_terms_phrases_and_length_bucket() {
        let extractor = WebFeatureExtractor::default();
        let features = extractor.extract_from_text("near duplicate web documents");
        let keys: Vec<_> = features
            .iter()
            .map(|feature| feature.key.as_str())
            .collect();

        assert!(keys.contains(&"term:near"));
        assert!(keys.contains(&"term:duplicate"));
        assert!(keys.contains(&"phrase:near duplicate"));
        assert!(keys.iter().any(|key| key.starts_with("len:")));
    }

    #[test]
    fn repeated_terms_increase_weight() {
        let extractor = WebFeatureExtractor::default();
        let features = extractor.extract_from_text("crawler crawler crawler");
        let crawler = features
            .iter()
            .find(|feature| feature.key == "term:crawler")
            .expect("crawler feature");

        assert_eq!(crawler.weight, 9);
    }
}
