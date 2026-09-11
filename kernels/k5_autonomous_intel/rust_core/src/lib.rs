//! bl_intel — K5 Rust Core: N-gram Scorer + URL Feature Extractor
//! Autor: Luis Sánchez — BLACK LEVIATAN v29
//!
//! Clasificación de URLs a velocidad de Rust:
//!   - Shannon entropy calculator (detección de secrets)
//!   - N-gram malicious pattern scorer
//!   - Batch URL processing para listas grandes

use pyo3::prelude::*;
use std::collections::HashMap;

/// Calcula entropía de Shannon de un string.
/// Alta entropía = probablemente un secret/token.
#[pyfunction]
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let len = s.len() as f64;
    let mut freq: HashMap<char, u64> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    -freq.values().map(|&count| {
        let p = count as f64 / len;
        if p > 0.0 { p * p.log2() } else { 0.0 }
    }).sum::<f64>()
}

/// Scorer de n-gramas para URLs.
/// Compara n-gramas de la URL contra un perfil de n-gramas maliciosos.
#[pyfunction]
fn ngram_score(url: &str, n: usize) -> f64 {
    // N-gramas frecuentes en URLs maliciosas (dataset PhishTank)
    let malicious_ngrams: Vec<&str> = vec![
        "login", "secure", "verify", "account", "update", "banking",
        "paypal", "amazon", "apple-id", "microsoft", "signin", "confirm",
        "wallet", "crypto", "alert", "suspended", ".tk", ".ml", ".ga",
        "xn--", "http://", "0x", "%20", "redirect", "click", "track",
    ];
    
    let url_lower = url.to_lowercase();
    let mut score = 0.0f64;
    let mut _matches = 0u32;
    
    for ng in &malicious_ngrams {
        if url_lower.contains(ng) {
            _matches += 1;
            // Peso proporcional a la especificidad del n-grama
            score += ng.len() as f64 * 0.3;
        }
    }
    
    // Generar n-gramas de caracteres del URL
    if n >= 2 && url.len() >= n {
        let chars: Vec<char> = url_lower.chars().collect();
        for window in chars.windows(n) {
            let ng: String = window.iter().collect();
            // Penalizar n-gramas con alta entropía (señal de ofuscación)
            if shannon_entropy(&ng) > 3.5 {
                score += 0.1;
            }
        }
    }
    
    // Normalizar a 0.0-1.0
    (score / 10.0).min(1.0)
}

/// Procesa un batch de URLs y retorna scores.
/// Mucho más rápido que llamar classify_url una por una desde Python.
#[pyfunction]
fn batch_score_urls(py: Python<'_>, urls: Vec<String>) -> PyObject {
    let result = pyo3::types::PyList::empty_bound(py);
    for url in urls {
        let entropy = shannon_entropy(&url);
        let ng_score = ngram_score(&url, 3);
        let length_score = (url.len() as f64 / 200.0).min(1.0);
        let combined = (entropy * 0.3 + ng_score * 0.5 + length_score * 0.2)
            .min(1.0);
        let item = pyo3::types::PyDict::new_bound(py);
        item.set_item("url", &url).unwrap();
        item.set_item("combined_score", combined).unwrap();
        item.set_item("entropy", entropy).unwrap();
        item.set_item("ngram_score", ng_score).unwrap();
        result.append(item).unwrap();
    }
    result.into()
}

/// Detecta patrones de secrets con regex simplificado en Rust.
#[pyfunction]
fn detect_secrets_fast(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    
    // AWS Access Key
    if let Some(pos) = find_pattern(text, "AKIA") {
        let end = (pos + 20).min(text.len());
        let candidate = &text[pos..end];
        if candidate.chars().all(|c| c.is_ascii_alphanumeric()) && candidate.len() >= 16 {
            found.push(format!("aws_key:{}", &candidate[..16]));
        }
    }
    
    // GitHub token
    if let Some(pos) = find_pattern(text, "ghp_") {
        let end = (pos + 40).min(text.len());
        found.push(format!("github_token:{}", &text[pos..end]));
    }
    
    // Generic high-entropy strings after common key patterns
    for marker in &["api_key=", "apikey=", "secret=", "token=", "password="] {
        if let Some(pos) = find_pattern(&text.to_lowercase(), marker) {
            let val_start = pos + marker.len();
            let val_end = (val_start + 60).min(text.len());
            if val_end > val_start {
                let candidate = &text[val_start..val_end]
                    .trim_matches(|c| c == '"' || c == '\'' || c == ' ');
                if shannon_entropy(candidate) > 3.5 {
                    found.push(format!("secret_value:{}", &candidate[..candidate.len().min(20)]));
                }
            }
        }
    }
    
    found
}

fn find_pattern(text: &str, pattern: &str) -> Option<usize> {
    text.find(pattern)
}

#[pymodule]
fn bl_intel(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(ngram_score, m)?)?;
    m.add_function(wrap_pyfunction!(batch_score_urls, m)?)?;
    m.add_function(wrap_pyfunction!(detect_secrets_fast, m)?)?;
    Ok(())
}
