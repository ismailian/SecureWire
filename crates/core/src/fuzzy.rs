//! Fuzzy matching for the command palette: the query's characters must appear
//! in order (case-insensitive); consecutive runs and word starts score higher.

/// `None` = no match. Higher is better.
pub fn score(query: &str, text: &str) -> Option<i32> {
    let q: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if q.is_empty() {
        return Some(0);
    }
    let t: Vec<char> = text.chars().collect();
    let mut qi = 0;
    let mut total = 0;
    let mut run = 0;
    let mut first = None;
    for (i, &c) in t.iter().enumerate() {
        if qi == q.len() {
            break;
        }
        if c.to_lowercase().eq(std::iter::once(q[qi])) {
            first.get_or_insert(i);
            let word_start = i == 0 || !t[i - 1].is_alphanumeric();
            run += 1;
            total += 1 + run * 2 + if word_start { 6 } else { 0 };
            qi += 1;
        } else {
            run = 0;
        }
    }
    if qi < q.len() {
        return None;
    }
    // Earlier matches and shorter texts win ties.
    Some(total * 4 - first.unwrap_or(0) as i32 - t.len() as i32 / 8)
}

#[cfg(test)]
mod tests {
    use super::score;

    #[test]
    fn subsequence_in_order() {
        assert!(score("rst ngx", "Restart nginx").is_some());
        assert!(score("xr", "Restart nginx").is_none());
        assert_eq!(score("", "anything"), Some(0));
        assert!(score("NGINX", "restart nginx").is_some());
    }

    #[test]
    fn word_starts_and_runs_rank_higher() {
        let a = score("rn", "Restart nginx").unwrap();
        let b = score("rn", "Error rendering").unwrap();
        assert!(a > b, "{a} vs {b}");
        let exact = score("logs", "Logs: nginx").unwrap();
        let scattered = score("logs", "Largest dirs on /var").unwrap_or(i32::MIN);
        assert!(exact > scattered);
    }
}
