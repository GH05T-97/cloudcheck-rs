use tabled::{Table, Tabled};

#[derive(Tabled)]
struct Finding {
    role: String,
    summary: String,
}

pub fn print_findings(data: &[(String, String)]) {
    let rows: Vec<Finding> = data
        .iter()
        .map(|(role, doc)| Finding {
            role: role.clone(),
            summary: summarize(doc),
        })
        .collect();

    let table = Table::new(rows);
    println!("{}", table);
}

fn summarize(doc: &str) -> String {
    if doc.len() > 120 {
        format!("{}...", &doc[..120])
    } else {
        doc.to_string()
    }
}
