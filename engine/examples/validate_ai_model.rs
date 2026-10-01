use everbloom_engine::{AiModel, AiModelKind};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: validate_ai_model <model.onnx> [cnn|transformer]");
        std::process::exit(2);
    };
    let kind = match args
        .next()
        .unwrap_or_else(|| "cnn".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "transformer" | "tf" => AiModelKind::Transformer,
        _ => AiModelKind::CNN,
    };
    let report = AiModel::validate_model_for_scanner(path, kind);
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize validation report")
    );
    if !report.usable {
        std::process::exit(1);
    }
}
