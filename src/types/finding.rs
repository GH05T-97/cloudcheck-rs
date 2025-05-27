#[derive(Debug, Clone)]
pub struct Finding {
    pub service: String,     // e.g., "S3", "Lambda"
    pub resource: String,    // e.g., "bucket-name", "lambda-fn-name"
    pub issue: String,       // e.g., "Public ACL", "Excessive IAM permissions"
}
