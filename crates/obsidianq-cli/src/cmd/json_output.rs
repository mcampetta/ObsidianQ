use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct JsonError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonResponse<T: Serialize> {
    pub ok: bool,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonError>,
}

pub fn print_json_success<T: Serialize>(command: &str, data: T) -> Result<()> {
    let out = JsonResponse {
        ok: true,
        command: command.to_string(),
        data: Some(data),
        error: None,
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

pub fn print_json_error(command: &str, code: &str, message: &str, field: Option<&str>) -> Result<()> {
    let out = JsonResponse::<serde_json::Value> {
        ok: false,
        command: command.to_string(),
        data: None,
        error: Some(JsonError {
            code: code.to_string(),
            message: message.to_string(),
            field: field.map(|s| s.to_string()),
        }),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

