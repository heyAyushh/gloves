use std::io::Read;

use chrono::Duration;

use crate::error::{GlovesError, Result};

pub(crate) fn parse_duration_value(value: &str, field_name: &str) -> Result<Duration> {
    if value.len() < 2 {
        return Err(GlovesError::InvalidInput(format!(
            "{field_name} must use a positive duration with unit (m/h/d)"
        )));
    }
    let (amount_raw, unit) = value.split_at(value.len() - 1);
    let amount = amount_raw.parse::<i64>().map_err(|_| {
        GlovesError::InvalidInput(format!(
            "{field_name} must use a positive duration with unit (m/h/d)"
        ))
    })?;
    if amount <= 0 {
        return Err(GlovesError::InvalidInput(format!(
            "{field_name} must be greater than zero"
        )));
    }

    match unit {
        "m" => Ok(Duration::minutes(amount)),
        "h" => Ok(Duration::hours(amount)),
        "d" => Ok(Duration::days(amount)),
        _ => Err(GlovesError::InvalidInput(format!(
            "{field_name} unit must be one of: m, h, d"
        ))),
    }
}

pub(crate) fn resolve_daemon_secret_input(
    generate: bool,
    value: Option<String>,
) -> Result<Vec<u8>> {
    if generate {
        if value.is_some() {
            return Err(GlovesError::InvalidInput(
                "generate cannot be combined with value".to_owned(),
            ));
        }
        return Ok(uuid::Uuid::new_v4().to_string().into_bytes());
    }

    let value = value.ok_or_else(|| {
        GlovesError::InvalidInput("set requires value or generate=true".to_owned())
    })?;
    if value.is_empty() {
        return Err(GlovesError::InvalidInput(
            "set value cannot be empty".to_owned(),
        ));
    }
    Ok(value.into_bytes())
}

pub(crate) fn resolve_secret_input(
    generate: bool,
    value: Option<String>,
    stdin: bool,
) -> Result<Vec<u8>> {
    if generate {
        if value.is_some() || stdin {
            return Err(GlovesError::InvalidInput(
                "--generate cannot be combined with --value/--stdin".to_owned(),
            ));
        }
        return Ok(uuid::Uuid::new_v4().to_string().into_bytes());
    }

    match (value, stdin) {
        (Some(input), false) => {
            if input.is_empty() {
                return Err(GlovesError::InvalidInput(
                    "secret value cannot be empty".to_owned(),
                ));
            }
            Ok(input.into_bytes())
        }
        (None, true) => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)?;
            while bytes.last().copied() == Some(b'\n') || bytes.last().copied() == Some(b'\r') {
                bytes.pop();
            }
            if bytes.is_empty() {
                return Err(GlovesError::InvalidInput(
                    "stdin secret is empty".to_owned(),
                ));
            }
            Ok(bytes)
        }
        _ => Err(GlovesError::InvalidInput(
            "choose one input source: --generate, --value, or --stdin".to_owned(),
        )),
    }
}
