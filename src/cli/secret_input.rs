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

#[cfg(test)]
mod tests {
    use super::{parse_duration_value, resolve_daemon_secret_input, resolve_secret_input};
    use chrono::Duration;

    #[test]
    fn parse_duration_value_accepts_supported_units() {
        assert_eq!(
            parse_duration_value("15m", "--ttl").unwrap(),
            Duration::minutes(15)
        );
        assert_eq!(
            parse_duration_value("2h", "--ttl").unwrap(),
            Duration::hours(2)
        );
        assert_eq!(
            parse_duration_value("3d", "--ttl").unwrap(),
            Duration::days(3)
        );
    }

    #[test]
    fn parse_duration_value_rejects_invalid_literals() {
        let short = parse_duration_value("9", "--ttl").unwrap_err();
        assert!(short.to_string().contains("positive duration"));

        let zero = parse_duration_value("0m", "--ttl").unwrap_err();
        assert!(zero.to_string().contains("greater than zero"));

        let invalid_unit = parse_duration_value("10w", "--ttl").unwrap_err();
        assert!(invalid_unit.to_string().contains("unit must be one of"));
    }

    #[test]
    fn resolve_daemon_secret_input_covers_generate_and_value_modes() {
        let generated = resolve_daemon_secret_input(true, None).unwrap();
        assert!(!generated.is_empty());

        let explicit = resolve_daemon_secret_input(false, Some("secret".to_owned())).unwrap();
        assert_eq!(explicit, b"secret");
    }

    #[test]
    fn resolve_daemon_secret_input_rejects_invalid_combinations() {
        let combined = resolve_daemon_secret_input(true, Some("secret".to_owned())).unwrap_err();
        assert!(combined
            .to_string()
            .contains("generate cannot be combined with value"));

        let missing = resolve_daemon_secret_input(false, None).unwrap_err();
        assert!(missing.to_string().contains("requires value"));

        let empty = resolve_daemon_secret_input(false, Some(String::new())).unwrap_err();
        assert!(empty.to_string().contains("cannot be empty"));
    }

    #[test]
    fn resolve_secret_input_covers_generate_and_value_modes() {
        let generated = resolve_secret_input(true, None, false).unwrap();
        assert!(!generated.is_empty());

        let explicit = resolve_secret_input(false, Some("secret".to_owned()), false).unwrap();
        assert_eq!(explicit, b"secret");
    }

    #[test]
    fn resolve_secret_input_rejects_invalid_sources() {
        let combined = resolve_secret_input(true, Some("secret".to_owned()), false).unwrap_err();
        assert!(combined.to_string().contains("--generate"));

        let empty = resolve_secret_input(false, Some(String::new()), false).unwrap_err();
        assert!(empty.to_string().contains("cannot be empty"));

        let ambiguous = resolve_secret_input(false, Some("secret".to_owned()), true).unwrap_err();
        assert!(ambiguous.to_string().contains("choose one input source"));
    }
}
