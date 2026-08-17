//! Integer-microsecond duration encoding for the recording schema.
//!
//! Hunt JSON already reports intervals in microseconds. Recordings use the same
//! unit so replay math does not depend on serde's `{secs, nanos}` Duration
//! representation.

use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let micros = u64::try_from(duration.as_micros()).map_err(serde::ser::Error::custom)?;
    serializer.serialize_u64(micros)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let micros = u64::deserialize(deserializer)?;
    Ok(Duration::from_micros(micros))
}
