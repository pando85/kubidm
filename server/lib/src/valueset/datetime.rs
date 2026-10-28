use crate::{
    prelude::*,
    schema::SchemaAttribute,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut},
};
use kubidm_proto::scim_v1::{client::ScimDateTime, JsonValue};
use smolset::SmolSet;
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};

/// Kubidm: the latest UTC time that RFC 3339 can store, `9999-12-31T23:59:59.999999999Z`.
///
/// Built from its date rather than taken from `PrimitiveDateTime::MAX`, which is in year
/// 999999 when the `large-dates` feature of the `time` crate is enabled by any crate in
/// the build. Evaluated at compile time: a component out of range fails the build.
const STORABLE_MAX: OffsetDateTime = match Date::from_calendar_date(9999, Month::December, 31) {
    Ok(date) => date.with_time(Time::MAX).assume_utc(),
    Err(_) => unreachable!(),
};

/// Kubidm: the earliest UTC time that RFC 3339 can store, `0000-01-01T00:00:00Z`. As
/// [`STORABLE_MAX`], evaluated at compile time.
const STORABLE_MIN: OffsetDateTime = match Date::from_calendar_date(0, Month::January, 1) {
    Ok(date) => date.midnight().assume_utc(),
    Err(_) => unreachable!(),
};

/// Kubidm: `odt` in UTC, clamped to the range RFC 3339 can store (years 0 to 9999), and
/// whether it had to be clamped.
fn clamp_to_storable_utc(odt: OffsetDateTime) -> (OffsetDateTime, bool) {
    match odt.checked_to_offset(UtcOffset::UTC) {
        Some(utc) if utc > STORABLE_MAX => (STORABLE_MAX, true),
        Some(utc) if utc < STORABLE_MIN => (STORABLE_MIN, true),
        Some(utc) => (utc, false),
        // Only a negative offset can push a time past the end of the representable range,
        // only a positive one before its start.
        None if odt.offset().is_negative() => (STORABLE_MAX, true),
        None => (STORABLE_MIN, true),
    }
}

/// Kubidm: format `odt` as RFC 3339 in UTC, as it is stored and indexed.
///
/// RFC 3339 formatting fails only for a year outside 0 to 9999 or an offset that is not a
/// whole number of minutes (or 24 hours or more). The value formatted here is in UTC and
/// clamped to [`STORABLE_MIN`]..=[`STORABLE_MAX`], so it can not fail. Every value of the
/// set already is (loads clamp, every other path normalises to UTC); clamping again here
/// keeps a value from any other path from panicking. Should formatting still fail, the
/// nearest bound is written: never a panic, and never a string that can not be loaded.
fn format_storable_utc(odt: &OffsetDateTime) -> String {
    debug_assert_eq!(odt.offset(), UtcOffset::UTC);
    let (utc, clamped) = clamp_to_storable_utc(*odt);
    if clamped {
        error!(value = %odt, clamped = %utc, "DateTime is out of the storable range, clamping it");
    }
    utc.format(&Rfc3339).unwrap_or_else(|err| {
        error!(?err, value = %odt, "Unable to format DateTime as RFC 3339");
        if utc < OffsetDateTime::UNIX_EPOCH {
            "0000-01-01T00:00:00Z".to_string()
        } else {
            "9999-12-31T23:59:59.999999999Z".to_string()
        }
    })
}

/// Kubidm: load a stored RFC 3339 time, normalised to UTC.
///
/// Released versions stored a SCIM put without normalising it to UTC, so a stored time may
/// be out of range in UTC (`9999-12-31T23:59:59-23:59` is in year 10000), or in range but
/// not storable as RFC 3339 again (`0000-01-01T00:00:00+01:00` is in year -1). Failing
/// would make the whole entry unloadable, so such a time is clamped to the latest (or
/// earliest) time that can be stored, and an error is logged. A value that does not parse
/// at all is still invalid.
fn load_utc_clamped(s: &str) -> Result<OffsetDateTime, OperationError> {
    let odt = OffsetDateTime::parse(s, &Rfc3339).map_err(|err| {
        error!(?err, "Stored DateTime is not valid RFC 3339");
        OperationError::InvalidValueState
    })?;

    let (utc, clamped) = clamp_to_storable_utc(odt);
    if clamped {
        error!(
            stored = %s,
            clamped = %utc,
            "Stored DateTime can not be expressed in UTC within the storable range, clamping it"
        );
    }
    Ok(utc)
}

#[derive(Debug, Clone)]
pub struct ValueSetDateTime {
    set: SmolSet<[OffsetDateTime; 1]>,
}

impl ValueSetDateTime {
    pub fn new(b: OffsetDateTime) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetDateTime { set })
    }

    pub fn push(&mut self, b: OffsetDateTime) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data
            .into_iter()
            .map(|s| load_utc_clamped(&s))
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetDateTime { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and offset date time is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = OffsetDateTime>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetDateTime { set }))
    }
}

impl ValueSetScimPut for ValueSetDateTime {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let ScimDateTime { date_time } = serde_json::from_value(value).map_err(|err| {
            error!(?err, "SCIM DateTime syntax invalid");
            OperationError::SC0010DateTimeSyntaxInvalid
        })?;

        // Kubidm: normalise to UTC like every other path, checked: a time out of range in
        // UTC would make `to_offset` panic, here or when the value is loaded.
        let date_time = date_time
            .checked_to_offset(time::UtcOffset::UTC)
            .ok_or_else(|| {
                error!("SCIM DateTime can not be expressed in UTC");
                OperationError::SC0010DateTimeSyntaxInvalid
            })?;

        let mut set = SmolSet::new();
        set.insert(date_time);

        Ok(ValueSetResolveStatus::Resolved(Box::new(
            ValueSetDateTime { set },
        )))
    }
}

impl ValueSetT for ValueSetDateTime {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::DateTime(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        if let PartialValue::DateTime(u) = pv {
            self.set.remove(u);
        };
        self.set.is_empty()
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::DateTime(u) => self.set.contains(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::DateTime(u) => self.set.iter().all(|set_value| set_value < u),
            _ => false,
        }
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(format_storable_utc).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::DateTime
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(format_storable_utc))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        self.set.iter().next().copied().map(|v| v.into())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::DateTime(self.set.iter().map(format_storable_utc).collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::DateTime))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::DateTime))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_datetime_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_datetime_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_datetime_single(&self) -> Option<OffsetDateTime> {
        if self.set.len() == 1 {
            self.set.iter().cloned().take(1).next()
        } else {
            None
        }
    }

    fn as_datetime_set(&self) -> Option<&SmolSet<[OffsetDateTime; 1]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetDateTime;
    use crate::prelude::ValueSet;
    use std::time::Duration;
    use time::OffsetDateTime;

    #[test]
    fn test_scim_datetime() {
        let odt = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(69_420);
        let vs: ValueSet = ValueSetDateTime::new(odt);

        crate::valueset::scim_json_reflexive(&vs, r#""1970-01-01T19:17:00Z""#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetDateTime>(&vs, &[])
    }

    /// Kubidm: a time that can not be expressed in UTC is an error, not a panic, both when
    /// it is put through SCIM and when it is loaded.
    #[test]
    fn test_datetime_out_of_range_in_utc() {
        use crate::prelude::OperationError;
        use crate::valueset::ValueSetScimPut;

        let out_of_range = "9999-12-31T23:59:59-23:59";
        assert!(matches!(
            ValueSetDateTime::from_scim_json_put(serde_json::json!(out_of_range)),
            Err(OperationError::SC0010DateTimeSyntaxInvalid)
        ));

        // A value that does not parse is still invalid.
        assert!(matches!(
            ValueSetDateTime::from_dbvs2(vec!["not a time".to_string()]),
            Err(OperationError::InvalidValueState)
        ));

        // A time with an offset is normalised to UTC.
        let vs = ValueSetDateTime::from_dbvs2(vec!["2024-01-01T10:00:00+02:00".to_string()])
            .expect("valid");
        assert_eq!(
            vs.to_datetime_single().map(|odt| odt.offset()),
            Some(time::UtcOffset::UTC)
        );
    }

    /// Kubidm: a stored time out of range in UTC (written by a SCIM put of a released
    /// version, which did not normalise to UTC) is clamped on load, so that its entry still
    /// loads, and it can be stored again.
    #[test]
    fn test_datetime_out_of_range_in_utc_is_clamped_on_load() {
        use crate::valueset::DbValueSetV2;
        use time::format_description::well_known::Rfc3339;

        let load = |s: &str| {
            ValueSetDateTime::from_dbvs2(vec![s.to_string()])
                .ok()
                .and_then(|vs| vs.to_datetime_single())
        };
        let stored_again = |s: &str| {
            ValueSetDateTime::from_dbvs2(vec![s.to_string()])
                .map(|vs| vs.to_db_valueset_v2())
                .ok()
        };

        // Past the end of year 9999 in UTC: the latest storable time.
        let max = OffsetDateTime::parse("9999-12-31T23:59:59.999999999Z", &Rfc3339)
            .expect("latest storable time");
        assert_eq!(super::STORABLE_MAX, max);
        assert_eq!(load("9999-12-31T23:59:59-23:59"), Some(max));
        assert_eq!(load("9999-12-31T23:00:00-01:00"), Some(max));
        assert!(matches!(
            stored_again("9999-12-31T23:59:59-23:59"),
            Some(DbValueSetV2::DateTime(ref v)) if v == &["9999-12-31T23:59:59.999999999Z"]
        ));

        // Before year 0 in UTC: the earliest storable time.
        let min = OffsetDateTime::parse("0000-01-01T00:00:00Z", &Rfc3339).ok();
        assert!(min.is_some());
        assert_eq!(load("0000-01-01T00:00:00+01:00"), min);
        assert!(matches!(
            stored_again("0000-01-01T00:00:00+01:00"),
            Some(DbValueSetV2::DateTime(ref v)) if v == &["0000-01-01T00:00:00Z"]
        ));

        // The edges themselves are kept as they are.
        assert_eq!(
            load("9999-12-31T23:59:59Z"),
            OffsetDateTime::parse("9999-12-31T23:59:59Z", &Rfc3339).ok()
        );
        assert_eq!(load("0000-01-01T00:00:00Z"), min);
        assert_eq!(Some(super::STORABLE_MIN), min);
    }

    /// Kubidm: formatting a value for storage, indexing or display never panics, even for a
    /// value outside the storable range that did not come from a load: it is clamped.
    #[test]
    fn test_datetime_out_of_storable_range_formats_clamped() {
        use crate::valueset::DbValueSetV2;
        use time::{Date, Month};

        let before_year_0 = Date::from_calendar_date(-5, Month::June, 1)
            .expect("valid date")
            .midnight()
            .assume_utc();
        let vs: ValueSet = ValueSetDateTime::new(before_year_0);
        assert!(matches!(
            vs.to_db_valueset_v2(),
            DbValueSetV2::DateTime(ref v) if v == &["0000-01-01T00:00:00Z"]
        ));
        assert_eq!(vs.generate_idx_eq_keys(), vec!["0000-01-01T00:00:00Z"]);
        assert_eq!(
            vs.to_proto_string_clone_iter().collect::<Vec<_>>(),
            vec!["0000-01-01T00:00:00Z"]
        );

        // The bounds themselves format as they are.
        for (bound, expected) in [
            (super::STORABLE_MAX, "9999-12-31T23:59:59.999999999Z"),
            (super::STORABLE_MIN, "0000-01-01T00:00:00Z"),
        ] {
            assert!(matches!(
                (ValueSetDateTime::new(bound) as ValueSet).to_db_valueset_v2(),
                DbValueSetV2::DateTime(ref v) if v == &[expected]
            ));
        }
    }
}
