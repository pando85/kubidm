use time::OffsetDateTime;

/// Is an access control profile with this time restriction active at `now` (the
/// transaction time)? The window is `[start, end)`: the start is inclusive and the end
/// exclusive, matching time-bounded group membership.
pub fn check_time_restriction(
    time_start: Option<OffsetDateTime>,
    time_end: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> bool {
    time_start.is_none_or(|start| now >= start) && time_end.is_none_or(|end| now < end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
    }

    #[test]
    fn test_check_time_restriction_none_none() {
        assert!(check_time_restriction(None, None, now()));
    }

    #[test]
    fn test_check_time_restriction_start_only() {
        let now = now();
        assert!(check_time_restriction(
            Some(now - Duration::hours(1)),
            None,
            now
        ));
        assert!(!check_time_restriction(
            Some(now + Duration::hours(1)),
            None,
            now
        ));
    }

    #[test]
    fn test_check_time_restriction_end_only() {
        let now = now();
        assert!(check_time_restriction(
            None,
            Some(now + Duration::hours(1)),
            now
        ));
        assert!(!check_time_restriction(
            None,
            Some(now - Duration::hours(1)),
            now
        ));
    }

    #[test]
    fn test_check_time_restriction_window() {
        let now = now();
        assert!(check_time_restriction(
            Some(now - Duration::hours(1)),
            Some(now + Duration::hours(1)),
            now
        ));
        // Expired.
        assert!(!check_time_restriction(
            Some(now - Duration::hours(2)),
            Some(now - Duration::hours(1)),
            now
        ));
        // Not yet open.
        assert!(!check_time_restriction(
            Some(now + Duration::hours(1)),
            Some(now + Duration::hours(2)),
            now
        ));
    }

    /// The window is `[start, end)`, like time-bounded membership.
    #[test]
    fn test_check_time_restriction_bounds() {
        let now = now();
        assert!(check_time_restriction(Some(now), None, now));
        assert!(!check_time_restriction(None, Some(now), now));
        assert!(!check_time_restriction(Some(now), Some(now), now));
        assert!(check_time_restriction(
            Some(now),
            Some(now + Duration::seconds(1)),
            now
        ));
    }

    /// The time is the caller supplied (transaction) time, not the wall clock.
    #[test]
    fn test_check_time_restriction_uses_supplied_time() {
        let start = now();
        let end = start + Duration::days(1);
        assert!(!check_time_restriction(
            Some(start),
            Some(end),
            OffsetDateTime::UNIX_EPOCH
        ));
        assert!(check_time_restriction(
            Some(start),
            Some(end),
            start + Duration::hours(12)
        ));
    }
}
