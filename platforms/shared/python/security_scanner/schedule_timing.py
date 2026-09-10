"""KST recurrence slots; persisted slot keys make polling idempotent."""
import datetime as dt

KST = dt.timezone(dt.timedelta(hours=9))


def due_slot(target, now):
    now = now.astimezone(KST)
    hour, minute = map(int, target.get("schedule_time", "01:00").split(":"))
    frequency = target.get("schedule_frequency", "daily")
    due = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "hourly":
        step = dt.timedelta(hours=target.get("schedule_interval_hours", 1))
        anchor = dt.datetime(1970, 1, 1, hour, minute, tzinfo=KST)
        due = anchor + ((now - anchor) // step) * step
    else:
        if now < due:
            return None
        if frequency == "weekly" and now.weekday() not in target.get("schedule_weekdays", []):
            return None
    # Do not schedule a slot predating creation or an administrator's edit.
    modified = target.get("updated_at") or target.get("created_at")
    if modified:
        try:
            boundary = dt.datetime.fromisoformat(modified.replace("Z", "+00:00"))
            if boundary.tzinfo is None:
                boundary = boundary.replace(tzinfo=dt.timezone.utc)
            if due < boundary:
                return None
        except ValueError:
            return None
    # Retain the old daily 01:00 key so upgrades do not repeat today's run.
    if frequency == "daily" and (hour, minute) == (1, 0):
        return due.date().isoformat()
    return due.isoformat(timespec="minutes")
