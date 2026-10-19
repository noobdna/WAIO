"""security/snd_behavior/snd_id_mock.py -- TEST MOCK of an SND@ID event
source. SND@ID is not implemented anywhere on this machine; this file
exists so the behavior monitor can be exercised end to end, and it is
labelled a mock in every event it emits (device ids carry "mock-").

  history SEED DAYS OUT.jsonl      -- 3 synthetic principals' normal weeks
  scenario NAME OUT.jsonl          -- one named scenario (see SCENARIOS)

All data is synthetic. The pseudo-random generator here is seeded for
reproducible test data only; it is never used for keys or tokens.
"""

import datetime
import json
import random
import sys

T0 = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)
# principal -> (local work start hour JST, end hour, region, device)
PEOPLE = {
    "alice": (9, 18, "JP-13", "mock-alice-laptop"),
    "bob": (10, 19, "JP-27", "mock-bob-laptop"),
    "carol": (8, 17, "JP-13", "mock-carol-desktop"),
}


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(eid, when, principal, action, region, device, **extra):
    d = {"source": "snd_id", "event_id": eid, "ts": ts(when), "principal": principal, "action": action,
         "region": region, "device_id": device}
    d.update(extra)
    return d


def history(seed, days):
    rng = random.Random(seed)
    out, n = [], 0
    for day in range(days):
        date = T0 + datetime.timedelta(days=day)
        if date.weekday() >= 5:
            continue
        for p, (start, end, region, device) in PEOPLE.items():
            for _ in range(2):
                local_h = rng.randint(start, end)
                when = date + datetime.timedelta(hours=local_h - 9, minutes=rng.randint(0, 59))
                n += 1
                out.append(ev("h-%05d" % n, when, p, "login_success", region, device))
                n += 1
                out.append(ev("h-%05d" % n, when + datetime.timedelta(minutes=5), p, "data_access", region, device,
                              bytes=rng.randint(100_000, 5_000_000)))
            if rng.random() < 0.1:
                n += 1
                out.append(ev("h-%05d" % n, date + datetime.timedelta(hours=1), p, "login_failure", region, device))
    return out


def at(day, local_hour, minute=0):
    return T0 + datetime.timedelta(days=day, hours=local_hour - 9, minutes=minute)


SCENARIOS = {
    # ---- benign (must not raise HIGH/CRITICAL) ----
    "normal_day": lambda: [ev("n-1", at(40, 10), "alice", "login_success", "JP-13", "mock-alice-laptop"),
                           ev("n-2", at(40, 11), "alice", "data_access", "JP-13", "mock-alice-laptop", bytes=2_000_000),
                           ev("n-3", at(40, 14), "bob", "login_success", "JP-27", "mock-bob-laptop"),
                           ev("n-4", at(40, 15), "carol", "login_failure", "JP-13", "mock-carol-desktop"),
                           ev("n-5", at(40, 15, 1), "carol", "login_success", "JP-13", "mock-carol-desktop")],
    "shift_change": lambda: [ev("s-1", at(41, 23), "bob", "login_success", "JP-27", "mock-bob-laptop")],
    "business_trip": lambda: [ev("t-1", at(42, 9), "alice", "login_success", "JP-13", "mock-alice-laptop"),
                              ev("t-2", at(42, 10, 30), "alice", "login_success", "SG", "mock-alice-laptop")],
    "emergency_work": lambda: [ev("e-1", at(43, 3), "carol", "login_success", "JP-13", "mock-carol-desktop"),
                               ev("e-2", at(43, 3, 10), "carol", "privilege_change", "JP-13", "mock-carol-desktop",
                                  role="admin")],
    # ---- attacks (must raise HIGH/CRITICAL) ----
    "credential_stuffing": lambda: [ev("a-%d" % i, at(44, 2, i), "alice", "login_failure", "RU", "mock-unknown-1")
                                    for i in range(6)] +
                                   [ev("a-9", at(44, 2, 7), "alice", "login_success", "RU", "mock-unknown-1")],
    "token_theft_travel": lambda: [ev("b-1", at(45, 10), "bob", "login_success", "JP-27", "mock-bob-laptop"),
                                   ev("b-2", at(45, 10, 20), "bob", "login_success", "US", "mock-unknown-2")],
    "insider_exfil": lambda: [ev("x-%d" % i, at(46, 13, i), "carol", "data_access", "JP-13", "mock-carol-desktop",
                                 bytes=40_000_000) for i in range(5)],
    "priv_escalation": lambda: [ev("p-1", at(47, 11), "bob", "privilege_change", "JP-27", "mock-bob-laptop",
                                   role="global_admin")],
    "mfa_reset_attack": lambda: [ev("m-1", at(48, 4), "alice", "mfa_change", "NG", "mock-unknown-3")],
}


def main(argv):
    if len(argv) == 5 and argv[1] == "history":
        rows = history(int(argv[2]), int(argv[3]))
        path = argv[4]
    elif len(argv) == 4 and argv[1] == "scenario" and argv[2] in SCENARIOS:
        rows = SCENARIOS[argv[2]]()
        path = argv[3]
    else:
        print("usage: history SEED DAYS OUT | scenario {%s} OUT" % ",".join(SCENARIOS), file=sys.stderr)
        return 2
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    print(json.dumps({"ok": True, "events": len(rows), "mock": True}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
