from ichnos.ratelimit import TokenBucket


def test_starts_full_then_empty():
    t = [0.0]
    bucket = TokenBucket(5.0, burst=1, clock=lambda: t[0])
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False


def test_refills_after_interval():
    t = [0.0]
    bucket = TokenBucket(5.0, burst=1, clock=lambda: t[0])
    bucket.try_acquire()
    t[0] += 5.0
    assert bucket.try_acquire() is True


def test_seconds_until_next_token_counts_down():
    t = [0.0]
    bucket = TokenBucket(5.0, burst=1, clock=lambda: t[0])
    bucket.try_acquire()
    assert bucket.seconds_until_next_token() == 5.0
    t[0] += 2.5
    assert bucket.seconds_until_next_token() == 2.5


def test_wait_sleeps_exactly_until_available():
    t = [0.0]
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        t[0] += seconds

    bucket = TokenBucket(5.0, burst=1, clock=lambda: t[0])
    bucket.try_acquire()
    bucket.wait(sleep=fake_sleep)
    assert sleeps == [5.0]


def test_burst_capacity_never_exceeded():
    t = [0.0]
    bucket = TokenBucket(5.0, burst=1, clock=lambda: t[0])
    t[0] += 100.0  # idle for a long time
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False  # no catch-up burst, per design
