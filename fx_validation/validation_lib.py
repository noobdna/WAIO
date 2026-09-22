"""fx_validation/validation_lib.py -- pure computation core for the FX
Forecast Validation Engine (error calc, direction scoring, range-zone
classification). Kept as a standalone module, imported by both
run_validation.sh's Pass 2 step and tests/fx_validation_test.sh, so the
scoring rules are defined exactly once and the test suite exercises the
real logic directly rather than a duplicated copy.

No I/O, no network, no filesystem access in this module -- every
function here is a pure function of its arguments, which is what makes
it directly unit-testable without any fixture snapshot/server.
"""


def sign(x):
    return (x > 0) - (x < 0)


def classify_zone(actual, downside_range, base_range, upside_range):
    """Classify an observed actual rate into one of the four scenario
    bands. Ranges are treated as contiguous (downside_high ==
    base_low, base_high == upside_low, as every WAIO FX scenario
    report constructs them): DOWNSIDE and UPSIDE are checked as the
    half-open bands outside Base, anything beyond the outer edge of
    Downside/Upside is OUTSIDE_RANGE -- the actual moved further than
    any modeled scenario anticipated.
    """
    d_lo, _d_hi = downside_range
    b_lo, b_hi = base_range
    _u_lo, u_hi = upside_range

    if d_lo <= actual < b_lo:
        return "DOWNSIDE"
    if b_lo <= actual <= b_hi:
        return "BASE"
    if b_hi < actual <= u_hi:
        return "UPSIDE"
    return "OUTSIDE_RANGE"


def direction_correct(actual, median, current_at_forecast, base_range):
    """True/False: did the actual move the way the forecast implied?

    The forecast's directional call is read from (median -
    current_at_forecast): a Base Range built with a median above/below
    the forecast-time spot embeds an explicit skew. If the forecast
    carried no skew at all (median == current, a flat call), there is
    no up/down sign to compare against -- correctness instead falls
    back to "did it stay inside the Base Range" (the flat call itself).
    """
    predicted = sign(median - current_at_forecast)
    if predicted == 0:
        b_lo, b_hi = base_range
        return b_lo <= actual <= b_hi
    return sign(actual - current_at_forecast) == predicted


def compute_errors(actual, median):
    """Returns (absolute_error, percentage_error). median must be
    non-zero -- true for every real FX rate, so no zero-guard here."""
    abs_err = abs(actual - median)
    pct_err = (abs_err / median) * 100
    return abs_err, pct_err
