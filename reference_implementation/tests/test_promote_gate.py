"""Model terfi kapısı — doğrulanmamış bir model canlıya geçmemeli."""
from __future__ import annotations

from refimpl.evaluation.promote_gate import ACCURACY_TOLERANCE, MIN_ACCEPTED_ACCURACY, should_promote


def report(accepted: float, missed: int, exact: float = 0.80) -> dict:
    return {
        "accepted_accuracy": accepted,
        "exact_accuracy": exact,
        "missed_threats": missed,
        "false_threats": 0,
    }


class TestSanityFloor:
    def test_below_floor_is_rejected(self):
        ok, reason = should_promote(report(accepted=0.30, missed=1))
        assert ok is False
        assert "kabul edilebilir isabet" in reason

    def test_at_floor_is_accepted(self):
        ok, _ = should_promote(report(accepted=MIN_ACCEPTED_ACCURACY, missed=1))
        assert ok is True

    def test_no_baseline_needed_for_first_promotion(self):
        ok, _ = should_promote(report(accepted=0.93, missed=1), baseline=None)
        assert ok is True


class TestRegressionGuard:
    def test_more_missed_threats_is_rejected(self):
        """Kaçan THREAT müşteriyi açıkta bırakır — artışı kabul edilmez."""
        ok, reason = should_promote(
            report(accepted=0.95, missed=4),
            baseline=report(accepted=0.93, missed=1),
        )
        assert ok is False
        assert "kaçan THREAT" in reason

    def test_fewer_missed_threats_is_accepted(self):
        """Küçük isabet düşüşü, daha az kaçan tehdit karşılığında kabul edilir."""
        ok, _ = should_promote(
            report(accepted=0.92, missed=1),
            baseline=report(accepted=0.93, missed=4),
        )
        assert ok is True

    def test_equal_missed_threats_is_accepted(self):
        ok, _ = should_promote(
            report(accepted=0.93, missed=2),
            baseline=report(accepted=0.93, missed=2),
        )
        assert ok is True

    def test_higher_accuracy_does_not_excuse_more_misses(self):
        """Toplam isabet artsa bile kaçırılan tehdit takası kabul edilmez."""
        ok, _ = should_promote(
            report(accepted=0.99, exact=0.99, missed=5),
            baseline=report(accepted=0.80, exact=0.70, missed=2),
        )
        assert ok is False


class TestAccuracyRegression:
    def test_drop_beyond_tolerance_is_rejected(self):
        ok, reason = should_promote(
            report(accepted=0.80, missed=1),
            baseline=report(accepted=0.93, missed=1),
        )
        assert ok is False
        assert "geriledi" in reason

    def test_drop_within_tolerance_is_accepted(self):
        ok, _ = should_promote(
            report(accepted=0.93 - ACCURACY_TOLERANCE, missed=1),
            baseline=report(accepted=0.93, missed=1),
        )
        assert ok is True

    def test_improvement_is_accepted(self):
        ok, _ = should_promote(
            report(accepted=0.96, missed=0),
            baseline=report(accepted=0.93, missed=2),
        )
        assert ok is True


class TestMissingFields:
    def test_empty_report_is_rejected(self):
        ok, _ = should_promote({})
        assert ok is False
