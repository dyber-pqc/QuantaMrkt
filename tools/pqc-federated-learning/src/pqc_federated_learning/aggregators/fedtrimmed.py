"""FedTrimmedMean: drops top/bottom fraction of values per element before averaging."""

from __future__ import annotations

from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.errors import InsufficientUpdatesError, ShapeMismatchError
from pqc_federated_learning.update import ClientUpdate, GradientTensor


class FedTrimmedMeanAggregator(Aggregator):
    name = "fedtrimmedmean"

    def __init__(self, trim_ratio: float = 0.1):
        if not 0.0 <= trim_ratio < 0.5:
            raise ValueError("trim_ratio must be in [0, 0.5)")
        self.trim_ratio = trim_ratio

    def aggregate(self, updates: list[ClientUpdate]) -> list[GradientTensor]:
        if not updates:
            raise InsufficientUpdatesError("FedTrimmedMean requires at least one update")

        n = len(updates)
        trim = int(n * self.trim_ratio)

        names = [t.name for t in updates[0].tensors]
        shapes = {t.name: t.shape for t in updates[0].tensors}
        for u in updates[1:]:
            if [t.name for t in u.tensors] != names:
                raise ShapeMismatchError("tensor name mismatch across updates")

        out: list[GradientTensor] = []
        for name in names:
            shape = shapes[name]
            length = 1
            for d in shape:
                length *= d
            agg: list[float] = []
            for i in range(length):
                vals = []
                for u in updates:
                    tensor = next(t for t in u.tensors if t.name == name)
                    vals.append(tensor.values[i])
                vals.sort()
                kept = vals[trim : n - trim] if (n - 2 * trim) > 0 else vals
                agg.append(sum(kept) / len(kept))
            out.append(GradientTensor(name=name, shape=shape, values=tuple(agg)))
        return out
