"""FedMedian: element-wise median of client tensors. Robust to outliers."""

from __future__ import annotations

import statistics

from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.errors import InsufficientUpdatesError, ShapeMismatchError
from pqc_federated_learning.update import ClientUpdate, GradientTensor


class FedMedianAggregator(Aggregator):
    name = "fedmedian"

    def aggregate(self, updates: list[ClientUpdate]) -> list[GradientTensor]:
        if not updates:
            raise InsufficientUpdatesError("FedMedian requires at least one update")

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
                agg.append(statistics.median(vals))
            out.append(GradientTensor(name=name, shape=shape, values=tuple(agg)))
        return out
