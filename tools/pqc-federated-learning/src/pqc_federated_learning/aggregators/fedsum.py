"""FedSum: unweighted elementwise sum of client tensors."""

from __future__ import annotations

from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.errors import InsufficientUpdatesError, ShapeMismatchError
from pqc_federated_learning.update import ClientUpdate, GradientTensor


class FedSumAggregator(Aggregator):
    name = "fedsum"

    def aggregate(self, updates: list[ClientUpdate]) -> list[GradientTensor]:
        if not updates:
            raise InsufficientUpdatesError("FedSum requires at least one update")

        names = [t.name for t in updates[0].tensors]
        shapes = {t.name: t.shape for t in updates[0].tensors}
        for u in updates[1:]:
            if [t.name for t in u.tensors] != names:
                raise ShapeMismatchError("tensor name mismatch across updates")
            for t in u.tensors:
                if t.shape != shapes[t.name]:
                    raise ShapeMismatchError(
                        f"{t.name} shape mismatch: {t.shape} vs {shapes[t.name]}"
                    )

        out: list[GradientTensor] = []
        for name in names:
            shape = shapes[name]
            length = 1
            for d in shape:
                length *= d
            agg = [0.0] * length
            for u in updates:
                tensor = next(t for t in u.tensors if t.name == name)
                for i, v in enumerate(tensor.values):
                    agg[i] += v
            out.append(GradientTensor(name=name, shape=shape, values=tuple(agg)))
        return out
