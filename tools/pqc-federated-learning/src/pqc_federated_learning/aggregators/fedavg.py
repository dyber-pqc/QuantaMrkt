"""FedAvg: num_samples-weighted mean of client gradient tensors."""

from __future__ import annotations

from pqc_federated_learning.aggregators.base import Aggregator
from pqc_federated_learning.errors import InsufficientUpdatesError, ShapeMismatchError
from pqc_federated_learning.update import ClientUpdate, GradientTensor


class FedAvgAggregator(Aggregator):
    name = "fedavg"

    def aggregate(self, updates: list[ClientUpdate]) -> list[GradientTensor]:
        if not updates:
            raise InsufficientUpdatesError("FedAvg requires at least one update")

        # Build tensor-name -> list of (weight, values, shape)
        tensor_names = [t.name for t in updates[0].tensors]
        shapes = {t.name: t.shape for t in updates[0].tensors}
        for u in updates[1:]:
            if [t.name for t in u.tensors] != tensor_names:
                raise ShapeMismatchError(
                    f"client {u.metadata.client_did} has different tensor names"
                )
            for t in u.tensors:
                if t.shape != shapes[t.name]:
                    raise ShapeMismatchError(
                        f"tensor {t.name} shape mismatch: {t.shape} vs {shapes[t.name]}"
                    )

        total_weight = sum(max(1, u.metadata.num_samples) for u in updates)
        out: list[GradientTensor] = []
        for tname in tensor_names:
            shape = shapes[tname]
            length = 1
            for d in shape:
                length *= d
            agg = [0.0] * length
            for u in updates:
                weight = max(1, u.metadata.num_samples) / total_weight
                tensor = next(t for t in u.tensors if t.name == tname)
                for i, v in enumerate(tensor.values):
                    agg[i] += weight * v
            out.append(GradientTensor(name=tname, shape=shape, values=tuple(agg)))
        return out
