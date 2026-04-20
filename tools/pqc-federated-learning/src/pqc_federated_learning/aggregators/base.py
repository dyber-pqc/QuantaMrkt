"""Aggregator strategy interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pqc_federated_learning.update import ClientUpdate, GradientTensor


class Aggregator(ABC):
    name: str = ""

    @abstractmethod
    def aggregate(self, updates: list[ClientUpdate]) -> list[GradientTensor]:
        """Produce a single aggregated tensor list from many client updates.

        Implementations MUST raise ShapeMismatchError if tensors across updates
        have inconsistent shapes or names.
        """
