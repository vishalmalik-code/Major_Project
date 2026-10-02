"""all-MiniLM-L6-v2 -> 384-dim vectors, loaded once at startup, CPU, local.

Small and fast enough to embed every query inline on the request path, which is
what lets semantic_similarity run per query without a batch job.
"""

import numpy as np

from app.core.config import settings


class Encoder:
    _instance: "Encoder | None" = None

    def __init__(self) -> None:
        self.model_name = settings.embedding_model
        self.dim = settings.embedding_dim
        self._model = None

    @classmethod
    def instance(cls) -> "Encoder":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load(self) -> None:
        """Called from the FastAPI lifespan hook so the first user request does
        not pay the model-load cost."""
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self.model_name, device="cpu")

    def encode(self, text: str) -> np.ndarray:
        """L2-normalized 384-dim vector, so cosine similarity is a dot product."""
        if self._model is None:
            self.load()
        vec = self._model.encode(text, normalize_embeddings=True,
                                 convert_to_numpy=True)
        return vec.astype(np.float32)
