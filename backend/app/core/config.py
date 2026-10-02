"""Every tunable in one place. Thresholds and weights are configurable by design:
the admin dashboard can read and tune them live via /api/admin/config."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # service
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    cors_origins: str = "http://localhost:5173"

    # database
    database_url: str = (
        "postgresql+psycopg:///llm_firewall?host=/var/run/postgresql"
    )

    # ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b-instruct-q4_K_M"
    ollama_timeout_seconds: int = 120

    # embeddings
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dim: int = 384

    # admin
    admin_token: str = "change-me-local-only"

    # the ONE admin account, created by scripts/seed_admin.py -- never
    # hardcoded in frontend source, only read here from .env
    admin_seed_username: str = "admin"
    admin_seed_password: str = "ChangeMe123!"

    # --- query window -------------------------------------------------------
    # QUERY-BASED, never time-based. Eviction happens only when a new query
    # arrives. Set both to 10 for the literal "last 10 queries" behaviour.
    query_window_size: int = 20   # full analysis window
    tight_window_size: int = 10   # recency slice for repetition / burst

    # --- risk bands ---------------------------------------------------------
    risk_threshold_medium: float = 30.0
    risk_threshold_high: float = 55.0
    risk_threshold_critical: float = 80.0
    throttle_delay_seconds: float = 5.0

    # --- risk update --------------------------------------------------------
    # risk moves ONLY on query arrival. There is no time term anywhere.
    suspicion_threshold: float = 0.35   # weighted >= this  -> escalate
    benign_threshold: float = 0.15      # weighted <= this  -> small relief
    gain_scale: float = 18.0            # escalation scale
    decay_step: float = 4.0             # relief per dissimilar query

    # --- signal weights -----------------------------------------------------
    # Heaviest on the structural signals (4-7): they are what distinguishes an
    # extraction campaign from a curious human, and they keep working when the
    # attacker slows down.
    weight_exact_repetition: float = 1.0
    weight_text_similarity: float = 0.8
    weight_semantic_similarity: float = 0.9
    weight_systematic_modification: float = 1.2
    weight_value_progression: float = 1.2
    weight_constraint_progression: float = 1.1
    weight_boundary_progression: float = 1.1
    weight_burst_rate: float = 0.5      # capped: slow attacks must still be caught

    # --- attack pacing ------------------------------------------------------
    fast_delay_max: float = 0.05
    slow_delay_min: float = 20.0
    slow_delay_max: float = 120.0

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
