#!/usr/bin/env python3
"""
SchemaPin .well-known Server

Reference HTTP server for serving ``.well-known/schemapin.json`` endpoints for
one or more developer domains, with authenticated key management and
revocation lists.

Security model
--------------

* Every mutation under ``/api/`` requires a bearer token
  (``security.admin_token`` in the config or the ``SCHEMAPIN_ADMIN_TOKEN``
  environment variable) and ``features.admin_api`` must be enabled;
  otherwise the mutation routes do not exist.
* Key upload merges into the existing record: a previously published key is
  moved to ``revoked_keys`` on rotation and the revocation list is never
  wiped by an upload.
* CORS credentials are never combined with a wildcard origin.
* A per-client rate limit (``security.rate_limit.requests_per_minute``) is
  enforced on every request.
* ``/.well-known/schemapin.json`` resolves the developer from the request
  ``Host`` header (RFC 8615 layout). There is no "first developer" fallback:
  an unknown host is a 404, so a client resolving ``bob.example.com`` can
  never be handed Alice's key. ``/.well-known/schemapin/{domain}.json`` is a
  non-standard multi-tenant path for deployments that rewrite per host.
* The server binds to ``127.0.0.1`` with debug and reload off unless the
  configuration says otherwise.
"""

import json
import logging
import os
import secrets
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent directory to path to import schemapin
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from schemapin.crypto import KeyManager as SchemaPinKeyManager  # noqa: E402
from schemapin.domain import InvalidDomainError, validate_domain  # noqa: E402
from schemapin.utils import create_well_known_response  # noqa: E402

SERVER_VERSION = "1.4.0"
ADMIN_TOKEN_ENV = "SCHEMAPIN_ADMIN_TOKEN"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# Pydantic models
class DeveloperInfo(BaseModel):
    name: str
    contact: str
    enabled: bool = True


class RevocationRequest(BaseModel):
    fingerprint: str
    reason: Optional[str] = None


class KeyUploadRequest(BaseModel):
    public_key_pem: str
    developer_name: str
    contact: str


class ServerConfig:
    """Server configuration management with safe defaults."""

    DEFAULTS: Dict[str, Any] = {
        "server": {"host": "127.0.0.1", "port": 8000, "debug": False, "reload": False},
        "cors": {
            "allow_origins": [],
            "allow_credentials": False,
            "allow_methods": ["GET", "OPTIONS"],
            "allow_headers": ["*"],
        },
        "security": {"rate_limit": {"requests_per_minute": 60}, "admin_token": None},
        "storage": {"keys_directory": "./keys"},
        "logging": {"level": "INFO", "file": "./logs/server.log"},
        "developers": {},
        "features": {"admin_api": False},
    }

    def __init__(self, config_file: Path, setup_logging: bool = True):
        self.config_file = config_file
        self.config = self.load_config()
        if setup_logging:
            self.setup_logging()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file, layering it over the safe defaults."""
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        with open(self.config_file, "r") as f:
            loaded = json.load(f)

        config: Dict[str, Any] = json.loads(json.dumps(self.DEFAULTS))
        for section, values in loaded.items():
            if isinstance(values, dict) and isinstance(config.get(section), dict):
                config[section].update(values)
            else:
                config[section] = values

        token = os.environ.get(ADMIN_TOKEN_ENV)
        if token:
            config["security"]["admin_token"] = token
        return config

    @property
    def admin_token(self) -> Optional[str]:
        return self.config["security"].get("admin_token") or None

    @property
    def admin_api_enabled(self) -> bool:
        return bool(self.config["features"].get("admin_api", False))

    def setup_logging(self) -> None:
        """Set up logging configuration."""
        log_config = self.config.get("logging", {})
        log_file = Path(log_config.get("file", "./logs/server.log"))
        log_file.parent.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=getattr(logging, log_config.get("level", "INFO")),
            format=log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
        )


class ServerKeyManager:
    """Manages developer keys and revocation lists."""

    def __init__(self, keys_directory: Path):
        self.keys_dir = keys_directory
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def get_developer_key_file(self, domain: str) -> Path:
        """Get the key file path for a (validated) developer domain."""
        return self.keys_dir / f"{validate_domain(domain)}.json"

    def load_developer_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Load developer data from file."""
        try:
            key_file = self.get_developer_key_file(domain)
        except InvalidDomainError:
            return None
        if not key_file.exists():
            return None
        try:
            with open(key_file, "r") as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading developer data for {domain}: {e}")
            return None

    def save_developer_data(self, domain: str, data: Dict[str, Any]) -> bool:
        """Save developer data to file."""
        try:
            key_file = self.get_developer_key_file(domain)
            with open(key_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            self.logger.error(f"Error saving developer data for {domain}: {e}")
            return False

    def create_developer(
        self, domain: str, public_key_pem: str, developer_name: str, contact: str
    ) -> bool:
        """Create or rotate a developer's key.

        Uploading over an existing record *merges*: the previous current key
        (if different) is moved to ``revoked_keys`` and existing revocations
        are preserved, so a rotation can never un-revoke a compromised key.
        """
        try:
            public_key = SchemaPinKeyManager.load_public_key_pem(public_key_pem)
            fingerprint = SchemaPinKeyManager.calculate_key_fingerprint(public_key)
        except Exception as e:
            self.logger.error(f"Rejected key for {domain}: {e}")
            return False

        now = _utcnow()
        existing = self.load_developer_data(domain)
        revoked_keys = list(existing.get("revoked_keys", [])) if existing else []
        if existing and existing.get("current_key"):
            old_fp = existing["current_key"].get("fingerprint")
            if old_fp and old_fp != fingerprint and old_fp not in revoked_keys:
                revoked_keys.append(old_fp)
        if fingerprint in revoked_keys:
            self.logger.error(f"Rejected previously revoked key for {domain}")
            return False

        data = {
            "domain": validate_domain(domain),
            "developer_name": developer_name,
            "contact": contact,
            "schema_version": "1.2",
            "current_key": {
                "public_key_pem": public_key_pem,
                "fingerprint": fingerprint,
                "created_at": now,
                "revoked": False,
            },
            "revoked_keys": revoked_keys,
            "created_at": existing.get("created_at", now) if existing else now,
            "updated_at": now,
        }
        return self.save_developer_data(domain, data)

    def revoke_key(self, domain: str, fingerprint: str, reason: Optional[str] = None) -> bool:
        """Revoke a key for a developer."""
        data = self.load_developer_data(domain)
        if not data:
            return False

        try:
            if data["current_key"]["fingerprint"] == fingerprint:
                data["current_key"]["revoked"] = True
                data["current_key"]["revoked_at"] = _utcnow()
                if reason:
                    data["current_key"]["revocation_reason"] = reason

            if fingerprint not in data["revoked_keys"]:
                data["revoked_keys"].append(fingerprint)

            data["updated_at"] = _utcnow()
            return self.save_developer_data(domain, data)
        except Exception as e:
            self.logger.error(f"Error revoking key {fingerprint} for {domain}: {e}")
            return False

    def get_well_known_response(self, domain: str) -> Optional[Dict[str, Any]]:
        """Generate .well-known response for a developer."""
        data = self.load_developer_data(domain)
        if not data:
            return None

        # Don't serve revoked keys
        if data["current_key"]["revoked"]:
            return None

        return create_well_known_response(
            public_key_pem=data["current_key"]["public_key_pem"],
            developer_name=data["developer_name"],
            contact=data["contact"],
            revoked_keys=data["revoked_keys"],
            schema_version=data["schema_version"],
        )


class RateLimiter:
    """Fixed-window per-client limiter (in-memory, single process)."""

    def __init__(self, requests_per_minute: int):
        self.limit = max(int(requests_per_minute), 0)
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        if self.limit == 0:
            return True
        now = time.monotonic()
        with self._lock:
            window = self._hits.setdefault(client, deque())
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= self.limit:
                return False
            window.append(now)
            return True


def _host_from_request(request: Request) -> Optional[str]:
    host = request.headers.get("host", "")
    host = host.split(":", 1)[0].strip().lower()
    try:
        return validate_domain(host)
    except InvalidDomainError:
        return None


def create_app(config: ServerConfig) -> FastAPI:
    """Build the FastAPI application for ``config``."""
    key_manager = ServerKeyManager(Path(config.config["storage"]["keys_directory"]))
    logger = logging.getLogger(__name__)
    limiter = RateLimiter(config.config["security"]["rate_limit"]["requests_per_minute"])

    app = FastAPI(
        title="SchemaPin .well-known Server",
        description="Reference server for SchemaPin key discovery and management",
        version=SERVER_VERSION,
        debug=bool(config.config["server"].get("debug", False)),
    )
    app.state.config = config
    app.state.key_manager = key_manager

    cors = config.config["cors"]
    allow_origins = list(cors.get("allow_origins", []))
    allow_credentials = bool(cors.get("allow_credentials", False))
    if "*" in allow_origins and allow_credentials:
        logger.warning("CORS: allow_credentials disabled because allow_origins contains '*'")
        allow_credentials = False
    if allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_credentials=allow_credentials,
            allow_methods=cors.get("allow_methods", ["GET", "OPTIONS"]),
            allow_headers=cors.get("allow_headers", ["*"]),
        )

    @app.middleware("http")
    async def rate_limit_and_log(request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        if not limiter.allow(client):
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        start_time = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start_time
        logger.info(
            f"{client} - {request.method} {request.url.path} - "
            f"{response.status_code} - {duration:.3f}s"
        )
        return response

    def require_admin(request: Request) -> None:
        """Bearer-token gate for every mutation."""
        if not config.admin_api_enabled:
            raise HTTPException(status_code=404, detail="Not Found")
        token = config.admin_token
        if not token:
            raise HTTPException(status_code=503, detail="Admin API has no token configured")
        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(presented.strip(), token):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def developers() -> Dict[str, Any]:
        return config.config.get("developers", {})

    def serve_well_known(domain: str) -> JSONResponse:
        if domain not in developers():
            logger.warning(f"Domain not configured: {domain}")
            raise HTTPException(status_code=404, detail="Developer domain not found")
        if not developers()[domain].get("enabled", True):
            logger.warning(f"Domain disabled: {domain}")
            raise HTTPException(status_code=404, detail="Developer domain not available")
        well_known = key_manager.get_well_known_response(domain)
        if not well_known:
            logger.warning(f"No valid key found for domain: {domain}")
            raise HTTPException(status_code=404, detail="No valid key found for domain")
        return JSONResponse(
            content=well_known,
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "timestamp": _utcnow(), "version": SERVER_VERSION}

    @app.get("/.well-known/schemapin.json")
    async def get_well_known_for_host(request: Request):
        """RFC 8615 discovery: the developer is selected by the request Host."""
        host = _host_from_request(request)
        if host is None:
            raise HTTPException(status_code=404, detail="Developer domain not found")
        return serve_well_known(host)

    @app.get("/.well-known/schemapin/{domain}.json")
    async def get_well_known(domain: str):
        """Non-standard multi-tenant path for deployments that rewrite per host."""
        try:
            domain = validate_domain(domain)
        except InvalidDomainError:
            raise HTTPException(status_code=404, detail="Developer domain not found")
        return serve_well_known(domain)

    @app.get("/api/developers")
    async def list_developers():
        """List all configured developers."""
        result = []
        for domain, dev_config in developers().items():
            dev_data = key_manager.load_developer_data(domain)
            result.append(
                {
                    "domain": domain,
                    "name": dev_config["name"],
                    "contact": dev_config["contact"],
                    "enabled": dev_config.get("enabled", True),
                    "has_key": dev_data is not None,
                    "key_revoked": dev_data["current_key"]["revoked"] if dev_data else None,
                }
            )
        return {"developers": result}

    @app.get("/api/developers/{domain}")
    async def get_developer_info(domain: str):
        """Get detailed (public) information about a developer."""
        if domain not in developers():
            raise HTTPException(status_code=404, detail="Developer domain not found")
        dev_data = key_manager.load_developer_data(domain)
        if not dev_data:
            raise HTTPException(status_code=404, detail="No key data found for developer")
        return {
            "domain": domain,
            "developer_name": dev_data["developer_name"],
            "contact": dev_data["contact"],
            "schema_version": dev_data["schema_version"],
            "current_key": {
                "fingerprint": dev_data["current_key"]["fingerprint"],
                "created_at": dev_data["current_key"]["created_at"],
                "revoked": dev_data["current_key"]["revoked"],
            },
            "revoked_keys": dev_data["revoked_keys"],
            "created_at": dev_data["created_at"],
            "updated_at": dev_data["updated_at"],
        }

    @app.post("/api/developers/{domain}/keys", dependencies=[Depends(require_admin)])
    async def upload_key(domain: str, body: KeyUploadRequest):
        """Upload (or rotate to) a new public key for a developer. Admin only."""
        if domain not in developers():
            raise HTTPException(status_code=404, detail="Developer domain not found")
        success = key_manager.create_developer(
            domain=domain,
            public_key_pem=body.public_key_pem,
            developer_name=body.developer_name,
            contact=body.contact,
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to upload key")
        logger.info(f"Key uploaded for domain: {domain}")
        return {"message": "Key uploaded successfully"}

    @app.post("/api/developers/{domain}/revoke", dependencies=[Depends(require_admin)])
    async def revoke_key(domain: str, body: RevocationRequest):
        """Revoke a key for a developer. Admin only."""
        if domain not in developers():
            raise HTTPException(status_code=404, detail="Developer domain not found")
        success = key_manager.revoke_key(domain=domain, fingerprint=body.fingerprint, reason=body.reason)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to revoke key")
        logger.info(f"Key revoked for domain {domain}: {body.fingerprint}")
        return {"message": "Key revoked successfully"}

    @app.get("/api/metrics")
    async def get_metrics():
        """Get server metrics."""
        devs = developers()
        developers_with_keys = 0
        total_revoked_keys = 0
        for domain in devs:
            dev_data = key_manager.load_developer_data(domain)
            if dev_data:
                developers_with_keys += 1
                total_revoked_keys += len(dev_data.get("revoked_keys", []))
        return {
            "total_developers": len(devs),
            "enabled_developers": len([d for d in devs.values() if d.get("enabled", True)]),
            "developers_with_keys": developers_with_keys,
            "total_revoked_keys": total_revoked_keys,
            "timestamp": _utcnow(),
        }

    return app


def setup_demo_data(config: ServerConfig, key_manager: ServerKeyManager) -> None:
    """Set up demo data if keys directory is empty."""
    logger = logging.getLogger(__name__)
    if any(key_manager.keys_dir.glob("*.json")):
        return
    demo_keys_dir = Path(__file__).parent.parent / "integration_demo" / "test_data" / "keys"
    if not demo_keys_dir.exists():
        return
    logger.info("Setting up demo data...")
    for domain, dev_config in config.config.get("developers", {}).items():
        public_key_file = demo_keys_dir / f"{domain}_public.pem"
        if public_key_file.exists():
            key_manager.create_developer(
                domain=domain,
                public_key_pem=public_key_file.read_text(),
                developer_name=dev_config.get("name", domain),
                contact=dev_config.get("contact", f"security@{domain}"),
            )
            logger.info(f"Created demo data for {domain}")


def main() -> None:
    """Main entry point."""
    import uvicorn

    config = ServerConfig(Path(__file__).parent / "config.json")
    application = create_app(config)
    setup_demo_data(config, application.state.key_manager)

    server_config = config.config["server"]
    logger = logging.getLogger(__name__)
    if config.admin_api_enabled and not config.admin_token:
        logger.warning(
            f"features.admin_api is enabled but no admin token is configured; "
            f"set security.admin_token or {ADMIN_TOKEN_ENV}"
        )
    logger.info(
        f"Starting SchemaPin .well-known server on {server_config['host']}:{server_config['port']}"
    )
    uvicorn.run(
        application,
        host=server_config["host"],
        port=int(server_config["port"]),
        log_level=config.config["logging"]["level"].lower(),
    )


if __name__ == "__main__":
    main()
