#!/usr/bin/env python3
"""
SchemaPin .well-known Server

Production-ready HTTP server for serving .well-known/schemapin.json endpoints
with support for multiple developers, key management, and revocation lists.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent directory to path to import schemapin
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from schemapin.utils import create_well_known_response


# Pydantic models
class DeveloperInfo(BaseModel):
    name: str
    contact: str
    enabled: bool = True


class KeyInfo(BaseModel):
    public_key_pem: str
    fingerprint: str
    created_at: datetime
    revoked: bool = False
    revoked_at: Optional[datetime] = None


class RevocationRequest(BaseModel):
    fingerprint: str
    reason: Optional[str] = None


class KeyUploadRequest(BaseModel):
    public_key_pem: str
    developer_name: str
    contact: str


class ServerConfig:
    """Server configuration management."""
    
    def __init__(self, config_file: Path):
        self.config_file = config_file
        self.config = self.load_config()
        self.setup_logging()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        
        with open(self.config_file, 'r') as f:
            return json.load(f)
    
    def setup_logging(self):
        """Set up logging configuration."""
        log_config = self.config.get("logging", {})
        
        # Create logs directory
        log_file = Path(log_config.get("file", "./logs/server.log"))
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_config.get("level", "INFO")),
            format=log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )


class ServerKeyManager:
    """Manages developer keys and revocation lists."""
    
    def __init__(self, keys_directory: Path):
        self.keys_dir = keys_directory
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def get_developer_key_file(self, domain: str) -> Path:
        """Get the key file path for a developer domain."""
        return self.keys_dir / f"{domain}.json"
    
    def load_developer_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Load developer data from file."""
        key_file = self.get_developer_key_file(domain)
        
        if not key_file.exists():
            return None
        
        try:
            with open(key_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading developer data for {domain}: {e}")
            return None
    
    def save_developer_data(self, domain: str, data: Dict[str, Any]) -> bool:
        """Save developer data to file."""
        key_file = self.get_developer_key_file(domain)
        
        try:
            with open(key_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            self.logger.error(f"Error saving developer data for {domain}: {e}")
            return False
    
    def create_developer(self, domain: str, public_key_pem: str, 
                        developer_name: str, contact: str) -> bool:
        """Create a new developer entry."""
        try:
            # Validate public key
            from schemapin.crypto import KeyManager as SchemaPinKeyManager
            public_key = SchemaPinKeyManager.load_public_key_pem(public_key_pem)
            fingerprint = SchemaPinKeyManager.calculate_key_fingerprint(public_key)
            
            data = {
                "domain": domain,
                "developer_name": developer_name,
                "contact": contact,
                "schema_version": "1.1",
                "current_key": {
                    "public_key_pem": public_key_pem,
                    "fingerprint": fingerprint,
                    "created_at": datetime.utcnow().isoformat(),
                    "revoked": False
                },
                "revoked_keys": [],
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            return self.save_developer_data(domain, data)
        
        except Exception as e:
            self.logger.error(f"Error creating developer {domain}: {e}")
            return False
    
    def revoke_key(self, domain: str, fingerprint: str, reason: Optional[str] = None) -> bool:
        """Revoke a key for a developer."""
        data = self.load_developer_data(domain)
        if not data:
            return False
        
        try:
            # Check if it's the current key
            if data["current_key"]["fingerprint"] == fingerprint:
                data["current_key"]["revoked"] = True
                data["current_key"]["revoked_at"] = datetime.utcnow().isoformat()
                if reason:
                    data["current_key"]["revocation_reason"] = reason
            
            # Add to revoked keys list if not already there
            if fingerprint not in data["revoked_keys"]:
                data["revoked_keys"].append(fingerprint)
            
            data["updated_at"] = datetime.utcnow().isoformat()
            
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
            schema_version=data["schema_version"]
        )


# Global instances
config = ServerConfig(Path(__file__).parent / "config.json")
key_manager = ServerKeyManager(Path(config.config["storage"]["keys_directory"]))

# FastAPI app
app = FastAPI(
    title="SchemaPin .well-known Server",
    description="Production server for SchemaPin key discovery and management",
    version="1.1.5",
    debug=config.config["server"]["debug"]
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.config["cors"]["allow_origins"],
    allow_credentials=config.config["cors"]["allow_credentials"],
    allow_methods=config.config["cors"]["allow_methods"],
    allow_headers=config.config["cors"]["allow_headers"],
)

# Logging
logger = logging.getLogger(__name__)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests."""
    start_time = datetime.utcnow()
    
    response = await call_next(request)
    
    duration = (datetime.utcnow() - start_time).total_seconds()
    
    logger.info(
        f"{request.client.host} - {request.method} {request.url.path} - "
        f"{response.status_code} - {duration:.3f}s"
    )
    
    return response


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.1.5"
    }


@app.get("/.well-known/schemapin/{domain}.json")
async def get_well_known(domain: str):
    """Get .well-known/schemapin.json for a specific developer domain."""
    logger.info(f"Serving .well-known for domain: {domain}")
    
    # Check if domain is configured
    if domain not in config.config.get("developers", {}):
        logger.warning(f"Domain not configured: {domain}")
        raise HTTPException(status_code=404, detail="Developer domain not found")
    
    # Check if domain is enabled
    dev_config = config.config["developers"][domain]
    if not dev_config.get("enabled", True):
        logger.warning(f"Domain disabled: {domain}")
        raise HTTPException(status_code=404, detail="Developer domain not available")
    
    # Get well-known response
    well_known = key_manager.get_well_known_response(domain)
    if not well_known:
        logger.warning(f"No valid key found for domain: {domain}")
        raise HTTPException(status_code=404, detail="No valid key found for domain")
    
    return JSONResponse(
        content=well_known,
        headers={
            "Cache-Control": "public, max-age=3600",
            "Content-Type": "application/json"
        }
    )


@app.get("/.well-known/schemapin.json")
async def get_default_well_known():
    """Get default .well-known/schemapin.json (first configured developer)."""
    developers = config.config.get("developers", {})
    
    if not developers:
        raise HTTPException(status_code=404, detail="No developers configured")
    
    # Use first enabled developer
    for domain, dev_config in developers.items():
        if dev_config.get("enabled", True):
            return await get_well_known(domain)
    
    raise HTTPException(status_code=404, detail="No enabled developers found")


@app.get("/api/developers")
async def list_developers():
    """List all configured developers."""
    developers = []
    
    for domain, dev_config in config.config.get("developers", {}).items():
        dev_data = key_manager.load_developer_data(domain)
        
        developers.append({
            "domain": domain,
            "name": dev_config["name"],
            "contact": dev_config["contact"],
            "enabled": dev_config.get("enabled", True),
            "has_key": dev_data is not None,
            "key_revoked": dev_data["current_key"]["revoked"] if dev_data else None
        })
    
    return {"developers": developers}


@app.get("/api/developers/{domain}")
async def get_developer_info(domain: str):
    """Get detailed information about a developer."""
    if domain not in config.config.get("developers", {}):
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
            "revoked": dev_data["current_key"]["revoked"]
        },
        "revoked_keys": dev_data["revoked_keys"],
        "created_at": dev_data["created_at"],
        "updated_at": dev_data["updated_at"]
    }


@app.post("/api/developers/{domain}/keys")
async def upload_key(domain: str, request: KeyUploadRequest):
    """Upload a new public key for a developer."""
    if domain not in config.config.get("developers", {}):
        raise HTTPException(status_code=404, detail="Developer domain not found")
    
    success = key_manager.create_developer(
        domain=domain,
        public_key_pem=request.public_key_pem,
        developer_name=request.developer_name,
        contact=request.contact
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to upload key")
    
    logger.info(f"Key uploaded for domain: {domain}")
    
    return {"message": "Key uploaded successfully"}


@app.post("/api/developers/{domain}/revoke")
async def revoke_key(domain: str, request: RevocationRequest):
    """Revoke a key for a developer."""
    if domain not in config.config.get("developers", {}):
        raise HTTPException(status_code=404, detail="Developer domain not found")
    
    success = key_manager.revoke_key(
        domain=domain,
        fingerprint=request.fingerprint,
        reason=request.reason
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to revoke key")
    
    logger.info(f"Key revoked for domain {domain}: {request.fingerprint}")
    
    return {"message": "Key revoked successfully"}


@app.get("/api/metrics")
async def get_metrics():
    """Get server metrics."""
    developers = config.config.get("developers", {})
    
    total_developers = len(developers)
    enabled_developers = len([d for d in developers.values() if d.get("enabled", True)])
    
    developers_with_keys = 0
    total_revoked_keys = 0
    
    for domain in developers.keys():
        dev_data = key_manager.load_developer_data(domain)
        if dev_data:
            developers_with_keys += 1
            total_revoked_keys += len(dev_data.get("revoked_keys", []))
    
    return {
        "total_developers": total_developers,
        "enabled_developers": enabled_developers,
        "developers_with_keys": developers_with_keys,
        "total_revoked_keys": total_revoked_keys,
        "server_uptime": "N/A",  # Would need to track start time
        "timestamp": datetime.utcnow().isoformat()
    }


def setup_demo_data():
    """Set up demo data if keys directory is empty."""
    if not any(key_manager.keys_dir.glob("*.json")):
        logger.info("Setting up demo data...")
        
        # Import demo keys from integration demo
        demo_keys_dir = Path(__file__).parent.parent / "integration_demo" / "test_data" / "keys"
        
        if demo_keys_dir.exists():
            for domain in ["alice.example.com", "bob.example.com", "charlie.example.com"]:
                public_key_file = demo_keys_dir / f"{domain}_public.pem"
                
                if public_key_file.exists():
                    public_key_pem = public_key_file.read_text()
                    dev_config = config.config["developers"].get(domain, {})
                    
                    key_manager.create_developer(
                        domain=domain,
                        public_key_pem=public_key_pem,
                        developer_name=dev_config.get("name", domain),
                        contact=dev_config.get("contact", f"security@{domain}")
                    )
                    
                    logger.info(f"Created demo data for {domain}")


def main():
    """Main entry point."""
    # Set up demo data if needed
    setup_demo_data()
    
    # Start server
    server_config = config.config["server"]
    
    logger.info(f"Starting SchemaPin .well-known server on {server_config['host']}:{server_config['port']}")
    
    uvicorn.run(
        "well_known_server:app",
        host=server_config["host"],
        port=server_config["port"],
        reload=server_config.get("reload", False),
        log_level=config.config["logging"]["level"].lower()
    )


if __name__ == "__main__":
    main()