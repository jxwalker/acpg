"""Webhook notifications for ACPG events."""
import os
import json
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from enum import Enum
import httpx



class WebhookEvent(str, Enum):
    """Types of webhook events."""
    ANALYSIS_COMPLETE = "analysis.complete"
    ANALYSIS_FAILED = "analysis.failed"
    ENFORCEMENT_COMPLETE = "enforcement.complete"
    ENFORCEMENT_FAILED = "enforcement.failed"
    PROOF_GENERATED = "proof.generated"
    VIOLATION_DETECTED = "violation.detected"
    COMPLIANCE_ACHIEVED = "compliance.achieved"


class WebhookPayload:
    """Webhook payload builder."""
    
    def __init__(
        self,
        event: WebhookEvent,
        data: Dict[str, Any],
        artifact_hash: Optional[str] = None
    ):
        self.event = event
        self.data = data
        self.artifact_hash = artifact_hash
        self.timestamp = datetime.now(tz=timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event.value,
            "timestamp": self.timestamp,
            "artifact_hash": self.artifact_hash,
            "data": self.data,
            "source": "acpg",
            "version": "1.0"
        }


class WebhookManager:
    """
    Manages webhook subscriptions and deliveries.
    
    Webhooks can be configured via:
    1. Environment variables (ACPG_WEBHOOK_URL)
    2. Database (for multi-tenant setups)
    3. API registration
    """
    
    def __init__(self):
        self.endpoints: List[Dict[str, Any]] = []
        self._load_from_env()
    
    def _load_from_env(self):
        """Load webhook endpoints from environment."""
        webhook_url = os.environ.get("ACPG_WEBHOOK_URL")
        if webhook_url:
            self.endpoints.append({
                "url": webhook_url,
                "secret": os.environ.get("ACPG_WEBHOOK_SECRET"),
                "events": ["*"],  # All events
                "active": True
            })
        
        # Support multiple webhooks via ACPG_WEBHOOK_URL_1, etc.
        for i in range(1, 10):
            url = os.environ.get(f"ACPG_WEBHOOK_URL_{i}")
            if url:
                self.endpoints.append({
                    "url": url,
                    "secret": os.environ.get(f"ACPG_WEBHOOK_SECRET_{i}"),
                    "events": os.environ.get(f"ACPG_WEBHOOK_EVENTS_{i}", "*").split(","),
                    "active": True
                })
    
    def register_endpoint(
        self,
        url: str,
        events: List[str] = None,
        secret: Optional[str] = None
    ):
        """Register a new webhook endpoint."""
        self.endpoints.append({
            "url": url,
            "secret": secret,
            "events": events or ["*"],
            "active": True
        })
    
    def _should_deliver(self, endpoint: Dict, event: WebhookEvent) -> bool:
        """Check if event should be delivered to endpoint."""
        if not endpoint.get("active", True):
            return False
        
        events = endpoint.get("events", ["*"])
        if "*" in events:
            return True
        
        return event.value in events
    
    def _sign_payload(self, payload: str, secret: Optional[str]) -> Optional[str]:
        """Create HMAC signature for payload."""
        if not secret:
            return None
        
        import hmac
        import hashlib
        
        signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"sha256={signature}"
    
    async def deliver(self, payload: WebhookPayload):
        """Deliver webhook to all registered endpoints."""
        if not self.endpoints:
            return
        
        payload_dict = payload.to_dict()
        payload_json = json.dumps(payload_dict)
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            tasks = []
            
            for endpoint in self.endpoints:
                if self._should_deliver(endpoint, payload.event):
                    tasks.append(
                        self._deliver_to_endpoint(
                            client, 
                            endpoint, 
                            payload_json,
                            payload_dict
                        )
                    )
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _deliver_to_endpoint(
        self,
        client: httpx.AsyncClient,
        endpoint: Dict,
        payload_json: str,
        payload_dict: Dict
    ):
        """Deliver to a single endpoint."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ACPG-Webhook/1.0",
            "X-ACPG-Event": payload_dict["event"],
            "X-ACPG-Timestamp": payload_dict["timestamp"]
        }
        
        # Add signature if secret is configured
        signature = self._sign_payload(payload_json, endpoint.get("secret"))
        if signature:
            headers["X-ACPG-Signature"] = signature
        
        try:
            response = await client.post(
                endpoint["url"],
                content=payload_json,
                headers=headers
            )
            
            if response.status_code >= 400:
                print(f"Webhook delivery failed: {endpoint['url']} - {response.status_code}")
        
        except Exception as e:
            print(f"Webhook delivery error: {endpoint['url']} - {e}")


# Global webhook manager
_webhook_manager: Optional[WebhookManager] = None


def get_webhook_manager() -> WebhookManager:
    """Get or create the global webhook manager."""
    global _webhook_manager
    if _webhook_manager is None:
        _webhook_manager = WebhookManager()
    return _webhook_manager


# Convenience functions for sending webhooks
async def notify_analysis_complete(
    artifact_hash: str,
    compliant: bool,
    violation_count: int,
    violations: List[Dict]
):
    """Send notification when analysis completes."""
    manager = get_webhook_manager()
    
    event = WebhookEvent.COMPLIANCE_ACHIEVED if compliant else WebhookEvent.VIOLATION_DETECTED
    
    await manager.deliver(WebhookPayload(
        event=event,
        artifact_hash=artifact_hash,
        data={
            "compliant": compliant,
            "violation_count": violation_count,
            "violations": violations[:10]  # Limit to first 10
        }
    ))


async def notify_enforcement_complete(
    artifact_hash: str,
    compliant: bool,
    iterations: int,
    violations_fixed: List[str]
):
    """Send notification when enforcement completes."""
    manager = get_webhook_manager()
    
    event = WebhookEvent.ENFORCEMENT_COMPLETE if compliant else WebhookEvent.ENFORCEMENT_FAILED
    
    await manager.deliver(WebhookPayload(
        event=event,
        artifact_hash=artifact_hash,
        data={
            "compliant": compliant,
            "iterations": iterations,
            "violations_fixed": violations_fixed
        }
    ))


async def notify_proof_generated(
    artifact_hash: str,
    decision: str,
    signature_fingerprint: str
):
    """Send notification when proof is generated."""
    manager = get_webhook_manager()
    
    await manager.deliver(WebhookPayload(
        event=WebhookEvent.PROOF_GENERATED,
        artifact_hash=artifact_hash,
        data={
            "decision": decision,
            "signature_fingerprint": signature_fingerprint
        }
    ))

