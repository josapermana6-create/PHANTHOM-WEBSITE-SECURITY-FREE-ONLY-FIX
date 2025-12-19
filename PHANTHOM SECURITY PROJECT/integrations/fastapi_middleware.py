"""
FastAPI Middleware Integration for Phantom WAF
Async-compatible middleware for FastAPI applications
"""
from phantom_waf import PhantomWAF, WAFAction
import time
import json
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class FastAPIWAFMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for Phantom WAF with async support"""
    
    def __init__(self, app, config_path='config.yaml'):
        """
        Initialize FastAPI WAF middleware
        
        Args:
            app: FastAPI application instance
            config_path: Path to WAF configuration file
        """
        super().__init__(app)
        self.waf = PhantomWAF(config_path)
    
    async def dispatch(self, request: Request, call_next):
        """Process request through WAF"""
        # Build request data for WAF
        request_data = {
            'method': request.method,
            'path': request.url.path,
            'headers': dict(request.headers),
            'params': dict(request.query_params),
            'body': await self._get_body(request),
            'ip': self._get_client_ip(request)
        }
        
        # Analyze with WAF (synchronous operation)
        result = self.waf.analyze_request(request_data)
        
        # Take action based on result
        if result.action == WAFAction.BLOCK:
            return self._block_response(result)
        elif result.action == WAFAction.CHALLENGE:
            return self._challenge_response(result)
        
        # Allow request to proceed
        response = await call_next(request)
        return response
    
    async def _get_body(self, request: Request):
        """Get request body"""
        try:
            content_type = request.headers.get('content-type', '')
            
            if 'application/json' in content_type:
                return await request.json()
            elif 'application/x-www-form-urlencoded' in content_type:
                form = await request.form()
                return dict(form)
            else:
                body = await request.body()
                return body.decode('utf-8') if body else ''
        except:
            return {}
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check X-Forwarded-For header
        forwarded = request.headers.get('x-forwarded-for')
        if forwarded:
            return forwarded.split(',')[0].strip()
        
        # Check X-Real-IP
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Client host
        if request.client:
            return request.client.host
        
        return 'unknown'
    
    def _block_response(self, result) -> JSONResponse:
        """Return blocked response"""
        response_data = {
            'error': 'Request blocked by WAF',
            'threat_score': result.threat_score,
            'blocked_by': result.blocked_by,
            'request_id': str(time.time())
        }
        
        return JSONResponse(
            status_code=403,
            content=response_data
        )
    
    def _challenge_response(self, result) -> JSONResponse:
        """Return challenge response"""
        response_data = {
            'error': 'Request requires verification',
            'threat_score': result.threat_score,
            'message': 'Please complete verification to proceed'
        }
        
        return JSONResponse(
            status_code=429,
            content=response_data
        )


# WAF management routes for FastAPI
from fastapi import APIRouter

def create_waf_router(waf: PhantomWAF) -> APIRouter:
    """Create WAF management router"""
    router = APIRouter(prefix="/_waf", tags=["WAF"])
    
    @router.get("/stats")
    async def get_stats():
        """Get WAF statistics"""
        return waf.get_stats()
    
    @router.get("/modules")
    async def get_modules():
        """Get WAF modules information"""
        return waf.get_module_info()
    
    @router.get("/ip/{ip_address}")
    async def get_ip_status(ip_address: str):
        """Get IP status"""
        return waf.get_ip_status(ip_address)
    
    @router.post("/whitelist/{ip_address}")
    async def whitelist_ip(ip_address: str):
        """Add IP to whitelist"""
        waf.whitelist_ip(ip_address)
        return {
            'status': 'success',
            'ip': ip_address,
            'action': 'whitelisted'
        }
    
    @router.post("/blacklist/{ip_address}")
    async def blacklist_ip(ip_address: str):
        """Add IP to blacklist"""
        waf.blacklist_ip(ip_address)
        return {
            'status': 'success',
            'ip': ip_address,
            'action': 'blacklisted'
        }
    
    return router


# Example usage
"""
from fastapi import FastAPI
from integrations.fastapi_middleware import FastAPIWAFMiddleware, create_waf_router

# Create app
app = FastAPI()

# Initialize WAF middleware
waf_middleware = FastAPIWAFMiddleware(app, config_path='config.yaml')
app.add_middleware(FastAPIWAFMiddleware, config_path='config.yaml')

# Add WAF management routes
waf_router = create_waf_router(waf_middleware.waf)
app.include_router(waf_router)

# Your routes
@app.get("/")
async def read_root():
    return {"message": "Protected by Phantom WAF"}

@app.post("/api/data")
async def create_data(data: dict):
    # All routes automatically protected
    return {"status": "success", "data": data}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
"""
