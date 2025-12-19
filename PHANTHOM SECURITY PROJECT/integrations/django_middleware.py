"""
Django Middleware Integration for Phantom WAF
"""
from phantom_waf import PhantomWAF, WAFAction
import time
import json


class DjangoWAFMiddleware:
    """Django middleware for Phantom WAF"""
    
    def __init__(self, get_response, config_path='config.yaml'):
        """
        Initialize Django WAF middleware
        
        Args:
            get_response: Django get_response callable
            config_path: Path to WAF configuration file
        """
        self.get_response = get_response
        self.waf = PhantomWAF(config_path)
    
    def __call__(self, request):
        """Process request through WAF"""
        # Build request data for WAF
        request_data = {
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
            'params': dict(request.GET),
            'body': self._get_body(request),
            'ip': self._get_client_ip(request)
        }
        
        # Analyze with WAF
        result = self.waf.analyze_request(request_data)
        
        # Take action based on result
        if result.action == WAFAction.BLOCK:
            return self._block_response(result)
        elif result.action == WAFAction.CHALLENGE:
            return self._challenge_response(result)
        
        # Allow request to proceed
        response = self.get_response(request)
        return response
    
    def _get_body(self, request):
        """Get request body"""
        try:
            if request.content_type == 'application/json':
                return json.loads(request.body)
            else:
                return dict(request.POST)
        except:
            return {}
    
    def _get_client_ip(self, request):
        """Get client IP address"""
        # Check X-Forwarded-For header
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        
        # Check X-Real-IP
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            return x_real_ip
        
        # Remote addr
        return request.META.get('REMOTE_ADDR', 'unknown')
    
    def _block_response(self, result):
        """Return blocked response"""
        from django.http import JsonResponse
        
        response_data = {
            'error': 'Request blocked by WAF',
            'threat_score': result.threat_score,
            'blocked_by': result.blocked_by,
            'request_id': str(time.time())
        }
        
        return JsonResponse(response_data, status=403)
    
    def _challenge_response(self, result):
        """Return challenge response"""
        from django.http import JsonResponse
        
        response_data = {
            'error': 'Request requires verification',
            'threat_score': result.threat_score,
            'message': 'Please complete verification to proceed'
        }
        
        return JsonResponse(response_data, status=429)


# WAF management views for Django
from django.http import JsonResponse
from django.views import View


class WAFStatsView(View):
    """Get WAF statistics"""
    waf = None  # Will be set by middleware
    
    def get(self, request):
        if not self.waf:
            return JsonResponse({'error': 'WAF not initialized'}, status=500)
        
        stats = self.waf.get_stats()
        return JsonResponse(stats)


class WAFModulesView(View):
    """Get WAF modules info"""
    waf = None
    
    def get(self, request):
        if not self.waf:
            return JsonResponse({'error': 'WAF not initialized'}, status=500)
        
        modules = self.waf.get_module_info()
        return JsonResponse(modules)


class WAFIPStatusView(View):
    """Get IP status"""
    waf = None
    
    def get(self, request, ip_address):
        if not self.waf:
            return JsonResponse({'error': 'WAF not initialized'}, status=500)
        
        status = self.waf.get_ip_status(ip_address)
        return JsonResponse(status)


class WAFWhitelistView(View):
    """Whitelist IP"""
    waf = None
    
    def post(self, request, ip_address):
        if not self.waf:
            return JsonResponse({'error': 'WAF not initialized'}, status=500)
        
        self.waf.whitelist_ip(ip_address)
        return JsonResponse({'status': 'success', 'ip': ip_address, 'action': 'whitelisted'})


class WAFBlacklistView(View):
    """Blacklist IP"""
    waf = None
    
    def post(self, request, ip_address):
        if not self.waf:
            return JsonResponse({'error': 'WAF not initialized'}, status=500)
        
        self.waf.blacklist_ip(ip_address)
        return JsonResponse({'status': 'success', 'ip': ip_address, 'action': 'blacklisted'})


# Example usage in Django settings.py:
"""
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'integrations.django_middleware.DjangoWAFMiddleware',  # Add WAF here
    'django.contrib.sessions.middleware.SessionMiddleware',
    # ... other middleware
]

# WAF Configuration (optional)
WAF_CONFIG_PATH = 'config.yaml'


# urls.py

from integrations.django_middleware import (
    WAFStatsView, WAFModulesView, WAFIPStatusView,
    WAFWhitelistView, WAFBlacklistView
)

urlpatterns = [
    # WAF management endpoints
    path('_waf/stats/', WAFStatsView.as_view(), name='waf_stats'),
    path('_waf/modules/', WAFModulesView.as_view(), name='waf_modules'),
    path('_waf/ip/<str:ip_address>/', WAFIPStatusView.as_view(), name='waf_ip_status'),
    path('_waf/whitelist/<str:ip_address>/', WAFWhitelistView.as_view(), name='waf_whitelist'),
    path('_waf/blacklist/<str:ip_address>/', WAFBlacklistView.as_view(), name='waf_blacklist'),
    
    # Your other URLs
    # ...
]
"""
