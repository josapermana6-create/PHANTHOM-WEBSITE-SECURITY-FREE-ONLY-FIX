"""
Flask Middleware Integration for Phantom WAF
"""
from flask import request, jsonify, abort
from functools import wraps
from phantom_waf import PhantomWAF, WAFAction
import time


class FlaskWAFMiddleware:
    """Flask middleware for Phantom WAF"""
    
    def __init__(self, app=None, config_path='config.yaml'):
        """
        Initialize Flask WAF middleware
        
        Args:
            app: Flask application instance
            config_path: Path to WAF configuration file
        """
        self.waf = PhantomWAF(config_path)
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        self.app = app
        
        # Register before_request handler
        @app.before_request
        def waf_check():
            return self._check_request()
        
        # Register WAF management endpoints
        @app.route('/_waf/stats', methods=['GET'])
        def waf_stats():
            return jsonify(self.waf.get_stats())
        
        @app.route('/_waf/modules', methods=['GET'])
        def waf_modules():
            return jsonify(self.waf.get_module_info())
        
        @app.route('/_waf/ip/<ip_address>', methods=['GET'])
        def waf_ip_status(ip_address):
            return jsonify(self.waf.get_ip_status(ip_address))
        
        @app.route('/_waf/whitelist/<ip_address>', methods=['POST'])
        def waf_whitelist(ip_address):
            self.waf.whitelist_ip(ip_address)
            return jsonify({'status': 'success', 'ip': ip_address, 'action': 'whitelisted'})
        
        @app.route('/_waf/blacklist/<ip_address>', methods=['POST'])
        def waf_blacklist(ip_address):
            self.waf.blacklist_ip(ip_address)
            return jsonify({'status': 'success', 'ip': ip_address, 'action': 'blacklisted'})
    
    def _check_request(self):
        """Check incoming request with WAF"""
        # Build request data
        request_data = {
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
            'params': dict(request.args),
            'body': self._get_body(),
            'ip': self._get_client_ip()
        }
        
        # Analyze with WAF
        result = self.waf.analyze_request(request_data)
        
        # Take action based on result
        if result.action == WAFAction.BLOCK:
            return self._block_response(result)
        elif result.action == WAFAction.CHALLENGE:
            return self._challenge_response(result)
        
        # Log if monitoring
        if result.action == WAFAction.MONITOR and result.threat_score > 0:
            self.app.logger.warning(
                f"WAF: Potential threat detected (score: {result.threat_score}) "
                f"from {request_data['ip']} to {request.path}"
            )
        
        # Allow request to proceed
        return None
    
    def _get_body(self):
        """Get request body"""
        try:
            if request.is_json:
                return request.get_json()
            elif request.form:
                return dict(request.form)
            else:
                return request.get_data(as_text=True)
        except Exception:
            return ''
    
    def _get_client_ip(self):
        """Get client IP address"""
        # Check X-Forwarded-For header
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr or 'unknown'
    
    def _block_response(self, result):
        """Return blocked response"""
        response = jsonify({
            'error': 'Request blocked by WAF',
            'threat_score': result.threat_score,
            'blocked_by': result.blocked_by,
            'request_id': str(time.time())
        })
        response.status_code = 403
        return response
    
    def _challenge_response(self, result):
        """Return challenge response"""
        response = jsonify({
            'error': 'Request requires verification',
            'threat_score': result.threat_score,
            'message': 'Please complete verification to proceed'
        })
        response.status_code = 429
        return response


def waf_protected(f):
    """
    Decorator for protecting specific routes
    
    Usage:
        @app.route('/api/secret')
        @waf_protected
        def secret_endpoint():
            return 'Secret data'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # WAF check is already done in before_request
        # This decorator can add additional route-specific checks if needed
        return f(*args, **kwargs)
    return decorated_function


# Example usage
if __name__ == '__main__':
    from flask import Flask
    
    app = Flask(__name__)
    waf = FlaskWAFMiddleware(app)
    
    @app.route('/')
    def index():
        return 'Hello, World!'
    
    @app.route('/api/data')
    @waf_protected
    def get_data():
        return jsonify({'data': 'sensitive information'})
    
    app.run(debug=True, port=5000)
