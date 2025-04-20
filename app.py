import base64
import binascii
import ipaddress
import json
import re
import socket
import time
import urllib.parse
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, abort
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Helper functions for validation
def is_valid_base64(s):
    try:
        # Check if string is valid base64 by attempting to decode it
        if not s:
            return False
        s = s.strip()
        # Check if length is a multiple of 4 (padded correctly)
        if len(s) % 4 != 0:
            return False
        # Check if only valid base64 characters are present
        if not re.match(r'^[A-Za-z0-9+/=]+$', s):
            return False
        return True
    except Exception:
        return False

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def is_valid_ipv6(ip):
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False

def is_valid_url(url):
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def is_valid_epoch(epoch_str):
    try:
        # Try to convert to float or int
        epoch = float(epoch_str)
        # Check if it's a reasonable epoch time (after 1970 and before 100 years in the future)
        return 0 <= epoch <= 4102444800  # Roughly 2100
    except ValueError:
        return False

def get_ip_info(ip_address):
    """Get geolocation info about an IP address using ipinfo.io"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to get IP info: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error retrieving IP info: {str(e)}"}

# Route for the main page
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# Route for Base64 operations
@app.route('/api/base64', methods=['POST'])
def base64_operation():
    try:
        data = request.form.get('data', '')
        operation = request.form.get('operation', '')
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if operation == 'encode':
            encoded = base64.b64encode(data.encode('utf-8')).decode('utf-8')
            return jsonify({'result': encoded})
        elif operation == 'decode':
            if not is_valid_base64(data):
                return jsonify({'error': 'Invalid base64 string'}), 400
            try:
                decoded = base64.b64decode(data).decode('utf-8')
                return jsonify({'result': decoded})
            except (binascii.Error, UnicodeDecodeError):
                return jsonify({'error': 'Unable to decode base64 string'}), 400
        else:
            return jsonify({'error': 'Invalid operation'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for IP conversion
@app.route('/api/ip', methods=['POST'])
def ip_conversion():
    try:
        ip = request.form.get('ip', '')
        
        if not ip:
            return jsonify({'error': 'No IP address provided'}), 400
        
        if is_valid_ipv4(ip):
            # Convert IPv4 to binary
            ip_obj = ipaddress.IPv4Address(ip)
            binary = bin(int(ip_obj))[2:].zfill(32)
            formatted_binary = ' '.join(binary[i:i+8] for i in range(0, len(binary), 8))
            
            # Get subnet information
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            subnet = str(network.network_address)
            subnet_mask = str(network.netmask)
            
            # Determine IP class
            first_octet = int(ip.split('.')[0])
            if first_octet < 128:
                ip_class = 'A'
            elif first_octet < 192:
                ip_class = 'B'
            elif first_octet < 224:
                ip_class = 'C'
            elif first_octet < 240:
                ip_class = 'D (Multicast)'
            else:
                ip_class = 'E (Reserved)'
                
            # Get geolocation info for the IP
            geo_info = get_ip_info(ip)
            
            return jsonify({
                'binary': formatted_binary,
                'subnet': subnet,
                'subnet_mask': subnet_mask,
                'ip_class': ip_class,
                'type': 'IPv4',
                'geo_info': geo_info
            })
            
        elif is_valid_ipv6(ip):
            # Convert IPv6 to binary
            ip_obj = ipaddress.IPv6Address(ip)
            binary = bin(int(ip_obj))[2:].zfill(128)
            formatted_binary = ' '.join(binary[i:i+16] for i in range(0, len(binary), 16))
            
            # Get geolocation info for the IP
            geo_info = get_ip_info(ip)
            
            return jsonify({
                'binary': formatted_binary,
                'type': 'IPv6',
                'geo_info': geo_info
            })
        else:
            return jsonify({'error': 'Invalid IP address'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for URL operations
@app.route('/api/url', methods=['POST'])
def url_operation():
    try:
        url = request.form.get('url', '')
        operation = request.form.get('operation', '')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        if operation == 'encode':
            encoded = urllib.parse.quote(url)
            return jsonify({'result': encoded})
        elif operation == 'decode':
            decoded = urllib.parse.unquote(url)
            return jsonify({'result': decoded})
        elif operation == 'extract':
            if not is_valid_url(url):
                return jsonify({'error': 'Invalid URL'}), 400
                
            parsed = urllib.parse.urlparse(url)
            query_params = dict(urllib.parse.parse_qsl(parsed.query))
            
            return jsonify({
                'host': parsed.netloc,
                'scheme': parsed.scheme,
                'path': parsed.path,
                'params': query_params
            })
        else:
            return jsonify({'error': 'Invalid operation'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for URL redirection tracing
@app.route('/api/trace', methods=['POST'])
def trace_redirects():
    try:
        url = request.form.get('url', '')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
            
        if not is_valid_url(url):
            return jsonify({'error': 'Invalid URL'}), 400
            
        redirects = []
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            
            for resp in response.history:
                redirects.append({
                    'url': resp.url,
                    'status_code': resp.status_code
                })
                
            # Add the final URL
            redirects.append({
                'url': response.url,
                'status_code': response.status_code
            })
            
            return jsonify({'redirects': redirects})
        except requests.exceptions.RequestException as e:
            return jsonify({'error': f'Connection error: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for Epoch time conversion
@app.route('/api/epoch', methods=['POST'])
def epoch_conversion():
    try:
        epoch_time = request.form.get('epoch', '')
        
        if not epoch_time:
            return jsonify({'error': 'No epoch time provided'}), 400
            
        if not is_valid_epoch(epoch_time):
            return jsonify({'error': 'Invalid epoch time'}), 400
            
        epoch_float = float(epoch_time)
        
        # Check if milliseconds
        if epoch_float > 1000000000000:
            epoch_float = epoch_float / 1000
            
        dt = datetime.fromtimestamp(epoch_float)
        
        formats = {
            'readable': dt.strftime('%Y-%m-%d %H:%M:%S'),
            'iso': dt.isoformat(),
            'rfc': dt.strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'local': dt.strftime('%c')
        }
        
        return jsonify(formats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# New route to get user information
@app.route('/api/user-info', methods=['GET'])
def user_info():
    try:
        # Get client IP address (respecting X-Forwarded-For if present)
        client_ip = request.remote_addr
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
            
        # Get user agent
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Get additional headers
        headers = {
            'Accept-Language': request.headers.get('Accept-Language', 'Unknown'),
            'Accept-Encoding': request.headers.get('Accept-Encoding', 'Unknown'),
            'Referer': request.headers.get('Referer', 'None'),
            'Connection': request.headers.get('Connection', 'Unknown')
        }
        
        # Get geolocation info for the IP
        geo_info = get_ip_info(client_ip)
        
        return jsonify({
            'ip_address': client_ip,
            'user_agent': user_agent,
            'headers': headers,
            'geo_info': geo_info
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# HTML Templates
@app.route('/templates/index.html', methods=['GET'])
def get_index_template():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)