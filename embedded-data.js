const ERRORS_DATA = [
  {
    "id": "connection-refused",
    "title": "Connection refused",
    "category": "Network",
    "explanation": "The target server is not accepting connections on the specified port. The service may be down, blocked by a firewall, or not listening on that port.",
    "fix_snippet": "# Check if service is running\nsudo netstat -tulpn | grep :80\n# Or check with curl\ncurl -v http://localhost:8080",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors"
    ]
  },
  {
    "id": "502-bad-gateway",
    "title": "502 Bad Gateway",
    "category": "HTTP",
    "explanation": "The server received an invalid response from an upstream service. Usually indicates the backend server is down or misconfigured.",
    "fix_snippet": "# Check upstream service\nsudo systemctl status nginx\n# Check Nginx config\nnginx -t\n# Restart if needed\nsudo systemctl restart nginx",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/502"
    ]
  },
  {
    "id": "503-service-unavailable",
    "title": "503 Service Unavailable",
    "category": "HTTP",
    "explanation": "The server is temporarily unable to handle requests, often due to maintenance or overload.",
    "fix_snippet": "# Check server load\nhtop\n# Check service status\nsudo systemctl status apache2\n# Increase worker limits in config",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/503"
    ]
  },
  {
    "id": "504-gateway-timeout",
    "title": "504 Gateway Timeout",
    "category": "HTTP",
    "explanation": "The server didn't receive a timely response from an upstream server while acting as a gateway or proxy.",
    "fix_snippet": "# Increase proxy timeout in Nginx\nproxy_read_timeout 300s;\nproxy_connect_timeout 300s;\n# Or in Apache\nProxyTimeout 300",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/504"
    ]
  },
  {
    "id": "ssl-certificate-unknown-authority",
    "title": "x509: certificate signed by unknown authority",
    "category": "TLS",
    "explanation": "The SSL certificate was signed by a Certificate Authority that isn't trusted by the client system.",
    "fix_snippet": "# Skip verification (development only)\ncurl -k https://example.com\n# Or add CA certificate\nsudo cp ca-cert.crt /usr/local/share/ca-certificates/\nsudo update-ca-certificates",
    "sources": [
      "https://golang.org/pkg/crypto/x509/"
    ]
  },
  {
    "id": "curl-ssl-read-connection-reset",
    "title": "curl: (56) OpenSSL SSL_read: Connection reset by peer",
    "category": "TLS",
    "explanation": "The SSL connection was abruptly closed by the remote server, often due to protocol mismatch or server configuration issues.",
    "fix_snippet": "# Try different TLS version\ncurl --tlsv1.2 https://example.com\n# Or specify cipher\ncurl --ciphers ECDHE+AESGCM https://example.com",
    "sources": [
      "https://curl.se/docs/sslcerts.html"
    ]
  },
  {
    "id": "err-ssl-protocol-error",
    "title": "ERR_SSL_PROTOCOL_ERROR",
    "category": "TLS",
    "explanation": "Browser detected an SSL protocol violation or misconfiguration. Often caused by mixed HTTP/HTTPS content or outdated TLS settings.",
    "fix_snippet": "# Check certificate configuration\nopenssl s_client -connect example.com:443\n# Update TLS configuration to support modern protocols",
    "sources": [
      "https://developer.chrome.com/docs/security/"
    ]
  },
  {
    "id": "dns-resolution-failed",
    "title": "DNS resolution failed",
    "category": "DNS",
    "explanation": "The domain name could not be resolved to an IP address. DNS server may be unreachable or the domain doesn't exist.",
    "fix_snippet": "# Test DNS resolution\nnslookup example.com\n# Try different DNS server\nnslookup example.com 8.8.8.8\n# Flush DNS cache\nsudo systemctl restart systemd-resolved",
    "sources": [
      "https://linux.die.net/man/1/nslookup"
    ]
  },
  {
    "id": "connection-timeout",
    "title": "Connection timeout",
    "category": "Network",
    "explanation": "The connection attempt took too long and was aborted. Network connectivity issues or server overload.",
    "fix_snippet": "# Test connectivity\nping example.com\n# Increase timeout\ncurl --connect-timeout 30 https://example.com\n# Check firewall rules",
    "sources": [
      "https://curl.se/docs/manpage.html"
    ]
  },
  {
    "id": "401-unauthorized",
    "title": "401 Unauthorized",
    "category": "HTTP",
    "explanation": "The request requires authentication credentials. The client must authenticate to get the requested response.",
    "fix_snippet": "# Add basic auth\ncurl -u username:password https://api.example.com\n# Or use bearer token\ncurl -H \"Authorization: Bearer $TOKEN\" https://api.example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401"
    ]
  },
  {
    "id": "403-forbidden",
    "title": "403 Forbidden",
    "category": "HTTP",
    "explanation": "The server understood the request but refuses to authorize it. Often due to insufficient permissions.",
    "fix_snippet": "# Check file permissions\nls -la /var/www/html/\n# Fix permissions\nsudo chmod 644 file.html\nsudo chown www-data:www-data file.html",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403"
    ]
  },
  {
    "id": "404-not-found",
    "title": "404 Not Found",
    "category": "HTTP",
    "explanation": "The requested resource could not be found on the server. URL may be incorrect or resource was moved/deleted.",
    "fix_snippet": "# Check if file exists\nls -la /var/www/html/page.html\n# Check web server error logs\nsudo tail -f /var/log/nginx/error.log",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404"
    ]
  },
  {
    "id": "500-internal-server-error",
    "title": "500 Internal Server Error",
    "category": "HTTP",
    "explanation": "The server encountered an unexpected condition that prevented it from fulfilling the request.",
    "fix_snippet": "# Check error logs\nsudo tail -f /var/log/apache2/error.log\n# Check syntax\nphp -l script.php\n# Restart web server\nsudo systemctl restart apache2",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500"
    ]
  },
  {
    "id": "cors-policy-error",
    "title": "CORS policy error",
    "category": "Client",
    "explanation": "Cross-Origin Resource Sharing policy blocked the request. Browser security feature preventing unauthorized cross-domain requests.",
    "fix_snippet": "# Add CORS headers in server config\nHeader add Access-Control-Allow-Origin \"*\"\n# Or in Nginx\nadd_header Access-Control-Allow-Origin *;",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
    ]
  },
  {
    "id": "mixed-content-error",
    "title": "Mixed Content Error",
    "category": "Client",
    "explanation": "HTTPS page trying to load insecure HTTP resources. Browsers block HTTP content on HTTPS pages for security.",
    "fix_snippet": "# Update all URLs to HTTPS\n<script src=\"https://example.com/script.js\"></script>\n# Or use protocol-relative URLs\n<script src=\"//example.com/script.js\"></script>",
    "sources": [
      "https://developers.google.com/web/fundamentals/security/prevent-mixed-content"
    ]
  },
  {
    "id": "ssl-handshake-failed",
    "title": "SSL handshake failed",
    "category": "TLS",
    "explanation": "The SSL/TLS handshake process failed, often due to protocol version mismatch or cipher incompatibility.",
    "fix_snippet": "# Check supported protocols\nopenssl s_client -connect example.com:443 -tls1_2\n# Test different cipher suites\ncurl --tlsv1.2 --ciphers HIGH https://example.com",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/s_client.html"
    ]
  },
  {
    "id": "certificate-expired",
    "title": "Certificate has expired",
    "category": "TLS",
    "explanation": "The SSL certificate is past its expiration date and is no longer valid for secure connections.",
    "fix_snippet": "# Check certificate expiry\nopenssl x509 -in cert.pem -text -noout | grep \"Not After\"\n# Renew with Let's Encrypt\nsudo certbot renew",
    "sources": [
      "https://letsencrypt.org/docs/"
    ]
  },
  {
    "id": "hostname-verification-failed",
    "title": "Hostname verification failed",
    "category": "TLS",
    "explanation": "The SSL certificate's hostname doesn't match the requested domain name.",
    "fix_snippet": "# Check certificate details\nopenssl s_client -connect example.com:443 | openssl x509 -noout -text\n# Generate certificate with correct SAN\nopenssl req -new -x509 -days 365 -subj '/CN=example.com'",
    "sources": [
      "https://www.openssl.org/docs/"
    ]
  },
  {
    "id": "proxy-connection-failed",
    "title": "Proxy connection failed",
    "category": "Proxy",
    "explanation": "Unable to establish connection through the configured proxy server. Proxy may be down or misconfigured.",
    "fix_snippet": "# Test proxy connectivity\ncurl --proxy proxy.example.com:8080 https://httpbin.org/ip\n# Bypass proxy for testing\ncurl --noproxy '*' https://example.com",
    "sources": [
      "https://curl.se/docs/manpage.html"
    ]
  },
  {
    "id": "upstream-connect-error",
    "title": "Upstream connect error",
    "category": "Proxy",
    "explanation": "Reverse proxy couldn't connect to the upstream server. Backend service may be unreachable.",
    "fix_snippet": "# Check upstream in Nginx config\nupstream backend {\n  server 127.0.0.1:3000;\n}\n# Test backend directly\ncurl http://127.0.0.1:3000/health",
    "sources": [
      "http://nginx.org/en/docs/http/ngx_http_upstream_module.html"
    ]
  },
  {
    "id": "rate-limit-exceeded",
    "title": "Rate limit exceeded",
    "category": "HTTP",
    "explanation": "Too many requests sent in a given time period. API or server has request rate limiting enabled.",
    "fix_snippet": "# Add delay between requests\nsleep 1\n# Check rate limit headers\ncurl -I https://api.example.com\n# Implement exponential backoff",
    "sources": [
      "https://tools.ietf.org/html/rfc6585#section-4"
    ]
  },
  {
    "id": "redirect-loop",
    "title": "Too many redirects",
    "category": "HTTP",
    "explanation": "The request is stuck in an infinite redirect loop, often caused by misconfigured redirect rules.",
    "fix_snippet": "# Check redirect chain\ncurl -L -v https://example.com\n# Limit redirects\ncurl --max-redirs 5 https://example.com\n# Fix redirect configuration",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections"
    ]
  },
  {
    "id": "invalid-ssl-certificate",
    "title": "Invalid SSL certificate",
    "category": "TLS",
    "explanation": "The SSL certificate is malformed, self-signed, or doesn't meet security requirements.",
    "fix_snippet": "# Validate certificate\nopenssl verify cert.pem\n# Check certificate chain\nopenssl s_client -connect example.com:443 -showcerts",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/verify.html"
    ]
  },
  {
    "id": "port-unreachable",
    "title": "Port unreachable",
    "category": "Network",
    "explanation": "The specified port on the target host is not accessible, likely blocked by firewall or service not running.",
    "fix_snippet": "# Test port connectivity\ntelnet example.com 80\n# Or use nmap\nnmap -p 80 example.com\n# Check firewall rules\nsudo ufw status",
    "sources": [
      "https://linux.die.net/man/1/telnet"
    ]
  },
  {
    "id": "http2-protocol-error",
    "title": "HTTP/2 protocol error",
    "category": "HTTP",
    "explanation": "Error in HTTP/2 protocol handling, often due to server configuration or unsupported features.",
    "fix_snippet": "# Force HTTP/1.1\ncurl --http1.1 https://example.com\n# Check HTTP/2 support\ncurl -I --http2 https://example.com",
    "sources": [
      "https://tools.ietf.org/html/rfc7540"
    ]
  },
  {
    "id": "network-unreachable",
    "title": "Network is unreachable",
    "category": "Network",
    "explanation": "No route to the destination network. Routing table may be missing entries or network interface is down.",
    "fix_snippet": "# Check routing table\nroute -n\n# Test network interface\nip addr show\n# Ping gateway\nping $(ip route | grep default | awk '{print $3}')",
    "sources": [
      "https://linux.die.net/man/8/route"
    ]
  },
  {
    "id": "content-encoding-error",
    "title": "Content encoding error",
    "category": "HTTP",
    "explanation": "Server sent compressed content but client couldn't decode it, or encoding header mismatch.",
    "fix_snippet": "# Disable compression\ncurl -H \"Accept-Encoding: identity\" https://example.com\n# Check server compression config\n# In Apache: mod_deflate settings",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding"
    ]
  },
  {
    "id": "websocket-connection-failed",
    "title": "WebSocket connection failed",
    "category": "Network",
    "explanation": "Unable to establish WebSocket connection, often due to proxy issues or unsupported protocols.",
    "fix_snippet": "# Test WebSocket connection\nwscat -c ws://example.com/websocket\n# Check proxy WebSocket support\n# Configure Nginx WebSocket proxy",
    "sources": [
      "https://tools.ietf.org/html/rfc6455"
    ]
  },
  {
    "id": "client-certificate-required",
    "title": "Client certificate required",
    "category": "TLS",
    "explanation": "Server requires client certificate authentication but none was provided.",
    "fix_snippet": "# Provide client certificate\ncurl --cert client.crt --key client.key https://example.com\n# Check certificate requirements\nopenssl s_client -connect example.com:443",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/s_client.html"
    ]
  },
  {
    "id": "http-version-not-supported",
    "title": "HTTP version not supported",
    "category": "HTTP",
    "explanation": "Server doesn't support the HTTP protocol version used in the request.",
    "fix_snippet": "# Force HTTP/1.1\ncurl --http1.1 https://example.com\n# Check supported versions\ncurl -I --http1.0 https://example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/505"
    ]
  },
  {
    "id": "dns-timeout",
    "title": "DNS lookup timeout",
    "category": "DNS",
    "explanation": "DNS query took too long to complete, often due to slow or unresponsive DNS servers.",
    "fix_snippet": "# Use faster DNS servers\necho 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf\n# Test DNS response time\ndig +time=5 example.com",
    "sources": [
      "https://linux.die.net/man/1/dig"
    ]
  },
  {
    "id": "invalid-response-headers",
    "title": "Invalid response headers",
    "category": "HTTP",
    "explanation": "Server sent malformed HTTP headers that the client couldn't parse properly.",
    "fix_snippet": "# Check raw HTTP response\ncurl -D headers.txt https://example.com\n# Validate header format\n# Fix server header generation",
    "sources": [
      "https://tools.ietf.org/html/rfc7230#section-3.2"
    ]
  },
  {
    "id": "chunk-encoding-error",
    "title": "Chunk encoding error",
    "category": "HTTP",
    "explanation": "Error in HTTP chunked transfer encoding, often due to incomplete or malformed chunks.",
    "fix_snippet": "# Disable chunked encoding\ncurl -H \"Transfer-Encoding:\" https://example.com\n# Check server chunking implementation",
    "sources": [
      "https://tools.ietf.org/html/rfc7230#section-4.1"
    ]
  },
  {
    "id": "proxy-authentication-required",
    "title": "Proxy authentication required",
    "category": "Proxy",
    "explanation": "Proxy server requires authentication before allowing the request to proceed.",
    "fix_snippet": "# Authenticate with proxy\ncurl --proxy-user username:password --proxy proxy.example.com:8080 https://example.com\nexport HTTP_PROXY=http://user:pass@proxy.example.com:8080",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/407"
    ]
  },
  {
    "id": "request-timeout",
    "title": "Request timeout",
    "category": "HTTP",
    "explanation": "Server timed out waiting for the client to complete the request within the allowed time limit.",
    "fix_snippet": "# Increase client timeout\ncurl --max-time 300 https://example.com\n# Check server timeout settings\n# In Apache: TimeOut directive",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/408"
    ]
  },
  {
    "id": "content-length-mismatch",
    "title": "Content-Length mismatch",
    "category": "HTTP",
    "explanation": "The actual content size doesn't match the Content-Length header value.",
    "fix_snippet": "# Check content length\ncurl -I https://example.com\n# Verify actual vs declared size\n# Fix server content length calculation",
    "sources": [
      "https://tools.ietf.org/html/rfc7230#section-3.3.2"
    ]
  },
  {
    "id": "ssl-version-mismatch",
    "title": "SSL version or cipher mismatch",
    "category": "TLS",
    "explanation": "Client and server don't support compatible SSL/TLS versions or cipher suites.",
    "fix_snippet": "# Check supported ciphers\nnmap --script ssl-enum-ciphers -p 443 example.com\n# Use specific TLS version\ncurl --tlsv1.2 https://example.com",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/ciphers.html"
    ]
  },
  {
    "id": "bad-gateway-dns",
    "title": "Bad Gateway - DNS resolution",
    "category": "DNS",
    "explanation": "Reverse proxy cannot resolve the upstream server's hostname to an IP address.",
    "fix_snippet": "# Check DNS resolution from proxy server\nnslookup backend.local\n# Add to /etc/hosts if needed\necho '127.0.0.1 backend.local' >> /etc/hosts",
    "sources": [
      "https://nginx.org/en/docs/http/ngx_http_proxy_module.html"
    ]
  },
  {
    "id": "certificate-chain-incomplete",
    "title": "Certificate chain incomplete",
    "category": "TLS",
    "explanation": "SSL certificate chain is missing intermediate certificates, causing trust validation to fail.",
    "fix_snippet": "# Check certificate chain\nopenssl s_client -connect example.com:443 -showcerts\n# Install intermediate certificates\ncat cert.crt intermediate.crt > fullchain.crt",
    "sources": [
      "https://www.ssllabs.com/ssltest/"
    ]
  },
  {
    "id": "http-method-not-allowed",
    "title": "Method not allowed",
    "category": "HTTP",
    "explanation": "The HTTP method used in the request is not supported for the requested resource.",
    "fix_snippet": "# Check allowed methods\ncurl -X OPTIONS https://api.example.com/resource\n# Use correct method\ncurl -X POST https://api.example.com/resource",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405"
    ]
  },
  {
    "id": "payload-too-large",
    "title": "Payload too large",
    "category": "HTTP",
    "explanation": "The request payload exceeds the server's size limits for processing.",
    "fix_snippet": "# Check server limits\n# In Nginx: client_max_body_size\n# In Apache: LimitRequestBody\ncurl -F 'file=@small_file.zip' https://upload.example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/413"
    ]
  },
  {
    "id": "insufficient-storage",
    "title": "Insufficient storage",
    "category": "HTTP",
    "explanation": "Server cannot store the representation needed to complete the request due to lack of storage space.",
    "fix_snippet": "# Check disk space\ndf -h\n# Clean up logs\nsudo journalctl --vacuum-time=7d\n# Check upload directory permissions",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/507"
    ]
  },
  {
    "id": "connection-reset-by-peer",
    "title": "Connection reset by peer",
    "category": "Network",
    "explanation": "The remote server abruptly closed the connection, often due to server overload or configuration issues.",
    "fix_snippet": "# Retry with keep-alive disabled\ncurl -H \"Connection: close\" https://example.com\n# Check server connection limits\n# Monitor server resources",
    "sources": [
      "https://linux.die.net/man/2/recv"
    ]
  },
  {
    "id": "ssl-peer-certificate-error",
    "title": "SSL peer certificate verification failed",
    "category": "TLS",
    "explanation": "The peer's SSL certificate could not be verified against known Certificate Authorities.",
    "fix_snippet": "# Skip verification (dev only)\ncurl -k https://example.com\n# Add custom CA\ncurl --cacert custom-ca.crt https://example.com",
    "sources": [
      "https://curl.se/docs/sslcerts.html"
    ]
  },
  {
    "id": "network-changed",
    "title": "Network changed",
    "category": "Network",
    "explanation": "The network configuration changed during the request, causing connection failure.",
    "fix_snippet": "# Restart network service\nsudo systemctl restart NetworkManager\n# Renew DHCP lease\nsudo dhclient -r && sudo dhclient",
    "sources": [
      "https://wiki.archlinux.org/title/NetworkManager"
    ]
  },
  {
    "id": "unsupported-media-type",
    "title": "Unsupported media type",
    "category": "HTTP",
    "explanation": "The server doesn't support the media type of the request payload.",
    "fix_snippet": "# Set correct Content-Type\ncurl -H \"Content-Type: application/json\" -d '{\"key\":\"value\"}' https://api.example.com\n# Check accepted media types\ncurl -H \"Accept: */*\" https://api.example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/415"
    ]
  },
  {
    "id": "expectation-failed",
    "title": "Expectation failed",
    "category": "HTTP",
    "explanation": "Server cannot meet the requirements specified in the Expect request header field.",
    "fix_snippet": "# Disable Expect header\ncurl -H \"Expect:\" https://example.com\n# Or handle 100-continue properly\ncurl -H \"Expect: 100-continue\" https://example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/417"
    ]
  },
  {
    "id": "kubernetes-ingress-error",
    "title": "Kubernetes Ingress error",
    "category": "Ingress",
    "explanation": "Ingress controller cannot route traffic to the specified service, often due to misconfigured rules.",
    "fix_snippet": "# Check ingress status\nkubectl get ingress\n# Describe ingress for details\nkubectl describe ingress my-ingress\n# Check ingress controller logs\nkubectl logs -n ingress-nginx deployment/ingress-nginx-controller",
    "sources": [
      "https://kubernetes.io/docs/concepts/services-networking/ingress/"
    ]
  },
  {
    "id": "envoy-upstream-reset",
    "title": "Envoy upstream reset",
    "category": "Proxy",
    "explanation": "Envoy proxy received a reset from the upstream service before completing the request.",
    "fix_snippet": "# Check Envoy admin interface\ncurl localhost:9901/clusters\n# Increase upstream timeout\ntimeout: 30s\n# Check upstream health",
    "sources": [
      "https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/router_filter"
    ]
  },
  {
    "id": "traefik-no-backend",
    "title": "Traefik backend not found",
    "category": "Proxy",
    "explanation": "Traefik reverse proxy cannot find a healthy backend service to route the request to.",
    "fix_snippet": "# Check Traefik dashboard\n# Verify service labels\nlabels:\n  - \"traefik.http.routers.app.rule=Host(`example.com`)\"\n# Check service health",
    "sources": [
      "https://doc.traefik.io/traefik/routing/routers/"
    ]
  },
  {
    "id": "caddy-upstream-error",
    "title": "Caddy upstream error",
    "category": "Proxy",
    "explanation": "Caddy web server failed to connect to or receive response from upstream server.",
    "fix_snippet": "# Check Caddy config\ncaddy validate --config Caddyfile\n# Test upstream directly\ncurl http://localhost:3000\n# Check Caddy logs\ncaddy logs",
    "sources": [
      "https://caddyserver.com/docs/caddyfile/directives/reverse_proxy"
    ]
  },
  {
    "id": "apache-mod-ssl-error",
    "title": "Apache mod_ssl error",
    "category": "TLS",
    "explanation": "Apache's SSL module encountered an error, often due to misconfigured SSL directives.",
    "fix_snippet": "# Check Apache SSL config\napache2ctl -S\n# Test SSL configuration\nopenssl s_client -connect localhost:443\n# Check SSL module is loaded\napache2ctl -M | grep ssl",
    "sources": [
      "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html"
    ]
  },
  {
    "id": "haproxy-server-error",
    "title": "HAProxy server error",
    "category": "Proxy",
    "explanation": "HAProxy load balancer encountered an error with backend servers, often health check failures.",
    "fix_snippet": "# Check HAProxy stats\necho \"show stat\" | socat stdio /var/run/haproxy.sock\n# Verify backend health\necho \"show servers state\" | socat stdio /var/run/haproxy.sock",
    "sources": [
      "https://www.haproxy.org/download/2.4/doc/management.txt"
    ]
  },
  {
    "id": "cloudflare-error",
    "title": "Cloudflare error",
    "category": "Proxy",
    "explanation": "Cloudflare CDN encountered an error, often related to origin server connectivity or SSL issues.",
    "fix_snippet": "# Bypass Cloudflare for testing\ncurl -H \"Host: example.com\" http://origin-ip-address\n# Check origin server SSL\nopenssl s_client -connect origin-ip:443",
    "sources": [
      "https://developers.cloudflare.com/support/troubleshooting/"
    ]
  },
  {
    "id": "grpc-unavailable",
    "title": "gRPC unavailable",
    "category": "Network",
    "explanation": "gRPC service is temporarily unavailable, often due to server overload or network issues.",
    "fix_snippet": "# Test gRPC service\ngrpcurl -plaintext localhost:8080 list\n# Check service health\ngrpcurl -plaintext localhost:8080 grpc.health.v1.Health/Check",
    "sources": [
      "https://grpc.io/docs/guides/error/"
    ]
  },
  {
    "id": "docker-network-error",
    "title": "Docker network error",
    "category": "Network",
    "explanation": "Docker containers cannot communicate due to network configuration issues or DNS resolution problems.",
    "fix_snippet": "# Check Docker networks\ndocker network ls\n# Inspect network details\ndocker network inspect bridge\n# Test container connectivity\ndocker exec container1 ping container2",
    "sources": [
      "https://docs.docker.com/network/"
    ]
  },
  {
    "id": "redis-connection-error",
    "title": "Redis connection error",
    "category": "Network",
    "explanation": "Unable to connect to Redis server, often due to authentication, network, or configuration issues.",
    "fix_snippet": "# Test Redis connection\nredis-cli ping\n# Check authentication\nredis-cli -a password ping\n# Verify Redis is running\nsudo systemctl status redis",
    "sources": [
      "https://redis.io/topics/clients"
    ]
  },
  {
    "id": "database-connection-timeout",
    "title": "Database connection timeout",
    "category": "Network",
    "explanation": "Database connection attempt exceeded the timeout limit, often due to network latency or server load.",
    "fix_snippet": "# Test database connectivity\nmysql -h hostname -u user -p\n# Increase connection timeout\nSET GLOBAL connect_timeout=60;\n# Check database server load",
    "sources": [
      "https://dev.mysql.com/doc/refman/8.0/en/connection-options.html"
    ]
  },
  {
    "id": "oauth-invalid-token",
    "title": "OAuth invalid token",
    "category": "HTTP",
    "explanation": "The OAuth access token is expired, malformed, or doesn't have sufficient permissions.",
    "fix_snippet": "# Refresh OAuth token\ncurl -X POST https://oauth.example.com/token \\\n  -d 'refresh_token=xxx&grant_type=refresh_token'\n# Verify token\ncurl -H \"Authorization: Bearer $TOKEN\" https://api.example.com/user",
    "sources": [
      "https://tools.ietf.org/html/rfc6749"
    ]
  },
  {
    "id": "json-parse-error",
    "title": "JSON parse error",
    "category": "Client",
    "explanation": "Client received invalid JSON response that cannot be parsed, often due to malformed syntax.",
    "fix_snippet": "# Validate JSON response\ncurl -s https://api.example.com | jq .\n# Check raw response\ncurl -v https://api.example.com\n# Fix JSON syntax on server",
    "sources": [
      "https://www.json.org/json-en.html"
    ]
  },
  {
    "id": "websocket-upgrade-failed",
    "title": "WebSocket upgrade failed",
    "category": "Network",
    "explanation": "HTTP connection could not be upgraded to WebSocket protocol, often due to proxy or server configuration.",
    "fix_snippet": "# Check WebSocket headers\ncurl -H \"Upgrade: websocket\" -H \"Connection: Upgrade\" https://example.com/ws\n# Configure proxy for WebSocket\nproxy_set_header Upgrade $http_upgrade;",
    "sources": [
      "https://tools.ietf.org/html/rfc6455#section-4.2"
    ]
  },
  {
    "id": "csrf-token-mismatch",
    "title": "CSRF token mismatch",
    "category": "HTTP",
    "explanation": "Cross-Site Request Forgery protection rejected the request due to invalid or missing token.",
    "fix_snippet": "# Get CSRF token first\nCSRF_TOKEN=$(curl -c cookies.txt https://example.com/form | grep csrf_token)\n# Include token in request\ncurl -b cookies.txt -d \"csrf_token=$CSRF_TOKEN\" https://example.com/submit",
    "sources": [
      "https://owasp.org/www-community/attacks/csrf"
    ]
  },
  {
    "id": "load-balancer-error",
    "title": "Load balancer error",
    "category": "Proxy",
    "explanation": "Load balancer cannot route requests due to no healthy backend servers being available.",
    "fix_snippet": "# Check backend health\n# In AWS ALB: Check target group health\n# In nginx: upstream server status\n# Verify health check endpoints",
    "sources": [
      "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html"
    ]
  },
  {
    "id": "session-expired",
    "title": "Session expired",
    "category": "HTTP",
    "explanation": "User session has expired and needs to be renewed, often returning 401 or redirect to login.",
    "fix_snippet": "# Clear cookies and re-authenticate\nrm cookies.txt\n# Login again\ncurl -c cookies.txt -d \"user=xxx&pass=xxx\" https://example.com/login",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
    ]
  },
  {
    "id": "api-rate-limit-global",
    "title": "API rate limit exceeded (global)",
    "category": "HTTP",
    "explanation": "Global API rate limit exceeded across all endpoints or users, temporary throttling in effect.",
    "fix_snippet": "# Check rate limit headers\ncurl -I https://api.example.com\n# Implement exponential backoff\nfor i in {1..5}; do sleep $((2**i)); curl https://api.example.com && break; done",
    "sources": [
      "https://tools.ietf.org/html/rfc6585#section-4"
    ]
  },
  {
    "id": "dns-server-unreachable",
    "title": "DNS server unreachable",
    "category": "DNS",
    "explanation": "Configured DNS servers are not responding, preventing domain name resolution.",
    "fix_snippet": "# Test DNS servers\nfor dns in 8.8.8.8 1.1.1.1; do dig @$dns google.com; done\n# Change DNS servers\necho 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf",
    "sources": [
      "https://linux.die.net/man/1/dig"
    ]
  },
  {
    "id": "firewall-blocking",
    "title": "Firewall blocking connection",
    "category": "Network",
    "explanation": "Network firewall is blocking the connection attempt to the destination port or IP address.",
    "fix_snippet": "# Check firewall rules\nsudo ufw status verbose\n# Allow specific port\nsudo ufw allow 80/tcp\n# Test from different network",
    "sources": [
      "https://help.ubuntu.com/community/UFW"
    ]
  },
  {
    "id": "ssl-sni-error",
    "title": "SSL SNI (Server Name Indication) error",
    "category": "TLS",
    "explanation": "Server doesn't support SNI or client didn't send the server name, causing SSL certificate mismatch.",
    "fix_snippet": "# Test with specific SNI\nopenssl s_client -connect example.com:443 -servername example.com\n# Check server SNI support\ncurl --resolve example.com:443:1.2.3.4 https://example.com",
    "sources": [
      "https://tools.ietf.org/html/rfc6066#section-3"
    ]
  },
  {
    "id": "http-pipeline-error",
    "title": "HTTP pipelining error",
    "category": "HTTP",
    "explanation": "Error in HTTP pipelining where multiple requests are sent before receiving responses.",
    "fix_snippet": "# Disable HTTP pipelining\ncurl --no-http1.1-pipeline https://example.com\n# Use HTTP/1.0 instead\ncurl --http1.0 https://example.com",
    "sources": [
      "https://tools.ietf.org/html/rfc2616#section-8.1.2.2"
    ]
  },
  {
    "id": "content-type-mismatch",
    "title": "Content-Type mismatch",
    "category": "HTTP",
    "explanation": "The Content-Type header doesn't match the actual content being sent or expected by the server.",
    "fix_snippet": "# Set correct Content-Type\ncurl -H \"Content-Type: application/json\" -d '{\"key\":\"value\"}' https://api.example.com\n# Check server expectations\ncurl -I https://api.example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type"
    ]
  },
  {
    "id": "proxy-tunnel-failed",
    "title": "Proxy tunnel failed",
    "category": "Proxy",
    "explanation": "HTTPS tunnel through HTTP proxy failed, often due to proxy configuration or authentication issues.",
    "fix_snippet": "# Test proxy tunnel\ncurl -x proxy.example.com:8080 https://example.com\n# Use different proxy method\ncurl --proxy-tunnel proxy.example.com:8080 https://example.com",
    "sources": [
      "https://tools.ietf.org/html/rfc7231#section-4.3.6"
    ]
  },
  {
    "id": "dns-nxdomain",
    "title": "DNS NXDOMAIN",
    "category": "DNS",
    "explanation": "Domain name does not exist in DNS, the queried domain is not registered or configured.",
    "fix_snippet": "# Check domain existence\ndig example.com\n# Verify domain spelling\nwhois example.com\n# Check DNS propagation\ndig @8.8.8.8 example.com",
    "sources": [
      "https://tools.ietf.org/html/rfc1035"
    ]
  },
  {
    "id": "ssl-weak-cipher",
    "title": "SSL weak cipher rejected",
    "category": "TLS",
    "explanation": "Server or client rejected connection due to weak or deprecated cipher suites being offered.",
    "fix_snippet": "# Use strong ciphers only\ncurl --ciphers ECDHE+AESGCM:ECDHE+CHACHA20 https://example.com\n# Check supported ciphers\nnmap --script ssl-enum-ciphers -p 443 example.com",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/ciphers.html"
    ]
  },
  {
    "id": "http-header-too-large",
    "title": "HTTP header too large",
    "category": "HTTP",
    "explanation": "Request or response headers exceed the server's configured maximum header size limit.",
    "fix_snippet": "# Reduce header size\ncurl -H \"User-Agent: curl\" https://example.com\n# Check server limits\n# In Nginx: large_client_header_buffers\n# In Apache: LimitRequestFieldSize",
    "sources": [
      "https://tools.ietf.org/html/rfc7230#section-3.2"
    ]
  },
  {
    "id": "websocket-protocol-error",
    "title": "WebSocket protocol error",
    "category": "Network",
    "explanation": "Violation of WebSocket protocol specification, often due to malformed frames or incorrect handshake.",
    "fix_snippet": "# Check WebSocket implementation\n# Validate frame format\n# Test with different WebSocket client\nwscat -c ws://example.com/websocket",
    "sources": [
      "https://tools.ietf.org/html/rfc6455#section-7.4"
    ]
  },
  {
    "id": "circuit-breaker-open",
    "title": "Circuit breaker open",
    "category": "Network",
    "explanation": "Circuit breaker pattern activated due to repeated failures, temporarily blocking requests to protect service.",
    "fix_snippet": "# Wait for circuit breaker reset\n# Check service health\ncurl http://service/health\n# Monitor circuit breaker metrics\n# Implement graceful degradation",
    "sources": [
      "https://martinfowler.com/bliki/CircuitBreaker.html"
    ]
  },
  {
    "id": "service-mesh-error",
    "title": "Service mesh routing error",
    "category": "Network",
    "explanation": "Service mesh (Istio, Linkerd) failed to route request properly due to configuration or policy issues.",
    "fix_snippet": "# Check service mesh config\nkubectl get virtualservice\n# Verify destination rules\nkubectl get destinationrule\n# Check sidecar logs\nkubectl logs pod-name -c istio-proxy",
    "sources": [
      "https://istio.io/latest/docs/ops/common-problems/network-issues/"
    ]
  },
  {
    "id": "mtls-verification-failed",
    "title": "Mutual TLS verification failed",
    "category": "TLS",
    "explanation": "Mutual TLS authentication failed due to invalid client certificate or trust chain issues.",
    "fix_snippet": "# Provide client certificate\ncurl --cert client.crt --key client.key --cacert ca.crt https://example.com\n# Verify certificate chain\nopenssl verify -CAfile ca.crt client.crt",
    "sources": [
      "https://tools.ietf.org/html/rfc8446#section-4.4.2"
    ]
  },
  {
    "id": "bandwidth-limit-exceeded",
    "title": "Bandwidth limit exceeded",
    "category": "Network",
    "explanation": "Network bandwidth quota has been exceeded, causing connection throttling or blocking.",
    "fix_snippet": "# Check bandwidth usage\niftop\n# Monitor network traffic\nss -tuln\n# Implement traffic shaping\ntc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms",
    "sources": [
      "https://linux.die.net/man/8/tc"
    ]
  },
  {
    "id": "geo-blocking",
    "title": "Geographic blocking",
    "category": "HTTP",
    "explanation": "Request blocked due to geographic restrictions based on client IP address location.",
    "fix_snippet": "# Check IP geolocation\ncurl ipinfo.io\n# Test from different location\n# Use VPN or proxy if permitted\ncurl --proxy socks5://proxy:1080 https://example.com",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403"
    ]
  },
  {
    "id": "protocol-downgrade-attack",
    "title": "Protocol downgrade detected",
    "category": "TLS",
    "explanation": "Potential security attack detected where connection is being forced to use weaker protocols.",
    "fix_snippet": "# Force modern TLS\ncurl --tlsv1.3 https://example.com\n# Check for MITM\ncurl -k -v https://example.com 2>&1 | grep -i downgrad\n# Verify certificate fingerprint",
    "sources": [
      "https://tools.ietf.org/html/rfc7457"
    ]
  },
  {
    "id": "dns-cache-poisoning",
    "title": "DNS cache poisoning detected",
    "category": "DNS",
    "explanation": "DNS resolver returned suspicious results, possibly indicating cache poisoning attack.",
    "fix_snippet": "# Flush DNS cache\nsudo systemd-resolve --flush-caches\n# Use secure DNS\ndig @1.1.1.1 example.com\n# Verify with multiple DNS servers",
    "sources": [
      "https://tools.ietf.org/html/rfc5452"
    ]
  },
  {
    "id": "connection-pool-exhausted",
    "title": "Connection pool exhausted",
    "category": "Network",
    "explanation": "All available connections in the connection pool are in use, unable to create new connections.",
    "fix_snippet": "# Monitor connection pool\n# Increase pool size in application config\n# Check for connection leaks\nnetstat -an | grep ESTABLISHED | wc -l",
    "sources": [
      "https://en.wikipedia.org/wiki/Connection_pool"
    ]
  },
  {
    "id": "keepalive-timeout",
    "title": "Keep-alive timeout",
    "category": "HTTP",
    "explanation": "HTTP keep-alive connection timed out, server closed the persistent connection.",
    "fix_snippet": "# Adjust keep-alive settings\ncurl -H \"Connection: keep-alive\" https://example.com\n# Configure server keep-alive timeout\n# In Nginx: keepalive_timeout 75s;",
    "sources": [
      "https://tools.ietf.org/html/rfc7230#section-6.3"
    ]
  },
  {
    "id": "ssl-renegotiation-failed",
    "title": "SSL renegotiation failed",
    "category": "TLS",
    "explanation": "SSL/TLS renegotiation process failed, often due to security policies or implementation bugs.",
    "fix_snippet": "# Disable SSL renegotiation\n# In OpenSSL: SSL_OP_NO_RENEGOTIATION\n# Test without renegotiation\ncurl --no-ssl-allow-beast https://example.com",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_options.html"
    ]
  },
  {
    "id": "http-smuggling-detected",
    "title": "HTTP request smuggling detected",
    "category": "HTTP",
    "explanation": "Potential HTTP request smuggling attack detected, request blocked for security.",
    "fix_snippet": "# Check request formatting\n# Avoid ambiguous headers\n# Use HTTP/2 when possible\ncurl --http2 https://example.com",
    "sources": [
      "https://portswigger.net/web-security/request-smuggling"
    ]
  },
  {
    "id": "database-deadlock",
    "title": "Database deadlock",
    "category": "Network",
    "explanation": "Database transaction deadlock occurred, causing request to fail or timeout.",
    "fix_snippet": "# Retry transaction\n# Implement deadlock detection\n# Optimise query order\n# Check database logs for deadlock details",
    "sources": [
      "https://dev.mysql.com/doc/refman/8.0/en/innodb-deadlocks.html"
    ]
  },
  {
    "id": "memory-allocation-failed",
    "title": "Memory allocation failed",
    "category": "Network",
    "explanation": "Server ran out of memory while processing the request, causing allocation failures.",
    "fix_snippet": "# Check memory usage\nfree -h\n# Monitor memory consumption\ntop\n# Increase server memory limits\n# Optimise application memory usage",
    "sources": [
      "https://linux.die.net/man/1/free"
    ]
  },
  {
    "id": "ssl-version-rollback",
    "title": "SSL version rollback attack",
    "category": "TLS",
    "explanation": "Detected attempt to force connection to use older, vulnerable SSL/TLS versions.",
    "fix_snippet": "# Force minimum TLS version\ncurl --tlsv1.2 https://example.com\n# Configure server minimum TLS\n# In Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
    "sources": [
      "https://tools.ietf.org/html/rfc7457#section-3.1"
    ]
  },
  {
    "id": "api-version-mismatch",
    "title": "API version mismatch",
    "category": "HTTP",
    "explanation": "Client is using an incompatible API version that the server no longer supports.",
    "fix_snippet": "# Specify API version\ncurl -H \"Accept: application/vnd.api+json;version=2\" https://api.example.com\n# Check supported versions\ncurl -I https://api.example.com",
    "sources": [
      "https://restfulapi.net/versioning/"
    ]
  },
  {
    "id": "compression-bomb-detected",
    "title": "Compression bomb detected",
    "category": "HTTP",
    "explanation": "Malicious compressed content detected that could cause resource exhaustion when decompressed.",
    "fix_snippet": "# Disable compression\ncurl -H \"Accept-Encoding: identity\" https://example.com\n# Limit decompression size\n# Implement compression ratio checks",
    "sources": [
      "https://en.wikipedia.org/wiki/Zip_bomb"
    ]
  },
  {
    "id": "duplicate-header-error",
    "title": "Duplicate header error",
    "category": "HTTP",
    "explanation": "Multiple instances of the same HTTP header found, violating protocol specification.",
    "fix_snippet": "# Check for duplicate headers\ncurl -D headers.txt https://example.com\ngrep -i 'content-type' headers.txt\n# Fix server header generation",
    "sources": [
      "https://tools.ietf.org/html/rfc7230#section-3.2.2"
    ]
  },
  {
    "id": "websocket-frame-too-large",
    "title": "WebSocket frame too large",
    "category": "Network",
    "explanation": "WebSocket frame size exceeds the maximum allowed limit, connection terminated.",
    "fix_snippet": "# Reduce frame size\n# Implement frame fragmentation\n# Check WebSocket server limits\n# Split large messages into smaller frames",
    "sources": [
      "https://tools.ietf.org/html/rfc6455#section-5.7"
    ]
  },
  {
    "id": "oauth-scope-insufficient",
    "title": "OAuth insufficient scope",
    "category": "HTTP",
    "explanation": "OAuth token doesn't have the required scope/permissions to access the requested resource.",
    "fix_snippet": "# Request token with correct scopes\ncurl -X POST https://oauth.example.com/token \\\n  -d 'scope=read write&grant_type=client_credentials'\n# Check required scopes in API documentation",
    "sources": [
      "https://tools.ietf.org/html/rfc6749#section-3.3"
    ]
  },
  {
    "id": "npm-eacces-permission",
    "title": "npm EACCES: permission denied",
    "category": "Client",
    "explanation": "npm lacks permissions to write to the global directory. Often happens when trying to install packages globally without proper permissions.",
    "fix_snippet": "# Fix npm permissions (preferred method)\nnpm config set prefix ~/.npm-global\nexport PATH=~/.npm-global/bin:$PATH\n# Or use npx instead of global install\nnpx package-name",
    "sources": [
      "https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally"
    ]
  },
  {
    "id": "git-permission-denied-publickey",
    "title": "git@github.com: Permission denied (publickey)",
    "category": "Client",
    "explanation": "Git cannot authenticate with the remote repository using SSH keys. SSH key is missing, incorrect, or not added to the SSH agent.",
    "fix_snippet": "# Generate new SSH key\nssh-keygen -t ed25519 -C \"your_email@example.com\"\n# Add to SSH agent\nssh-add ~/.ssh/id_ed25519\n# Copy public key and add to GitHub\ncat ~/.ssh/id_ed25519.pub",
    "sources": [
      "https://docs.github.com/en/authentication/connecting-to-github-with-ssh"
    ]
  },
  {
    "id": "docker-permission-denied",
    "title": "docker: permission denied",
    "category": "Client",
    "explanation": "User lacks permissions to access the Docker daemon socket. Docker daemon requires root privileges or docker group membership.",
    "fix_snippet": "# Add user to docker group\nsudo usermod -aG docker $USER\n# Restart session or run\nnewgrp docker\n# Test access\ndocker run hello-world",
    "sources": [
      "https://docs.docker.com/engine/install/linux-postinstall/"
    ]
  },
  {
    "id": "python-modulenotfounderror",
    "title": "ModuleNotFoundError: No module named 'X'",
    "category": "Client",
    "explanation": "Python cannot find the specified module. Module is not installed, wrong Python environment, or incorrect PYTHONPATH.",
    "fix_snippet": "# Install module\npip install module-name\n# Check Python path\npython -c \"import sys; print(sys.path)\"\n# Use virtual environment\npython -m venv venv && source venv/bin/activate",
    "sources": [
      "https://docs.python.org/3/tutorial/modules.html"
    ]
  },
  {
    "id": "node-enoent-package-json",
    "title": "npm ERR! enoent ENOENT: no such file or directory, open 'package.json'",
    "category": "Client",
    "explanation": "npm command was run in a directory without a package.json file. npm expects to be run from a Node.js project directory.",
    "fix_snippet": "# Initialize new project\nnpm init -y\n# Or navigate to correct directory\ncd path/to/your/project\n# Or install globally\nnpm install -g package-name",
    "sources": [
      "https://docs.npmjs.com/creating-a-package-json-file"
    ]
  },
  {
    "id": "kubectl-connection-refused",
    "title": "kubectl: connection refused",
    "category": "Network",
    "explanation": "kubectl cannot connect to the Kubernetes API server. Cluster may be down, kubeconfig incorrect, or network connectivity issues.",
    "fix_snippet": "# Check cluster status\nkubectl cluster-info\n# Verify kubeconfig\nkubectl config view\n# Set correct context\nkubectl config use-context context-name\n# Check connectivity\ntelnet api-server-ip 6443",
    "sources": [
      "https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/"
    ]
  },
  {
    "id": "mysql-access-denied",
    "title": "MySQL: Access denied for user",
    "category": "Network",
    "explanation": "MySQL authentication failed due to incorrect username, password, or insufficient privileges for the specified host.",
    "fix_snippet": "# Connect as root to fix\nmysql -u root -p\n# Grant privileges\nGRANT ALL PRIVILEGES ON database.* TO 'user'@'host' IDENTIFIED BY 'password';\nFLUSH PRIVILEGES;\n# Check user privileges\nSHOW GRANTS FOR 'user'@'host';",
    "sources": [
      "https://dev.mysql.com/doc/refman/8.0/en/access-denied.html"
    ]
  },
  {
    "id": "postgres-connection-refused",
    "title": "psql: connection to server refused",
    "category": "Network",
    "explanation": "PostgreSQL server is not accepting connections. Server may be down, wrong host/port, or connection limits exceeded.",
    "fix_snippet": "# Check if PostgreSQL is running\nsudo systemctl status postgresql\n# Start if needed\nsudo systemctl start postgresql\n# Check configuration\nsudo nano /etc/postgresql/*/main/postgresql.conf\n# Test connection\npsql -h localhost -p 5432 -U username -d database",
    "sources": [
      "https://www.postgresql.org/docs/current/runtime-config-connection.html"
    ]
  },
  {
    "id": "ssh-connection-refused",
    "title": "ssh: connect to host X port 22: Connection refused",
    "category": "Network",
    "explanation": "SSH daemon is not running on the target host, port 22 is blocked, or host is unreachable.",
    "fix_snippet": "# Check SSH service status\nsudo systemctl status ssh\n# Start SSH service\nsudo systemctl start ssh\n# Check if port is open\nnmap -p 22 hostname\n# Try different port\nssh -p 2222 user@hostname",
    "sources": [
      "https://www.openssh.com/manual.html"
    ]
  },
  {
    "id": "elasticsearch-cluster-unavailable",
    "title": "Elasticsearch cluster unavailable",
    "category": "Network",
    "explanation": "Elasticsearch cluster is not responding, nodes are down, or cluster health is red/yellow with no available shards.",
    "fix_snippet": "# Check cluster health\ncurl -X GET \"localhost:9200/_cluster/health?pretty\"\n# Check node status\ncurl -X GET \"localhost:9200/_nodes?pretty\"\n# Restart Elasticsearch\nsudo systemctl restart elasticsearch",
    "sources": [
      "https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-health.html"
    ]
  },
  {
    "id": "mongodb-connection-timeout",
    "title": "MongoDB connection timeout",
    "category": "Network",
    "explanation": "MongoDB client cannot establish connection within the specified timeout period. Server overload, network issues, or incorrect connection string.",
    "fix_snippet": "# Check MongoDB status\nsudo systemctl status mongod\n# Test connection\nmongo --host hostname:27017\n# Check connection limits\ndb.serverStatus().connections\n# Increase timeout in connection string\nmongodb://host:port/db?connectTimeoutMS=30000",
    "sources": [
      "https://docs.mongodb.com/manual/reference/connection-string/"
    ]
  },
  {
    "id": "java-outofmemoryerror",
    "title": "java.lang.OutOfMemoryError",
    "category": "Client",
    "explanation": "Java application has exhausted available heap memory. Memory leak, insufficient heap size, or processing too much data.",
    "fix_snippet": "# Increase heap size\njava -Xmx2g -Xms512m YourApp\n# Enable garbage collection logging\njava -XX:+PrintGC -XX:+PrintGCDetails YourApp\n# Use memory profiler\njstat -gc pid 1s",
    "sources": [
      "https://docs.oracle.com/javase/8/docs/technotes/guides/troubleshoot/memleaks002.html"
    ]
  },
  {
    "id": "python-indentationerror",
    "title": "IndentationError: unexpected indent",
    "category": "Client",
    "explanation": "Python code has inconsistent indentation. Mixed tabs and spaces, or incorrect indentation level for the code block.",
    "fix_snippet": "# Check for mixed tabs/spaces\npython -m tabnanny your_file.py\n# Convert tabs to spaces\nexpand -t 4 your_file.py > fixed_file.py\n# Use consistent indentation (4 spaces recommended)\n# Configure editor to show whitespace",
    "sources": [
      "https://docs.python.org/3/tutorial/introduction.html#first-steps-towards-programming"
    ]
  },
  {
    "id": "node-heap-out-of-memory",
    "title": "FATAL ERROR: JavaScript heap out of memory",
    "category": "Client",
    "explanation": "Node.js process has exceeded the default memory limit (typically ~1.7GB). Large datasets, memory leaks, or insufficient heap size.",
    "fix_snippet": "# Increase memory limit\nnode --max-old-space-size=4096 your-script.js\n# For npm scripts\nexport NODE_OPTIONS=\"--max-old-space-size=4096\"\n# Check memory usage\nprocess.memoryUsage()",
    "sources": [
      "https://nodejs.org/api/cli.html#cli_max_old_space_size_size_in_megabytes"
    ]
  },
  {
    "id": "webpack-module-not-found",
    "title": "Module not found: Can't resolve 'X'",
    "category": "Client",
    "explanation": "Webpack cannot find the specified module. Incorrect import path, missing dependency, or case-sensitive file system issues.",
    "fix_snippet": "# Install missing dependency\nnpm install package-name\n# Check import path\n# Use relative path: import './file' not 'file'\n# Check file exists and case matches\nls -la src/components/",
    "sources": [
      "https://webpack.js.org/concepts/module-resolution/"
    ]
  },
  {
    "id": "typescript-cannot-find-module",
    "title": "TypeScript: Cannot find module 'X'",
    "category": "Client",
    "explanation": "TypeScript cannot resolve module imports. Missing type definitions, incorrect tsconfig.json, or module resolution issues.",
    "fix_snippet": "# Install type definitions\nnpm install @types/package-name\n# Check tsconfig.json module resolution\n\"moduleResolution\": \"node\"\n# Add to types array\n\"types\": [\"node\", \"package-name\"]",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/module-resolution.html"
    ]
  },
  {
    "id": "react-hooks-dependency-warning",
    "title": "React Hook useEffect has missing dependencies",
    "category": "Client",
    "explanation": "React Hook has dependencies that are not included in the dependency array, potentially causing stale closures or infinite re-renders.",
    "fix_snippet": "# Add missing dependencies\nuseEffect(() => {\n  // effect code\n}, [dependency1, dependency2]);\n\n# Use ESLint plugin\nnpm install eslint-plugin-react-hooks\n# Add to .eslintrc\n\"extends\": [\"plugin:react-hooks/recommended\"]",
    "sources": [
      "https://reactjs.org/docs/hooks-effect.html#tip-optimizing-performance-by-skipping-effects"
    ]
  },
  {
    "id": "vue-template-compilation-error",
    "title": "Vue template compilation failed",
    "category": "Client",
    "explanation": "Vue template contains syntax errors or uses features not available in the current Vue version. Invalid directives or template structure.",
    "fix_snippet": "# Check template syntax\n# Ensure proper closing tags\n# Use v-if instead of v-show for conditional rendering\n# Check Vue version compatibility\nnpm list vue",
    "sources": [
      "https://vuejs.org/guide/essentials/template-syntax.html"
    ]
  },
  {
    "id": "angular-cannot-resolve-dependency",
    "title": "Angular: Can't resolve all parameters",
    "category": "Client",
    "explanation": "Angular dependency injection cannot resolve constructor parameters. Missing providers, circular dependencies, or incorrect imports.",
    "fix_snippet": "# Add to providers array\nproviders: [YourService]\n# Use @Injectable decorator\n@Injectable({ providedIn: 'root' })\n# Check for circular imports\n# Import in module, not component",
    "sources": [
      "https://angular.io/guide/dependency-injection"
    ]
  },
  {
    "id": "icmp-destination-unreachable",
    "title": "ICMP Destination Unreachable (Type 3)",
    "category": "ICMP",
    "explanation": "Router cannot forward packet to destination. Various codes indicate specific reasons like network unreachable, host unreachable, or port unreachable.",
    "fix_snippet": "# Check routing table\nip route show\n# Test connectivity\nping -c 4 destination\n# Check firewall rules\nsudo iptables -L\n# Traceroute to find where packets stop\ntraceroute destination",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-source-quench",
    "title": "ICMP Source Quench (Type 4)",
    "category": "ICMP",
    "explanation": "Deprecated message indicating congestion control. Router was dropping packets due to lack of buffer space. Rarely used in modern networks.",
    "fix_snippet": "# Check network congestion\nss -tuln | grep -c ESTABLISHED\n# Monitor bandwidth usage\niftop\n# Check buffer sizes\nsysctl net.core.rmem_max",
    "sources": [
      "https://tools.ietf.org/html/rfc792",
      "https://tools.ietf.org/html/rfc6633"
    ]
  },
  {
    "id": "icmp-redirect",
    "title": "ICMP Redirect (Type 5)",
    "category": "ICMP",
    "explanation": "Router informs host of a better route to destination. Can be security risk if not properly validated, often disabled in production.",
    "fix_snippet": "# Disable ICMP redirects (security)\nsudo sysctl net.ipv4.conf.all.accept_redirects=0\n# Check current setting\nsysctl net.ipv4.conf.all.accept_redirects\n# Update routing table if legitimate\nsudo ip route add destination via better_gateway",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-echo-request-reply",
    "title": "ICMP Echo Request/Reply (Type 8/0)",
    "category": "ICMP",
    "explanation": "Ping mechanism. Echo Request (8) sent by client, Echo Reply (0) returned by destination. Used for connectivity testing.",
    "fix_snippet": "# Basic ping test\nping -c 4 8.8.8.8\n# Ping with specific packet size\nping -s 1024 destination\n# Continuous ping\nping destination\n# Enable ICMP if blocked\nsudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-time-exceeded",
    "title": "ICMP Time Exceeded (Type 11)",
    "category": "ICMP",
    "explanation": "TTL expired in transit (Code 0) or fragment reassembly timeout (Code 1). Common in traceroute operations or routing loops.",
    "fix_snippet": "# Check for routing loops\ntraceroute destination\n# Increase TTL if needed\nping -t 64 destination\n# Check fragmentation\nping -M do -s 1500 destination\n# Fix routing loop in config",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-parameter-problem",
    "title": "ICMP Parameter Problem (Type 12)",
    "category": "ICMP",
    "explanation": "Malformed IP header or required option missing. Indicates packet structure issues or unsupported IP options.",
    "fix_snippet": "# Check packet structure with tcpdump\nsudo tcpdump -i eth0 -v icmp\n# Verify IP options\nping -R destination\n# Check MTU settings\nip link show eth0",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-timestamp-request-reply",
    "title": "ICMP Timestamp Request/Reply (Type 13/14)",
    "category": "ICMP",
    "explanation": "Time synchronization mechanism. Often disabled for security reasons as it can leak system time information.",
    "fix_snippet": "# Disable timestamp replies (security)\nsudo iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP\n# Check if enabled\nsudo sysctl net.ipv4.icmp_echo_ignore_all",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-information-request-reply",
    "title": "ICMP Information Request/Reply (Type 15/16)",
    "category": "ICMP",
    "explanation": "Obsolete mechanism for obtaining network address information. Deprecated due to security concerns and better alternatives.",
    "fix_snippet": "# Block information requests (security)\nsudo iptables -A INPUT -p icmp --icmp-type info-request -j DROP\n# Use DHCP for network configuration instead\ndhclient eth0",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-network",
    "title": "ICMP Network Unreachable (Type 3, Code 0)",
    "category": "ICMP",
    "explanation": "No route to the destination network exists in router's routing table. Network may be down or improperly configured.",
    "fix_snippet": "# Check routing table\nip route show\n# Add missing route\nsudo ip route add network/mask via gateway\n# Check network interface status\nip addr show\n# Verify gateway connectivity\nping gateway_ip",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-host",
    "title": "ICMP Host Unreachable (Type 3, Code 1)",
    "category": "ICMP",
    "explanation": "Router cannot reach the specific host within the destination network. Host may be down, unreachable, or blocking ICMP.",
    "fix_snippet": "# Check ARP table\narp -a\n# Clear ARP cache if stale\nsudo arp -d host_ip\n# Test with different protocols\ntelnet host_ip port\n# Check if host is up\nnmap -sn host_ip",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-protocol",
    "title": "ICMP Protocol Unreachable (Type 3, Code 2)",
    "category": "ICMP",
    "explanation": "Destination host cannot process the packet due to unsupported or disabled protocol (TCP, UDP, etc.).",
    "fix_snippet": "# Check available protocols\ncat /proc/net/protocols\n# Test with different protocol\nnc -u host port  # UDP instead of TCP\n# Check firewall protocol rules\nsudo iptables -L -n",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-port",
    "title": "ICMP Port Unreachable (Type 3, Code 3)",
    "category": "ICMP",
    "explanation": "Destination host received packet but no application is listening on the specified UDP port. TCP uses RST instead.",
    "fix_snippet": "# Check if port is open\nnmap -p port host\n# List listening ports\nsudo netstat -tulpn | grep port\n# Test with TCP instead\ntelnet host port\n# Check firewall port rules\nsudo iptables -L -n | grep port",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-fragmentation",
    "title": "ICMP Fragmentation Needed (Type 3, Code 4)",
    "category": "ICMP",
    "explanation": "Packet too large for next hop link, but Don't Fragment bit is set. Critical for Path MTU Discovery.",
    "fix_snippet": "# Discover Path MTU\nping -M do -s 1500 destination\n# Set MTU on interface\nsudo ip link set dev eth0 mtu 1450\n# Check current MTU\nip link show eth0\n# Test different packet sizes\nfor size in 1500 1400 1300; do ping -M do -s $size -c 1 dest; done",
    "sources": [
      "https://tools.ietf.org/html/rfc1191"
    ]
  },
  {
    "id": "icmp-destination-unreachable-source-route",
    "title": "ICMP Source Route Failed (Type 3, Code 5)",
    "category": "ICMP",
    "explanation": "Packet with source routing option cannot be forwarded along the specified route. Often disabled for security.",
    "fix_snippet": "# Disable source routing (security)\nsudo sysctl net.ipv4.conf.all.accept_source_route=0\n# Check current setting\nsysctl net.ipv4.conf.all.accept_source_route\n# Remove source routing from packet",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-network-unknown",
    "title": "ICMP Destination Network Unknown (Type 3, Code 6)",
    "category": "ICMP",
    "explanation": "Router has no information about the destination network. Different from network unreachable - indicates unknown network.",
    "fix_snippet": "# Update routing table\nsudo ip route add network/mask via gateway\n# Check routing protocols\nsudo systemctl status quagga\n# Verify network configuration\nip addr show\n# Check DNS resolution\nnslookup destination",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-host-unknown",
    "title": "ICMP Destination Host Unknown (Type 3, Code 7)",
    "category": "ICMP",
    "explanation": "Router has no information about the specific host. Host may not exist or network infrastructure is incomplete.",
    "fix_snippet": "# Check ARP resolution\nping -c 1 host_ip\narp -a | grep host_ip\n# Update ARP table manually\nsudo arp -s host_ip mac_address\n# Check DHCP assignments\nsudo tail /var/log/dhcp/dhcpd.log",
    "sources": [
      "https://tools.ietf.org/html/rfc792"
    ]
  },
  {
    "id": "icmp-destination-unreachable-isolated",
    "title": "ICMP Network Administratively Prohibited (Type 3, Code 9)",
    "category": "ICMP",
    "explanation": "Network access is blocked by administrative policy, firewall rules, or access control lists.",
    "fix_snippet": "# Check firewall rules\nsudo iptables -L -v\n# Check access control lists\nsudo iptables -L FORWARD\n# Review routing policies\nip rule show\n# Contact network administrator",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "icmp-destination-unreachable-host-prohibited",
    "title": "ICMP Host Administratively Prohibited (Type 3, Code 10)",
    "category": "ICMP",
    "explanation": "Host access is specifically blocked by administrative policy or security rules.",
    "fix_snippet": "# Check host-based firewall\nsudo ufw status\n# Review iptables rules\nsudo iptables -L INPUT -v\n# Check hosts.allow/deny\ncat /etc/hosts.allow\ncat /etc/hosts.deny",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "icmp-destination-unreachable-tos-network",
    "title": "ICMP Network Unreachable for TOS (Type 3, Code 11)",
    "category": "ICMP",
    "explanation": "No route to destination network for the specified Type of Service. QoS routing issue.",
    "fix_snippet": "# Check TOS routing\nip route show table all\n# Remove TOS requirement\nping -Q 0 destination\n# Check QoS configuration\ntc qdisc show",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "icmp-destination-unreachable-tos-host",
    "title": "ICMP Host Unreachable for TOS (Type 3, Code 12)",
    "category": "ICMP",
    "explanation": "No route to destination host for the specified Type of Service. Host doesn't support required QoS.",
    "fix_snippet": "# Test without TOS\nping destination\n# Check TOS settings\nip route get destination\n# Modify TOS value\nping -Q 0x10 destination",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "icmp-destination-unreachable-communication-prohibited",
    "title": "ICMP Communication Administratively Prohibited (Type 3, Code 13)",
    "category": "ICMP",
    "explanation": "Communication between source and destination is blocked by administrative policy or firewall.",
    "fix_snippet": "# Check firewall policies\nsudo iptables -L -v -n\n# Review security policies\nsudo fail2ban-client status\n# Check SELinux policies\nsestatus",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "icmp-destination-unreachable-host-precedence",
    "title": "ICMP Host Precedence Violation (Type 3, Code 14)",
    "category": "ICMP",
    "explanation": "Packet precedence level is not permitted for the destination host. Security or QoS policy violation.",
    "fix_snippet": "# Check packet precedence\ntcpdump -i eth0 -v 'icmp'\n# Remove precedence bits\nping -Q 0 destination\n# Review QoS policies",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "icmp-destination-unreachable-precedence-cutoff",
    "title": "ICMP Precedence Cutoff in Effect (Type 3, Code 15)",
    "category": "ICMP",
    "explanation": "Network is dropping packets below a certain precedence level due to congestion or policy.",
    "fix_snippet": "# Increase packet precedence\nping -Q 0xc0 destination\n# Check network congestion\nping -f destination\n# Wait for congestion to clear",
    "sources": [
      "https://tools.ietf.org/html/rfc1812"
    ]
  },
  {
    "id": "docker-no-space-left",
    "title": "Docker: no space left on device",
    "category": "Docker",
    "explanation": "Docker has run out of disk space for images, containers, or volumes. /var/lib/docker partition is full or Docker storage driver quota exceeded.",
    "fix_snippet": "# Clean up unused resources\ndocker system prune -a --volumes\n# Check disk usage\ndocker system df\n# Remove specific images\ndocker rmi $(docker images -q)\n# Increase Docker storage",
    "sources": [
      "https://docs.docker.com/config/pruning/"
    ]
  },
  {
    "id": "docker-cannot-connect-daemon",
    "title": "Docker: Cannot connect to the Docker daemon",
    "category": "Docker",
    "explanation": "Docker client cannot communicate with Docker daemon. Daemon not running, socket permissions issue, or wrong socket path.",
    "fix_snippet": "# Start Docker daemon\nsudo systemctl start docker\n# Check daemon status\nsudo systemctl status docker\n# Check socket permissions\nsudo chmod 666 /var/run/docker.sock\n# Or add user to docker group\nsudo usermod -aG docker $USER",
    "sources": [
      "https://docs.docker.com/config/daemon/"
    ]
  },
  {
    "id": "docker-pull-rate-limit",
    "title": "Docker: pull rate limit exceeded",
    "category": "Docker",
    "explanation": "Docker Hub anonymous pull rate limit exceeded (100 pulls per 6 hours). Need authentication or use alternative registry.",
    "fix_snippet": "# Login to Docker Hub\ndocker login\n# Use authenticated pulls\ndocker pull username/image\n# Or use alternative registry\ndocker pull quay.io/image\n# Check rate limit status\ncurl https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull | jq",
    "sources": [
      "https://docs.docker.com/docker-hub/download-rate-limit/"
    ]
  },
  {
    "id": "docker-image-not-found",
    "title": "Docker: image not found",
    "category": "Docker",
    "explanation": "Specified Docker image does not exist in the registry, wrong image name, or missing tag specification.",
    "fix_snippet": "# Check image name and tag\ndocker search image-name\n# List available tags\ncurl -s https://registry.hub.docker.com/v2/repositories/library/image/tags | jq\n# Pull with explicit tag\ndocker pull image:tag\n# Check local images\ndocker images",
    "sources": [
      "https://docs.docker.com/engine/reference/commandline/pull/"
    ]
  },
  {
    "id": "docker-container-name-conflict",
    "title": "Docker: container name already in use",
    "category": "Docker",
    "explanation": "Attempting to create container with name that's already taken by existing container (running or stopped).",
    "fix_snippet": "# List all containers\ndocker ps -a\n# Remove existing container\ndocker rm container-name\n# Or force remove\ndocker rm -f container-name\n# Use different name\ndocker run --name new-name image",
    "sources": [
      "https://docs.docker.com/engine/reference/run/"
    ]
  },
  {
    "id": "docker-port-already-allocated",
    "title": "Docker: port is already allocated",
    "category": "Docker",
    "explanation": "Cannot bind container port because host port is already in use by another container or process.",
    "fix_snippet": "# Check what's using the port\nsudo netstat -tulpn | grep :port\nsudo lsof -i :port\n# Stop conflicting container\ndocker stop container-id\n# Use different host port\ndocker run -p 8081:80 image",
    "sources": [
      "https://docs.docker.com/config/containers/container-networking/"
    ]
  },
  {
    "id": "docker-build-failed-cache",
    "title": "Docker build: layer caching issues",
    "category": "Docker",
    "explanation": "Docker build failing or not using cache properly, resulting in slow builds or unexpected behavior.",
    "fix_snippet": "# Build without cache\ndocker build --no-cache -t image:tag .\n# Pull base image first\ndocker pull base-image:tag\n# Clean build cache\ndocker builder prune\n# Check layer caching\ndocker history image:tag",
    "sources": [
      "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
    ]
  },
  {
    "id": "docker-compose-network-error",
    "title": "Docker Compose: network configuration error",
    "category": "Docker",
    "explanation": "Docker Compose cannot create or connect to network. Name conflict, subnet overlap, or network driver issues.",
    "fix_snippet": "# Check existing networks\ndocker network ls\n# Remove old networks\ndocker network prune\n# Recreate with compose\ndocker-compose down && docker-compose up\n# Inspect network\ndocker network inspect network-name",
    "sources": [
      "https://docs.docker.com/compose/networking/"
    ]
  },
  {
    "id": "k8s-imagepullbackoff",
    "title": "Kubernetes: ImagePullBackOff",
    "category": "Kubernetes",
    "explanation": "Kubelet cannot pull container image. Wrong image name, authentication failed, or registry unreachable.",
    "fix_snippet": "# Check pod events\nkubectl describe pod pod-name\n# Verify image exists\ndocker pull image:tag\n# Create image pull secret\nkubectl create secret docker-registry regcred --docker-server=registry --docker-username=user --docker-password=pass\n# Check node connectivity\nkubectl get nodes",
    "sources": [
      "https://kubernetes.io/docs/concepts/containers/images/"
    ]
  },
  {
    "id": "k8s-crashloopbackoff",
    "title": "Kubernetes: CrashLoopBackOff",
    "category": "Kubernetes",
    "explanation": "Container starts but crashes immediately, Kubernetes repeatedly tries to restart it with exponential backoff.",
    "fix_snippet": "# Check logs\nkubectl logs pod-name --previous\n# Describe pod for events\nkubectl describe pod pod-name\n# Check liveness/readiness probes\nkubectl get pod pod-name -o yaml\n# Exec into container if possible\nkubectl exec -it pod-name -- /bin/sh",
    "sources": [
      "https://kubernetes.io/docs/tasks/debug-application-cluster/debug-pod-replication-controller/"
    ]
  },
  {
    "id": "k8s-insufficient-resources",
    "title": "Kubernetes: Insufficient CPU/Memory",
    "category": "Kubernetes",
    "explanation": "Pod cannot be scheduled because no node has enough CPU or memory resources available.",
    "fix_snippet": "# Check node resources\nkubectl top nodes\n# Describe node\nkubectl describe node node-name\n# Check pod resources\nkubectl top pods\n# Reduce resource requests\nkubectl edit deployment deployment-name\n# Scale cluster\nkubectl scale nodes",
    "sources": [
      "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
    ]
  },
  {
    "id": "k8s-pod-security-policy",
    "title": "Kubernetes: Pod Security Policy violation",
    "category": "Kubernetes",
    "explanation": "Pod violates cluster's Pod Security Policy. Running as root, privileged mode, or using restricted capabilities.",
    "fix_snippet": "# Check PSP\nkubectl get psp\n# Run as non-root user\nsecurityContext:\n  runAsNonRoot: true\n  runAsUser: 1000\n# Remove privileged flag\nprivileged: false\n# Check RBAC\nkubectl auth can-i use psp/policy-name",
    "sources": [
      "https://kubernetes.io/docs/concepts/policy/pod-security-policy/"
    ]
  },
  {
    "id": "k8s-service-no-endpoints",
    "title": "Kubernetes: Service has no endpoints",
    "category": "Kubernetes",
    "explanation": "Service created but no pods match the selector, traffic cannot be routed.",
    "fix_snippet": "# Check service and endpoints\nkubectl get svc service-name\nkubectl get endpoints service-name\n# Verify pod labels\nkubectl get pods --show-labels\n# Check selector\nkubectl describe svc service-name\n# Fix label matching\nkubectl edit svc service-name",
    "sources": [
      "https://kubernetes.io/docs/concepts/services-networking/service/"
    ]
  },
  {
    "id": "k8s-pvc-pending",
    "title": "Kubernetes: PersistentVolumeClaim Pending",
    "category": "Kubernetes",
    "explanation": "PVC cannot find matching PersistentVolume or StorageClass cannot provision volume.",
    "fix_snippet": "# Check PVC status\nkubectl describe pvc pvc-name\n# List available PVs\nkubectl get pv\n# Check StorageClass\nkubectl get sc\n# Create PV manually or fix StorageClass\n# Check provisioner logs\nkubectl logs -n kube-system provisioner-pod",
    "sources": [
      "https://kubernetes.io/docs/concepts/storage/persistent-volumes/"
    ]
  },
  {
    "id": "k8s-forbidden-rbac",
    "title": "Kubernetes: Forbidden - RBAC denies access",
    "category": "Kubernetes",
    "explanation": "User or service account lacks required RBAC permissions for the requested operation.",
    "fix_snippet": "# Check current permissions\nkubectl auth can-i verb resource --as=user\n# View roles\nkubectl get rolebinding -n namespace\n# Create role and binding\nkubectl create role role-name --verb=get,list --resource=pods\nkubectl create rolebinding binding-name --role=role-name --serviceaccount=namespace:sa-name",
    "sources": [
      "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
    ]
  },
  {
    "id": "k8s-oomkilled",
    "title": "Kubernetes: OOMKilled",
    "category": "Kubernetes",
    "explanation": "Container exceeded memory limit and was killed by the Out Of Memory killer.",
    "fix_snippet": "# Check pod status\nkubectl describe pod pod-name | grep -A 5 \"Last State\"\n# Increase memory limits\nresources:\n  limits:\n    memory: \"2Gi\"\n  requests:\n    memory: \"1Gi\"\n# Monitor memory usage\nkubectl top pod pod-name",
    "sources": [
      "https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/"
    ]
  },
  {
    "id": "terraform-state-locked",
    "title": "Terraform: State locked",
    "category": "Terraform",
    "explanation": "State file is locked by another Terraform operation. Previous operation didn't complete or crashed.",
    "fix_snippet": "# Force unlock (dangerous)\nterraform force-unlock lock-id\n# Check who has lock\nterraform state list\n# Wait for operation to complete\n# Check backend for lock info\n# Use different workspace\nterraform workspace select other",
    "sources": [
      "https://www.terraform.io/docs/language/state/locking.html"
    ]
  },
  {
    "id": "terraform-provider-not-found",
    "title": "Terraform: Provider not found",
    "category": "Terraform",
    "explanation": "Required provider is not installed or version constraint cannot be satisfied.",
    "fix_snippet": "# Initialize providers\nterraform init\n# Upgrade providers\nterraform init -upgrade\n# Check provider requirements\ncat versions.tf\n# Clear provider cache\nrm -rf .terraform\nterraform init",
    "sources": [
      "https://www.terraform.io/docs/language/providers/requirements.html"
    ]
  },
  {
    "id": "terraform-resource-already-exists",
    "title": "Terraform: Resource already exists",
    "category": "Terraform",
    "explanation": "Trying to create resource that already exists in cloud provider. Resource created outside Terraform or import needed.",
    "fix_snippet": "# Import existing resource\nterraform import resource.name id\n# Remove from state\nterraform state rm resource.name\n# Use data source instead\ndata \"aws_instance\" \"existing\" {\n  instance_id = \"i-xxxxx\"\n}",
    "sources": [
      "https://www.terraform.io/docs/cli/import/"
    ]
  },
  {
    "id": "terraform-cycle-dependency",
    "title": "Terraform: Cycle dependency detected",
    "category": "Terraform",
    "explanation": "Circular dependency in resource definitions, resources depend on each other in a loop.",
    "fix_snippet": "# Review resource dependencies\nterraform graph | dot -Tpng > graph.png\n# Use depends_on sparingly\n# Break circular reference\n# Use data sources for existing resources\n# Refactor resource dependencies",
    "sources": [
      "https://www.terraform.io/docs/internals/graph.html"
    ]
  },
  {
    "id": "terraform-authentication-failed",
    "title": "Terraform: Provider authentication failed",
    "category": "Terraform",
    "explanation": "Cannot authenticate with cloud provider. Missing credentials, expired tokens, or incorrect configuration.",
    "fix_snippet": "# Set AWS credentials\nexport AWS_ACCESS_KEY_ID=xxx\nexport AWS_SECRET_ACCESS_KEY=xxx\n# Or use AWS CLI config\naws configure\n# For Azure\naz login\n# Check provider config\nterraform console\nprovider::aws::region",
    "sources": [
      "https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication"
    ]
  },
  {
    "id": "terraform-remote-backend-error",
    "title": "Terraform: Remote backend configuration error",
    "category": "Terraform",
    "explanation": "Cannot access remote backend for state storage. S3 bucket missing, permission denied, or backend misconfigured.",
    "fix_snippet": "# Reconfigure backend\nterraform init -reconfigure\n# Check backend config\ncat backend.tf\n# Verify bucket exists and accessible\naws s3 ls s3://bucket-name\n# Migrate to local\nterraform init -migrate-state",
    "sources": [
      "https://www.terraform.io/docs/language/settings/backends/"
    ]
  },
  {
    "id": "ansible-unreachable-host",
    "title": "Ansible: Host unreachable",
    "category": "Ansible",
    "explanation": "Cannot connect to target host via SSH. Network issues, wrong IP, SSH not running, or key authentication failed.",
    "fix_snippet": "# Test SSH manually\nssh user@host\n# Check inventory\nansible-inventory --list\n# Test with ping module\nansible all -m ping\n# Use password auth\nansible-playbook playbook.yml --ask-pass\n# Increase timeout\nansible-playbook playbook.yml -e \"ansible_ssh_timeout=30\"",
    "sources": [
      "https://docs.ansible.com/ansible/latest/user_guide/intro_getting_started.html"
    ]
  },
  {
    "id": "ansible-sudo-password-required",
    "title": "Ansible: Privilege escalation password required",
    "category": "Ansible",
    "explanation": "Task requires sudo but password not provided. Target user needs sudo password for privilege escalation.",
    "fix_snippet": "# Provide sudo password\nansible-playbook playbook.yml --ask-become-pass\n# Or configure passwordless sudo\n# On target: visudo\nuser ALL=(ALL) NOPASSWD: ALL\n# Use become in playbook\nbecome: yes\nbecome_method: sudo",
    "sources": [
      "https://docs.ansible.com/ansible/latest/user_guide/become.html"
    ]
  },
  {
    "id": "ansible-module-not-found",
    "title": "Ansible: Module not found",
    "category": "Ansible",
    "explanation": "Specified module doesn't exist or isn't installed. Wrong module name or collection not installed.",
    "fix_snippet": "# Check module exists\nansible-doc module-name\n# Install collection\nansible-galaxy collection install community.general\n# Use FQCN\n- name: Task\n  community.general.module_name:\n# List installed modules\nansible-doc -l",
    "sources": [
      "https://docs.ansible.com/ansible/latest/user_guide/modules.html"
    ]
  },
  {
    "id": "ansible-syntax-error",
    "title": "Ansible: Playbook syntax error",
    "category": "Ansible",
    "explanation": "YAML syntax error in playbook. Indentation issues, invalid YAML, or missing required fields.",
    "fix_snippet": "# Check syntax\nansible-playbook playbook.yml --syntax-check\n# Validate YAML\nyamllint playbook.yml\n# Common issues: wrong indentation, missing colons\n# Use 2-space indentation\n# Check for tabs vs spaces",
    "sources": [
      "https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html"
    ]
  },
  {
    "id": "github-actions-quota-exceeded",
    "title": "GitHub Actions: Usage limit exceeded",
    "category": "CI/CD",
    "explanation": "Free tier minutes exhausted or concurrent job limit reached. Need to upgrade plan or wait for quota reset.",
    "fix_snippet": "# Check usage\n# Go to Settings -> Billing -> Actions\n# Optimise workflows\nif: github.event_name == 'push' && github.ref == 'refs/heads/main'\n# Use self-hosted runners\nruns-on: self-hosted\n# Cache dependencies\nuses: actions/cache@v3",
    "sources": [
      "https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions"
    ]
  },
  {
    "id": "gitlab-ci-artifact-expired",
    "title": "GitLab CI: Artifact expired",
    "category": "CI/CD",
    "explanation": "Build artifact has expired based on retention policy. Cannot download or use in dependent jobs.",
    "fix_snippet": "# Extend artifact expiration\nartifacts:\n  expire_in: 1 week\n  paths:\n    - build/\n# Or never expire\nartifacts:\n  expire_in: never\n# Re-run pipeline to regenerate",
    "sources": [
      "https://docs.gitlab.com/ee/ci/yaml/#artifactsexpire_in"
    ]
  },
  {
    "id": "jenkins-workspace-cleanup-failed",
    "title": "Jenkins: Workspace cleanup failed",
    "category": "CI/CD",
    "explanation": "Cannot clean workspace due to permission issues or file locks. Prevents build from starting.",
    "fix_snippet": "# Manual cleanup\nrm -rf /var/jenkins_home/workspace/job-name\n# In Jenkinsfile\ncleanWs()\n# Check permissions\nsudo chown -R jenkins:jenkins /var/jenkins_home\n# Use Docker for isolation\nagent { docker { image 'maven:3' } }",
    "sources": [
      "https://www.jenkins.io/doc/pipeline/tour/running-multiple-steps/"
    ]
  },
  {
    "id": "circleci-out-of-memory",
    "title": "CircleCI: Container ran out of memory",
    "category": "CI/CD",
    "explanation": "Build process exceeded container memory limit. Need larger resource class or Optimise build.",
    "fix_snippet": "# Use larger resource class\nresource_class: large\n# Or in config.yml\ndocker:\n  - image: cimg/node:16.10\n    resource_class: xlarge\n# Optimise build\n# Reduce parallel processes\n# Clear caches",
    "sources": [
      "https://circleci.com/docs/2.0/configuration-reference/#resource_class"
    ]
  },
  {
    "id": "aws-s3-bucket-access-denied",
    "title": "AWS S3: Access Denied",
    "category": "Cloud",
    "explanation": "IAM permissions insufficient to access S3 bucket. Bucket policy, ACL, or IAM policy blocking access.",
    "fix_snippet": "# Check IAM permissions\naws iam get-user-policy --user-name username --policy-name policy\n# Test access\naws s3 ls s3://bucket-name\n# Update bucket policy\naws s3api put-bucket-policy --bucket bucket-name --policy file://policy.json\n# Check ACL\naws s3api get-bucket-acl --bucket bucket-name",
    "sources": [
      "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-denied-errors.html"
    ]
  },
  {
    "id": "aws-ec2-instance-limit",
    "title": "AWS EC2: Instance limit exceeded",
    "category": "Cloud",
    "explanation": "Account has reached the limit for number of instances of a specific type in a region.",
    "fix_snippet": "# Check limits\naws service-quotas list-service-quotas --service-code ec2\n# Request increase\naws service-quotas request-service-quota-increase --service-code ec2 --quota-code L-1216C47A --desired-value 20\n# Or use AWS console\n# Service Quotas -> EC2 -> Request quota increase",
    "sources": [
      "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-resource-limits.html"
    ]
  },
  {
    "id": "aws-rds-connection-timeout",
    "title": "AWS RDS: Connection timeout",
    "category": "Cloud",
    "explanation": "Cannot connect to RDS instance. Security group blocking, wrong endpoint, or instance not publicly accessible.",
    "fix_snippet": "# Check security group\naws rds describe-db-instances --db-instance-identifier mydb\n# Allow inbound on port 3306/5432\naws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 3306 --cidr 0.0.0.0/0\n# Test connection\nmysql -h endpoint -u admin -p\n# Check public accessibility",
    "sources": [
      "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.Scenarios.html"
    ]
  },
  {
    "id": "aws-lambda-timeout",
    "title": "AWS Lambda: Function timeout",
    "category": "Cloud",
    "explanation": "Lambda function exceeded maximum execution time. Default is 3 seconds, max is 15 minutes.",
    "fix_snippet": "# Increase timeout\naws lambda update-function-configuration --function-name my-function --timeout 300\n# Check CloudWatch logs\naws logs tail /aws/lambda/my-function --follow\n# Optimise function code\n# Use async processing\n# Consider Step Functions for long workflows",
    "sources": [
      "https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-common.html"
    ]
  },
  {
    "id": "aws-iam-policy-syntax-error",
    "title": "AWS IAM: Policy syntax error",
    "category": "Cloud",
    "explanation": "IAM policy JSON is malformed or contains invalid actions, resources, or conditions.",
    "fix_snippet": "# Validate policy\naws iam simulate-principal-policy --policy-source-arn arn --action-names action\n# Check JSON syntax\njq . policy.json\n# Common issues:\n# - Missing comma\n# - Invalid action name\n# - Wrong resource ARN format\n# Use AWS Policy Simulator",
    "sources": [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
    ]
  },
  {
    "id": "azure-authentication-failed",
    "title": "Azure: Authentication failed",
    "category": "Cloud",
    "explanation": "Cannot authenticate with Azure. Expired credentials, wrong tenant, or insufficient permissions.",
    "fix_snippet": "# Login interactively\naz login\n# Use service principal\naz login --service-principal -u client-id -p client-secret --tenant tenant-id\n# Check account\naz account show\n# Set subscription\naz account set --subscription subscription-id",
    "sources": [
      "https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli"
    ]
  },
  {
    "id": "azure-resource-not-found",
    "title": "Azure: Resource not found",
    "category": "Cloud",
    "explanation": "Specified Azure resource doesn't exist or is in different resource group/subscription.",
    "fix_snippet": "# List resources\naz resource list\n# Search in all resource groups\naz resource list --name resource-name\n# Check resource group\naz group show --name resource-group\n# Check subscription\naz account show",
    "sources": [
      "https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resources-cli"
    ]
  },
  {
    "id": "azure-quota-exceeded",
    "title": "Azure: Quota exceeded",
    "category": "Cloud",
    "explanation": "Subscription has reached quota limit for VMs, cores, or other resources in a region.",
    "fix_snippet": "# Check quota\naz vm list-usage --location eastus -o table\n# Request increase\n# Go to Azure portal -> Subscriptions -> Usage + quotas\n# Or use support ticket\naz support tickets create",
    "sources": [
      "https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits"
    ]
  },
  {
    "id": "gcp-permission-denied",
    "title": "GCP: Permission denied",
    "category": "Cloud",
    "explanation": "Service account or user lacks required IAM permissions for the operation.",
    "fix_snippet": "# Check permissions\ngcloud projects get-iam-policy project-id\n# Add role\ngcloud projects add-iam-policy-binding project-id --member=user:email --role=roles/editor\n# Test permissions\ngcloud auth list\n# Use service account\ngcloud auth activate-service-account --key-file=key.json",
    "sources": [
      "https://cloud.google.com/iam/docs/overview"
    ]
  },
  {
    "id": "gcp-quota-exceeded",
    "title": "GCP: Quota exceeded",
    "category": "Cloud",
    "explanation": "Project has exceeded quota for API requests, compute instances, or other resources.",
    "fix_snippet": "# Check quotas\ngcloud compute project-info describe --project=project-id\n# Request increase\n# Go to Cloud Console -> IAM & Admin -> Quotas\n# Filter and select quota\n# Click \"Edit Quotas\"\n# Optimise usage or wait for quota reset",
    "sources": [
      "https://cloud.google.com/docs/quota"
    ]
  },
  {
    "id": "mysql-too-many-connections",
    "title": "MySQL: Too many connections",
    "category": "Database",
    "explanation": "Maximum number of concurrent connections reached. Connection pool exhausted or connection leak.",
    "fix_snippet": "# Check current connections\nSHOW PROCESSLIST;\n# Increase max connections\nSET GLOBAL max_connections = 500;\n# In my.cnf\nmax_connections = 500\n# Kill idle connections\nKILL connection_id;\n# Check for connection leaks in application",
    "sources": [
      "https://dev.mysql.com/doc/refman/8.0/en/too-many-connections.html"
    ]
  },
  {
    "id": "postgres-deadlock-detected",
    "title": "PostgreSQL: Deadlock detected",
    "category": "Database",
    "explanation": "Two or more transactions are waiting for each other to release locks, creating a deadlock.",
    "fix_snippet": "# Check active locks\nSELECT * FROM pg_locks WHERE NOT granted;\n# View blocking queries\nSELECT * FROM pg_stat_activity WHERE wait_event_type = 'Lock';\n# Kill blocking query\nSELECT pg_terminate_backend(pid);\n# Optimise transaction order\n# Use NOWAIT or lock timeout",
    "sources": [
      "https://www.postgresql.org/docs/current/explicit-locking.html"
    ]
  },
  {
    "id": "mongodb-write-concern-error",
    "title": "MongoDB: Write concern error",
    "category": "Database",
    "explanation": "Write operation failed to meet specified write concern. Replica set nodes unavailable or acknowledgment timeout.",
    "fix_snippet": "# Check replica set status\nrs.status()\n# Use lower write concern\ndb.collection.insertOne(doc, { writeConcern: { w: 1 } })\n# Check network connectivity\n# Increase wtimeout\nwriteConcern: { w: \"majority\", wtimeout: 5000 }",
    "sources": [
      "https://docs.mongodb.com/manual/reference/write-concern/"
    ]
  },
  {
    "id": "redis-maxmemory-reached",
    "title": "Redis: OOM command not allowed when used memory > 'maxmemory'",
    "category": "Database",
    "explanation": "Redis has reached maximum memory limit and cannot accept write operations.",
    "fix_snippet": "# Check memory usage\nredis-cli INFO memory\n# Increase maxmemory\nredis-cli CONFIG SET maxmemory 2gb\n# Set eviction policy\nredis-cli CONFIG SET maxmemory-policy allkeys-lru\n# Clear old keys\nredis-cli FLUSHDB\n# Monitor memory\nredis-cli --stat",
    "sources": [
      "https://redis.io/topics/lru-cache"
    ]
  },
  {
    "id": "prometheus-target-down",
    "title": "Prometheus: Target down",
    "category": "Monitoring",
    "explanation": "Prometheus cannot scrape metrics from target endpoint. Service down, network issue, or wrong configuration.",
    "fix_snippet": "# Check target status\ncurl http://prometheus:9090/targets\n# Test endpoint\ncurl http://target:9090/metrics\n# Check Prometheus config\nprometheus --config.file=prometheus.yml --dry-run\n# Reload config\nkill -HUP prometheus-pid",
    "sources": [
      "https://prometheus.io/docs/prometheus/latest/configuration/configuration/"
    ]
  },
  {
    "id": "grafana-datasource-error",
    "title": "Grafana: Data source connection error",
    "category": "Monitoring",
    "explanation": "Grafana cannot connect to data source. Wrong URL, authentication failed, or data source unreachable.",
    "fix_snippet": "# Test data source\n# Go to Configuration -> Data Sources -> Test\n# Check URL and credentials\n# For Prometheus: http://prometheus:9090\n# Check network connectivity\ncurl http://datasource-url\n# Check Grafana logs\ntail -f /var/log/grafana/grafana.log",
    "sources": [
      "https://grafana.com/docs/grafana/latest/datasources/"
    ]
  },
  {
    "id": "elasticsearch-shard-allocation-failed",
    "title": "Elasticsearch: Shard allocation failed",
    "category": "Database",
    "explanation": "Cannot allocate shards to nodes. Disk space low, node disconnected, or allocation settings restrictive.",
    "fix_snippet": "# Check cluster health\ncurl -X GET \"localhost:9200/_cluster/health?pretty\"\n# Check shard allocation\ncurl -X GET \"localhost:9200/_cat/shards?v\"\n# Enable allocation\ncurl -X PUT \"localhost:9200/_cluster/settings\" -H 'Content-Type: application/json' -d'{\n  \"transient\": {\"cluster.routing.allocation.enable\": \"all\"}\n}'\n# Retry failed shards\ncurl -X POST \"localhost:9200/_cluster/reroute?retry_failed=true\"",
    "sources": [
      "https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-reroute.html"
    ]
  },
  {
    "id": "nginx-upstream-timeout",
    "title": "Nginx: Upstream request timeout",
    "category": "Proxy",
    "explanation": "Nginx timed out waiting for response from upstream server. Backend processing too slow or unresponsive.",
    "fix_snippet": "# Increase timeout in nginx.conf\nproxy_read_timeout 300s;\nproxy_connect_timeout 300s;\nproxy_send_timeout 300s;\n# Check upstream health\ncurl http://upstream-server/health\n# Check nginx error log\ntail -f /var/log/nginx/error.log",
    "sources": [
      "http://nginx.org/en/docs/http/ngx_http_proxy_module.html"
    ]
  },
  {
    "id": "ssl-certificate-validation-failed",
    "title": "SSL certificate validation failed",
    "category": "TLS",
    "explanation": "Certificate validation failed due to expired cert, wrong hostname, or untrusted CA.",
    "fix_snippet": "# Check certificate details\nopenssl s_client -connect example.com:443 -servername example.com\n# Verify certificate chain\nopenssl verify -CAfile ca-bundle.crt cert.pem\n# Check expiration\nopenssl x509 -in cert.pem -noout -dates\n# Renew certificate\ncertbot renew",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/verify.html"
    ]
  },
  {
    "id": "git-merge-conflict",
    "title": "Git: Merge conflict",
    "category": "Git",
    "explanation": "Cannot automatically merge changes because same lines were modified in different branches.",
    "fix_snippet": "# View conflicts\ngit status\n# Open conflicted files and resolve\n# After resolving\ngit add file.txt\ngit commit -m \"Resolved merge conflict\"\n# Or abort merge\ngit merge --abort",
    "sources": [
      "https://git-scm.com/docs/git-merge"
    ]
  },
  {
    "id": "git-large-file-rejected",
    "title": "Git: File size exceeds limit",
    "category": "Git",
    "explanation": "GitHub/GitLab rejects push because file exceeds size limit (typically 100MB). Need Git LFS.",
    "fix_snippet": "# Use Git LFS\ngit lfs install\ngit lfs track \"*.zip\"\ngit add .gitattributes\ngit add large-file.zip\ngit commit -m \"Add large file\"\n# Or remove from history\ngit filter-branch --tree-filter 'rm -f large-file.zip' HEAD",
    "sources": [
      "https://git-lfs.github.com/"
    ]
  },
  {
    "id": "pip-ssl-certificate-verify-failed",
    "title": "pip: SSL Certificate Verify Failed",
    "category": "Python",
    "explanation": "pip cannot verify SSL certificates when downloading packages. Corporate proxy, firewall, or outdated CA certificates.",
    "fix_snippet": "# Trust PyPI (temporary)\npip install --trusted-host pypi.org --trusted-host files.pythonhosted.org package-name\n# Update certificates\npip install --upgrade certifi",
    "sources": [
      "https://pip.pypa.io/en/stable/topics/https-certificates/"
    ]
  },
  {
    "id": "npm-network-socket-timeout",
    "title": "npm: Network socket timeout",
    "category": "JavaScript",
    "explanation": "npm registry request timed out. Slow network, firewall blocking, or npm registry issues.",
    "fix_snippet": "# Increase timeout\nnpm config set fetch-retry-mintimeout 20000\nnpm config set fetch-retry-maxtimeout 120000\n# Use different registry\nnpm config set registry https://registry.npmjs.org/\n# Clear cache\nnpm cache clean --force",
    "sources": [
      "https://docs.npmjs.com/cli/v8/commands/npm-config"
    ]
  },
  {
    "id": "linux-disk-space-full",
    "title": "Linux: No space left on device",
    "category": "System",
    "explanation": "File system is full. Cannot write files or create directories.",
    "fix_snippet": "# Check disk usage\ndf -h\n# Find large directories\ndu -sh /* | sort -hr | head -20\n# Clean package cache\nsudo apt clean\n# Clean logs\nsudo journalctl --vacuum-time=7d",
    "sources": [
      "https://linux.die.net/man/1/df"
    ]
  },
  {
    "id": "jwt-token-expired",
    "title": "JWT: Token expired",
    "category": "Security",
    "explanation": "JSON Web Token has exceeded its expiration time. Need to refresh token or re-authenticate.",
    "fix_snippet": "# Decode token to check expiry\nimport jwt\ndecoded = jwt.decode(token, verify=False)\nprint(decoded['exp'])\n# Refresh token\nresponse = requests.post('https://api.example.com/refresh')\nnew_token = response.json()['access_token']",
    "sources": [
      "https://jwt.io/introduction"
    ]
  },
  {
    "id": "api-rate-limit-per-minute",
    "title": "API: Rate limit exceeded (per minute)",
    "category": "API",
    "explanation": "Too many API requests in the last minute. Need to implement rate limiting or backoff.",
    "fix_snippet": "# Implement exponential backoff\nimport time\nfor i in range(5):\n    response = requests.get(url)\n    if response.status_code == 429:\n        time.sleep(60)\n        continue\n    break",
    "sources": [
      "https://tools.ietf.org/html/rfc6585#section-4"
    ]
  },
  {
    "id": "s3-bucket-not-found",
    "title": "AWS S3: Bucket does not exist",
    "category": "Storage",
    "explanation": "Specified S3 bucket doesn't exist or is in different region.",
    "fix_snippet": "# Check bucket exists\naws s3 ls s3://bucket-name\n# List all buckets\naws s3 ls\n# Check region\naws s3api get-bucket-location --bucket bucket-name",
    "sources": [
      "https://docs.aws.amazon.com/cli/latest/reference/s3/"
    ]
  },
  {
    "id": "rabbitmq-connection-refused",
    "title": "RabbitMQ: Connection refused",
    "category": "MessageQueue",
    "explanation": "Cannot connect to RabbitMQ server. Service not running, wrong port, or firewall blocking.",
    "fix_snippet": "# Check RabbitMQ status\nsudo systemctl status rabbitmq-server\n# Start if needed\nsudo systemctl start rabbitmq-server\n# Test connection\nrabbitmqctl status\n# Check firewall\nsudo ufw allow 5672/tcp",
    "sources": [
      "https://www.rabbitmq.com/troubleshooting.html"
    ]
  },
  {
    "id": "selinux-permission-denied",
    "title": "SELinux: Permission denied",
    "category": "Security",
    "explanation": "SELinux policy blocking operation. File context mismatch or policy violation.",
    "fix_snippet": "# Check SELinux status\ngetenforce\n# Check denials\nausearch -m avc -ts recent\n# Fix file context\nrestorecon -Rv /path\n# Temporarily set permissive\nsetenforce 0",
    "sources": [
      "https://selinuxproject.org/"
    ]
  },
  {
    "id": "systemd-unit-failed",
    "title": "systemd: Unit failed to start",
    "category": "System",
    "explanation": "systemd service failed to start. Configuration error, dependency issues, or permission problems.",
    "fix_snippet": "# Check service status\nsystemctl status service-name\n# View logs\njournalctl -u service-name -n 50\n# Check unit file\nsystemctl cat service-name\n# Reload systemd\nsystemctl daemon-reload",
    "sources": [
      "https://www.freedesktop.org/software/systemd/man/"
    ]
  },
  {
    "id": "cron-job-not-running",
    "title": "Cron: Job not running",
    "category": "System",
    "explanation": "Cron job not executing. Syntax error, permission issues, or cron daemon not running.",
    "fix_snippet": "# Check cron service\nsystemctl status cron\n# View cron logs\ngrep CRON /var/log/syslog\n# Edit crontab\ncrontab -e\n# List cron jobs\ncrontab -l",
    "sources": [
      "https://man7.org/linux/man-pages/man5/crontab.5.html"
    ]
  },
  {
    "id": "nfs-mount-timeout",
    "title": "NFS: Mount timeout",
    "category": "Storage",
    "explanation": "NFS mount operation timed out. Server unreachable, firewall blocking, or NFS service down.",
    "fix_snippet": "# Check NFS server\nshowmount -e nfs-server\n# Test connectivity\nping nfs-server\n# Mount with options\nmount -t nfs -o soft,timeo=30 server:/export /mnt",
    "sources": [
      "https://linux.die.net/man/5/nfs"
    ]
  },
  {
    "id": "python-package-conflict",
    "title": "Python: Package version conflict",
    "category": "Python",
    "explanation": "pip cannot install package due to conflicting dependency versions.",
    "fix_snippet": "# Check installed packages\npip list\n# Show package dependencies\npip show package-name\n# Use virtual environment\npython -m venv venv\nsource venv/bin/activate\n# Force reinstall\npip install --force-reinstall package-name",
    "sources": [
      "https://pip.pypa.io/en/stable/"
    ]
  },
  {
    "id": "node-gyp-build-failed",
    "title": "Node.js: node-gyp build failed",
    "category": "JavaScript",
    "explanation": "Native module compilation failed. Missing build tools or incompatible Node version.",
    "fix_snippet": "# Install build tools (Windows)\nnpm install --global windows-build-tools\n# Install build tools (Linux)\nsudo apt-get install build-essential\n# Clear npm cache\nnpm cache clean --force\n# Rebuild\nnpm rebuild",
    "sources": [
      "https://github.com/nodejs/node-gyp"
    ]
  },
  {
    "id": "oauth-token-revoked",
    "title": "OAuth: Token revoked",
    "category": "Security",
    "explanation": "OAuth access token has been revoked. User revoked access or token was compromised.",
    "fix_snippet": "# Re-authenticate user\n# Redirect to authorization URL\n# Clear stored tokens\n# Request new access token\n# Check token status endpoint",
    "sources": [
      "https://tools.ietf.org/html/rfc7009"
    ]
  },
  {
    "id": "api-endpoint-deprecated",
    "title": "API: Endpoint deprecated",
    "category": "API",
    "explanation": "API endpoint is deprecated and will be removed. Need to migrate to new version.",
    "fix_snippet": "# Check API documentation for migration guide\n# Update API version in headers\n# Example: api.example.com/v2/endpoint\n# Test new endpoint thoroughly\n# Update all API calls",
    "sources": [
      "https://restfulapi.net/"
    ]
  },
  {
    "id": "kafka-offset-out-of-range",
    "title": "Kafka: Offset out of range",
    "category": "MessageQueue",
    "explanation": "Consumer trying to read from offset that doesn't exist. Data retention deleted old messages.",
    "fix_snippet": "# Reset consumer offset\nkafka-consumer-groups.sh --bootstrap-server localhost:9092 \\\n  --group my-group --reset-offsets --to-earliest --topic my-topic --execute\n# Or reset to latest\n--reset-offsets --to-latest",
    "sources": [
      "https://kafka.apache.org/documentation/"
    ]
  },
  {
    "id": "s3-access-denied-bucket-policy",
    "title": "S3: Access denied by bucket policy",
    "category": "Storage",
    "explanation": "S3 bucket policy explicitly denies access. Need to update bucket policy or IAM permissions.",
    "fix_snippet": "# Check bucket policy\naws s3api get-bucket-policy --bucket bucket-name\n# Check IAM permissions\naws iam get-user-policy --user-name user --policy-name policy\n# Test access\naws s3 ls s3://bucket-name --debug",
    "sources": [
      "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html"
    ]
  },
  {
    "id": "csrf-token-invalid",
    "title": "CSRF: Token invalid or missing",
    "category": "Security",
    "explanation": "Cross-Site Request Forgery token is invalid, expired, or missing from request.",
    "fix_snippet": "# Include CSRF token in form\n<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n# Or in AJAX header\nheaders: {'X-CSRF-Token': csrfToken}\n# Refresh token if expired",
    "sources": [
      "https://owasp.org/www-community/attacks/csrf"
    ]
  },
  {
    "id": "python-import-circular",
    "title": "Python: Circular import detected",
    "category": "Python",
    "explanation": "Module A imports module B which imports module A, creating a circular dependency.",
    "fix_snippet": "# Move import inside function\ndef my_function():\n    from module_b import something\n    ...\n# Or restructure code to avoid circular import\n# Use import at bottom of file\n# Refactor to common module",
    "sources": [
      "https://docs.python.org/3/faq/programming.html#what-are-the-best-practices-for-using-import-in-a-module"
    ]
  },
  {
    "id": "javascript-cors-credentials",
    "title": "JavaScript: CORS credentials not allowed",
    "category": "JavaScript",
    "explanation": "Cannot use credentials with wildcard origin. CORS policy requires specific origin when using credentials.",
    "fix_snippet": "# Server side - specify exact origin\nAccess-Control-Allow-Origin: https://example.com\nAccess-Control-Allow-Credentials: true\n# Client side\nfetch(url, {\n  credentials: 'include',\n  mode: 'cors'\n})",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
    ]
  },
  {
    "id": "api-payload-too-large",
    "title": "API: Request payload too large",
    "category": "API",
    "explanation": "API request body exceeds maximum allowed size. Need to reduce payload or use chunking.",
    "fix_snippet": "# Split into multiple requests\n# Use pagination for large datasets\n# Compress request body\n# Upload large files to S3 first, send URL\n# Check API limits in documentation",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/413"
    ]
  },
  {
    "id": "redis-maxclients-reached",
    "title": "Redis: Max clients reached",
    "category": "Database",
    "explanation": "Redis has reached maximum number of client connections. Need to close connections or increase limit.",
    "fix_snippet": "# Check current connections\nredis-cli CLIENT LIST | wc -l\n# Increase max clients\nredis-cli CONFIG SET maxclients 10000\n# In redis.conf\nmaxclients 10000\n# Check for connection leaks",
    "sources": [
      "https://redis.io/topics/clients"
    ]
  },
  {
    "id": "systemd-timeout",
    "title": "systemd: Start operation timed out",
    "category": "System",
    "explanation": "Service took longer than configured timeout to start. Increase timeout or fix slow startup.",
    "fix_snippet": "# Increase timeout in service unit\n[Service]\nTimeoutStartSec=300\n# Reload systemd\nsystemctl daemon-reload\n# Check what's causing slow start\njournalctl -u service-name",
    "sources": [
      "https://www.freedesktop.org/software/systemd/man/systemd.service.html"
    ]
  },
  {
    "id": "api-authentication-bearer-missing",
    "title": "API: Bearer token missing or malformed",
    "category": "API",
    "explanation": "API requires Bearer token in Authorization header but token is missing or invalid format.",
    "fix_snippet": "# Correct format\ncurl -H \"Authorization: Bearer YOUR_TOKEN_HERE\" https://api.example.com\n# In JavaScript\nfetch(url, {\n  headers: {\n    'Authorization': `Bearer ${token}`\n  }\n})",
    "sources": [
      "https://tools.ietf.org/html/rfc6750"
    ]
  },
  {
    "id": "python-asyncio-loop-closed",
    "title": "Python: Event loop is closed",
    "category": "Python",
    "explanation": "Attempting to use closed asyncio event loop. Need to create new loop or fix cleanup order.",
    "fix_snippet": "# Create new event loop\nimport asyncio\nloop = asyncio.new_event_loop()\nasyncio.set_event_loop(loop)\n# Or use asyncio.run()\nasyncio.run(main())\n# Avoid loop.close() in wrong place",
    "sources": [
      "https://docs.python.org/3/library/asyncio-eventloop.html"
    ]
  },
  {
    "id": "javascript-promise-unhandled-rejection",
    "title": "JavaScript: Unhandled promise rejection",
    "category": "JavaScript",
    "explanation": "Promise rejected but no .catch() handler or try/catch block present.",
    "fix_snippet": "# Add catch handler\npromise\n  .then(result => console.log(result))\n  .catch(error => console.error(error));\n# Or use async/await with try/catch\ntry {\n  const result = await promise;\n} catch (error) {\n  console.error(error);\n}",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises"
    ]
  },
  {
    "id": "storage-quota-exceeded-browser",
    "title": "Browser: Storage quota exceeded",
    "category": "Storage",
    "explanation": "localStorage or IndexedDB quota exceeded. Browser has storage limits per origin.",
    "fix_snippet": "# Check storage usage\nnavigator.storage.estimate().then(estimate => {\n  console.log(estimate.usage / estimate.quota);\n});\n# Clear old data\nlocalStorage.clear();\n# Use compression\n# Request persistent storage\nnavigator.storage.persist()",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/API/Storage_API"
    ]
  },
  {
    "id": "api-graphql-query-complexity",
    "title": "GraphQL: Query complexity exceeded",
    "category": "API",
    "explanation": "GraphQL query too complex and exceeds server limits. Reduce nesting or field count.",
    "fix_snippet": "# Reduce query depth\n# Remove unnecessary fields\n# Split into multiple simpler queries\n# Use query pagination\n# Check complexity limits in API docs",
    "sources": [
      "https://graphql.org/learn/"
    ]
  },
  {
    "id": "security-header-missing",
    "title": "Security: Required security header missing",
    "category": "Security",
    "explanation": "HTTP response missing important security headers like CSP, HSTS, or X-Frame-Options.",
    "fix_snippet": "# Add security headers in nginx\nadd_header X-Frame-Options \"SAMEORIGIN\";\nadd_header X-Content-Type-Options \"nosniff\";\nadd_header Content-Security-Policy \"default-src 'self'\";\nadd_header Strict-Transport-Security \"max-age=31536000;\"",
    "sources": [
      "https://owasp.org/www-project-secure-headers/"
    ]
  },
  {
    "id": "python-pickle-unpickling-error",
    "title": "Python: Unpickling error - module not found",
    "category": "Python",
    "explanation": "Cannot unpickle object because module or class definition changed or missing.",
    "fix_snippet": "# Use same Python version\n# Ensure all modules available\n# Alternative: use JSON instead\nimport json\nwith open('data.json', 'w') as f:\n    json.dump(data, f)\n# Or use dill for better compatibility\nimport dill",
    "sources": [
      "https://docs.python.org/3/library/pickle.html"
    ]
  },
  {
    "id": "javascript-memory-leak-event-listeners",
    "title": "JavaScript: Memory leak from event listeners",
    "category": "JavaScript",
    "explanation": "Event listeners not removed when elements destroyed, causing memory leaks.",
    "fix_snippet": "# Remove event listeners\nelement.removeEventListener('click', handler);\n# Or use AbortController\nconst controller = new AbortController();\nelement.addEventListener('click', handler, {\n  signal: controller.signal\n});\n// Later: controller.abort();",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/removeEventListener"
    ]
  },
  {
    "id": "system-zombie-process",
    "title": "System: Zombie process accumulation",
    "category": "System",
    "explanation": "Parent process not reaping child processes. Zombie processes accumulating in system.",
    "fix_snippet": "# Find zombie processes\nps aux | grep 'Z'\n# Kill parent process\nkill -9 parent_pid\n# In code: properly wait for children\nimport subprocess\nprocess.wait()  # Python\nwait()  // C",
    "sources": [
      "https://en.wikipedia.org/wiki/Zombie_process"
    ]
  },
  {
    "id": "api-webhook-verification-failed",
    "title": "API: Webhook signature verification failed",
    "category": "API",
    "explanation": "Webhook payload signature doesn't match computed signature. Possible tampering or wrong secret.",
    "fix_snippet": "# Verify webhook signature\nimport hmac\nimport hashlib\nexpected = hmac.new(\n    secret.encode(),\n    payload.encode(),\n    hashlib.sha256\n).hexdigest()\nif not hmac.compare_digest(expected, received):\n    raise ValueError('Invalid signature')",
    "sources": [
      "https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks"
    ]
  },
  {
    "id": "storage-s3-eventual-consistency",
    "title": "S3: Eventual consistency causing read-after-write issues",
    "category": "Storage",
    "explanation": "Reading S3 object immediately after write may return old version due to eventual consistency.",
    "fix_snippet": "# S3 is now strongly consistent for new objects\n# For older regions, add delay\nimport time\ntime.sleep(1)\n# Or add retry logic\n# Use versioning to ensure correct version\n# Enable strong consistency regions",
    "sources": [
      "https://aws.amazon.com/s3/consistency/"
    ]
  },
  {
    "id": "python-gil-bottleneck",
    "title": "Python: GIL causing performance bottleneck",
    "category": "Python",
    "explanation": "Global Interpreter Lock preventing true multithreading. CPU-bound tasks not parallelizing.",
    "fix_snippet": "# Use multiprocessing instead of threading\nfrom multiprocessing import Pool\nwith Pool(4) as p:\n    results = p.map(func, data)\n# Or use asyncio for I/O bound\n# Or use Cython/numba for performance",
    "sources": [
      "https://wiki.python.org/moin/GlobalInterpreterLock"
    ]
  },
  {
    "id": "javascript-this-undefined",
    "title": "JavaScript: 'this' is undefined in callback",
    "category": "JavaScript",
    "explanation": "Context lost when passing method as callback. Need to bind context or use arrow function.",
    "fix_snippet": "# Use arrow function\nsetTimeout(() => this.method(), 1000);\n# Or bind context\nsetTimeout(this.method.bind(this), 1000);\n# Or store context\nconst self = this;\nsetTimeout(function() { self.method(); }, 1000);",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/this"
    ]
  },
  {
    "id": "security-sql-injection-detected",
    "title": "Security: SQL injection vulnerability detected",
    "category": "Security",
    "explanation": "User input directly concatenated into SQL query. Critical security vulnerability.",
    "fix_snippet": "# Use parameterized queries\n# BAD: sql = f\"SELECT * FROM users WHERE id={user_id}\"\n# GOOD:\ncursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))\n# Or use ORM\nUser.objects.filter(id=user_id)",
    "sources": [
      "https://owasp.org/www-community/attacks/SQL_Injection"
    ]
  },
  {
    "id": "api-idempotency-key-conflict",
    "title": "API: Idempotency key conflict",
    "category": "API",
    "explanation": "Same idempotency key used with different request parameters. Indicates duplicate or conflicting request.",
    "fix_snippet": "# Generate unique idempotency key per request\nimport uuid\nidempotency_key = str(uuid.uuid4())\nheaders = {'Idempotency-Key': idempotency_key}\n# Store key with request params\n# Retry with same key if network fails",
    "sources": [
      "https://stripe.com/docs/api/idempotent_requests"
    ]
  },
  {
    "id": "messagequeue-poison-message",
    "title": "Message Queue: Poison message blocking queue",
    "category": "MessageQueue",
    "explanation": "Message causing consumer to crash repeatedly. Message stuck in queue blocking other messages.",
    "fix_snippet": "# Implement dead letter queue\n# Set max retry count\n# Log and skip poison message\ntry:\n    process_message(msg)\nexcept Exception as e:\n    if retry_count > 3:\n        send_to_dlq(msg)\n    else:\n        requeue(msg)",
    "sources": [
      "https://www.rabbitmq.com/dlx.html"
    ]
  },
  {
    "id": "python-gil-deadlock",
    "title": "Python: Deadlock with threading and GIL",
    "category": "Python",
    "explanation": "Multiple threads deadlocked waiting for GIL and other locks. Common with C extensions.",
    "fix_snippet": "# Use timeout on locks\nimport threading\nlock = threading.Lock()\nif lock.acquire(timeout=5):\n    try:\n        # critical section\n    finally:\n        lock.release()\n# Or use multiprocessing\n# Avoid nested locks",
    "sources": [
      "https://docs.python.org/3/library/threading.html"
    ]
  },
  {
    "id": "storage-azure-blob-lease-conflict",
    "title": "Azure Blob: Lease conflict",
    "category": "Storage",
    "explanation": "Blob is leased by another client. Cannot modify until lease expires or is released.",
    "fix_snippet": "# Check lease status\nblob_client.get_blob_properties().lease.status\n# Acquire lease\nlease = blob_client.acquire_lease()\ntry:\n    # modify blob\nfinally:\n    lease.release()\n# Or break lease\nblob_client.break_lease()",
    "sources": [
      "https://docs.microsoft.com/en-us/rest/api/storageservices/lease-blob"
    ]
  },
  {
    "id": "api-rest-method-override",
    "title": "API: HTTP method override not working",
    "category": "API",
    "explanation": "Some proxies/firewalls block PUT/PATCH/DELETE. Need to use X-HTTP-Method-Override header.",
    "fix_snippet": "# Use method override\ncurl -X POST https://api.example.com/resource/1 \\\n  -H \"X-HTTP-Method-Override: DELETE\"\n# Server must support header\n# Or tunnel through POST with _method param",
    "sources": [
      "https://restfulapi.net/http-method-override/"
    ]
  },
  {
    "id": "system-file-descriptor-limit",
    "title": "System: Too many open files",
    "category": "System",
    "explanation": "Process exceeded file descriptor limit. Need to increase ulimit or close unused files.",
    "fix_snippet": "# Check current limit\nulimit -n\n# Increase for current session\nulimit -n 65536\n# Permanent: edit /etc/security/limits.conf\n* soft nofile 65536\n* hard nofile 65536\n# Check open files\nlsof -p PID | wc -l",
    "sources": [
      "https://www.kernel.org/doc/Documentation/sysctl/fs.txt"
    ]
  },
  {
    "id": "javascript-race-condition-async",
    "title": "JavaScript: Race condition in async operations",
    "category": "JavaScript",
    "explanation": "Multiple async operations completing in unexpected order causing data inconsistency.",
    "fix_snippet": "# Use Promise.all for parallel\nconst [result1, result2] = await Promise.all([\n  promise1,\n  promise2\n]);\n# Or sequential with await\nconst result1 = await promise1;\nconst result2 = await promise2;\n# Add version/timestamp checks",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all"
    ]
  },
  {
    "id": "security-jwt-algorithm-confusion",
    "title": "Security: JWT algorithm confusion attack",
    "category": "Security",
    "explanation": "JWT using 'none' algorithm or algorithm confusion between RS256 and HS256. Critical vulnerability.",
    "fix_snippet": "# Always specify algorithm\nimport jwt\ntoken = jwt.decode(\n    token,\n    key,\n    algorithms=['RS256']  # Explicit!\n)\n# Never allow 'none'\n# Validate algorithm in token header",
    "sources": [
      "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
    ]
  },
  {
    "id": "python-pandas-memory-error",
    "title": "Python pandas: Memory error loading large CSV",
    "category": "Python",
    "explanation": "CSV file too large to fit in memory. Need to use chunking or alternative approach.",
    "fix_snippet": "# Read in chunks\nimport pandas as pd\nchunksize = 10000\nfor chunk in pd.read_csv('large.csv', chunksize=chunksize):\n    process(chunk)\n# Or specify dtypes to reduce memory\ndf = pd.read_csv('file.csv', dtype={'col': 'int32'})\n# Use dask for large datasets",
    "sources": [
      "https://pandas.pydata.org/docs/user_guide/io.html#io-chunking"
    ]
  },
  {
    "id": "javascript-closure-loop-variable",
    "title": "JavaScript: Closure capturing wrong loop variable",
    "category": "JavaScript",
    "explanation": "Loop variable captured by closure refers to final value, not value at time of creation.",
    "fix_snippet": "# Use let instead of var\nfor (let i = 0; i < 10; i++) {\n  setTimeout(() => console.log(i), 100);\n}\n# Or use forEach\narray.forEach((item, i) => {\n  setTimeout(() => console.log(i), 100);\n});",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Closures"
    ]
  },
  {
    "id": "api-cors-preflight-failed",
    "title": "API: CORS preflight request failed",
    "category": "API",
    "explanation": "Browser sent OPTIONS preflight but server returned error. Need to handle OPTIONS requests.",
    "fix_snippet": "# Server must respond to OPTIONS\nif request.method == 'OPTIONS':\n    return '', 200, {\n        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',\n        'Access-Control-Allow-Headers': 'Content-Type, Authorization',\n        'Access-Control-Max-Age': '3600'\n    }",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request"
    ]
  },
  {
    "id": "storage-gcs-signed-url-expired",
    "title": "Google Cloud Storage: Signed URL expired",
    "category": "Storage",
    "explanation": "GCS signed URL has exceeded its expiration time. Need to generate new signed URL.",
    "fix_snippet": "# Generate new signed URL\nfrom google.cloud import storage\nclient = storage.Client()\nbucket = client.bucket('bucket-name')\nblob = bucket.blob('file.txt')\nurl = blob.generate_signed_url(\n    expiration=3600,  # 1 hour\n    method='GET'\n)",
    "sources": [
      "https://cloud.google.com/storage/docs/access-control/signed-urls"
    ]
  },
  {
    "id": "system-oom-killer-activated",
    "title": "System: OOM killer terminated process",
    "category": "System",
    "explanation": "Linux Out-Of-Memory killer terminated process consuming too much memory.",
    "fix_snippet": "# Check OOM killer logs\ndmesg | grep -i 'killed process'\n# Increase memory or add swap\n# Optimize application memory usage\n# Adjust OOM score\necho -1000 > /proc/PID/oom_score_adj  # Less likely to kill",
    "sources": [
      "https://www.kernel.org/doc/gorman/html/understand/understand016.html"
    ]
  },
  {
    "id": "messagequeue-consumer-lag-high",
    "title": "Message Queue: Consumer lag too high",
    "category": "MessageQueue",
    "explanation": "Messages accumulating faster than consumers can process. Queue backlog growing.",
    "fix_snippet": "# Add more consumers\n# Increase consumer parallelism\n# Optimize message processing\n# Check for slow consumers\n# Monitor lag metrics\n# Consider batch processing",
    "sources": [
      "https://kafka.apache.org/documentation/#monitoring"
    ]
  },
  {
    "id": "python-multiprocessing-pickle-error",
    "title": "Python: Cannot pickle local object in multiprocessing",
    "category": "Python",
    "explanation": "multiprocessing cannot serialize local function or lambda. Need to use top-level function.",
    "fix_snippet": "# Define function at module level\ndef worker(x):\n    return x * 2\n\nif __name__ == '__main__':\n    from multiprocessing import Pool\n    with Pool() as p:\n        results = p.map(worker, data)\n# Or use dill\nimport dill",
    "sources": [
      "https://docs.python.org/3/library/multiprocessing.html"
    ]
  },
  {
    "id": "security-path-traversal",
    "title": "Security: Path traversal vulnerability",
    "category": "Security",
    "explanation": "User input used in file path allows access to files outside intended directory. Critical vulnerability.",
    "fix_snippet": "# Validate and sanitize file paths\nimport os\nbase_dir = '/var/www/uploads'\nuser_file = request.args.get('file')\nfull_path = os.path.realpath(os.path.join(base_dir, user_file))\nif not full_path.startswith(base_dir):\n    raise ValueError('Invalid path')",
    "sources": [
      "https://owasp.org/www-community/attacks/Path_Traversal"
    ]
  },
  {
    "id": "api-json-schema-validation-failed",
    "title": "API: JSON schema validation failed",
    "category": "API",
    "explanation": "Request body doesn't match expected JSON schema. Missing required fields or wrong types.",
    "fix_snippet": "# Check API schema documentation\n# Validate request before sending\nimport jsonschema\nschema = {...}\ntry:\n    jsonschema.validate(data, schema)\nexcept jsonschema.ValidationError as e:\n    print(e.message)",
    "sources": [
      "https://json-schema.org/"
    ]
  },
  {
    "id": "go-nil-pointer",
    "title": "Go: panic: runtime error: invalid memory address or nil pointer dereference",
    "category": "System",
    "explanation": "Attempting to dereference a nil pointer. Often happens when initializing a pointer but not assigning a value, or accessing a field of a nil struct.",
    "fix_snippet": "# Check for nil before access\nif ptr != nil {\n    fmt.Println(*ptr)\n}\n# Initialize pointer\nptr = new(Type)\n# Or use address of variable\nval := Type{}\nptr = &val",
    "sources": [
      "https://go.dev/tour/moretypes/1"
    ]
  },
  {
    "id": "go-import-cycle",
    "title": "Go: import cycle not allowed",
    "category": "System",
    "explanation": "Circular dependency between packages. Package A imports Package B, and Package B imports Package A.",
    "fix_snippet": "# Refactor to third package\n# Move common code to 'common' or 'types' package\n# Use interfaces to break dependency\n# Pass dependencies as arguments",
    "sources": [
      "https://go.dev/doc/faq#import_cycles"
    ]
  },
  {
    "id": "rust-borrow-moved",
    "title": "Rust: borrow of moved value",
    "category": "System",
    "explanation": "Attempting to use a value after it has been moved (ownership transferred). Rust ownership rules prevent using a variable after move.",
    "fix_snippet": "# Clone if type implements Clone\nlet y = x.clone();\n# Use reference if ownership not needed\nfunc(&x);\n# Implement Copy trait for small types\n#[derive(Copy, Clone)]",
    "sources": [
      "https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html"
    ]
  },
  {
    "id": "rust-lifetime-mismatch",
    "title": "Rust: lifetime mismatch",
    "category": "System",
    "explanation": "References in function have different lifetimes but are required to be related. Rust borrow checker cannot guarantee validity.",
    "fix_snippet": "# Add lifetime annotations\nfn longest<'a>(x: &'a str, y: &'a str) -> &'a str {\n# Ensure referenced data lives long enough\n# Use owned types (String instead of &str) if feasible",
    "sources": [
      "https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html"
    ]
  },
  {
    "id": "java-null-pointer",
    "title": "Java: java.lang.NullPointerException",
    "category": "Client",
    "explanation": "Attempting to use an object reference that has not been initialized (is null).",
    "fix_snippet": "# Check for null\nif (obj != null) {\n    obj.method();\n}\n# Use Optional\nOptional.ofNullable(obj).ifPresent(o -> o.method());\n# Initialize variable\nString str = \"\";",
    "sources": [
      "https://docs.oracle.com/javase/8/docs/api/java/lang/NullPointerException.html"
    ]
  },
  {
    "id": "java-class-not-found",
    "title": "Java: java.lang.ClassNotFoundException",
    "category": "Client",
    "explanation": "Application tries to load a class through its string name but no definition for the class with the specified name could be found.",
    "fix_snippet": "# Check classpath\njava -cp .:lib/* MyClass\n# Check Maven dependencies\nmvn dependency:tree\n# Verify JAR contains class\njar tf library.jar | grep ClassName",
    "sources": [
      "https://docs.oracle.com/javase/8/docs/api/java/lang/ClassNotFoundException.html"
    ]
  },
  {
    "id": "git-detached-head",
    "title": "Git: You are in 'detached HEAD' state",
    "category": "Git",
    "explanation": "Checked out a specific commit directly instead of a branch. New commits will not be associated with any branch and may be lost.",
    "fix_snippet": "# Create branch from current commit\ngit switch -c new-branch-name\n# Or go back to existing branch\ngit switch main\n# If you made commits, cherry-pick them\ngit cherry-pick <commit-hash>",
    "sources": [
      "https://git-scm.com/docs/git-checkout#_detached_head"
    ]
  },
  {
    "id": "docker-exec-format-error",
    "title": "Docker: exec user process caused \"exec format error\"",
    "category": "Docker",
    "explanation": "Container binary architecture doesn't match host (e.g., trying to run ARM binary on x86). Or missing shebang in script.",
    "fix_snippet": "# Build for correct platform\ndocker buildx build --platform linux/amd64 -t image .\n# Check binary architecture\nfile /path/to/binary\n# Add shebang to script\n#!/bin/sh",
    "sources": [
      "https://docs.docker.com/build/building/multi-platform/"
    ]
  },
  {
    "id": "system-segfault",
    "title": "System: Segmentation fault (core dumped)",
    "category": "System",
    "explanation": "Program attempted to access memory it wasn't allowed to. Invalid memory access, buffer overflow, or stack overflow.",
    "fix_snippet": "# Debug with GDB\ngdb ./program core\n# Check for null pointers\n# Check array bounds\n# Run with Valgrind\nvalgrind ./program",
    "sources": [
      "https://en.wikipedia.org/wiki/Segmentation_fault"
    ]
  },
  {
    "id": "k8s-context-deadline-exceeded",
    "title": "Kubernetes: context deadline exceeded",
    "category": "Kubernetes",
    "explanation": "Operation took longer than allowed timeout. API server too slow, etcd issues, or network latency.",
    "fix_snippet": "# Check API server health\nkubectl get --raw /healthz\n# Increase timeout flags\nkubectl get pods --request-timeout=30s\n# Check etcd performance\n# Monitor control plane resources",
    "sources": [
      "https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands"
    ]
  },
  {
    "id": "cloudflare-522-origin-connection",
    "title": "Cloudflare 522: Connection timed out",
    "category": "Proxy",
    "explanation": "Cloudflare edge could not establish TCP handshake to your origin. Origin offline, blocked by firewall, or wrong DNS/port.",
    "fix_snippet": "# Test origin directly\ncurl -v http://origin-ip:80\n# Check firewall/WAF allow Cloudflare IPs\n# Verify DNS A/AAAA records point to correct origin\n# Temporarily pause Cloudflare to isolate issue",
    "sources": [
      "https://developers.cloudflare.com/support/troubleshooting/cloudflare-errors/troubleshooting-cloudflare-5xx-errors/#error-522"
    ]
  },
  {
    "id": "cloudflare-worker-1101-runtime-error",
    "title": "Cloudflare Worker 1101 runtime error",
    "category": "Proxy",
    "explanation": "Worker script threw an exception during execution. Common causes: undefined variables, failed fetch, exceeded CPU/time limits.",
    "fix_snippet": "# Check Worker logs\nwrangler tail worker-name\n# Add try/catch around fetch/JSON parse\n# Reduce heavy CPU work; move to origin or queue\n# Ensure environment variables are set",
    "sources": [
      "https://developers.cloudflare.com/workers/platform/errors/#1101-runtime-error"
    ]
  },
  {
    "id": "openai-api-429-rate-limit",
    "title": "OpenAI API: 429 rate limit exceeded",
    "category": "AI",
    "explanation": "Requests exceed your organization or model rate limits. Returns 429 with retry headers.",
    "fix_snippet": "# Respect Retry-After header\nsleep ${RETRY_AFTER}\n# Implement exponential backoff\n# Reduce request frequency or batch prompts\n# Use smaller models or request quota increase",
    "sources": [
      "https://platform.openai.com/docs/guides/rate-limits"
    ]
  },
  {
    "id": "openai-context-length-exceeded",
    "title": "OpenAI API: context_length_exceeded",
    "category": "AI",
    "explanation": "Prompt + response tokens exceed model's context window. Model refuses to generate.",
    "fix_snippet": "# Trim prompt history or system message\n# Use shorter model (e.g., gpt-3.5-turbo vs 4o-mini)\n# Summarize conversation before sending\n# Switch to model with larger context window if available",
    "sources": [
      "https://platform.openai.com/docs/guides/text-generation"
    ]
  },
  {
    "id": "nextjs-hydration-mismatch",
    "title": "Next.js: Hydration failed because the initial UI does not match",
    "category": "JavaScript",
    "explanation": "Server-rendered HTML differs from client render. Causes include non-deterministic renders, browser-only APIs on server, or locale/time differences.",
    "fix_snippet": "# Avoid random/Date in render; move to useEffect\n# Guard browser APIs\nif (typeof window !== 'undefined') { ... }\n# Ensure data fetched at build/server matches client\n# Use suppressHydrationWarning for intentional differences",
    "sources": [
      "https://nextjs.org/docs/messages/react-hydration-error"
    ]
  },
  {
    "id": "vercel-framework-detection-failed",
    "title": "Vercel build: framework detection failed",
    "category": "CI/CD",
    "explanation": "Vercel could not detect framework/output directory. Missing dependencies or build config.",
    "fix_snippet": "# Install deps during build\nnpm ci\n# Add vercel.json\n{\\\"framework\\\":\\\"nextjs\\\",\\\"outputDirectory\\\":\\\".next\\\"}\n# Set correct build command\n\\\"buildCommand\\\": \\\"npm run build\\\"\n# Ensure package.json has scripts",
    "sources": [
      "https://vercel.com/docs/deployments/frameworks"
    ]
  },
  {
    "id": "apigw-413-payload-too-large",
    "title": "API Gateway 413: Payload too large",
    "category": "API",
    "explanation": "Request body exceeds API Gateway/Lambda payload limits (10MB REST, 6MB HTTP API by default).",
    "fix_snippet": "# Upload large files to S3 first and pass presigned URL\n# Enable binary media types if needed\n# Compress payload (gzip)\n# Split request into chunks",
    "sources": [
      "https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html"
    ]
  },
  {
    "id": "oauth-invalid-grant-refresh-expired",
    "title": "OAuth2: invalid_grant (refresh token expired)",
    "category": "Security",
    "explanation": "Refresh token is expired/revoked or used with wrong client/redirect URI, returning invalid_grant.",
    "fix_snippet": "# Re-authenticate user to issue new refresh token\n# Ensure redirect_uri matches exactly\n# Do not reuse refresh token across clients\n# Check provider token expiry/rotation policy",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
    ]
  },
  {
    "id": "jwt-invalid-audience",
    "title": "JWT: Invalid audience claim",
    "category": "Security",
    "explanation": "aud claim in JWT does not match expected audience for the API or resource server.",
    "fix_snippet": "# Configure resource server expected aud\n# Issue tokens with correct aud from IdP\n# Validate aud before processing request\n# Rotate client IDs consistently across environments",
    "sources": [
      "https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3"
    ]
  },
  {
    "id": "postgres-too-many-connections",
    "title": "PostgreSQL: too many connections",
    "category": "Database",
    "explanation": "All available Postgres connections are in use. Connection pool exhaustion or insufficient max_connections.",
    "fix_snippet": "# Check current connections\nSELECT count(*) FROM pg_stat_activity;\n# Increase max_connections (postgresql.conf)\n# Tune pooler (PgBouncer) with max_client_conn\n# Fix connection leaks and use pooling",
    "sources": [
      "https://www.postgresql.org/docs/current/runtime-config-connection.html"
    ]
  },
  {
    "id": "redis-readonly-replica",
    "title": "Redis: READONLY You can't write against a read only replica",
    "category": "Database",
    "explanation": "Client connected to Redis replica with read-only mode. Writes are rejected.",
    "fix_snippet": "# Connect to primary endpoint instead of replica\n# For cluster, follow MOVED/ASK redirections\n# Disable readonly on replica only for testing: CONFIG SET slave-read-only no\n# Update client connection string/endpoint",
    "sources": [
      "https://redis.io/docs/latest/operate/oss_and_stack/management/replication/"
    ]
  },
  {
    "id": "kafka-leader-not-available",
    "title": "Kafka: LEADER_NOT_AVAILABLE",
    "category": "MessageQueue",
    "explanation": "Partition has no elected leader. Broker down, ISR empty, or topic just created and metadata not propagated.",
    "fix_snippet": "# Wait a few seconds after topic creation\n# Check broker health and controller logs\n# Ensure replicas in-sync; increase min.insync.replicas\n# Restart affected broker or reassign partitions",
    "sources": [
      "https://kafka.apache.org/documentation/#replication"
    ]
  },
  {
    "id": "gha-resource-not-accessible",
    "title": "GitHub Actions: Resource not accessible by integration",
    "category": "CI/CD",
    "explanation": "Workflow on fork PR lacks permission to access secrets or write operations.",
    "fix_snippet": "# Enable 'Allow GitHub Actions to create and approve pull requests' or set permissions\npermissions:\n  contents: read\n  pull-requests: write\n# Use pull_request_target for trusted workflows\n# Avoid using secrets on forked PRs",
    "sources": [
      "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request"
    ]
  },
  {
    "id": "docker-registry-rate-limit",
    "title": "Docker registry: 429 too many requests",
    "category": "Docker",
    "explanation": "Registry (e.g., Docker Hub) rate limits unauthenticated or high-volume pulls.",
    "fix_snippet": "# docker login to use authenticated limits\ndocker login\n# Pull through registry mirror or cache\n# Reduce parallel pulls / add backoff\n# For CI, use private registry or image cache",
    "sources": [
      "https://docs.docker.com/docker-hub/download-rate-limit/"
    ]
  },
  {
    "id": "otel-exporter-queue-full",
    "title": "OpenTelemetry Collector: exporter queue is full",
    "category": "Monitoring",
    "explanation": "Exporter queue/batch processor dropped spans/metrics because downstream endpoint too slow or queue too small.",
    "fix_snippet": "# Increase queue_size in batch/exporter config\nprocessors:\n  batch:\n    send_batch_size: 512\n    queue_size: 2048\n# Throttle export rate or scale collector\n# Fix latency/availability of backend (Tempo/Jaeger/OTLP)",
    "sources": [
      "https://opentelemetry.io/docs/collector/configuration/"
    ]
  },
  {
    "id": "csp-refused-to-connect",
    "title": "CSP: Refused to connect to URL",
    "category": "Security",
    "explanation": "Content Security Policy blocks outbound fetch/WebSocket/XHR to the target origin because connect-src is restrictive.",
    "fix_snippet": "# Add origin to connect-src\nContent-Security-Policy: connect-src 'self' https://api.example.com;\n# For WebSockets include wss:// endpoint\n# Keep least-privilege and avoid wildcard * where possible",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src"
    ]
  },
  {
    "id": "react-hydration-mismatch",
    "title": "React: Hydration failed because the initial UI does not match",
    "category": "JavaScript",
    "explanation": "The HTML rendered on the server (SSR) doesn't match what React rendered on the client. Common causes: invalid HTML nesting (p inside p), random values (Math.random), or timestamps.",
    "fix_snippet": "# Fix invalid nesting\n<p><div>Don't do this</div></p> -> <div><div>Do this</div></div>\n# Handle dynamic content\nconst [isMounted, setIsMounted] = useState(false);\nuseEffect(() => setIsMounted(true), []);\nif (!isMounted) return null;",
    "sources": [
      "https://react.dev/reference/react-dom/client/hydrateRoot#handling-different-client-and-server-content"
    ]
  },
  {
    "id": "docker-exec-format-error",
    "title": "Docker: exec format error",
    "category": "Docker",
    "explanation": "Container binary architecture doesn't match the host (e.g., trying to run amd64 container on Apple Silicon M1/M2/M3 without emulation).",
    "fix_snippet": "# Build for specific platform\ndocker build --platform linux/amd64 -t my-image .\n# Or use buildx for multi-arch\ndocker buildx build --platform linux/amd64,linux/arm64 -t my-image .\n# Check image architecture\ndocker inspect my-image | grep Architecture",
    "sources": [
      "https://docs.docker.com/build/building/multi-platform/"
    ]
  },
  {
    "id": "python-externally-managed-env",
    "title": "Python: error: externally-managed-environment",
    "category": "Python",
    "explanation": "Newer Linux distros (Debian 12+, Ubuntu 23.04+) block global pip installs to protect system packages (PEP 668).",
    "fix_snippet": "# Use a virtual environment (Recommended)\npython3 -m venv .venv\nsource .venv/bin/activate\npip install package-name\n# Or use pipx for tools\npipx install package-name\n# Last resort (risky): --break-system-packages",
    "sources": [
      "https://peps.python.org/pep-0668/"
    ]
  },
  {
    "id": "git-push-rejected-non-fast-forward",
    "title": "Git: failed to push some refs to ... (non-fast-forward)",
    "category": "Git",
    "explanation": "Remote branch has commits that you don't have locally. Someone else pushed changes.",
    "fix_snippet": "# Pull remote changes first\ngit pull origin main\n# Rebase on top of remote\ngit pull --rebase origin main\n# Force push (Destructive! Only if you know what you're doing)\ngit push --force-with-lease origin main",
    "sources": [
      "https://git-scm.com/docs/git-push#_note_about_fast_forwards"
    ]
  },
  {
    "id": "ssh-host-key-verification-failed",
    "title": "SSH: Host key verification failed",
    "category": "Security",
    "explanation": "The remote server's SSH host key has changed, or you're connecting to a new server with the same IP (Man-in-the-Middle warning).",
    "fix_snippet": "# Remove old key for IP/Hostname\nssh-keygen -R 192.168.1.10\n# View the keys\ncat ~/.ssh/known_hosts\n# Manually edit known_hosts to remove the offending line",
    "sources": [
      "https://man.openbsd.org/ssh-keygen#R"
    ]
  },
  {
    "id": "aws-missing-authentication-token",
    "title": "AWS: MissingAuthenticationTokenException",
    "category": "Cloud",
    "explanation": "Request is missing valid credentials, or the specific API endpoint/region combination is incorrect.",
    "fix_snippet": "# Check configured region\naws configure get region\n# Export credentials explicitly\nexport AWS_PROFILE=my-profile\n# Verify endpoint URL\n# Check if service is available in that region",
    "sources": [
      "https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html"
    ]
  },
  {
    "id": "node-err-code-elifecycle",
    "title": "npm ERR! code ELIFECYCLE",
    "category": "JavaScript",
    "explanation": "A script referenced in package.json failed to execute (exit code != 0). The error is in the script itself, not npm.",
    "fix_snippet": "# Clear npm cache\nnpm cache clean --force\n# Delete node_modules and lock file\nrm -rf node_modules package-lock.json\n# Reinstall dependencies\nnpm install\n# Check the script debug logs",
    "sources": [
      "https://docs.npmjs.com/cli/v8/using-npm/scripts"
    ]
  },
  {
    "id": "postgres-authentication-failed",
    "title": "PostgreSQL: FATAL: password authentication failed for user",
    "category": "Database",
    "explanation": "Authentication failed for the Postgres user. Password mismatch or pg_hba.conf configuration issue.",
    "fix_snippet": "# Check pg_hba.conf\n# Allow md5/scram-sha-256 instead of ident/peer\nhost all all 127.0.0.1/32 scram-sha-256\n# Reset password\nALTER USER postgres WITH PASSWORD 'newpassword';",
    "sources": [
      "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"
    ]
  },
  {
    "id": "pytorch-cuda-oom",
    "title": "PyTorch: CUDA out of memory",
    "category": "AI",
    "explanation": "GPU memory exhausted when trying to allocate tensors. Common when model batch size is too large or previous tensors weren't freed.",
    "fix_snippet": "# Clear CUDA cache (Python)\nimport torch\ntorch.cuda.empty_cache()\n# Reduce batch size in training loop\n# Use gradient accumulation\n# Use mixed precision (fp16) training",
    "sources": [
      "https://pytorch.org/docs/stable/notes/cuda.html#memory-management"
    ]
  },
  {
    "id": "rust-borrow-checker-mutable",
    "title": "Rust: cannot borrow `x` as mutable more than once at a time",
    "category": "Rust",
    "explanation": "Rust's ownership rules prevent multiple mutable references to the same data simultaneously to avoid data races.",
    "fix_snippet": "# Scope the first borrow to end early\n{ let y = &mut x; y.do_something(); }\nlet z = &mut x; // Now allowed\n# Or clone data if ownership isn't needed\n# Or use RefCell for interior mutability (runtime check)",
    "sources": [
      "https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html"
    ]
  },
  {
    "id": "go-panic-nil-map",
    "title": "Go: panic: assignment to entry in nil map",
    "category": "Go",
    "explanation": "Attempting to write to a map that hasn't been initialized. In Go, zero-value maps are nil and read-only.",
    "fix_snippet": "# Initialize map before use\nm := make(map[string]int)\nm[\"key\"] = 1\n# Incorrect: var m map[string]int; m[\"key\"] = 1 (Panics)",
    "sources": [
      "https://go.dev/blog/maps"
    ]
  },
  {
    "id": "gradle-build-failed",
    "title": "Gradle: Execution failed for task ':app:...'",
    "category": "Mobile",
    "explanation": "Generic Android build failure. Often due to cached dependencies, JDK version mismatch, or XML layout errors.",
    "fix_snippet": "# Clean project\n./gradlew clean\n# Run with stacktrace for details\n./gradlew assembleDebug --stacktrace\n# Check JDK version matches Gradle requirements",
    "sources": [
      "https://developer.android.com/studio/build"
    ]
  },
  {
    "id": "cocoapods-sandbox-sync",
    "title": "CocoaPods: The sandbox is not in sync with the Podfile.lock",
    "category": "Mobile",
    "explanation": "Installed pods don't match the manifest lockfile. Common after switching git branches.",
    "fix_snippet": "# Re-install pods\npod install\n# If that fails, update repo\npod repo update && pod install\n# Delete Pods folder (nuclear option)\nrm -rf Pods && pod install",
    "sources": [
      "https://guides.cocoapods.org/using/using-cocoapods.html"
    ]
  },
  {
    "id": "prisma-unique-constraint-failed",
    "title": "Prisma: Unique constraint failed on the fields: (`x`)",
    "category": "Database",
    "explanation": "Attempted to create a record with a value that already exists in a unique column (P2002).",
    "fix_snippet": "# Handle error in try/catch\nif (e.code === 'P2002') {\n  console.log('User already exists')\n}\n# Use upsert (update if exists, create if not)\nawait prisma.user.upsert({ ... })",
    "sources": [
      "https://www.prisma.io/docs/reference/api-reference/error-reference#p2002"
    ]
  },
  {
    "id": "typescript-null-not-assignable",
    "title": "TypeScript: Type 'null' is not assignable to type 'string'",
    "category": "JavaScript",
    "explanation": "Strict null checks are enabled. You are trying to pass null/undefined to a variable expected to be a string.",
    "fix_snippet": "# Allow null in type definition\nlet name: string | null;\n# Or use optional chaining/nullish coalescing\nconst val = data?.name ?? 'default';\n# Or ensure value exists (narrowing)\nif (name) { ... }",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#strictnullchecks"
    ]
  },
  {
    "id": "spring-bean-override-exception",
    "title": "Spring Boot: BeanDefinitionOverrideException",
    "category": "Java",
    "explanation": "Two beans have the same name, and Spring Boot's default configuration prevents silent overriding (since 2.1).",
    "fix_snippet": "# Allow bean overriding (application.properties)\nspring.main.allow-bean-definition-overriding=true\n# Or rename one of the beans\n@Bean(\"myCustomBean\")\n# Or use @Primary to prioritize one",
    "sources": [
      "https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html"
    ]
  },
  {
    "id": "cpp-segmentation-fault",
    "title": "C++: Segmentation fault (core dumped)",
    "category": "C++",
    "explanation": "Program attempted to access memory it doesn't own (e.g., dereferencing null pointer, buffer overflow, or stack overflow).",
    "fix_snippet": "# Compile with debug symbols\ng++ -g main.cpp\n# Run with GDB\ngdb ./a.out\n(gdb) run\n(gdb) backtrace\n# Check for null pointers and array bounds",
    "sources": [
      "https://www.gnu.org/software/gdb/documentation/"
    ]
  },
  {
    "id": "laravel-target-class-not-exist",
    "title": "Laravel: Target class [X] does not exist",
    "category": "PHP",
    "explanation": "Laravel container cannot resolve the class. Usually due to missing 'use' statement, typo, or outdated Composer autoloader.",
    "fix_snippet": "# Refresh autoloader\ncomposer dump-autoload\n# Check namespace and imports\nuse App\\Services\\MyService;\n# Clear cache\nphp artisan config:clear\nphp artisan cache:clear",
    "sources": [
      "https://laravel.com/docs/container"
    ]
  },
  {
    "id": "elasticsearch-flood-stage-watermark",
    "title": "Elasticsearch: flood stage disk watermark exceeded",
    "category": "Database",
    "explanation": "Disk usage >95%. Node effectively read-only to prevent data corruption. Requires manual reset even after freeing space.",
    "fix_snippet": "# 1. Free up disk space first!\n# 2. Reset read-only block\ncurl -X PUT \"localhost:9200/_all/_settings\" -H 'Content-Type: application/json' -d'{\n  \"index.blocks.read_only_allow_delete\": null\n}'",
    "sources": [
      "https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-cluster.html#disk-based-shard-allocation"
    ]
  },
  {
    "id": "powershell-execution-policy",
    "title": "PowerShell: .ps1 cannot be loaded because running scripts is disabled",
    "category": "System",
    "explanation": "Windows default security policy blocks script execution to prevent malware.",
    "fix_snippet": "# Allow local scripts (requires Admin)\nSet-ExecutionPolicy RemoteSigned\n# Or bypass for current process only (no Admin needed)\nSet-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass",
    "sources": [
      "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy"
    ]
  },
  {
    "id": "bundler-gem-not-found",
    "title": "Bundler: Could not find gem",
    "category": "Ruby",
    "explanation": "Bundler cannot locate the specified gem in any of the configured sources (e.g., RubyGems).",
    "fix_snippet": "# Install missing gems\nbundle install\n# Update sources\nbundle update\n# Check Gemfile for typos",
    "sources": [
      "https://bundler.io/docs.html"
    ]
  },
  {
    "id": "rails-pending-migrations",
    "title": "Rails: PendingMigrationError",
    "category": "Ruby",
    "explanation": "Database schema migrations have not been applied to the database.",
    "fix_snippet": "# Run pending migrations\nrails db:migrate\n# For test environment\nrails db:migrate RAILS_ENV=test",
    "sources": [
      "https://guides.rubyonrails.org/active_record_migrations.html"
    ]
  },
  {
    "id": "ruby-syntax-error",
    "title": "Ruby: syntax error, unexpected end-of-input",
    "category": "Ruby",
    "explanation": "Ruby parser reached end of file but expected more code. Often missing 'end' keyword for a block.",
    "fix_snippet": "# Check for missing 'end' keywords\n# Ensure all do/def/if blocks are closed\n# Check for unclosed strings or parentheses\nruby -c file.rb",
    "sources": [
      "https://www.ruby-lang.org/en/documentation/"
    ]
  },
  {
    "id": "dotnet-nuget-restore-failed",
    "title": ".NET: NuGet restore failed",
    "category": "C#",
    "explanation": "NuGet package restore failed. Network issues, invalid package source, or missing credentials.",
    "fix_snippet": "# Restore packages\ndotnet restore\n# Clear local cache\ndotnet nuget locals all --clear\n# Check nuget.config sources",
    "sources": [
      "https://docs.microsoft.com/en-us/nuget/consume-packages/package-restore"
    ]
  },
  {
    "id": "csharp-null-reference",
    "title": "C#: NullReferenceException",
    "category": "C#",
    "explanation": "Attempting to access a member on a type that is null.",
    "fix_snippet": "# Check for null\nif (obj != null) { obj.Method(); }\n# Use null-conditional operator\nobj?.Method();\n# Enable nullable reference types in .csproj\n<Nullable>enable</Nullable>",
    "sources": [
      "https://docs.microsoft.com/en-us/dotnet/api/system.nullreferenceexception"
    ]
  },
  {
    "id": "entity-framework-update-database",
    "title": "EF Core: Update-Database not recognized",
    "category": "C#",
    "explanation": "EF Core tools not installed or path issue. PowerShell command not found.",
    "fix_snippet": "# Install EF Core tools\ndotnet tool install --global dotnet-ef\n# Use dotnet CLI equivalent\ndotnet ef database update\n# Add tools to project\ndotnet add package Microsoft.EntityFrameworkCore.Tools",
    "sources": [
      "https://docs.microsoft.com/en-us/ef/core/cli/"
    ]
  },
  {
    "id": "flutter-doctor-issues",
    "title": "Flutter: Android toolchain - develop for Android devices",
    "category": "Mobile",
    "explanation": "Flutter cannot find Android SDK or licenses not accepted.",
    "fix_snippet": "# Accept licenses\nflutter doctor --android-licenses\n# Set SDK path\nflutter config --android-sdk /path/to/android/sdk\n# Run diagnosis\nflutter doctor",
    "sources": [
      "https://docs.flutter.dev/get-started/install"
    ]
  },
  {
    "id": "ios-signing-certificate",
    "title": "iOS: Code signing is required",
    "category": "Mobile",
    "explanation": "Xcode build failed because no valid signing certificate or provisioning profile was found.",
    "fix_snippet": "# Check signing in Xcode\n# Project -> Targets -> Signing & Capabilities\n# Enable 'Automatically manage signing'\n# Select valid Team",
    "sources": [
      "https://developer.apple.com/support/code-signing/"
    ]
  },
  {
    "id": "react-native-metro-bundler",
    "title": "React Native: Metro Bundler error",
    "category": "Mobile",
    "explanation": "Metro bundler failed to start or connection refused. Cache issues or port 8081 in use.",
    "fix_snippet": "# Start bundler with reset cache\nnpm start -- --reset-cache\n# Clear watchman\nwatchman watch-del-all\n# Check port 8081\nlsof -i :8081",
    "sources": [
      "https://reactnative.dev/docs/troubleshooting"
    ]
  },
  {
    "id": "spark-executor-oom",
    "title": "Spark: Executor Lost (OutOfMemoryError)",
    "category": "BigData",
    "explanation": "Spark executor ran out of heap memory processing a partition.",
    "fix_snippet": "# Increase executor memory\n--executor-memory 4g\n# Increase overhead memory\n--conf spark.executor.memoryOverhead=1g\n# Reduce partition size\ndf.repartition(100)",
    "sources": [
      "https://spark.apache.org/docs/latest/configuration.html"
    ]
  },
  {
    "id": "airflow-scheduler-not-running",
    "title": "Airflow: Scheduler not running",
    "category": "BigData",
    "explanation": "Airflow scheduler process is down or tasks are stuck in queued state.",
    "fix_snippet": "# Restart scheduler\nairflow scheduler\n# Check scheduler logs\n# Verify database connection\nairflow db check",
    "sources": [
      "https://airflow.apache.org/docs/apache-airflow/stable/troubleshooting.html"
    ]
  },
  {
    "id": "snowflake-warehouse-suspended",
    "title": "Snowflake: Warehouse suspended",
    "category": "BigData",
    "explanation": "Attempting to run query on a suspended warehouse that didn't auto-resume.",
    "fix_snippet": "# Resume warehouse\nALTER WAREHOUSE my_wh RESUME;\n# Enable auto-resume\nALTER WAREHOUSE my_wh SET AUTO_RESUME = TRUE;",
    "sources": [
      "https://docs.snowflake.com/en/user-guide/warehouses-tasks.html"
    ]
  },
  {
    "id": "nginx-emerg-bind-failed",
    "title": "Nginx: bind() to 0.0.0.0:80 failed",
    "category": "WebServer",
    "explanation": "Nginx cannot bind to port 80 because it is already in use by another process (Apache, another Nginx, etc.).",
    "fix_snippet": "# Find process using port 80\nsudo lsof -i :80\n# Stop conflicting process\nsudo systemctl stop apache2\n# Restart Nginx\nsudo systemctl start nginx",
    "sources": [
      "https://nginx.org/en/docs/beginners_guide.html"
    ]
  },
  {
    "id": "apache-htaccess-not-allowed",
    "title": "Apache: .htaccess: Option Indexes not allowed",
    "category": "WebServer",
    "explanation": "Directory listing (Options Indexes) is disabled in main config but requested in .htaccess.",
    "fix_snippet": "# Allow override in apache2.conf\n<Directory /var/www/html>\n    AllowOverride All\n</Directory>\n# Or remove 'Options Indexes' from .htaccess",
    "sources": [
      "https://httpd.apache.org/docs/2.4/howto/htaccess.html"
    ]
  },
  {
    "id": "graphql-validation-error",
    "title": "GraphQL: Validation error",
    "category": "GraphQL",
    "explanation": "Query failed validation against the schema. Field undefined or argument mismatch.",
    "fix_snippet": "# Check schema for field existence\n# Validate query structure\n# Use GraphiQL/Playground to test query\n# Check types",
    "sources": [
      "https://graphql.org/learn/validation/"
    ]
  },
  {
    "id": "graphql-syntax-error",
    "title": "GraphQL: Syntax Error",
    "category": "GraphQL",
    "explanation": "Malformed GraphQL query syntax. Missing braces, invalid characters, or bad formatting.",
    "fix_snippet": "# Validate JSON/Query syntax\n# Check for matching braces\n# Ensure variables are defined\nquery GetUser($id: ID!) { ... }",
    "sources": [
      "https://graphql.org/learn/queries/"
    ]
  }
];
