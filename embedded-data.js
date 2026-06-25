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
    "explanation": "The server understood the request but refuses to authorise it. Often due to insufficient permissions.",
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
    "explanation": "Cross-Origin Resource Sharing policy blocked the request. Browser security feature preventing unauthorised cross-domain requests.",
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
    "explanation": "Time synchronisation mechanism. Often disabled for security reasons as it can leak system time information.",
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
    "explanation": "Docker build failing or not using cache properly, resulting in slow builds or unexpected behaviour.",
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
    "explanation": "API requires Bearer token in Authorisation header but token is missing or invalid format.",
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
    "explanation": "multiprocessing cannot serialise local function or lambda. Need to use top-level function.",
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
    "explanation": "Attempting to dereference a nil pointer. Often happens when initialising a pointer but not assigning a value, or accessing a field of a nil struct.",
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
    "explanation": "Attempting to use an object reference that has not been initialised (is null).",
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
    "explanation": "Requests exceed your organisation or model rate limits. Returns 429 with retry headers.",
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
    "id": "docker-exec-format-error-multiarch",
    "title": "Docker: exec format error (multi-arch)",
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
    "explanation": "Attempting to write to a map that hasn't been initialised. In Go, zero-value maps are nil and read-only.",
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
    "explanation": "Flutter cannot find Android SDK or licences not accepted.",
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
  },
  {
    "id": "go-race-condition",
    "title": "fatal error: concurrent map writes",
    "category": "Go",
    "explanation": "Multiple goroutines are reading and writing to a map concurrently without synchronisation. Go maps are not safe for concurrent use.",
    "fix_snippet": "# Use sync.Mutex to protect map access\nvar mu sync.Mutex\nmu.Lock()\nm[key] = value\nmu.Unlock()\n# Or use sync.Map for concurrent access\nvar m sync.Map\nm.Store(key, value)\n# Detect with race detector\ngo run -race main.go",
    "sources": [
      "https://go.dev/doc/articles/race_detector"
    ]
  },
  {
    "id": "go-context-canceled",
    "title": "context canceled",
    "category": "Go",
    "explanation": "A context was cancelled before the operation completed. Typically because a parent context was cancelled, a timeout expired, or the caller cancelled the request.",
    "fix_snippet": "# Check context error type\nif ctx.Err() == context.Canceled {\n    log.Println(\"request was canceled\")\n}\n# Set appropriate timeout\nctx, cancel := context.WithTimeout(ctx, 30*time.Second)\ndefer cancel()",
    "sources": [
      "https://pkg.go.dev/context"
    ]
  },
  {
    "id": "go-goroutine-leak",
    "title": "goroutine leak detected",
    "category": "Go",
    "explanation": "Goroutines are not being properly terminated, causing memory growth over time. Often caused by blocked channel operations or missing context cancellation.",
    "fix_snippet": "# Use context for cancellation\nctx, cancel := context.WithCancel(context.Background())\ndefer cancel()\ngo func(ctx context.Context) {\n    select {\n    case <-ctx.Done():\n        return\n    case msg := <-ch:\n        process(msg)\n    }\n}(ctx)\n# Monitor goroutine count\nruntime.NumGoroutine()",
    "sources": [
      "https://go.dev/blog/pipelines"
    ]
  },
  {
    "id": "go-module-not-found",
    "title": "cannot find module providing package",
    "category": "Go",
    "explanation": "Go cannot resolve a package import. The module may not be downloaded, the import path may be wrong, or go.mod may be missing the dependency.",
    "fix_snippet": "# Download missing modules\ngo mod tidy\n# Add specific dependency\ngo get github.com/pkg/errors\n# Verify modules\ngo mod verify\n# Clear module cache\ngo clean -modcache",
    "sources": [
      "https://go.dev/ref/mod"
    ]
  },
  {
    "id": "go-interface-assertion-panic",
    "title": "interface conversion: interface is nil, not X",
    "category": "Go",
    "explanation": "A type assertion on an interface failed because the value is nil or holds a different concrete type than expected.",
    "fix_snippet": "# Use comma-ok pattern (safe assertion)\nval, ok := i.(MyType)\nif !ok {\n    log.Println(\"type assertion failed\")\n}\n# Check for nil first\nif i != nil {\n    val := i.(MyType)\n}",
    "sources": [
      "https://go.dev/doc/effective_go#interface_conversions"
    ]
  },
  {
    "id": "go-deadlock",
    "title": "fatal error: all goroutines are asleep - deadlock!",
    "category": "Go",
    "explanation": "All goroutines are blocked waiting on channels or locks with no goroutine able to make progress. Detected by the Go runtime.",
    "fix_snippet": "# Ensure channels are buffered or have receivers\nch := make(chan int, 1)\n# Close channels when done sending\nclose(ch)\n# Use select with default for non-blocking ops\nselect {\ncase msg := <-ch:\n    process(msg)\ndefault:\n    // non-blocking\n}",
    "sources": [
      "https://go.dev/ref/spec#Program_execution"
    ]
  },
  {
    "id": "rust-cannot-move-borrowed",
    "title": "cannot move out of borrowed content",
    "category": "Rust",
    "explanation": "Attempting to move a value out of a reference, which would invalidate the borrow. Rust's ownership system prevents this to ensure memory safety.",
    "fix_snippet": "# Clone the value instead of moving\nlet val = borrowed_ref.clone();\n# Or use .to_owned() for strings\nlet s = borrowed_str.to_owned();\n# Or restructure to avoid the move\nif let Some(ref val) = option { ... }",
    "sources": [
      "https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html"
    ]
  },
  {
    "id": "rust-trait-not-implemented",
    "title": "the trait X is not implemented for Y",
    "category": "Rust",
    "explanation": "A type does not implement a required trait. This happens when a trait bound is specified but the type doesn't satisfy it.",
    "fix_snippet": "# Derive common traits\n#[derive(Debug, Clone, PartialEq)]\nstruct MyType { ... }\n# Implement trait manually\nimpl Display for MyType {\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\n        write!(f, \"...\")\n    }\n}",
    "sources": [
      "https://doc.rust-lang.org/book/ch10-02-traits.html"
    ]
  },
  {
    "id": "rust-mismatched-types",
    "title": "mismatched types: expected X, found Y",
    "category": "Rust",
    "explanation": "The compiler expected one type but found another. Common with integer types, string types (&str vs String), or return types.",
    "fix_snippet": "# Convert between string types\nlet s: String = \"hello\".to_string();\nlet s: &str = &my_string;\n# Convert between numeric types\nlet x: i64 = my_i32 as i64;\n# Use .into() for From implementations\nlet val: TargetType = source.into();",
    "sources": [
      "https://doc.rust-lang.org/book/ch03-02-data-types.html"
    ]
  },
  {
    "id": "rust-unused-must-use",
    "title": "unused Result that must be used",
    "category": "Rust",
    "explanation": "A function returning Result was called but the return value was not handled. Ignoring errors can lead to silent failures.",
    "fix_snippet": "# Handle error with match\nmatch do_something() {\n    Ok(val) => println!(\"Success: {}\", val),\n    Err(e) => eprintln!(\"Error: {}\", e),\n}\n# Or use ? operator\nlet val = do_something()?;\n# Or explicitly ignore\nlet _ = do_something();",
    "sources": [
      "https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html"
    ]
  },
  {
    "id": "rust-cannot-borrow-immutable",
    "title": "cannot borrow as mutable, as it is behind a & reference",
    "category": "Rust",
    "explanation": "Attempting to mutate data through a shared (immutable) reference. Rust enforces either one mutable reference or any number of immutable references.",
    "fix_snippet": "# Use &mut reference\nfn modify(data: &mut Vec<i32>) {\n    data.push(42);\n}\n# Use interior mutability\nuse std::cell::RefCell;\nlet data = RefCell::new(vec![1, 2, 3]);\ndata.borrow_mut().push(4);",
    "sources": [
      "https://doc.rust-lang.org/book/ch15-05-interior-mutability.html"
    ]
  },
  {
    "id": "rust-cargo-dependency-conflict",
    "title": "failed to select a version for X",
    "category": "Rust",
    "explanation": "Cargo cannot resolve a compatible set of dependency versions. Two or more crates require incompatible versions of the same dependency.",
    "fix_snippet": "# Update all dependencies\ncargo update\n# Check dependency tree for conflicts\ncargo tree -d\n# Force specific version in Cargo.toml\n[dependencies]\nproblematic-crate = \"=1.2.3\"\n# Audit for issues\ncargo audit",
    "sources": [
      "https://doc.rust-lang.org/cargo/reference/resolver.html"
    ]
  },
  {
    "id": "java-stackoverflow",
    "title": "StackOverflowError",
    "category": "Java",
    "explanation": "The call stack has exceeded its maximum size, usually caused by infinite recursion or extremely deep recursive calls.",
    "fix_snippet": "# Increase stack size\njava -Xss4m MyApp\n# Convert recursion to iteration\nStack<Frame> stack = new Stack<>();\nwhile (!stack.isEmpty()) { ... }\n# Add base case to recursive method\nif (depth > MAX_DEPTH) return;",
    "sources": [
      "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/StackOverflowError.html"
    ]
  },
  {
    "id": "java-classcastexception",
    "title": "ClassCastException",
    "category": "Java",
    "explanation": "An object was cast to a type it is not an instance of. Common when using raw types or incorrect downcasting.",
    "fix_snippet": "# Check type before casting\nif (obj instanceof MyClass) {\n    MyClass mc = (MyClass) obj;\n}\n# Use generics to avoid raw types\nList<String> list = new ArrayList<>();\n# Use pattern matching (Java 16+)\nif (obj instanceof MyClass mc) { ... }",
    "sources": [
      "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/ClassCastException.html"
    ]
  },
  {
    "id": "java-concurrentmodification",
    "title": "ConcurrentModificationException",
    "category": "Java",
    "explanation": "A collection was modified while being iterated over. This can happen in single-threaded code when modifying a list during a for-each loop.",
    "fix_snippet": "# Use Iterator.remove()\nIterator<String> it = list.iterator();\nwhile (it.hasNext()) {\n    if (condition) it.remove();\n}\n# Or use ConcurrentHashMap\nMap<K,V> map = new ConcurrentHashMap<>();\n# Or collect and remove after\nlist.removeIf(item -> condition);",
    "sources": [
      "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/ConcurrentModificationException.html"
    ]
  },
  {
    "id": "java-unsupported-class-version",
    "title": "UnsupportedClassVersionError",
    "category": "Java",
    "explanation": "A class was compiled with a newer version of the JDK than the JRE running it. For example, compiled with Java 17 but running on Java 11.",
    "fix_snippet": "# Check Java version\njava -version\njavac -version\n# Set target compatibility in Maven\n<maven.compiler.target>11</maven.compiler.target>\n# Or in Gradle\nsourceCompatibility = '11'\ntargetCompatibility = '11'",
    "sources": [
      "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/UnsupportedClassVersionError.html"
    ]
  },
  {
    "id": "java-maven-dependency-resolution",
    "title": "Could not resolve dependencies",
    "category": "Java",
    "explanation": "Maven or Gradle cannot download or resolve project dependencies. May be caused by missing repositories, network issues, or version conflicts.",
    "fix_snippet": "# Force update dependencies\nmvn clean install -U\n# Check dependency tree\nmvn dependency:tree\n# Clear local cache\nrm -rf ~/.m2/repository/com/problem/package\n# For Gradle\ngradle build --refresh-dependencies",
    "sources": [
      "https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html"
    ]
  },
  {
    "id": "java-connection-pool-exhausted",
    "title": "Cannot get a connection, pool error",
    "category": "Java",
    "explanation": "The database connection pool (HikariCP, DBCP, etc.) has no available connections. All connections are in use and the wait timeout was exceeded.",
    "fix_snippet": "# Increase pool size in application.properties\nspring.datasource.hikari.maximum-pool-size=20\n# Set connection timeout\nspring.datasource.hikari.connection-timeout=30000\n# Ensure connections are closed\ntry (Connection conn = dataSource.getConnection()) {\n    // use connection\n}",
    "sources": [
      "https://github.com/brettwooldridge/HikariCP#configuration-knobs-baby"
    ]
  },
  {
    "id": "php-allowed-memory-size",
    "title": "Allowed memory size exhausted",
    "category": "PHP",
    "explanation": "The PHP script exceeded the configured memory_limit. Usually caused by loading large datasets, infinite loops, or memory leaks.",
    "fix_snippet": "# Increase memory limit in php.ini\nmemory_limit = 256M\n# Or at runtime\nini_set('memory_limit', '256M');\n# Process data in chunks\nforeach (array_chunk($data, 1000) as $chunk) {\n    process($chunk);\n}",
    "sources": [
      "https://www.php.net/manual/en/ini.core.php#ini.memory-limit"
    ]
  },
  {
    "id": "php-max-execution-time",
    "title": "Maximum execution time exceeded",
    "category": "PHP",
    "explanation": "The PHP script ran longer than the max_execution_time setting allows. Default is usually 30 seconds.",
    "fix_snippet": "# Increase in php.ini\nmax_execution_time = 120\n# Or at runtime\nset_time_limit(120);\n# For CLI scripts (unlimited)\nset_time_limit(0);\n# Move long tasks to background jobs",
    "sources": [
      "https://www.php.net/manual/en/info.configuration.php#ini.max-execution-time"
    ]
  },
  {
    "id": "php-class-not-found",
    "title": "Class 'X' not found",
    "category": "PHP",
    "explanation": "PHP cannot find the specified class. Usually caused by a missing use statement, incorrect namespace, or autoloader not configured.",
    "fix_snippet": "# Add use statement\nuse App\\Models\\User;\n# Regenerate autoloader\ncomposer dump-autoload\n# Check namespace matches directory structure\n# PSR-4: src/Models/User.php -> App\\Models\\User",
    "sources": [
      "https://www.php.net/manual/en/language.oop5.autoload.php"
    ]
  },
  {
    "id": "php-composer-dependency-conflict",
    "title": "Your requirements could not be resolved to an installable set of packages",
    "category": "PHP",
    "explanation": "Composer cannot find compatible versions for all dependencies. Two or more packages require conflicting versions of a shared dependency.",
    "fix_snippet": "# Update with dependency resolution\ncomposer update --with-dependencies\n# Check why a package can't be installed\ncomposer why-not package/name 2.0\n# Allow more flexibility\ncomposer require package/name:^2.0\n# Clear cache\ncomposer clear-cache",
    "sources": [
      "https://getcomposer.org/doc/articles/troubleshooting.md"
    ]
  },
  {
    "id": "php-undefined-index",
    "title": "Undefined index / Undefined array key",
    "category": "PHP",
    "explanation": "Accessing an array key that does not exist. In PHP 8+ this is a warning; in older versions it was a notice.",
    "fix_snippet": "# Check key exists before access\nif (isset($array['key'])) {\n    $val = $array['key'];\n}\n# Use null coalescing operator\n$val = $array['key'] ?? 'default';\n# Use array_key_exists()\nif (array_key_exists('key', $array)) { ... }",
    "sources": [
      "https://www.php.net/manual/en/language.types.array.php"
    ]
  },
  {
    "id": "php-pdo-connection-failed",
    "title": "SQLSTATE[HY000]: Connection refused",
    "category": "PHP",
    "explanation": "PDO cannot connect to the database server. The database may be down, credentials wrong, or the host/port incorrect.",
    "fix_snippet": "# Verify database is running\nsudo systemctl status mysql\n# Test connection manually\nmysql -u user -p -h localhost\n# Check PDO DSN\n$dsn = 'mysql:host=127.0.0.1;port=3306;dbname=mydb';\n# Check socket path\nmysql -u user -p --socket=/var/run/mysqld/mysqld.sock",
    "sources": [
      "https://www.php.net/manual/en/pdo.connections.php"
    ]
  },
  {
    "id": "cpp-undefined-reference",
    "title": "undefined reference to 'function'",
    "category": "C++",
    "explanation": "The linker cannot find the definition of a function or variable that was declared. The source file may not be compiled or linked.",
    "fix_snippet": "# Include source file in compilation\ng++ main.cpp utils.cpp -o program\n# Check for missing library linkage\ng++ main.cpp -lmylib -L/path/to/lib\n# In CMake, add source files\nadd_executable(app main.cpp utils.cpp)\ntarget_link_libraries(app mylib)",
    "sources": [
      "https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html"
    ]
  },
  {
    "id": "cpp-double-free",
    "title": "double free or corruption",
    "category": "C++",
    "explanation": "Heap memory was freed twice, corrupting the memory allocator. Often caused by manual delete on already-freed memory or missing copy constructors.",
    "fix_snippet": "# Use smart pointers instead of raw pointers\nstd::unique_ptr<MyClass> ptr = std::make_unique<MyClass>();\n# Follow Rule of Five\n// Define copy/move constructors and assignment operators\n# Detect with AddressSanitizer\ng++ -fsanitize=address -g main.cpp",
    "sources": [
      "https://github.com/google/sanitizers/wiki/AddressSanitizer"
    ]
  },
  {
    "id": "cpp-stack-buffer-overflow",
    "title": "stack-buffer-overflow",
    "category": "C++",
    "explanation": "A write exceeded the bounds of a stack-allocated buffer. Detected by AddressSanitizer or causing a crash/segfault.",
    "fix_snippet": "# Use std::array or std::vector instead of C arrays\nstd::vector<int> vec(100);\n# Enable bounds checking\nvec.at(index); // throws on out-of-bounds\n# Compile with sanitizer\ng++ -fsanitize=address -fstack-protector-strong -g main.cpp",
    "sources": [
      "https://github.com/google/sanitizers/wiki/AddressSanitizer"
    ]
  },
  {
    "id": "cpp-template-deduction-failed",
    "title": "template argument deduction/substitution failed",
    "category": "C++",
    "explanation": "The compiler could not deduce template arguments from the function call or the substituted types are invalid (SFINAE).",
    "fix_snippet": "# Explicitly specify template arguments\nfoo<int, double>(42, 3.14);\n# Ensure argument types match template expectations\n# Use static_assert for clearer errors\nstatic_assert(std::is_integral_v<T>, \"T must be integral\");\n# Check for missing includes of type traits",
    "sources": [
      "https://en.cppreference.com/w/cpp/language/template_argument_deduction"
    ]
  },
  {
    "id": "cpp-linker-multiple-definition",
    "title": "multiple definition of 'symbol'",
    "category": "C++",
    "explanation": "The same symbol is defined in multiple translation units. Usually caused by defining functions/variables in headers without inline or static.",
    "fix_snippet": "# Use inline for functions defined in headers\ninline void myFunc() { ... }\n# Use header guards\n#pragma once\n# For global variables, use inline (C++17)\ninline int globalVar = 42;\n# Or declare extern in header, define in one .cpp",
    "sources": [
      "https://en.cppreference.com/w/cpp/language/inline"
    ]
  },
  {
    "id": "cpp-use-after-free",
    "title": "heap-use-after-free",
    "category": "C++",
    "explanation": "Accessing memory after it has been freed. Detected by AddressSanitizer. Causes undefined behaviour and potential security vulnerabilities.",
    "fix_snippet": "# Use smart pointers\nstd::shared_ptr<MyClass> ptr = std::make_shared<MyClass>();\n# Set raw pointers to nullptr after delete\ndelete ptr;\nptr = nullptr;\n# Detect with ASan\ng++ -fsanitize=address -g main.cpp\n./a.out",
    "sources": [
      "https://github.com/google/sanitizers/wiki/AddressSanitizer"
    ]
  },
  {
    "id": "ingress-default-backend-404",
    "title": "Ingress: default backend - 404",
    "category": "Ingress",
    "explanation": "No Ingress rule matched the request, so it was routed to the default backend which returned 404. The host or path may not match any Ingress resource.",
    "fix_snippet": "# Check ingress rules\nkubectl get ingress -A\n# Verify host matches\nkubectl describe ingress my-ingress\n# Check the request host header\ncurl -H 'Host: myapp.example.com' http://<ingress-ip>\n# Ensure DNS points to ingress controller",
    "sources": [
      "https://kubernetes.io/docs/concepts/services-networking/ingress/"
    ]
  },
  {
    "id": "ingress-tls-secret-not-found",
    "title": "Ingress: TLS secret not found",
    "category": "Ingress",
    "explanation": "The TLS secret referenced in the Ingress spec does not exist in the same namespace. HTTPS termination will fail.",
    "fix_snippet": "# Check if secret exists in the right namespace\nkubectl get secrets -n my-namespace\n# Create TLS secret\nkubectl create secret tls my-tls --cert=cert.pem --key=key.pem -n my-namespace\n# Verify secret is referenced correctly in Ingress spec\nkubectl describe ingress my-ingress",
    "sources": [
      "https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"
    ]
  },
  {
    "id": "ingress-class-not-found",
    "title": "IngressClass not found",
    "category": "Ingress",
    "explanation": "The specified IngressClass does not exist or no ingress controller is installed that handles that class.",
    "fix_snippet": "# List available IngressClasses\nkubectl get ingressclass\n# Set the correct class in your Ingress\nspec:\n  ingressClassName: nginx\n# Install an ingress controller if missing\nhelm install ingress-nginx ingress-nginx/ingress-nginx",
    "sources": [
      "https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class"
    ]
  },
  {
    "id": "ingress-path-not-matching",
    "title": "Ingress: path not matching any backend",
    "category": "Ingress",
    "explanation": "The request path does not match any rule defined in the Ingress resource. May be a pathType (Prefix vs Exact) or regex mismatch.",
    "fix_snippet": "# Check path configuration\nspec:\n  rules:\n  - http:\n      paths:\n      - path: /api\n        pathType: Prefix\n        backend:\n          service:\n            name: api-svc\n            port:\n              number: 80\n# Use Prefix for wildcard matching",
    "sources": [
      "https://kubernetes.io/docs/concepts/services-networking/ingress/#path-types"
    ]
  },
  {
    "id": "ingress-too-many-redirects",
    "title": "Ingress: too many redirects (redirect loop)",
    "category": "Ingress",
    "explanation": "An infinite redirect loop between the ingress controller and backend, usually caused by SSL redirect annotations conflicting with a load balancer that already terminates TLS.",
    "fix_snippet": "# Disable SSL redirect if LB handles TLS\nmetadata:\n  annotations:\n    nginx.ingress.kubernetes.io/ssl-redirect: \"false\"\n# Or use X-Forwarded-Proto\nnginx.ingress.kubernetes.io/use-forwarded-headers: \"true\"",
    "sources": [
      "https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/"
    ]
  },
  {
    "id": "graphql-max-depth-exceeded",
    "title": "GraphQL: Max query depth exceeded",
    "category": "GraphQL",
    "explanation": "The query exceeds the server's maximum allowed nesting depth. This is a security measure to prevent deeply nested queries from overloading the server.",
    "fix_snippet": "# Reduce query nesting depth\n# Instead of deeply nested queries, fetch in separate requests\n# Adjust server config if needed\nconst server = new ApolloServer({\n  validationRules: [depthLimit(10)]\n});",
    "sources": [
      "https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries"
    ]
  },
  {
    "id": "graphql-authentication-error",
    "title": "GraphQL: Not authenticated",
    "category": "GraphQL",
    "explanation": "The resolver requires authentication but no valid token or session was provided in the request context.",
    "fix_snippet": "# Include auth header in request\nfetch('/graphql', {\n  headers: {\n    'Authorization': 'Bearer <token>',\n    'Content-Type': 'application/json'\n  }\n})\n# Check token expiration\n# Verify context setup in server",
    "sources": [
      "https://graphql.org/learn/authorization/"
    ]
  },
  {
    "id": "graphql-field-type-mismatch",
    "title": "GraphQL: Expected type X, found Y",
    "category": "GraphQL",
    "explanation": "A variable or argument type does not match the schema definition. For example, passing a String where an Int is expected.",
    "fix_snippet": "# Check schema for expected types\ntype Query {\n  user(id: ID!): User\n}\n# Ensure variables match declared types\nquery GetUser($id: ID!) {\n  user(id: $id) { name }\n}\n# Variables: { \"id\": \"123\" }",
    "sources": [
      "https://graphql.org/learn/schema/"
    ]
  },
  {
    "id": "graphql-n-plus-one",
    "title": "GraphQL: N+1 query problem",
    "category": "GraphQL",
    "explanation": "Each item in a list triggers a separate database query for related data, causing performance degradation. Resolvers fetch data individually instead of batching.",
    "fix_snippet": "# Use DataLoader for batching\nconst userLoader = new DataLoader(ids => batchGetUsers(ids));\n# In resolver\nresolve(parent) {\n  return userLoader.load(parent.userId);\n}\n# Install: npm install dataloader",
    "sources": [
      "https://github.com/graphql/dataloader"
    ]
  },
  {
    "id": "graphql-circular-fragment",
    "title": "GraphQL: Cannot spread fragment within itself",
    "category": "GraphQL",
    "explanation": "A fragment references itself directly or indirectly, creating a circular reference. GraphQL does not allow recursive fragments.",
    "fix_snippet": "# Remove circular fragment reference\n# Instead of recursive fragments, inline nested fields\nquery {\n  category {\n    name\n    children {\n      name\n      children {\n        name\n      }\n    }\n  }\n}\n# Or limit depth server-side",
    "sources": [
      "https://graphql.org/learn/queries/#fragments"
    ]
  },
  {
    "id": "nginx-413-request-entity-too-large",
    "title": "Nginx: 413 Request Entity Too Large",
    "category": "WebServer",
    "explanation": "The request body exceeds Nginx's client_max_body_size directive. Default is 1MB.",
    "fix_snippet": "# Increase in nginx.conf (http, server, or location block)\nclient_max_body_size 50M;\n# Test configuration\nnginx -t\n# Reload\nsudo systemctl reload nginx",
    "sources": [
      "https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size"
    ]
  },
  {
    "id": "nginx-permission-denied-log",
    "title": "Nginx: open() failed (13: Permission denied)",
    "category": "WebServer",
    "explanation": "Nginx worker process cannot read the requested file or write to log files due to filesystem permissions.",
    "fix_snippet": "# Check Nginx worker user\ngrep 'user' /etc/nginx/nginx.conf\n# Fix file permissions\nsudo chown -R www-data:www-data /var/www/html\nsudo chmod -R 755 /var/www/html\n# Fix log permissions\nsudo chown www-data:adm /var/log/nginx/*.log",
    "sources": [
      "https://nginx.org/en/docs/beginners_guide.html"
    ]
  },
  {
    "id": "apache-mod-rewrite-not-working",
    "title": "Apache: mod_rewrite not enabled",
    "category": "WebServer",
    "explanation": "URL rewriting rules in .htaccess are not working because the mod_rewrite module is not loaded in Apache.",
    "fix_snippet": "# Enable mod_rewrite\nsudo a2enmod rewrite\n# Ensure AllowOverride is set\n<Directory /var/www/html>\n    AllowOverride All\n</Directory>\n# Restart Apache\nsudo systemctl restart apache2",
    "sources": [
      "https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html"
    ]
  },
  {
    "id": "iis-500-19-config-error",
    "title": "IIS: HTTP Error 500.19 - Internal Server Error",
    "category": "WebServer",
    "explanation": "IIS cannot read the web.config file due to syntax errors, missing modules, or insufficient permissions.",
    "fix_snippet": "# Check web.config for XML syntax errors\n# Install missing IIS modules\nInstall-WindowsFeature Web-Asp-Net45\n# Fix permissions on web.config\nicacls web.config /grant \"IIS_IUSRS:(R)\"\n# Check applicationHost.config for locked sections",
    "sources": [
      "https://learn.microsoft.com/en-us/iis/troubleshoot/diagnosing-http-errors"
    ]
  },
  {
    "id": "caddy-reverse-proxy-502",
    "title": "Caddy: 502 Bad Gateway (reverse proxy)",
    "category": "WebServer",
    "explanation": "Caddy's reverse proxy cannot reach the upstream backend. The backend service may be down or listening on a different address.",
    "fix_snippet": "# Verify backend is running\ncurl http://localhost:3000/health\n# Check Caddyfile config\nreverse_proxy localhost:3000 {\n    transport http {\n        dial_timeout 10s\n    }\n}\n# Reload Caddy\ncaddy reload",
    "sources": [
      "https://caddyserver.com/docs/caddyfile/directives/reverse_proxy"
    ]
  },
  {
    "id": "nginx-ssl-no-shared-cipher",
    "title": "Nginx: no shared cipher (SSL)",
    "category": "WebServer",
    "explanation": "The client and Nginx have no common SSL/TLS cipher suite. Usually caused by overly restrictive ssl_ciphers configuration.",
    "fix_snippet": "# Update cipher configuration in nginx.conf\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';\nssl_protocols TLSv1.2 TLSv1.3;\n# Test cipher compatibility\nopenssl s_client -connect example.com:443 -cipher ECDHE",
    "sources": [
      "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_ciphers"
    ]
  },
  {
    "id": "datadog-agent-no-data",
    "title": "Datadog: Agent not reporting data",
    "category": "Monitoring",
    "explanation": "The Datadog Agent is installed but not sending metrics to the Datadog platform. May be caused by API key issues, network blocks, or agent misconfiguration.",
    "fix_snippet": "# Check agent status\nsudo datadog-agent status\n# Verify API key\nsudo datadog-agent configcheck\n# Check connectivity\nsudo datadog-agent diagnose\n# Restart agent\nsudo systemctl restart datadog-agent",
    "sources": [
      "https://docs.datadoghq.com/agent/troubleshooting/"
    ]
  },
  {
    "id": "cloudwatch-insufficient-data",
    "title": "CloudWatch Alarm: INSUFFICIENT_DATA",
    "category": "Monitoring",
    "explanation": "A CloudWatch alarm has no data to evaluate against. The metric may not be emitting data, the namespace may be wrong, or the evaluation period is too short.",
    "fix_snippet": "# Check if metric exists\naws cloudwatch list-metrics --namespace AWS/EC2\n# Verify dimensions match\naws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --dimensions Name=InstanceId,Value=i-xxx --period 300 --statistics Average --start-time ... --end-time ...\n# Check alarm configuration\naws cloudwatch describe-alarms --alarm-names my-alarm",
    "sources": [
      "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
    ]
  },
  {
    "id": "prometheus-scrape-timeout",
    "title": "Prometheus: context deadline exceeded (scrape)",
    "category": "Monitoring",
    "explanation": "Prometheus timed out while scraping a target. The target is too slow to respond within the configured scrape_timeout.",
    "fix_snippet": "# Increase scrape timeout in prometheus.yml\nscrape_configs:\n  - job_name: 'slow-target'\n    scrape_timeout: 30s\n    scrape_interval: 60s\n# Check target health\ncurl http://target:9090/metrics\n# Verify target status in Prometheus UI\n# Status -> Targets",
    "sources": [
      "https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config"
    ]
  },
  {
    "id": "jaeger-span-dropped",
    "title": "Jaeger: spans dropped",
    "category": "Monitoring",
    "explanation": "The Jaeger collector is dropping spans because its internal queue is full. The collector cannot process spans fast enough.",
    "fix_snippet": "# Increase collector queue size\n--collector.queue-size=10000\n# Scale collectors horizontally\n# Check storage backend performance\n# Reduce sampling rate on client side\nsampler:\n  type: probabilistic\n  param: 0.1",
    "sources": [
      "https://www.jaegertracing.io/docs/latest/troubleshooting/"
    ]
  },
  {
    "id": "sentry-rate-limit-exceeded",
    "title": "Sentry: Rate limit exceeded",
    "category": "Monitoring",
    "explanation": "The project has exceeded its Sentry event quota. New error events are being dropped.",
    "fix_snippet": "# Configure sample rate in SDK\nSentry.init({\n  tracesSampleRate: 0.2,\n  sampleRate: 0.5\n});\n# Set up inbound filters in Sentry UI\n# Project Settings -> Inbound Filters\n# Upgrade plan or increase quota",
    "sources": [
      "https://docs.sentry.io/product/accounts/quotas/"
    ]
  },
  {
    "id": "openai-api-key-invalid",
    "title": "OpenAI: Incorrect API key provided",
    "category": "AI",
    "explanation": "The API key used in the request is invalid, expired, or revoked. May also occur if the key is from a different organisation.",
    "fix_snippet": "# Verify API key is set correctly\nexport OPENAI_API_KEY=sk-...\n# Test with curl\ncurl https://api.openai.com/v1/models -H \"Authorization: Bearer $OPENAI_API_KEY\"\n# Generate new key at platform.openai.com/api-keys\n# Check organization ID if using multiple orgs",
    "sources": [
      "https://platform.openai.com/docs/api-reference/authentication"
    ]
  },
  {
    "id": "huggingface-cuda-mismatch",
    "title": "HuggingFace/PyTorch: CUDA version mismatch",
    "category": "AI",
    "explanation": "The installed PyTorch version was compiled for a different CUDA version than what's available on the system.",
    "fix_snippet": "# Check CUDA version\nnvcc --version\nnvidia-smi\n# Install matching PyTorch version\npip install torch --index-url https://download.pytorch.org/whl/cu121\n# Verify\npython -c \"import torch; print(torch.cuda.is_available())\"",
    "sources": [
      "https://pytorch.org/get-started/locally/"
    ]
  },
  {
    "id": "tensorflow-gpu-not-found",
    "title": "TensorFlow: Could not find GPU",
    "category": "AI",
    "explanation": "TensorFlow cannot detect any GPU devices. CUDA, cuDNN, or GPU drivers may not be installed or are incompatible.",
    "fix_snippet": "# Check GPU detection\npython -c \"import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))\"\n# Verify NVIDIA driver\nnvidia-smi\n# Install compatible versions\npip install tensorflow[and-cuda]\n# Check CUDA/cuDNN compatibility matrix",
    "sources": [
      "https://www.tensorflow.org/install/pip"
    ]
  },
  {
    "id": "langchain-token-limit",
    "title": "LangChain: Token limit exceeded for chain",
    "category": "AI",
    "explanation": "The combined input (prompt + context + history) exceeds the model's context window size.",
    "fix_snippet": "# Use a model with larger context\nllm = ChatOpenAI(model=\"gpt-4-turbo\")\n# Truncate context\nfrom langchain.text_splitter import TokenTextSplitter\nsplitter = TokenTextSplitter(chunk_size=2000)\n# Use ConversationSummaryMemory instead of buffer\nmemory = ConversationSummaryMemory(llm=llm)",
    "sources": [
      "https://python.langchain.com/docs/concepts/tokens/"
    ]
  },
  {
    "id": "ollama-model-not-found",
    "title": "Ollama: model not found",
    "category": "AI",
    "explanation": "The requested model has not been pulled/downloaded locally. Ollama requires models to be downloaded before use.",
    "fix_snippet": "# Pull the model first\nollama pull llama3\n# List available models\nollama list\n# Run model\nollama run llama3\n# Check model library\n# https://ollama.com/library",
    "sources": [
      "https://github.com/ollama/ollama/blob/main/docs/README.md"
    ]
  },
  {
    "id": "anthropic-api-overloaded",
    "title": "Anthropic API: Overloaded (529)",
    "category": "AI",
    "explanation": "The Anthropic API is temporarily overloaded and cannot process your request. This is a transient server-side issue.",
    "fix_snippet": "# Implement exponential backoff\nimport time\nfor attempt in range(5):\n    try:\n        response = client.messages.create(...)\n        break\n    except anthropic.APIStatusError as e:\n        if e.status_code == 529:\n            time.sleep(2 ** attempt)\n        else:\n            raise",
    "sources": [
      "https://docs.anthropic.com/en/api/errors"
    ]
  },
  {
    "id": "vllm-kv-cache-oom",
    "title": "vLLM: KV cache out of memory",
    "category": "AI",
    "explanation": "The vLLM inference server ran out of GPU memory for the key-value cache, which stores attention states for concurrent requests.",
    "fix_snippet": "# Reduce GPU memory utilization\npython -m vllm.entrypoints.openai.api_server --gpu-memory-utilization 0.85\n# Limit max concurrent sequences\n--max-num-seqs 128\n# Use quantization\n--quantization awq\n# Reduce max model length\n--max-model-len 4096",
    "sources": [
      "https://docs.vllm.ai/en/latest/serving/engine_args.html"
    ]
  },
  {
    "id": "hadoop-namenode-safe-mode",
    "title": "Hadoop: NameNode is in safe mode",
    "category": "BigData",
    "explanation": "HDFS NameNode is in safe mode, making the filesystem read-only. This happens at startup until enough DataNodes report their blocks.",
    "fix_snippet": "# Check safe mode status\nhdfs dfsadmin -safemode get\n# Wait for automatic exit or force leave\nhdfs dfsadmin -safemode leave\n# Check for under-replicated blocks\nhdfs dfsadmin -report\n# Fix corrupt blocks\nhdfs fsck / -delete",
    "sources": [
      "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-hdfs/HdfsUserGuide.html"
    ]
  },
  {
    "id": "hive-metastore-connection-failed",
    "title": "Hive: MetaStore connection failed",
    "category": "BigData",
    "explanation": "Hive cannot connect to its MetaStore service, which stores table schemas and partition info. The MetaStore process may be down or misconfigured.",
    "fix_snippet": "# Check MetaStore status\nsudo systemctl status hive-metastore\n# Start MetaStore\nhive --service metastore &\n# Check connection config in hive-site.xml\n# hive.metastore.uris = thrift://localhost:9083\n# Verify database backend\nmysql -u hive -p -e 'SELECT 1'",
    "sources": [
      "https://cwiki.apache.org/confluence/display/Hive/AdminManual+Metastore+Administration"
    ]
  },
  {
    "id": "kafka-consumer-group-rebalance",
    "title": "Kafka: Consumer group rebalancing",
    "category": "BigData",
    "explanation": "Kafka consumer group is stuck in a rebalance loop. Consumers are frequently joining and leaving, causing partition reassignment storms.",
    "fix_snippet": "# Increase session timeout\nsession.timeout.ms=45000\nheartbeat.interval.ms=15000\n# Increase max poll interval\nmax.poll.interval.ms=600000\n# Reduce max.poll.records\nmax.poll.records=100\n# Check consumer group status\nkafka-consumer-groups.sh --describe --group my-group",
    "sources": [
      "https://kafka.apache.org/documentation/#consumerconfigs"
    ]
  },
  {
    "id": "flink-checkpoint-failed",
    "title": "Flink: Checkpoint failed",
    "category": "BigData",
    "explanation": "Apache Flink failed to complete a checkpoint within the timeout. Usually caused by backpressure, slow state backend, or network issues.",
    "fix_snippet": "# Increase checkpoint timeout\nexecution.checkpointing.timeout: 600000\n# Use incremental checkpoints for RocksDB\nstate.backend.incremental: true\n# Increase parallelism\n# Check backpressure in Flink UI\n# Tune RocksDB memory\nstate.backend.rocksdb.memory.managed: true",
    "sources": [
      "https://nightlies.apache.org/flink/flink-docs-stable/docs/ops/state/checkpoints/"
    ]
  },
  {
    "id": "databricks-cluster-terminated",
    "title": "Databricks: Cluster terminated unexpectedly",
    "category": "BigData",
    "explanation": "A Databricks cluster was terminated due to spot instance reclamation, out of memory, or cloud provider issues.",
    "fix_snippet": "# Check cluster event log in Databricks UI\n# Compute -> Cluster -> Event Log\n# Use on-demand instances for critical jobs\n# Increase driver/worker memory\n# Enable cluster auto-scaling\n# Configure spot fallback to on-demand",
    "sources": [
      "https://docs.databricks.com/clusters/troubleshooting.html"
    ]
  },
  {
    "id": "csharp-stackoverflow",
    "title": "StackOverflowException",
    "category": "C#",
    "explanation": "Infinite recursion or very deep call stack exceeded the stack size. Unlike most exceptions, StackOverflowException cannot be caught in C#.",
    "fix_snippet": "# Convert recursion to iteration\nvar stack = new Stack<Node>();\nstack.Push(root);\nwhile (stack.Count > 0) {\n    var node = stack.Pop();\n    // process node\n}\n# Check for accidental property recursion\n// BAD: public int X { get { return X; } }\n# Increase stack size for thread\nnew Thread(Method, 4 * 1024 * 1024);",
    "sources": [
      "https://learn.microsoft.com/en-us/dotnet/api/system.stackoverflowexception"
    ]
  },
  {
    "id": "csharp-task-canceled",
    "title": "TaskCanceledException",
    "category": "C#",
    "explanation": "An async operation was cancelled via a CancellationToken or the HttpClient request timed out.",
    "fix_snippet": "# Increase HttpClient timeout\nvar client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };\n# Handle cancellation gracefully\ntry {\n    await DoWorkAsync(cancellationToken);\n} catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested) {\n    // expected cancellation\n}",
    "sources": [
      "https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.taskcanceledexception"
    ]
  },
  {
    "id": "csharp-deadlock-async",
    "title": "C#: Deadlock in async/await",
    "category": "C#",
    "explanation": "Calling .Result or .Wait() on an async method from a synchronisation context (UI thread, ASP.NET) causes a deadlock. The awaited task needs the same context that is blocked.",
    "fix_snippet": "# Use async all the way\nawait DoWorkAsync(); // not DoWorkAsync().Result\n# Use ConfigureAwait(false) in libraries\nawait httpClient.GetAsync(url).ConfigureAwait(false);\n# If you must call sync, use Task.Run\nvar result = Task.Run(() => DoWorkAsync()).Result;",
    "sources": [
      "https://learn.microsoft.com/en-us/archive/msdn-magazine/2015/july/async-programming-brownfield-async-development"
    ]
  },
  {
    "id": "aspnet-connection-string-error",
    "title": "ASP.NET: Connection string not found in configuration",
    "category": "C#",
    "explanation": "The application cannot find the database connection string in appsettings.json or environment variables.",
    "fix_snippet": "# Add to appsettings.json\n{\n  \"ConnectionStrings\": {\n    \"DefaultConnection\": \"Server=localhost;Database=mydb;User=sa;Password=...;\"\n  }\n}\n# Access in code\nbuilder.Services.AddDbContext<AppDbContext>(options =>\n    options.UseSqlServer(builder.Configuration.GetConnectionString(\"DefaultConnection\")));",
    "sources": [
      "https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/"
    ]
  },
  {
    "id": "blazor-js-interop-failed",
    "title": "Blazor: JavaScript interop call failed",
    "category": "C#",
    "explanation": "A Blazor JS interop call threw an error because the JavaScript function was not found, threw an exception, or was called before the JS runtime was available.",
    "fix_snippet": "# Ensure JS function exists in wwwroot/js/site.js\nwindow.myFunction = (arg) => { return arg; };\n# Wait for first render before calling JS\nprotected override async Task OnAfterRenderAsync(bool firstRender) {\n    if (firstRender) {\n        await JS.InvokeVoidAsync(\"myFunction\", arg);\n    }\n}",
    "sources": [
      "https://learn.microsoft.com/en-us/aspnet/core/blazor/javascript-interoperability/"
    ]
  },
  {
    "id": "ruby-gem-native-extension-error",
    "title": "Ruby: Failed to build gem native extension",
    "category": "Ruby",
    "explanation": "A gem with C extensions failed to compile because system libraries or development headers are missing.",
    "fix_snippet": "# Install build tools (Ubuntu/Debian)\nsudo apt-get install build-essential libssl-dev libffi-dev\n# For nokogiri\nsudo apt-get install libxml2-dev libxslt-dev\n# For pg gem\nsudo apt-get install libpq-dev\n# macOS\nbrew install openssl libffi",
    "sources": [
      "https://guides.rubygems.org/faqs/"
    ]
  },
  {
    "id": "ruby-load-error",
    "title": "LoadError: cannot load such file",
    "category": "Ruby",
    "explanation": "Ruby cannot find the required file or gem. The gem may not be installed, or the require path is incorrect.",
    "fix_snippet": "# Install missing gem\ngem install missing_gem\n# Or add to Gemfile and run\nbundle install\n# Check load path\nputs $LOAD_PATH\n# Use require_relative for local files\nrequire_relative 'lib/my_module'",
    "sources": [
      "https://ruby-doc.org/core/Kernel.html#method-i-require"
    ]
  },
  {
    "id": "ruby-encoding-error",
    "title": "Encoding::InvalidByteSequenceError",
    "category": "Ruby",
    "explanation": "A string contains bytes that are invalid for the expected encoding (e.g., invalid UTF-8 bytes).",
    "fix_snippet": "# Force encoding\nstr = str.force_encoding('UTF-8')\n# Encode with replacement\nstr = str.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')\n# Read file with encoding\nFile.read('file.txt', encoding: 'UTF-8')\n# Add magic comment\n# encoding: utf-8",
    "sources": [
      "https://ruby-doc.org/core/Encoding.html"
    ]
  },
  {
    "id": "rails-asset-not-precompiled",
    "title": "Rails: Asset not precompiled",
    "category": "Ruby",
    "explanation": "A referenced asset (CSS, JS, image) was not included in the precompiled asset list for production.",
    "fix_snippet": "# Precompile assets\nRAILS_ENV=production bundle exec rails assets:precompile\n# Add custom assets to precompile list in config/initializers/assets.rb\nRails.application.config.assets.precompile += %w( admin.js admin.css )\n# Clear old assets\nbundle exec rails assets:clobber",
    "sources": [
      "https://guides.rubyonrails.org/asset_pipeline.html"
    ]
  },
  {
    "id": "rails-routing-error",
    "title": "Rails: No route matches",
    "category": "Ruby",
    "explanation": "The requested URL does not match any route defined in config/routes.rb.",
    "fix_snippet": "# List all routes\nbundle exec rails routes\n# Add missing route in config/routes.rb\nRails.application.routes.draw do\n  resources :users\n  get '/about', to: 'pages#about'\nend\n# Check for typos in path helpers\n# users_path vs user_path(@user)",
    "sources": [
      "https://guides.rubyonrails.org/routing.html"
    ]
  },
  {
    "id": "git-rebase-conflict",
    "title": "Git: CONFLICT during rebase",
    "category": "Git",
    "explanation": "A merge conflict occurred while replaying commits during a rebase. The same lines were modified in both branches.",
    "fix_snippet": "# Fix conflicts in marked files\n# Look for <<<<<<< HEAD markers\n# After fixing, stage the files\ngit add resolved-file.txt\n# Continue rebase\ngit rebase --continue\n# Or abort to go back\ngit rebase --abort",
    "sources": [
      "https://git-scm.com/docs/git-rebase"
    ]
  },
  {
    "id": "git-submodule-not-initialized",
    "title": "Git: Submodule path not initialized",
    "category": "Git",
    "explanation": "A git submodule was not initialised or updated after cloning. The submodule directory is empty.",
    "fix_snippet": "# Initialize and update submodules\ngit submodule update --init --recursive\n# Clone with submodules\ngit clone --recurse-submodules https://repo.git\n# Update existing submodules\ngit submodule update --remote",
    "sources": [
      "https://git-scm.com/docs/git-submodule"
    ]
  },
  {
    "id": "git-lfs-missing-objects",
    "title": "Git LFS: missing objects",
    "category": "Git",
    "explanation": "Git LFS pointer files exist but the actual large file content was not downloaded. The LFS server may be unreachable or the files were not fetched.",
    "fix_snippet": "# Fetch LFS objects\ngit lfs fetch --all\n# Pull LFS content\ngit lfs pull\n# Check LFS status\ngit lfs status\n# Re-install LFS hooks\ngit lfs install",
    "sources": [
      "https://git-lfs.com/"
    ]
  },
  {
    "id": "git-remote-rejected-protected",
    "title": "Git: remote rejected (protected branch)",
    "category": "Git",
    "explanation": "Direct push to a protected branch was rejected. The branch requires pull requests or specific permissions.",
    "fix_snippet": "# Push to a feature branch instead\ngit checkout -b feature/my-change\ngit push origin feature/my-change\n# Create PR via CLI\ngh pr create --base main --head feature/my-change\n# If you need to force push (admin only)\ngit push --force-with-lease origin main",
    "sources": [
      "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches"
    ]
  },
  {
    "id": "git-stash-apply-conflict",
    "title": "Git: Could not apply stash",
    "category": "Git",
    "explanation": "Applying a stash caused conflicts because the working tree has diverged from when the stash was created.",
    "fix_snippet": "# Apply stash and resolve conflicts\ngit stash apply\n# Fix conflict markers then stage\ngit add .\n# If stash conflicts badly, try on a new branch\ngit stash branch new-branch\n# List stashes\ngit stash list\n# Drop stash after resolving\ngit stash drop stash@{0}",
    "sources": [
      "https://git-scm.com/docs/git-stash"
    ]
  },
  {
    "id": "ansible-vault-password-missing",
    "title": "Ansible: Vault password not provided",
    "category": "Ansible",
    "explanation": "A playbook uses encrypted vault variables but no vault password was supplied at runtime.",
    "fix_snippet": "# Provide vault password interactively\nansible-playbook playbook.yml --ask-vault-pass\n# Use a password file\nansible-playbook playbook.yml --vault-password-file=.vault_pass\n# Set in ansible.cfg\n[defaults]\nvault_password_file = .vault_pass",
    "sources": [
      "https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html"
    ]
  },
  {
    "id": "ansible-jinja2-template-error",
    "title": "Ansible: Jinja2 template error",
    "category": "Ansible",
    "explanation": "A Jinja2 template in a playbook or template file has a syntax error such as unclosed braces, undefined filters, or bad expressions.",
    "fix_snippet": "# Check for unclosed braces\n{{ variable }}  # correct\n{ variable }}   # wrong\n# Escape literal braces\n{% raw %}{{ not_a_variable }}{% endraw %}\n# Test template rendering\nansible all -m debug -a \"msg={{ my_var }}\"",
    "sources": [
      "https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_templating.html"
    ]
  },
  {
    "id": "ansible-variable-undefined",
    "title": "Ansible: 'variable' is undefined",
    "category": "Ansible",
    "explanation": "A variable used in a playbook or template was not defined in inventory, group_vars, host_vars, or the playbook itself.",
    "fix_snippet": "# Define in playbook vars\nvars:\n  my_var: value\n# Or in group_vars/all.yml\n# Or provide at runtime\nansible-playbook playbook.yml -e \"my_var=value\"\n# Use default filter\n{{ my_var | default('fallback') }}",
    "sources": [
      "https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html"
    ]
  },
  {
    "id": "ansible-ssh-timeout",
    "title": "Ansible: SSH connection timeout",
    "category": "Ansible",
    "explanation": "Ansible timed out trying to establish an SSH connection to the target host. The host may be unreachable, the SSH service down, or a firewall is blocking.",
    "fix_snippet": "# Test SSH manually\nssh user@host\n# Increase timeout in ansible.cfg\n[defaults]\ntimeout = 30\n# Check inventory host/IP\nansible-inventory --list\n# Use verbose mode to debug\nansible-playbook playbook.yml -vvvv",
    "sources": [
      "https://docs.ansible.com/ansible/latest/inventory_guide/connection_details.html"
    ]
  },
  {
    "id": "android-gradle-sync-failed",
    "title": "Android Studio: Gradle sync failed",
    "category": "Mobile",
    "explanation": "Android Studio cannot sync the project with Gradle files. Usually caused by SDK version mismatch, missing dependencies, or corrupted cache.",
    "fix_snippet": "# Invalidate caches\nFile -> Invalidate Caches / Restart\n# Clean and rebuild\n./gradlew clean\n# Update Gradle wrapper\n./gradlew wrapper --gradle-version=8.4\n# Check SDK installation\nsdkmanager --list",
    "sources": [
      "https://developer.android.com/build/troubleshoot-build"
    ]
  },
  {
    "id": "android-dex-method-limit",
    "title": "Android: DEX method limit exceeded (64k)",
    "category": "Mobile",
    "explanation": "The app has more than 65,536 methods across all DEX files. Android's Dalvik bytecode format has a 64k method reference limit per DEX file.",
    "fix_snippet": "# Enable multidex in build.gradle\nandroid {\n    defaultConfig {\n        multiDexEnabled true\n    }\n}\n# Add dependency\nimplementation 'androidx.multidex:multidex:2.0.1'\n# Remove unused dependencies\n./gradlew app:dependencies",
    "sources": [
      "https://developer.android.com/build/multidex"
    ]
  },
  {
    "id": "xcode-build-input-not-found",
    "title": "Xcode: Build input file cannot be found",
    "category": "Mobile",
    "explanation": "Xcode references a file in the build phase that no longer exists on disk. The file was deleted or moved without updating the project.",
    "fix_snippet": "# Remove stale reference in Xcode\n# Build Phases -> Compile Sources -> Remove missing file\n# Or fix via command line\n# Check for red (missing) files in project navigator\n# Clean build folder\nProduct -> Clean Build Folder (Shift+Cmd+K)",
    "sources": [
      "https://developer.apple.com/documentation/xcode/building-your-project"
    ]
  },
  {
    "id": "swift-cannot-convert-value",
    "title": "Swift: Cannot convert value of type X to expected argument type Y",
    "category": "Mobile",
    "explanation": "A type mismatch in Swift. The value being passed does not match the expected parameter type.",
    "fix_snippet": "# Explicit type conversion\nlet intVal = Int(stringVal) ?? 0\nlet doubleVal = Double(intVal)\n# Optional unwrapping\nif let unwrapped = optionalValue {\n    useValue(unwrapped)\n}\n# Use as? for safe casting\nif let str = value as? String { ... }",
    "sources": [
      "https://docs.swift.org/swift-book/documentation/the-swift-programming-language/typecasting/"
    ]
  },
  {
    "id": "kotlin-unresolved-reference",
    "title": "Kotlin: Unresolved reference: X",
    "category": "Mobile",
    "explanation": "Kotlin cannot resolve a symbol. The class, function, or property may not be imported, the dependency is missing, or there's a typo.",
    "fix_snippet": "# Add missing import\nimport com.example.MyClass\n# Check build.gradle for dependency\nimplementation 'com.example:library:1.0'\n# Sync Gradle\n./gradlew --refresh-dependencies\n# Check for typos in symbol names",
    "sources": [
      "https://kotlinlang.org/docs/packages.html"
    ]
  },
  {
    "id": "rabbitmq-queue-length-exceeded",
    "title": "RabbitMQ: Queue length limit exceeded",
    "category": "MessageQueue",
    "explanation": "A queue has reached its maximum length policy. New messages are being dropped or dead-lettered.",
    "fix_snippet": "# Check queue status\nrabbitmqctl list_queues name messages consumers\n# Set/update queue policy\nrabbitmqctl set_policy max-length 'my-queue' '{\"max-length\": 100000}' --apply-to queues\n# Add more consumers to drain the queue\n# Configure dead letter exchange for overflow",
    "sources": [
      "https://www.rabbitmq.com/docs/maxlength"
    ]
  },
  {
    "id": "kafka-topic-authorization-failed",
    "title": "Kafka: Topic authorization failed",
    "category": "MessageQueue",
    "explanation": "The Kafka client does not have the required ACL permissions to produce to or consume from the topic.",
    "fix_snippet": "# List ACLs\nkafka-acls.sh --list --bootstrap-server localhost:9092\n# Grant produce permission\nkafka-acls.sh --add --allow-principal User:myapp --operation Write --topic my-topic --bootstrap-server localhost:9092\n# Grant consume permission\nkafka-acls.sh --add --allow-principal User:myapp --operation Read --topic my-topic --group my-group --bootstrap-server localhost:9092",
    "sources": [
      "https://kafka.apache.org/documentation/#security_authz"
    ]
  },
  {
    "id": "sqs-message-too-large",
    "title": "AWS SQS: Message too large (256KB limit)",
    "category": "MessageQueue",
    "explanation": "The SQS message body exceeds the 256KB maximum size limit.",
    "fix_snippet": "# Use SQS Extended Client Library (stores payload in S3)\n# pip install amazon-sqs-extended-client\n# Or compress the message\nimport gzip\ncompressed = gzip.compress(message.encode())\n# Or send a reference/pointer instead of the full payload\n{\"s3_key\": \"data/large-payload.json\"}",
    "sources": [
      "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html"
    ]
  },
  {
    "id": "celery-worker-lost",
    "title": "Celery: WorkerLostError",
    "category": "MessageQueue",
    "explanation": "A Celery worker process died unexpectedly during task execution, often due to OOM kill, segfault, or os._exit() in the task.",
    "fix_snippet": "# Increase worker memory limit\ncelery -A proj worker --max-memory-per-child=200000\n# Enable task soft time limit\n@app.task(soft_time_limit=300, time_limit=600)\ndef my_task(): ...\n# Check system OOM killer\ndmesg | grep -i oom\n# Use prefork pool with max tasks\n--max-tasks-per-child=100",
    "sources": [
      "https://docs.celeryq.dev/en/stable/userguide/workers.html"
    ]
  },
  {
    "id": "nats-slow-consumer",
    "title": "NATS: Slow consumer detected",
    "category": "MessageQueue",
    "explanation": "A NATS subscriber cannot process messages fast enough and its pending message buffer is full. The server may disconnect the consumer.",
    "fix_snippet": "# Increase pending message limits\nsub, err := nc.Subscribe(\"topic\", handler)\nsub.SetPendingLimits(1000000, 1024*1024*512)\n# Use queue groups for parallel processing\nnc.QueueSubscribe(\"topic\", \"workers\", handler)\n# Use JetStream for persistence and replay",
    "sources": [
      "https://docs.nats.io/using-nats/developer/connecting/pending"
    ]
  },
  {
    "id": "github-actions-secret-not-available",
    "title": "GitHub Actions: Secret not available in fork PRs",
    "category": "CI/CD",
    "explanation": "Secrets are not passed to workflows triggered by pull requests from forks for security reasons.",
    "fix_snippet": "# Use pull_request_target instead (runs in base repo context)\non:\n  pull_request_target:\n    types: [opened, synchronize]\n# Or skip secret-dependent steps in forks\n- if: github.event.pull_request.head.repo.full_name == github.repository\n  run: deploy.sh\n  env:\n    SECRET: ${{ secrets.MY_SECRET }}",
    "sources": [
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions"
    ]
  },
  {
    "id": "gitlab-runner-not-found",
    "title": "GitLab CI: No runner available",
    "category": "CI/CD",
    "explanation": "No registered GitLab runner matches the job's tags or the runner is offline.",
    "fix_snippet": "# Check runner status\ngitlab-runner list\n# Register a new runner\ngitlab-runner register\n# Verify runner is online in GitLab UI\n# Settings -> CI/CD -> Runners\n# Check job tags match runner tags\ntags:\n  - docker\n  - linux",
    "sources": [
      "https://docs.gitlab.com/runner/"
    ]
  },
  {
    "id": "jenkins-agent-offline",
    "title": "Jenkins: Agent is offline",
    "category": "CI/CD",
    "explanation": "A Jenkins build agent/node is disconnected. The agent process may have crashed, network issues, or the machine is down.",
    "fix_snippet": "# Reconnect agent from Jenkins UI\n# Manage Jenkins -> Nodes -> Select Node -> Reconnect\n# Check agent logs\n# On agent machine, restart the agent\njava -jar agent.jar -url http://jenkins:8080 -secret @secret-file -name my-agent\n# Verify network connectivity to Jenkins master",
    "sources": [
      "https://www.jenkins.io/doc/book/managing/nodes/"
    ]
  },
  {
    "id": "bitbucket-pipelines-memory-limit",
    "title": "Bitbucket Pipelines: Memory limit exceeded",
    "category": "CI/CD",
    "explanation": "The pipeline step exceeded the allocated memory (default 4GB). The build process or tests consumed too much RAM.",
    "fix_snippet": "# Increase memory with size option\npipelines:\n  default:\n    - step:\n        size: 2x  # 8GB RAM\n        script:\n          - npm test\n# Reduce memory usage in tests\n# Split into parallel steps\n# Use --max-workers flag for test runners",
    "sources": [
      "https://support.atlassian.com/bitbucket-cloud/docs/databases-and-service-containers/"
    ]
  },
  {
    "id": "dns-servfail",
    "title": "DNS: SERVFAIL",
    "category": "DNS",
    "explanation": "The DNS server failed to complete the query. The authoritative server may be down, DNSSEC validation failed, or there's a configuration error.",
    "fix_snippet": "# Query with diagnostic info\ndig example.com +trace\n# Check DNSSEC validation\ndig example.com +dnssec\n# Try different DNS server\ndig @8.8.8.8 example.com\n# Check authoritative nameserver\ndig NS example.com",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc1035"
    ]
  },
  {
    "id": "dns-zone-transfer-refused",
    "title": "DNS: Transfer refused (AXFR)",
    "category": "DNS",
    "explanation": "A DNS zone transfer (AXFR) request was denied. Zone transfers are typically restricted to authorised secondary nameservers.",
    "fix_snippet": "# Check if zone transfers are allowed\ndig @ns1.example.com example.com AXFR\n# Allow specific IPs in BIND config\nzone \"example.com\" {\n    allow-transfer { 10.0.0.2; };\n};\n# Use TSIG keys for secure transfers",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc5936"
    ]
  },
  {
    "id": "dns-cname-loop",
    "title": "DNS: CNAME loop detected",
    "category": "DNS",
    "explanation": "A CNAME record points to another CNAME that eventually points back, creating a circular reference that cannot be resolved.",
    "fix_snippet": "# Trace the CNAME chain\ndig +trace example.com CNAME\n# Check for circular references\nhost -t CNAME a.example.com\nhost -t CNAME b.example.com\n# Fix by pointing CNAME to an A/AAAA record\na.example.com. CNAME target.example.com.\ntarget.example.com. A 1.2.3.4",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.2"
    ]
  },
  {
    "id": "terraform-for-each-unknown",
    "title": "Terraform: for_each value depends on resource attributes that cannot be determined",
    "category": "Terraform",
    "explanation": "A for_each or count expression depends on a value that is not known until apply time. Terraform needs to know the collection keys at plan time.",
    "fix_snippet": "# Use -target to apply the dependency first\nterraform apply -target=aws_instance.example\n# Move dynamic values to variables\nvariable \"instance_names\" {\n  default = [\"web1\", \"web2\"]\n}\n# Or use data sources instead of resource outputs",
    "sources": [
      "https://developer.hashicorp.com/terraform/language/meta-arguments/for_each"
    ]
  },
  {
    "id": "terraform-import-resource-not-found",
    "title": "Terraform: Cannot import resource - not found",
    "category": "Terraform",
    "explanation": "The resource ID provided to terraform import does not match any existing resource in the cloud provider.",
    "fix_snippet": "# Verify resource exists\naws ec2 describe-instances --instance-ids i-1234567890\n# Use correct resource ID format\nterraform import aws_instance.example i-1234567890\n# Check correct provider/region is configured\n# Some resources use ARN, others use name or ID",
    "sources": [
      "https://developer.hashicorp.com/terraform/cli/import"
    ]
  },
  {
    "id": "terraform-plugin-crash",
    "title": "Terraform: Plugin crashed",
    "category": "Terraform",
    "explanation": "A Terraform provider plugin crashed during execution. Usually a bug in the provider or a version incompatibility.",
    "fix_snippet": "# Update provider to latest version\nterraform init -upgrade\n# Pin to known working version\nterraform {\n  required_providers {\n    aws = {\n      source  = \"hashicorp/aws\"\n      version = \"~> 5.0\"\n    }\n  }\n}\n# Clear plugin cache\nrm -rf .terraform/providers",
    "sources": [
      "https://developer.hashicorp.com/terraform/cli/config/config-file#provider-installation"
    ]
  },
  {
    "id": "ebs-volume-not-available",
    "title": "AWS: EBS volume not available in AZ",
    "category": "Storage",
    "explanation": "An EBS volume cannot be attached to an EC2 instance because they are in different Availability Zones. EBS volumes are AZ-specific.",
    "fix_snippet": "# Check volume AZ\naws ec2 describe-volumes --volume-ids vol-xxx --query 'Volumes[].AvailabilityZone'\n# Create snapshot and restore in correct AZ\naws ec2 create-snapshot --volume-id vol-xxx\naws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-1b",
    "sources": [
      "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volumes.html"
    ]
  },
  {
    "id": "nfs-stale-file-handle",
    "title": "NFS: Stale file handle",
    "category": "Storage",
    "explanation": "The NFS client holds a reference to a file or directory that no longer exists on the server, usually after the export was recreated or the server was rebuilt.",
    "fix_snippet": "# Unmount and remount\nsudo umount -f /mnt/nfs\nsudo mount -t nfs server:/export /mnt/nfs\n# If umount hangs, use lazy unmount\nsudo umount -l /mnt/nfs\n# Clear NFS client cache\necho 3 > /proc/sys/vm/drop_caches",
    "sources": [
      "https://linux.die.net/man/5/nfs"
    ]
  },
  {
    "id": "ceph-osd-down",
    "title": "Ceph: OSD down",
    "category": "Storage",
    "explanation": "A Ceph Object Storage Daemon is not running, reducing cluster redundancy and potentially causing degraded performance.",
    "fix_snippet": "# Check cluster health\nceph health detail\n# Check OSD status\nceph osd tree\n# Start the OSD\nsudo systemctl start ceph-osd@0\n# Check OSD logs\njournalctl -u ceph-osd@0 --since '10 min ago'",
    "sources": [
      "https://docs.ceph.com/en/latest/rados/troubleshooting/troubleshooting-osd/"
    ]
  },
  {
    "id": "lambda-cold-start-timeout",
    "title": "AWS Lambda: Task timed out after X seconds",
    "category": "Serverless",
    "explanation": "The Lambda function did not complete within the configured timeout. Cold starts, slow dependencies, or heavy processing can cause this.",
    "fix_snippet": "# Increase timeout (max 900s)\naws lambda update-function-configuration --function-name my-func --timeout 30\n# Use provisioned concurrency to eliminate cold starts\naws lambda put-provisioned-concurrency-config --function-name my-func --qualifier prod --provisioned-concurrent-executions 5\n# Optimize initialization code",
    "sources": [
      "https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-common.html"
    ]
  },
  {
    "id": "lambda-package-too-large",
    "title": "AWS Lambda: Unzipped size exceeds 250MB limit",
    "category": "Serverless",
    "explanation": "The Lambda deployment package (unzipped) exceeds the 250MB limit. Too many dependencies or large assets.",
    "fix_snippet": "# Use Lambda layers for shared dependencies\naws lambda publish-layer-version --layer-name my-deps --zip-file fileb://layer.zip\n# Use container image deployment (up to 10GB)\n# Prune unused dependencies\npip install --target ./package -r requirements.txt --no-deps\n# Use Lambda-optimized packages",
    "sources": [
      "https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html"
    ]
  },
  {
    "id": "lambda-vpc-eni-limit",
    "title": "AWS Lambda: ENI limit reached in VPC",
    "category": "Serverless",
    "explanation": "Lambda functions in a VPC create ENIs (Elastic Network Interfaces) and the account or subnet has hit its ENI limit.",
    "fix_snippet": "# Check ENI usage\naws ec2 describe-network-interfaces --filters Name=description,Values='AWS Lambda VPC ENI*' | jq '.NetworkInterfaces | length'\n# Request limit increase\naws service-quotas request-service-quota-increase --service-code vpc --quota-code L-DF5E4CA3 --desired-value 500\n# Use fewer subnets in Lambda config",
    "sources": [
      "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"
    ]
  },
  {
    "id": "azure-functions-host-not-running",
    "title": "Azure Functions: Host not running",
    "category": "Serverless",
    "explanation": "The Azure Functions host failed to start. Usually caused by invalid host.json, missing dependencies, or runtime version mismatch.",
    "fix_snippet": "# Check host.json for errors\n# Verify runtime version\nfunc --version\n# Install extensions\nfunc extensions install\n# Run locally to debug\nfunc start --verbose\n# Check Application Insights for errors",
    "sources": [
      "https://learn.microsoft.com/en-us/azure/azure-functions/functions-host-json"
    ]
  },
  {
    "id": "gcp-cloud-function-deploy-failed",
    "title": "GCP Cloud Functions: Deployment failed",
    "category": "Serverless",
    "explanation": "Cloud Function deployment failed during build or initialisation. Could be a dependency issue, code error, or quota limit.",
    "fix_snippet": "# Check build logs\ngcloud functions logs read my-function\n# Deploy with verbose logging\ngcloud functions deploy my-function --runtime python311 --trigger-http --verbosity=debug\n# Check quotas\ngcloud compute project-info describe\n# Test locally first\nfunctions-framework --target=my_function",
    "sources": [
      "https://cloud.google.com/functions/docs/troubleshooting"
    ]
  },
  {
    "id": "cloudflare-worker-size-limit",
    "title": "Cloudflare Worker: Script size exceeds limit",
    "category": "Serverless",
    "explanation": "The Cloudflare Worker script exceeds the 1MB (free) or 10MB (paid) compressed size limit.",
    "fix_snippet": "# Check bundle size\nnpx wrangler deploy --dry-run\n# Reduce dependencies\n# Use tree-shaking\n# Move large data to KV or R2 storage\nawait env.MY_KV.get('large-data')\n# Upgrade to paid plan for 10MB limit",
    "sources": [
      "https://developers.cloudflare.com/workers/platform/limits/"
    ]
  },
  {
    "id": "serverless-framework-stack-update-failed",
    "title": "Serverless Framework: UPDATE_ROLLBACK_COMPLETE",
    "category": "Serverless",
    "explanation": "A CloudFormation stack update failed and rolled back. The deployment was rejected due to resource limits, permissions, or template errors.",
    "fix_snippet": "# Check CloudFormation events for root cause\naws cloudformation describe-stack-events --stack-name my-stack\n# Retry deployment\nserverless deploy\n# If stuck in ROLLBACK state\naws cloudformation delete-stack --stack-name my-stack\n# Check for resource limits or IAM issues",
    "sources": [
      "https://www.serverless.com/framework/docs/troubleshooting"
    ]
  },
  {
    "id": "ts-type-not-assignable",
    "title": "TypeScript: Type 'X' is not assignable to type 'Y'",
    "category": "TypeScript",
    "explanation": "A value's type is incompatible with the expected type. This is TypeScript's most common error, catching type mismatches at compile time.",
    "fix_snippet": "# Widen the type\nlet value: string | number = getValue();\n# Use type assertion (if you're sure)\nconst val = unknownValue as MyType;\n# Add missing properties\ninterface User { name: string; age?: number; }\n# Check for null/undefined\nif (value !== null) { use(value); }",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/everyday-types.html"
    ]
  },
  {
    "id": "ts-property-does-not-exist",
    "title": "TypeScript: Property 'X' does not exist on type 'Y'",
    "category": "TypeScript",
    "explanation": "Accessing a property that is not defined in the type. The object may need a wider type or the property name has a typo.",
    "fix_snippet": "# Add property to interface\ninterface User {\n  name: string;\n  email: string; // add missing property\n}\n# Use optional chaining\nobj?.missingProp\n# Index signature for dynamic keys\ninterface Dict { [key: string]: unknown; }\n# Type guard\nif ('prop' in obj) { obj.prop }",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/objects.html"
    ]
  },
  {
    "id": "ts-cannot-find-module-declaration",
    "title": "TypeScript: Could not find a declaration file for module",
    "category": "TypeScript",
    "explanation": "A JS library has no TypeScript type declarations. The library has no built-in types and no @types package exists.",
    "fix_snippet": "# Install type declarations\nnpm install --save-dev @types/library-name\n# Or create a declaration file (src/types/library.d.ts)\ndeclare module 'library-name';\n# Or with more detail\ndeclare module 'library-name' {\n  export function doSomething(): void;\n}",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/type-declarations.html"
    ]
  },
  {
    "id": "ts-object-possibly-undefined",
    "title": "TypeScript: Object is possibly 'undefined'",
    "category": "TypeScript",
    "explanation": "Accessing a property on a value that might be undefined. TypeScript's strict null checks flag this as unsafe.",
    "fix_snippet": "# Optional chaining\nconst name = user?.profile?.name;\n# Nullish coalescing\nconst name = user?.name ?? 'default';\n# Type narrowing\nif (user !== undefined) {\n  console.log(user.name); // safe\n}\n# Non-null assertion (use sparingly)\nuser!.name",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/narrowing.html"
    ]
  },
  {
    "id": "ts-argument-not-assignable",
    "title": "TypeScript: Argument of type X is not assignable to parameter of type Y",
    "category": "TypeScript",
    "explanation": "A function argument's type doesn't match the parameter's declared type. Common when passing objects with extra or missing properties.",
    "fix_snippet": "# Match the expected type\nfunction greet(user: { name: string }) { ... }\ngreet({ name: 'Alice' }); // correct\n# Use Partial for optional fields\nfunction update(user: Partial<User>) { ... }\n# Check for excess property checks\nconst obj: User = { name: 'Alice' }; // assign first",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/functions.html"
    ]
  },
  {
    "id": "ts-no-overload-matches",
    "title": "TypeScript: No overload matches this call",
    "category": "TypeScript",
    "explanation": "None of the function's overload signatures match the provided arguments. The argument types or count don't match any declared overload.",
    "fix_snippet": "# Check available overloads in type definition\n// Example overloads:\nfunction createElement(tag: 'div'): HTMLDivElement;\nfunction createElement(tag: 'span'): HTMLSpanElement;\n# Ensure argument types match one overload exactly\n# Hover over function in IDE to see overloads",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/functions.html#function-overloads"
    ]
  },
  {
    "id": "ts-generic-constraint-error",
    "title": "TypeScript: Type X does not satisfy the constraint Y",
    "category": "TypeScript",
    "explanation": "A type argument does not meet the generic constraint. The type must extend or implement the constraint type.",
    "fix_snippet": "# Satisfy the constraint\nfunction getProperty<T extends { id: number }>(obj: T) {\n  return obj.id;\n}\n// Must pass object with 'id'\ngetProperty({ id: 1, name: 'test' }); // OK\n# Use keyof constraint\nfunction get<T, K extends keyof T>(obj: T, key: K): T[K]",
    "sources": [
      "https://www.typescriptlang.org/docs/handbook/2/generics.html#generic-constraints"
    ]
  },
  {
    "id": "bash-command-not-found",
    "title": "bash: command not found",
    "category": "Shell",
    "explanation": "The shell cannot find the specified command. The program is not installed, not in PATH, or there's a typo.",
    "fix_snippet": "# Check if command exists\nwhich mycommand\ntype mycommand\n# Check PATH\necho $PATH\n# Add directory to PATH\nexport PATH=$PATH:/usr/local/bin\n# Install the package (Debian/Ubuntu)\nsudo apt-get install package-name",
    "sources": [
      "https://www.gnu.org/software/bash/manual/bash.html#Command-Search-and-Execution"
    ]
  },
  {
    "id": "bash-permission-denied",
    "title": "bash: Permission denied",
    "category": "Shell",
    "explanation": "The script or binary does not have execute permission, or the user lacks permission to access the file.",
    "fix_snippet": "# Make script executable\nchmod +x script.sh\n# Run with bash explicitly\nbash script.sh\n# Check file permissions\nls -la script.sh\n# Check ownership\nstat script.sh",
    "sources": [
      "https://www.gnu.org/software/bash/manual/bash.html"
    ]
  },
  {
    "id": "bash-syntax-error-unexpected-token",
    "title": "bash: syntax error near unexpected token",
    "category": "Shell",
    "explanation": "The shell encountered a syntax error, often caused by incorrect quoting, missing escapes, Windows line endings (\\r\\n), or unmatched brackets.",
    "fix_snippet": "# Fix Windows line endings\nsed -i 's/\\r$//' script.sh\n# Or use dos2unix\ndos2unix script.sh\n# Check for unmatched quotes/brackets\n# Use shellcheck for linting\nshellcheck script.sh",
    "sources": [
      "https://www.shellcheck.net/"
    ]
  },
  {
    "id": "bash-unbound-variable",
    "title": "bash: unbound variable",
    "category": "Shell",
    "explanation": "A variable was referenced but not set, and the script uses 'set -u' (nounset) which treats unset variables as errors.",
    "fix_snippet": "# Set default value\n${MY_VAR:-default_value}\n# Or assign default\n: ${MY_VAR:=default_value}\n# Check if variable is set\nif [ -n \"${MY_VAR+x}\" ]; then\n    echo \"MY_VAR is set\"\nfi",
    "sources": [
      "https://www.gnu.org/software/bash/manual/bash.html#The-Set-Builtin"
    ]
  },
  {
    "id": "bash-bad-substitution",
    "title": "bash: bad substitution",
    "category": "Shell",
    "explanation": "Invalid parameter expansion syntax. May be caused by using bash-specific syntax in sh, or incorrect variable expansion.",
    "fix_snippet": "# Ensure script uses bash, not sh\n#!/bin/bash  # not #!/bin/sh\n# Correct variable substitution\necho ${var}     # basic\necho ${var:-default}  # with default\necho ${var%%pattern}  # suffix removal\n# Run with bash explicitly\nbash script.sh",
    "sources": [
      "https://www.gnu.org/software/bash/manual/bash.html#Shell-Parameter-Expansion"
    ]
  },
  {
    "id": "powershell-not-digitally-signed",
    "title": "PowerShell: File is not digitally signed",
    "category": "Shell",
    "explanation": "PowerShell's execution policy requires scripts to be digitally signed but the script has no valid signature.",
    "fix_snippet": "# Change execution policy for current user\nSet-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser\n# Or bypass for a single script\npowershell -ExecutionPolicy Bypass -File script.ps1\n# Unblock downloaded script\nUnblock-File -Path script.ps1",
    "sources": [
      "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies"
    ]
  },
  {
    "id": "zsh-no-matches-found",
    "title": "zsh: no matches found",
    "category": "Shell",
    "explanation": "Zsh's glob expansion found no files matching the pattern and errors by default (unlike bash which passes the literal pattern).",
    "fix_snippet": "# Quote the pattern to prevent glob expansion\ncurl 'https://api.example.com/items?page=1'\n# Or escape special characters\ncurl https://api.example.com/items\\?page=1\n# Disable nomatch globally in .zshrc\nsetopt nonomatch\n# Or use noglob for a single command\nnoglob curl https://api.example.com/items?page=1",
    "sources": [
      "https://zsh.sourceforge.io/Doc/Release/Options.html"
    ]
  },
  {
    "id": "jest-cannot-find-module",
    "title": "Jest: Cannot find module",
    "category": "Testing",
    "explanation": "Jest cannot resolve an import during test execution. Usually caused by missing moduleNameMapper config, untransformed file types, or path aliases.",
    "fix_snippet": "# Add moduleNameMapper in jest.config.js\nmoduleNameMapper: {\n  '^@/(.*)$': '<rootDir>/src/$1',\n  '\\\\.(css|scss)$': 'identity-obj-proxy'\n}\n# Transform non-JS files\ntransform: {\n  '^.+\\\\.tsx?$': 'ts-jest'\n}\n# Clear cache\nnpx jest --clearCache",
    "sources": [
      "https://jestjs.io/docs/configuration#modulenamemapper-objectstring-string--arraystring"
    ]
  },
  {
    "id": "jest-snapshot-mismatch",
    "title": "Jest: Snapshot does not match stored snapshot",
    "category": "Testing",
    "explanation": "The component output has changed since the snapshot was last recorded. This may be an intentional change or an unexpected regression.",
    "fix_snippet": "# Update snapshot if change is intentional\nnpx jest --updateSnapshot\n# Or update specific test\nnpx jest --updateSnapshot --testPathPattern=MyComponent\n# Review snapshot diff carefully before updating\n# Use inline snapshots for small outputs\nexpect(value).toMatchInlineSnapshot();",
    "sources": [
      "https://jestjs.io/docs/snapshot-testing"
    ]
  },
  {
    "id": "pytest-fixture-not-found",
    "title": "pytest: fixture 'X' not found",
    "category": "Testing",
    "explanation": "A test function requests a fixture that is not defined or not accessible. The fixture may be in a different conftest.py or misspelled.",
    "fix_snippet": "# Define fixture in conftest.py\n@pytest.fixture\ndef my_fixture():\n    return {'key': 'value'}\n# Check fixture is in the right conftest.py scope\n# List available fixtures\npytest --fixtures\n# Check for typos in fixture name",
    "sources": [
      "https://docs.pytest.org/en/stable/how-to/fixtures.html"
    ]
  },
  {
    "id": "pytest-collection-error",
    "title": "pytest: Collection error",
    "category": "Testing",
    "explanation": "pytest failed to collect tests, usually due to an import error in a test file or conftest.py. The module cannot be loaded.",
    "fix_snippet": "# Run with verbose to see import errors\npytest --tb=long -v\n# Check for circular imports\n# Ensure __init__.py exists if needed\n# Check sys.path\npython -c \"import sys; print(sys.path)\"\n# Install package in dev mode\npip install -e .",
    "sources": [
      "https://docs.pytest.org/en/stable/goodpractices.html"
    ]
  },
  {
    "id": "junit-no-runnable-methods",
    "title": "JUnit: No runnable methods",
    "category": "Testing",
    "explanation": "JUnit found no test methods in the class. Methods may be missing the @Test annotation or the wrong JUnit version annotation is used.",
    "fix_snippet": "# JUnit 5 - use correct import\nimport org.junit.jupiter.api.Test;\n@Test\nvoid myTest() { ... }\n# JUnit 4 - different import\nimport org.junit.Test;\n@Test\npublic void myTest() { ... }\n# Ensure test methods are public (JUnit 4)",
    "sources": [
      "https://junit.org/junit5/docs/current/user-guide/"
    ]
  },
  {
    "id": "cypress-element-not-found",
    "title": "Cypress: Timed out retrying - Expected to find element",
    "category": "Testing",
    "explanation": "Cypress could not find the specified element within the default timeout. The element may not exist, may have a different selector, or hasn't rendered yet.",
    "fix_snippet": "# Increase timeout for slow elements\ncy.get('[data-testid=\"submit\"]', { timeout: 10000 })\n# Use data-testid instead of CSS classes\ncy.get('[data-testid=\"my-button\"]')\n# Wait for element to be visible\ncy.get('.element').should('be.visible')\n# Check if element is in iframe\ncy.iframe().find('.element')",
    "sources": [
      "https://docs.cypress.io/guides/references/error-messages"
    ]
  },
  {
    "id": "playwright-timeout",
    "title": "Playwright: Timeout exceeded waiting for element",
    "category": "Testing",
    "explanation": "Playwright's auto-waiting timed out because the element did not become actionable (visible, enabled, stable) within the timeout period.",
    "fix_snippet": "# Increase timeout\nawait page.click('button', { timeout: 30000 });\n# Wait for specific state\nawait page.waitForSelector('.loaded', { state: 'visible' });\n# Use locators with auto-waiting\nawait page.getByRole('button', { name: 'Submit' }).click();\n# Debug with trace\nnpx playwright test --trace on",
    "sources": [
      "https://playwright.dev/docs/actionability"
    ]
  },
  {
    "id": "smtp-550-mailbox-not-found",
    "title": "SMTP: 550 Mailbox not found",
    "category": "Email",
    "explanation": "The recipient email address does not exist on the mail server. The mailbox may have been deleted or the address is misspelled.",
    "fix_snippet": "# Verify email address is correct\n# Check for typos in domain and username\n# Test with SMTP commands\ntelnet mail.example.com 25\nHELO test\nMAIL FROM:<sender@test.com>\nRCPT TO:<recipient@example.com>\n# Check MX records\ndig MX example.com",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc5321#section-4.2.3"
    ]
  },
  {
    "id": "smtp-554-relay-denied",
    "title": "SMTP: 554 Relay access denied",
    "category": "Email",
    "explanation": "The SMTP server refuses to relay mail for the sender. The server only accepts mail for its own domains and the sender is not authenticated.",
    "fix_snippet": "# Authenticate before sending\n# Enable SMTP AUTH in your email client\n# Check Postfix config\nmynetworks = 127.0.0.0/8\nsmtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination\n# Restart Postfix\nsudo systemctl restart postfix",
    "sources": [
      "https://www.postfix.org/SMTPD_ACCESS_README.html"
    ]
  },
  {
    "id": "smtp-421-too-many-connections",
    "title": "SMTP: 421 Too many connections",
    "category": "Email",
    "explanation": "The mail server is rate limiting connections. Too many simultaneous connections from the same IP address.",
    "fix_snippet": "# Reduce concurrent connections\n# Implement connection pooling\n# Add delays between sends\nimport time\nfor email in emails:\n    send(email)\n    time.sleep(1)\n# Use a proper email queue (e.g., Amazon SES, SendGrid)",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.2"
    ]
  },
  {
    "id": "smtp-535-authentication-failed",
    "title": "SMTP: 535 Authentication failed",
    "category": "Email",
    "explanation": "SMTP login credentials were rejected. The password may be wrong, or the account requires an app-specific password (e.g., Gmail with 2FA).",
    "fix_snippet": "# For Gmail: generate app password\n# Google Account -> Security -> App Passwords\n# For Office 365: check if basic auth is disabled\n# Use OAuth2 instead\n# Test credentials\nopenssl s_client -connect smtp.gmail.com:465\nAUTH LOGIN",
    "sources": [
      "https://support.google.com/accounts/answer/185833"
    ]
  },
  {
    "id": "smtp-tls-handshake-failed",
    "title": "SMTP: STARTTLS handshake failed",
    "category": "Email",
    "explanation": "The TLS negotiation during STARTTLS failed. The server certificate may be invalid, or there's a protocol version mismatch.",
    "fix_snippet": "# Test STARTTLS manually\nopenssl s_client -starttls smtp -connect mail.example.com:587\n# Check certificate\nopenssl s_client -starttls smtp -connect mail.example.com:587 | openssl x509 -noout -text\n# Try implicit TLS on port 465\nopenssl s_client -connect mail.example.com:465",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc3207"
    ]
  },
  {
    "id": "dkim-signature-invalid",
    "title": "DKIM: Signature verification failed",
    "category": "Email",
    "explanation": "The DKIM signature on the email does not match. The DNS public key record may be wrong, or the message was modified in transit.",
    "fix_snippet": "# Check DKIM DNS record\ndig TXT selector._domainkey.example.com\n# Verify DKIM signature with opendkim\nopendkim-testkey -d example.com -s selector\n# Regenerate DKIM keys\nopendkim-genkey -s selector -d example.com\n# Update DNS TXT record with new public key",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc6376"
    ]
  },
  {
    "id": "spf-fail-not-authorized",
    "title": "SPF: Sender not authorized",
    "category": "Email",
    "explanation": "The sending mail server's IP is not listed in the domain's SPF record. The email may be rejected or marked as spam.",
    "fix_snippet": "# Check current SPF record\ndig TXT example.com | grep spf\n# Add sending server IP to SPF\n# In DNS TXT record:\nv=spf1 ip4:1.2.3.4 include:_spf.google.com ~all\n# Test SPF\nnslookup -type=txt example.com\n# Use ~all (softfail) during testing, -all (fail) in production",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc7208"
    ]
  },
  {
    "id": "virtualbox-vt-x-not-available",
    "title": "VirtualBox: VT-x is not available",
    "category": "Virtualization",
    "explanation": "Hardware virtualization (VT-x/AMD-V) is disabled in BIOS or being used by another hypervisor (e.g., Hyper-V, WSL2).",
    "fix_snippet": "# Enable VT-x in BIOS/UEFI\n# Reboot -> Enter BIOS -> CPU settings -> Enable Virtualization\n# On Windows, disable Hyper-V if conflicting\nbcdedit /set hypervisorlaunchtype off\n# Check VT-x status (Linux)\negrep -c '(vmx|svm)' /proc/cpuinfo",
    "sources": [
      "https://www.virtualbox.org/manual/ch10.html#hwvirt"
    ]
  },
  {
    "id": "vmware-disk-consolidation-needed",
    "title": "VMware: Disk consolidation needed",
    "category": "Virtualization",
    "explanation": "The VM has orphaned snapshot delta disks that need to be merged back. Usually happens after a failed snapshot deletion.",
    "fix_snippet": "# Consolidate disks via vSphere client\n# Right-click VM -> Snapshots -> Consolidate\n# Or via PowerCLI\nGet-VM 'MyVM' | Get-Snapshot | Remove-Snapshot -Confirm:$false\n# Check consolidation needed status\n(Get-VM 'MyVM').ExtensionData.Runtime.ConsolidationNeeded",
    "sources": [
      "https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-vm-administration/GUID-2F4A6D8B-33FF-4C6B-9B02-C984D151F0D5.html"
    ]
  },
  {
    "id": "hyperv-switch-not-found",
    "title": "Hyper-V: Virtual switch not found",
    "category": "Virtualization",
    "explanation": "The VM references a virtual switch that doesn't exist. The switch may have been deleted or the host was rebuilt.",
    "fix_snippet": "# List existing switches\nGet-VMSwitch\n# Create a new virtual switch\nNew-VMSwitch -Name 'External' -NetAdapterName 'Ethernet' -AllowManagementOS $true\n# Connect VM to switch\nConnect-VMNetworkAdapter -VMName 'MyVM' -SwitchName 'External'",
    "sources": [
      "https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-switch-for-hyper-v-virtual-machines"
    ]
  },
  {
    "id": "wsl-not-installed",
    "title": "WSL: Windows Subsystem for Linux is not installed",
    "category": "Virtualization",
    "explanation": "WSL is not enabled on the Windows machine. The Windows feature needs to be installed and enabled.",
    "fix_snippet": "# Install WSL (Windows 10/11)\nwsl --install\n# Or enable manually\ndism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart\ndism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart\n# Restart and set WSL 2 as default\nwsl --set-default-version 2",
    "sources": [
      "https://learn.microsoft.com/en-us/windows/wsl/install"
    ]
  },
  {
    "id": "wsl-kernel-update-required",
    "title": "WSL 2: Kernel update required",
    "category": "Virtualization",
    "explanation": "WSL 2 requires a Linux kernel component update that hasn't been installed yet.",
    "fix_snippet": "# Update WSL kernel\nwsl --update\n# Or download manually from Microsoft\n# https://aka.ms/wsl2kernel\n# After update, restart WSL\nwsl --shutdown\nwsl",
    "sources": [
      "https://learn.microsoft.com/en-us/windows/wsl/install-manual#step-4---download-the-linux-kernel-update-package"
    ]
  },
  {
    "id": "vagrant-box-not-found",
    "title": "Vagrant: Box not found",
    "category": "Virtualization",
    "explanation": "The Vagrant box specified in the Vagrantfile has not been downloaded or the name is incorrect.",
    "fix_snippet": "# Add box manually\nvagrant box add ubuntu/jammy64\n# Search available boxes\n# https://app.vagrantup.com/boxes/search\n# Check installed boxes\nvagrant box list\n# Update boxes\nvagrant box update",
    "sources": [
      "https://developer.hashicorp.com/vagrant/docs/boxes"
    ]
  },
  {
    "id": "qemu-kvm-not-available",
    "title": "QEMU/KVM: /dev/kvm not available",
    "category": "Virtualization",
    "explanation": "KVM kernel module is not loaded or the user doesn't have permission to access /dev/kvm. Hardware virtualization may be disabled.",
    "fix_snippet": "# Check KVM support\nkvm-ok\n# Load KVM module\nsudo modprobe kvm_intel  # or kvm_amd\n# Fix permissions\nsudo usermod -aG kvm $USER\n# Check if nested virtualization is needed\ncat /sys/module/kvm_intel/parameters/nested",
    "sources": [
      "https://www.linux-kvm.org/page/FAQ"
    ]
  },
  {
    "id": "cache-stampede",
    "title": "Cache stampede / thundering herd",
    "category": "Caching",
    "explanation": "Multiple processes simultaneously attempt to rebuild the same expired cache entry, overwhelming the backend database or API.",
    "fix_snippet": "# Use lock-based cache rebuild\nif cache.get(key) is None:\n    if cache.add(key + ':lock', 1, timeout=60):\n        value = expensive_query()\n        cache.set(key, value, timeout=3600)\n        cache.delete(key + ':lock')\n# Or use stale-while-revalidate pattern\n# Or use probabilistic early expiration",
    "sources": [
      "https://redis.io/docs/manual/patterns/distributed-locks/"
    ]
  },
  {
    "id": "memcached-slab-oom",
    "title": "Memcached: SERVER_ERROR out of memory",
    "category": "Caching",
    "explanation": "Memcached cannot allocate memory for new items. The memory limit has been reached and no items are eligible for eviction.",
    "fix_snippet": "# Increase memory limit\nmemcached -m 1024  # 1GB\n# Check memory stats\necho 'stats' | nc localhost 11211 | grep bytes\n# Check slab allocation\necho 'stats slabs' | nc localhost 11211\n# Adjust slab growth factor\nmemcached -f 1.25",
    "sources": [
      "https://github.com/memcached/memcached/wiki/ConfiguringServer"
    ]
  },
  {
    "id": "varnish-503-backend-fetch-failed",
    "title": "Varnish: 503 Backend fetch failed",
    "category": "Caching",
    "explanation": "Varnish cannot fetch content from the origin server. The backend may be down, too slow, or returning errors.",
    "fix_snippet": "# Check backend health\nvarnishadm backend.list\n# Increase backend timeouts in VCL\nbackend default {\n    .host = \"127.0.0.1\";\n    .port = \"8080\";\n    .connect_timeout = 5s;\n    .first_byte_timeout = 60s;\n}\n# Check varnishlog for details\nvarnishlog -g request -q 'RespStatus == 503'",
    "sources": [
      "https://varnish-cache.org/docs/trunk/users-guide/troubleshooting.html"
    ]
  },
  {
    "id": "cdn-cache-miss-high",
    "title": "CDN: High cache miss ratio",
    "category": "Caching",
    "explanation": "The CDN is not caching responses effectively. Most requests are hitting the origin server, defeating the purpose of the CDN.",
    "fix_snippet": "# Set proper Cache-Control headers\nCache-Control: public, max-age=31536000, immutable\n# Remove Set-Cookie from cacheable responses\n# Normalize query strings and Vary headers\n# Check CDN caching rules\n# Use versioned URLs for cache busting\n<link href=\"/style.v2.css\" />",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching"
    ]
  },
  {
    "id": "cloudfront-403-access-denied",
    "title": "CloudFront: 403 Access Denied",
    "category": "Caching",
    "explanation": "CloudFront cannot access the S3 origin, usually because the bucket policy or Origin Access Control (OAC) is misconfigured.",
    "fix_snippet": "# Update S3 bucket policy for OAC\n{\n  \"Statement\": [{\n    \"Effect\": \"Allow\",\n    \"Principal\": {\"Service\": \"cloudfront.amazonaws.com\"},\n    \"Action\": \"s3:GetObject\",\n    \"Resource\": \"arn:aws:s3:::my-bucket/*\",\n    \"Condition\": {\"StringEquals\": {\"AWS:SourceArn\": \"arn:aws:cloudfront::ACCOUNT:distribution/DIST_ID\"}}\n  }]\n}",
    "sources": [
      "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html"
    ]
  },
  {
    "id": "browser-cache-stale",
    "title": "Browser serving stale cache after deployment",
    "category": "Caching",
    "explanation": "Users see old content after a deployment because their browsers cached the previous version. Cache-busting is not configured.",
    "fix_snippet": "# Use content-hash in filenames (Webpack/Vite)\noutput: { filename: '[name].[contenthash].js' }\n# Set correct headers for HTML (don't cache)\nCache-Control: no-cache\n# Set long cache for hashed assets\nCache-Control: public, max-age=31536000, immutable\n# Force refresh: Ctrl+Shift+R",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching"
    ]
  },
  {
    "id": "regex-catastrophic-backtracking",
    "title": "Regex: Catastrophic backtracking (ReDoS)",
    "category": "Regex",
    "explanation": "A regular expression takes exponential time on certain inputs due to nested quantifiers or overlapping alternations. Can freeze applications or be exploited as a denial-of-service.",
    "fix_snippet": "# Avoid nested quantifiers\n# BAD:  (a+)+$\n# GOOD: a+$\n# Use atomic groups or possessive quantifiers\n# Use specific character classes instead of .\n# Test with regex debugger tools\n# Use RE2 or rust regex for linear-time matching",
    "sources": [
      "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
    ]
  },
  {
    "id": "regex-invalid-group-reference",
    "title": "Regex: Invalid back reference",
    "category": "Regex",
    "explanation": "The regex references a capture group that doesn't exist (e.g., \\3 when there are only 2 groups).",
    "fix_snippet": "# Count capture groups (each '(' that isn't '(?')\n# Ensure backreference number matches\n(first)(second) -> \\1 and \\2 are valid, \\3 is not\n# Use named groups for clarity\n(?P<name>pattern) -> \\k<name>\n# In JavaScript\n(?<name>pattern) -> \\k<name>",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Groups_and_backreferences"
    ]
  },
  {
    "id": "regex-unescaped-special-char",
    "title": "Regex: Invalid regular expression - unexpected character",
    "category": "Regex",
    "explanation": "A special regex metacharacter (. * + ? | ^ $ [ ] { } ( ) \\) was used without escaping, causing a syntax error.",
    "fix_snippet": "# Escape special characters with backslash\n# Match literal dot: \\.\n# Match literal brackets: \\[ \\]\n# Match literal dollar sign: \\$\n# In code, use raw strings (Python)\nimport re\nre.search(r'price: \\$[0-9]+', text)\n# Or use re.escape() for literal strings\nre.escape('price ($)')",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping"
    ]
  },
  {
    "id": "regex-lookahead-not-supported",
    "title": "Regex: Lookbehind not supported",
    "category": "Regex",
    "explanation": "The regex engine does not support lookbehind assertions (or only supports fixed-width lookbehinds). Varies by language and engine.",
    "fix_snippet": "# Use capture groups as alternative\n# Instead of: (?<=@)\\w+\n# Use: @(\\w+) and access group 1\n# Python/Java support variable-width lookbehind\n# JavaScript supports lookbehind (ES2018+)\n# Go RE2 does NOT support lookbehind\n# Use a two-step match approach",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Regular_expressions/Lookbehind_assertion"
    ]
  },
  {
    "id": "log4j-appender-not-found",
    "title": "Log4j: Appender not found",
    "category": "Logging",
    "explanation": "The logging configuration references an appender that is not defined. The log4j2.xml or log4j.properties file has an incorrect appender reference.",
    "fix_snippet": "# Verify appender is defined in log4j2.xml\n<Configuration>\n  <Appenders>\n    <Console name=\"Console\" target=\"SYSTEM_OUT\">\n      <PatternLayout pattern=\"%d{HH:mm:ss} [%t] %-5level %logger - %msg%n\"/>\n    </Console>\n  </Appenders>\n  <Loggers>\n    <Root level=\"info\">\n      <AppenderRef ref=\"Console\"/>\n    </Root>\n  </Loggers>\n</Configuration>",
    "sources": [
      "https://logging.apache.org/log4j/2.x/manual/configuration.html"
    ]
  },
  {
    "id": "logback-file-permission-denied",
    "title": "Logback: Failed to create log file",
    "category": "Logging",
    "explanation": "Logback cannot create or write to the log file due to filesystem permissions or the directory not existing.",
    "fix_snippet": "# Create log directory with correct permissions\nsudo mkdir -p /var/log/myapp\nsudo chown appuser:appuser /var/log/myapp\n# Check logback.xml file path\n<appender name=\"FILE\" class=\"ch.qos.logback.core.FileAppender\">\n  <file>/var/log/myapp/app.log</file>\n</appender>\n# Use relative path as fallback\n<file>logs/app.log</file>",
    "sources": [
      "https://logback.qos.ch/manual/appenders.html"
    ]
  },
  {
    "id": "fluentd-buffer-overflow",
    "title": "Fluentd: Buffer overflow",
    "category": "Logging",
    "explanation": "Fluentd's output buffer is full because the destination cannot accept data fast enough. Logs may be dropped.",
    "fix_snippet": "# Increase buffer size in fluentd.conf\n<buffer>\n  @type file\n  path /var/log/fluentd/buffer\n  total_limit_size 5GB\n  chunk_limit_size 32MB\n  overflow_action throw_exception\n</buffer>\n# Scale destination or add retry\nretry_max_times 10\nretry_wait 5s",
    "sources": [
      "https://docs.fluentd.org/buffer"
    ]
  },
  {
    "id": "cloudwatch-logs-throttled",
    "title": "CloudWatch Logs: Rate exceeded (ThrottlingException)",
    "category": "Logging",
    "explanation": "PutLogEvents API calls are being throttled by CloudWatch Logs. The account or log group is exceeding the API rate limit.",
    "fix_snippet": "# Batch log events (max 10,000 per PutLogEvents)\n# Use CloudWatch Agent instead of direct API calls\n# Implement exponential backoff on retries\n# Request limit increase via AWS Support\n# Consider using Kinesis Data Firehose for high volume",
    "sources": [
      "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html"
    ]
  },
  {
    "id": "elk-logstash-pipeline-error",
    "title": "Logstash: Pipeline error",
    "category": "Logging",
    "explanation": "A Logstash pipeline failed to start or process events, usually due to a bad grok pattern, filter configuration, or output connection issue.",
    "fix_snippet": "# Test configuration\n/usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/\n# Debug grok patterns\n# Use Kibana Grok Debugger\n# Check pipeline logs\ntail -f /var/log/logstash/logstash-plain.log\n# Test with stdin input\ninput { stdin { } }\nfilter { grok { match => { \"message\" => \"%{COMBINEDAPACHELOG}\" } } }",
    "sources": [
      "https://www.elastic.co/guide/en/logstash/current/troubleshooting.html"
    ]
  },
  {
    "id": "mysql-lock-wait-timeout",
    "title": "MySQL: Lock wait timeout exceeded; try restarting transaction",
    "category": "Database",
    "explanation": "InnoDB could not acquire a row lock before innodb_lock_wait_timeout because another transaction was holding it. Usually caused by long-running transactions, missing indexes, or high write contention.",
    "fix_snippet": "-- Find long transactions\nSELECT * FROM information_schema.INNODB_TRX ORDER BY trx_started;\n-- Inspect locks\nSELECT * FROM performance_schema.data_locks;\n-- Kill the blocker only if safe\nKILL <trx_mysql_thread_id>;\n-- Keep transactions short and index WHERE clauses used by UPDATE/DELETE\nSET innodb_lock_wait_timeout = 120;",
    "sources": [
      "https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_lock_wait_timeout"
    ]
  },
  {
    "id": "mysql-server-has-gone-away",
    "title": "MySQL server has gone away (error 2006)",
    "category": "Database",
    "explanation": "The client lost its connection to MySQL, often because an idle pooled connection timed out, max_allowed_packet was too small, or the server restarted.",
    "fix_snippet": "SHOW VARIABLES LIKE 'wait_timeout';\nSHOW VARIABLES LIKE 'max_allowed_packet';\nSET GLOBAL wait_timeout = 86400;\nSET GLOBAL max_allowed_packet = 67108864;\n# Application side: ping/reconnect before reuse\n# PyMySQL example\nconnection.ping(reconnect=True)",
    "sources": [
      "https://dev.mysql.com/doc/refman/8.0/en/gone-away.html"
    ]
  },
  {
    "id": "mongodb-duplicate-key-error",
    "title": "MongoDB: E11000 duplicate key error",
    "category": "Database",
    "explanation": "An insert or upsert violated a unique index. Common during retries, imports, or migrations that do not account for existing records.",
    "fix_snippet": "// Inspect indexes\ndb.users.getIndexes()\n// Find the conflicting document\ndb.users.find({ email: 'user@example.com' })\n// Use idempotent upsert\ndb.users.updateOne(\n  { email },\n  { $setOnInsert: { email, createdAt: new Date() } },\n  { upsert: true }\n)",
    "sources": [
      "https://www.mongodb.com/docs/manual/core/index-unique/"
    ]
  },
  {
    "id": "sqlite-database-is-locked",
    "title": "SQLite: database is locked (SQLITE_BUSY)",
    "category": "Database",
    "explanation": "Another process or transaction is holding SQLite's write lock. SQLite allows many readers but only one writer at a time.",
    "fix_snippet": "PRAGMA journal_mode = WAL;\nPRAGMA synchronous = NORMAL;\nPRAGMA busy_timeout = 5000;\n# Python\nconn = sqlite3.connect('app.db', timeout=5, isolation_level=None)\nconn.execute('PRAGMA journal_mode=WAL')\n# Keep write transactions short",
    "sources": [
      "https://www.sqlite.org/wal.html"
    ]
  },
  {
    "id": "dynamodb-provisioned-throughput-exceeded",
    "title": "DynamoDB: ProvisionedThroughputExceededException",
    "category": "Database",
    "explanation": "The table or a hot partition exceeded its read/write capacity. A skewed partition key can throttle even when overall table capacity looks sufficient.",
    "fix_snippet": "aws dynamodb update-table --table-name MyTable --billing-mode PAY_PER_REQUEST\n# Or increase provisioned capacity\naws dynamodb update-table --table-name MyTable \\\n  --provisioned-throughput ReadCapacityUnits=200,WriteCapacityUnits=200\n# Add exponential backoff and fix hot partition keys",
    "sources": [
      "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ProvisionedThroughput.html"
    ]
  },
  {
    "id": "mssql-deadlock-victim",
    "title": "SQL Server: Transaction was deadlocked (Msg 1205)",
    "category": "Database",
    "explanation": "SQL Server chose your transaction as the deadlock victim after two or more sessions blocked each other in a cycle.",
    "fix_snippet": "-- Capture deadlock graph\nCREATE EVENT SESSION deadlocks ON SERVER\nADD EVENT sqlserver.xml_deadlock_report\nADD TARGET package0.event_file(SET filename='deadlocks.xel');\nALTER EVENT SESSION deadlocks ON SERVER STATE = START;\n-- Always retry error 1205 with backoff\n-- Use consistent table access order and keep transactions short",
    "sources": [
      "https://learn.microsoft.com/en-us/sql/relational-databases/sql-server-transaction-locking-and-row-versioning-guide"
    ]
  },
  {
    "id": "mtu-mismatch",
    "title": "MTU mismatch / fragmentation needed but DF set",
    "category": "Network",
    "explanation": "A link in the path has a smaller MTU than the sender used and the packet has Don't Fragment set. Common with VPNs, tunnels, PPPoE, VXLAN, WireGuard, and GRE.",
    "fix_snippet": "# Find largest packet that passes (Linux)\nping -M do -s 1472 8.8.8.8\nping -M do -s 1372 8.8.8.8\n# Lower interface MTU\nsudo ip link set dev eth0 mtu 1400\n# Clamp TCP MSS on a router/firewall\niptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc1191"
    ]
  },
  {
    "id": "socket-address-in-use",
    "title": "bind: address already in use (EADDRINUSE)",
    "category": "Network",
    "explanation": "Another process is already listening on the port, or a previous server instance did not shut down cleanly.",
    "fix_snippet": "sudo lsof -iTCP:8080 -sTCP:LISTEN\nsudo ss -lntp | grep :8080\nsudo fuser -k 8080/tcp\n# Node.js: avoid fixed dev ports when possible\nserver.listen({ port: 0, host: '0.0.0.0' })",
    "sources": [
      "https://man7.org/linux/man-pages/man2/bind.2.html"
    ]
  },
  {
    "id": "ipv6-no-route",
    "title": "IPv6: Network is unreachable / no route to host",
    "category": "Network",
    "explanation": "The client prefers IPv6 or receives AAAA records but has no working IPv6 path. This can add long fallback delays or fail outright.",
    "fix_snippet": "ip -6 route\nping6 -c 3 2606:4700:4700::1111\n# Force IPv4 for testing\ncurl -4 https://example.com\n# Prefer IPv4 temporarily on Linux\necho 'precedence ::ffff:0:0/96  100' | sudo tee -a /etc/gai.conf",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc6724"
    ]
  },
  {
    "id": "quic-handshake-failed",
    "title": "QUIC handshake failed / UDP 443 blocked",
    "category": "Network",
    "explanation": "HTTP/3 over QUIC requires UDP/443. Corporate networks and firewalls often block it, forcing fallback to TCP or causing failures when QUIC is required.",
    "fix_snippet": "nc -u -zv example.com 443\n# Force HTTP/2 while debugging\ncurl --http2 -v https://example.com\n# Server firewall\nsudo ufw allow 443/udp\n# CDN: disable HTTP/3 temporarily if users are on locked-down networks",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc9114"
    ]
  },
  {
    "id": "http-422-unprocessable-entity",
    "title": "422 Unprocessable Entity",
    "category": "HTTP",
    "explanation": "The request body is syntactically valid but semantically invalid. APIs commonly return this for validation errors such as missing required fields or invalid enum values.",
    "fix_snippet": "curl -i -X POST https://api.example.com/users \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"email\":\"not-an-email\"}'\n# Read the response body for field-level errors\n# Validate against OpenAPI/JSON Schema before sending",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/422"
    ]
  },
  {
    "id": "http-409-conflict",
    "title": "409 Conflict",
    "category": "HTTP",
    "explanation": "The request conflicts with the current resource state. Typical causes include duplicate creates, optimistic locking failures, stale ETags, or version mismatches.",
    "fix_snippet": "# Fetch latest ETag and retry with If-Match\nETAG=$(curl -sI https://api.example.com/things/42 | awk '/ETag:/ {print $2}' | tr -d '\\r')\ncurl -X PUT https://api.example.com/things/42 \\\n  -H \"If-Match: $ETAG\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"name\":\"new\"}'\n# Use idempotency keys for duplicate POSTs",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/409"
    ]
  },
  {
    "id": "http-410-gone",
    "title": "410 Gone",
    "category": "HTTP",
    "explanation": "The resource was intentionally removed and is not expected to return. Unlike 404, 410 tells clients and crawlers the removal is permanent.",
    "fix_snippet": "# Nginx\nlocation = /old-page { return 410; }\n# Express\napp.all('/old-page', (req, res) => res.sendStatus(410));\n# Remove the URL from sitemap.xml, but let crawlers see the 410",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/410"
    ]
  },
  {
    "id": "http-425-too-early",
    "title": "425 Too Early",
    "category": "HTTP",
    "explanation": "The server refuses to process a request that might be replayed, typically TLS 1.3 0-RTT early data on a non-idempotent method.",
    "fix_snippet": "# Nginx pattern\nssl_early_data on;\nproxy_set_header Early-Data $ssl_early_data;\nif ($ssl_early_data = \"1\") { return 425; }\n# Client: retry without early data and never send mutating requests via 0-RTT",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/425"
    ]
  },
  {
    "id": "http-100-continue-timeout",
    "title": "100-continue timeout / Expect: 100-continue stalls",
    "category": "HTTP",
    "explanation": "The client sent Expect: 100-continue and is waiting before streaming the body, but the proxy or server does not handle the interim response correctly.",
    "fix_snippet": "curl -H 'Expect:' -F file=@big.zip https://upload.example.com\n# Python requests\nimport requests\ns = requests.Session()\ns.headers.update({'Expect': ''})\n# Nginx upstreams\nproxy_http_version 1.1;\nproxy_request_buffering off;",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc7231#section-5.1.1"
    ]
  },
  {
    "id": "python-recursion-limit",
    "title": "Python: RecursionError: maximum recursion depth exceeded",
    "category": "Python",
    "explanation": "A function recursed beyond Python's recursion limit. Usually caused by a missing base case, cyclical data, or using recursion for a problem that should be iterative.",
    "fix_snippet": "import sys\nprint(sys.getrecursionlimit())\nsys.setrecursionlimit(5000)  # temporary workaround\n# Prefer iteration for deep trees\nstack = [root]\nwhile stack:\n    node = stack.pop()\n    stack.extend(node.children)",
    "sources": [
      "https://docs.python.org/3/library/sys.html#sys.setrecursionlimit"
    ]
  },
  {
    "id": "python-attribute-error",
    "title": "Python: AttributeError: 'NoneType' object has no attribute 'X'",
    "category": "Python",
    "explanation": "A function returned None and the caller tried to access an attribute on it. Common with failed lookups, regex matches, and optional database results.",
    "fix_snippet": "user = db.get(id)\nif user is None:\n    raise NotFound('user')\nname = user.name\n# Type-check Optional values\nfrom typing import Optional\ndef get_user(id: int) -> Optional[User]: ...",
    "sources": [
      "https://docs.python.org/3/library/exceptions.html#AttributeError"
    ]
  },
  {
    "id": "python-keyerror",
    "title": "Python: KeyError on dict access",
    "category": "Python",
    "explanation": "A dictionary key was accessed directly but does not exist. Often happens when parsing JSON from APIs you do not fully control.",
    "fix_snippet": "value = data.get('user', {}).get('email', '')\nfrom collections import defaultdict\ncounts = defaultdict(int)\ncounts['a'] += 1\ntry:\n    v = data['user']['email']\nexcept KeyError as e:\n    log.warning('missing field %s', e)",
    "sources": [
      "https://docs.python.org/3/library/exceptions.html#KeyError"
    ]
  },
  {
    "id": "python-utf8-decode-error",
    "title": "Python: UnicodeDecodeError: 'utf-8' codec can't decode byte",
    "category": "Python",
    "explanation": "Bytes were decoded as UTF-8 but the source uses another encoding such as CP1252, Latin-1, or UTF-16.",
    "fix_snippet": "# Detect encoding\npython -c \"import chardet; print(chardet.detect(open('file.csv','rb').read(10000)))\"\n# Open with the correct codec\nwith open('file.csv', encoding='cp1252') as f:\n    rows = f.read()\n# Or tolerate bad bytes\nopen('file.txt', encoding='utf-8', errors='replace')",
    "sources": [
      "https://docs.python.org/3/howto/unicode.html"
    ]
  },
  {
    "id": "django-improperlyconfigured",
    "title": "Django: ImproperlyConfigured: setting is not configured",
    "category": "Python",
    "explanation": "Django could not find a required setting such as SECRET_KEY, DATABASES, or ALLOWED_HOSTS. Often environment variables were not loaded in production.",
    "fix_snippet": "python manage.py diffsettings\n# Example with django-environ\nimport environ\nenv = environ.Env()\nenviron.Env.read_env()\nSECRET_KEY = env('SECRET_KEY')\nALLOWED_HOSTS = env.list('ALLOWED_HOSTS')",
    "sources": [
      "https://docs.djangoproject.com/en/stable/ref/settings/"
    ]
  },
  {
    "id": "javascript-cannot-read-properties-undefined",
    "title": "TypeError: Cannot read properties of undefined (reading 'X')",
    "category": "JavaScript",
    "explanation": "Code accessed a property on undefined, commonly because API data has not loaded yet or the response shape changed.",
    "fix_snippet": "const name = data?.user?.profile?.name ?? 'anonymous';\nif (!data || typeof data.user !== 'object') return;\n// React\nif (!user) return <Spinner />;\nreturn <Name name={user.profile.name} />;",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Optional_chaining"
    ]
  },
  {
    "id": "javascript-maximum-call-stack",
    "title": "RangeError: Maximum call stack size exceeded",
    "category": "JavaScript",
    "explanation": "JavaScript hit its call stack limit, usually from infinite recursion, circular getters, or trying to stringify a deeply nested/cyclic object.",
    "fix_snippet": "// Convert recursion to iteration\nconst stack = [root];\nwhile (stack.length) {\n  const node = stack.pop();\n  stack.push(...node.children);\n}\n// Avoid cycles in JSON.stringify with a seen Set",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Too_much_recursion"
    ]
  },
  {
    "id": "npm-eresolve-conflict",
    "title": "npm ERR! ERESOLVE unable to resolve dependency tree",
    "category": "JavaScript",
    "explanation": "npm 7+ enforces peer dependency constraints. One package requires a peer version that conflicts with another dependency.",
    "fix_snippet": "npm install --dry-run\n# Prefer upgrading the package with the outdated peer\n# package.json override if needed\n{\n  \"overrides\": { \"react\": \"^18.2.0\" }\n}\n# Last resort\nnpm install --legacy-peer-deps",
    "sources": [
      "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#overrides"
    ]
  },
  {
    "id": "pnpm-lockfile-mismatch",
    "title": "pnpm: ERR_PNPM_OUTDATED_LOCKFILE",
    "category": "JavaScript",
    "explanation": "pnpm-lock.yaml is out of sync with package.json and CI is running with --frozen-lockfile.",
    "fix_snippet": "pnpm install\ngit add pnpm-lock.yaml\n# CI should keep this strict\npnpm install --frozen-lockfile\n# Only if you intentionally want CI to update it\npnpm install --no-frozen-lockfile",
    "sources": [
      "https://pnpm.io/cli/install#--frozen-lockfile"
    ]
  },
  {
    "id": "docker-buildkit-credential-helper",
    "title": "Docker: error getting credentials - credential helper not installed",
    "category": "Docker",
    "explanation": "Docker is configured to use a credential helper such as docker-credential-desktop, but that helper is not installed or not on PATH.",
    "fix_snippet": "cat ~/.docker/config.json\n# Remove stale credsStore/credHelpers if not needed\n# Or install the helper your config references\n# CI-safe login\necho \"$DOCKER_PASSWORD\" | docker login -u \"$DOCKER_USERNAME\" --password-stdin",
    "sources": [
      "https://docs.docker.com/engine/reference/commandline/login/#credential-stores"
    ]
  },
  {
    "id": "k8s-node-not-ready",
    "title": "Kubernetes: Node status NotReady",
    "category": "Kubernetes",
    "explanation": "The kubelet stopped reporting healthy. Common causes include disk pressure, CNI failures, stopped kubelet, or lost API server connectivity.",
    "fix_snippet": "kubectl describe node bad-node\nsudo systemctl status kubelet\nsudo journalctl -u kubelet -n 200 --no-pager\ndf -h /var/lib/kubelet\nls /etc/cni/net.d/\n# If needed\nkubectl drain bad-node --ignore-daemonsets --delete-emptydir-data",
    "sources": [
      "https://kubernetes.io/docs/concepts/architecture/nodes/#node-status"
    ]
  },
  {
    "id": "k8s-evicted-pod",
    "title": "Kubernetes: Pod evicted - node was low on resource",
    "category": "Kubernetes",
    "explanation": "The kubelet evicted a pod to reclaim memory, disk, or inodes. Evictions often indicate missing resource requests/limits or node pressure.",
    "fix_snippet": "kubectl get pods --all-namespaces | grep Evicted\nkubectl describe pod my-pod\n# Clean old failed pods\nkubectl delete pods --field-selector=status.phase=Failed --all-namespaces\n# Add requests/limits\nresources:\n  requests: { memory: 256Mi, cpu: 100m }\n  limits: { memory: 512Mi, cpu: 500m }",
    "sources": [
      "https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/"
    ]
  },
  {
    "id": "helm-release-failed",
    "title": "Helm: release stuck in failed or pending state",
    "category": "Kubernetes",
    "explanation": "A previous Helm install or upgrade failed and left the release in a state that blocks later upgrades.",
    "fix_snippet": "helm history my-release -n my-ns\nhelm rollback my-release 3 -n my-ns\n# Or replace if safe\nhelm uninstall my-release -n my-ns\nhelm install my-release ./chart -n my-ns -f values.yaml\n# Safer future upgrades\nhelm upgrade --install --atomic --wait --timeout 5m my-release ./chart -n my-ns",
    "sources": [
      "https://helm.sh/docs/helm/helm_rollback/"
    ]
  },
  {
    "id": "git-cherry-pick-conflict",
    "title": "git cherry-pick: conflict",
    "category": "Git",
    "explanation": "The commit being cherry-picked modifies lines that diverged on the target branch, so Git needs manual conflict resolution.",
    "fix_snippet": "git status\n# Resolve files manually, then\ngit add <file>\ngit cherry-pick --continue\n# Abort the operation\ngit cherry-pick --abort\n# Skip this commit in a sequence\ngit cherry-pick --skip",
    "sources": [
      "https://git-scm.com/docs/git-cherry-pick"
    ]
  },
  {
    "id": "git-cannot-lock-ref",
    "title": "git: cannot lock ref",
    "category": "Git",
    "explanation": "Another Git process is holding a ref lock or a stale .lock file remains from a crashed Git process.",
    "fix_snippet": "ls -la .git/refs/heads/*.lock .git/index.lock 2>/dev/null\npgrep -a git\nrm -f .git/refs/heads/main.lock .git/index.lock\ngit pack-refs --all\ngit gc --prune=now",
    "sources": [
      "https://git-scm.com/docs/git-pack-refs"
    ]
  },
  {
    "id": "git-repository-corrupted",
    "title": "git: object file is empty / loose object is corrupt",
    "category": "Git",
    "explanation": "A Git object under .git/objects is unreadable, commonly after a crash, cloud-sync conflict, or filesystem issue.",
    "fix_snippet": "git fsck --full --no-dangling\nfind .git/objects -size 0 -delete\ngit fetch --all\n# If origin has everything, a fresh clone is often safest\n# Avoid syncing .git with OneDrive/Dropbox/iCloud",
    "sources": [
      "https://git-scm.com/docs/git-fsck"
    ]
  },
  {
    "id": "openai-insufficient-quota",
    "title": "OpenAI: 429 insufficient_quota",
    "category": "AI",
    "explanation": "The account has no remaining credits or has hit its billing quota. This is different from temporary rate limiting.",
    "fix_snippet": "# Confirm the key/account you are using\n# Check billing dashboard and usage limits\ntry:\n    resp = client.chat.completions.create(...)\nexcept openai.RateLimitError as e:\n    if 'insufficient_quota' in str(e):\n        notify_billing_or_disable_feature()",
    "sources": [
      "https://platform.openai.com/docs/guides/error-codes"
    ]
  },
  {
    "id": "claude-content-policy-violation",
    "title": "Claude: response blocked / safety refusal",
    "category": "AI",
    "explanation": "The model declined to answer because the prompt matched a disallowed or ambiguous safety category. Provide a clearer benign context or constrain the task.",
    "fix_snippet": "# Rephrase with benign intent and scope\nclient.messages.create(\n  model='claude-3-5-sonnet-latest',\n  system='You are a helpful Python tutor. Answer Python questions only.',\n  messages=[{'role':'user','content': user_input}]\n)\n# Do not retry the exact same unsafe prompt blindly",
    "sources": [
      "https://docs.anthropic.com/en/docs/build-with-claude/usage-policies"
    ]
  },
  {
    "id": "anthropic-prompt-too-long",
    "title": "Anthropic API: prompt is too long / context window exceeded",
    "category": "AI",
    "explanation": "Input tokens plus requested output tokens exceed the selected model's context window.",
    "fix_snippet": "# Count tokens first\ntoken_count = client.messages.count_tokens(\n  model='claude-3-5-sonnet-latest',\n  messages=messages\n)\nprint(token_count.input_tokens)\n# Reduce max_tokens, summarize history, use RAG, or use prompt caching for static context",
    "sources": [
      "https://docs.anthropic.com/en/docs/about-claude/models"
    ]
  },
  {
    "id": "macos-gatekeeper-blocked",
    "title": "macOS: app is damaged and can't be opened / Gatekeeper blocked",
    "category": "System",
    "explanation": "macOS quarantined a downloaded app or binary because it is unsigned, unnotarized, or not trusted yet.",
    "fix_snippet": "xattr -dr com.apple.quarantine /Applications/MyApp.app\n# Or for a CLI\nxattr -d com.apple.quarantine /usr/local/bin/mybin\n# For your own builds: sign and notarize\ncodesign --deep --force --options runtime --sign 'Developer ID Application: Your Name' MyApp.app",
    "sources": [
      "https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web"
    ]
  },
  {
    "id": "windows-error-1603-msi",
    "title": "Windows: MSI installer error 1603",
    "category": "System",
    "explanation": "A generic fatal MSI installation failure. The real error is usually near 'Return value 3' in verbose logs.",
    "fix_snippet": "msiexec /i installer.msi /L*v install.log\nSelect-String -Path install.log -Pattern 'Return value 3' -Context 5,10\n# Common fixes: run as Administrator, clear %TEMP%, remove a broken previous install, ensure SYSTEM can write to target folders",
    "sources": [
      "https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/msi-installation-error-1603"
    ]
  },
  {
    "id": "wsl-vmcompute-not-running",
    "title": "WSL2: Error 0x80370102 / vmcompute not running",
    "category": "System",
    "explanation": "WSL2 cannot start its VM because virtualization features are disabled, hypervisorlaunchtype is off, or vmcompute is stopped.",
    "fix_snippet": "dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart\ndism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart\nbcdedit /set hypervisorlaunchtype auto\nStart-Service vmcompute\nshutdown /r /t 0",
    "sources": [
      "https://learn.microsoft.com/en-us/windows/wsl/troubleshooting"
    ]
  },
  {
    "id": "react-too-many-renders",
    "title": "React: Too many re-renders",
    "category": "JavaScript",
    "explanation": "State is updated unconditionally during render, or an effect dependency changes every render and triggers an infinite update loop.",
    "fix_snippet": "// Bad\n<button onClick={setOpen(true)}>Open</button>\n// Good\n<button onClick={() => setOpen(true)}>Open</button>\n// Memoize object deps\nconst options = useMemo(() => ({ limit: 10 }), []);\nuseEffect(() => fetchData(options), [options]);",
    "sources": [
      "https://react.dev/reference/react/useState"
    ]
  },
  {
    "id": "vite-build-out-of-memory",
    "title": "Vite: JavaScript heap out of memory during build",
    "category": "JavaScript",
    "explanation": "The Node build process exceeded the default heap limit, often because of large source maps, many modules, or oversized bundles.",
    "fix_snippet": "NODE_OPTIONS=--max-old-space-size=8192 npx vite build\n# package.json\n\"build\": \"node --max-old-space-size=8192 ./node_modules/vite/bin/vite.js build\"\n# Reduce work: disable sourcemaps in CI, remove dead dependencies, split chunks",
    "sources": [
      "https://vitejs.dev/config/build-options.html"
    ]
  },
  {
    "id": "tailwind-class-not-applied",
    "title": "Tailwind CSS class does not appear in built CSS",
    "category": "JavaScript",
    "explanation": "Tailwind only generates class names it can see as literal strings. Dynamically constructed names can be purged from production CSS.",
    "fix_snippet": "// Bad\n<div className={`text-${color}-500`} />\n// Good\nconst classes = { red: 'text-red-500', blue: 'text-blue-500' };\n<div className={classes[color]} />\n// Or use safelist in tailwind.config.js",
    "sources": [
      "https://tailwindcss.com/docs/content-configuration#dynamic-class-names"
    ]
  },
  {
    "id": "stripe-webhook-signature-failed",
    "title": "Stripe: Webhook signature verification failed",
    "category": "API",
    "explanation": "The Stripe-Signature header does not match the raw request body and endpoint secret. Usually JSON middleware modified the body before verification.",
    "fix_snippet": "app.post('/webhook',\n  express.raw({ type: 'application/json' }),\n  (req, res) => {\n    const sig = req.headers['stripe-signature'];\n    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);\n    res.json({ received: true });\n  }\n)\n# Test locally\nstripe listen --forward-to localhost:3000/webhook",
    "sources": [
      "https://stripe.com/docs/webhooks/signatures"
    ]
  },
  {
    "id": "stripe-card-declined",
    "title": "Stripe: card_declined",
    "category": "API",
    "explanation": "The issuing bank refused the charge. The decline_code provides the actionable reason, such as insufficient_funds, expired_card, or do_not_honor.",
    "fix_snippet": "try {\n  await stripe.paymentIntents.confirm(piId);\n} catch (err) {\n  if (err.code === 'card_declined') {\n    console.log(err.decline_code);\n  }\n}\n# Map decline codes to user-friendly messages and retry options",
    "sources": [
      "https://stripe.com/docs/declines/codes"
    ]
  },
  {
    "id": "safari-third-party-cookie-blocked",
    "title": "Safari: third-party cookie blocked (ITP)",
    "category": "Client",
    "explanation": "Safari's Intelligent Tracking Prevention blocks cookies in third-party contexts such as iframes, embedded SSO, and cross-site widgets.",
    "fix_snippet": "Set-Cookie: session=abc; SameSite=None; Secure; HttpOnly\n# Prefer first-party redirects instead of iframe/popup auth\n# Embedded contexts can request storage access\ndocument.requestStorageAccess().then(() => {\n  // cookie access granted\n})",
    "sources": [
      "https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/"
    ]
  },
  {
    "id": "browser-cookie-samesite-missing",
    "title": "Browser warning: Cookie has no SameSite attribute",
    "category": "Client",
    "explanation": "Modern browsers default cookies without SameSite to Lax, which may break cross-site login, embedded widgets, or POST-based SSO flows.",
    "fix_snippet": "Set-Cookie: sessionid=abc; SameSite=Lax; Secure; HttpOnly\nSet-Cookie: embed=xyz; SameSite=None; Secure\n# Express\nres.cookie('sid', token, { sameSite: 'lax', secure: true, httpOnly: true });",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
    ]
  },
  {
    "id": "wasm-compile-error",
    "title": "WebAssembly: CompileError - invalid magic / section",
    "category": "WebAssembly",
    "explanation": "The .wasm file is not valid WebAssembly bytes. Often the server returned an HTML error page, the file was truncated, or the MIME type is wrong.",
    "fix_snippet": "curl -I https://example.com/app.wasm\nxxd -l 8 app.wasm  # should start: 00 61 73 6d 01 00 00 00\n# Nginx MIME type\ntypes { application/wasm wasm; }\n# Fallback if instantiateStreaming fails\nconst buf = await fetch('app.wasm').then(r => r.arrayBuffer());\nawait WebAssembly.instantiate(buf, imports);",
    "sources": [
      "https://webassembly.github.io/spec/core/binary/modules.html"
    ]
  },
  {
    "id": "wasm-memory-out-of-bounds",
    "title": "WebAssembly: RuntimeError - memory access out of bounds",
    "category": "WebAssembly",
    "explanation": "WASM code accessed memory outside its linear memory, usually from an out-of-bounds index, use-after-free, or insufficient memory growth.",
    "fix_snippet": "# Rust WASM: build with debug info\n[profile.release]\ndebug = true\n# Add better panic output\nconsole_error_panic_hook::set_once();\n# Inspect inputs and bounds before passing pointers to WASM\n# Increase initial/max memory if the workload genuinely needs it",
    "sources": [
      "https://rustwasm.github.io/docs/wasm-bindgen/"
    ]
  },
  {
    "id": "web3-insufficient-funds-gas",
    "title": "Web3: insufficient funds for gas * price + value",
    "category": "Web3",
    "explanation": "The wallet lacks enough native token to pay transaction value plus gas. This is separate from ERC-20 token balance.",
    "fix_snippet": "const gas = await contract.estimateGas.transfer(to, amount);\nconst feeData = await provider.getFeeData();\nconst balance = await provider.getBalance(wallet.address);\nif (balance < gas * feeData.gasPrice) throw new Error('Top up native token for gas');\n# Send ETH/MATIC/BNB/etc. to the wallet and retry",
    "sources": [
      "https://ethereum.org/en/developers/docs/gas/"
    ]
  },
  {
    "id": "web3-nonce-too-low",
    "title": "Web3: nonce too low / replacement transaction underpriced",
    "category": "Web3",
    "explanation": "The transaction nonce has already been mined, or a replacement transaction did not increase fees enough to replace the pending transaction.",
    "fix_snippet": "const nonce = await provider.getTransactionCount(address, 'pending');\nawait wallet.sendTransaction({ to, value, nonce });\n# Replace stuck tx: same nonce, higher maxFeePerGas / gasPrice\n# MetaMask: Settings -> Advanced -> Reset account to clear local nonce cache",
    "sources": [
      "https://ethereum.org/en/developers/docs/transactions/"
    ]
  },
  {
    "id": "web3-revert-execution",
    "title": "Web3: execution reverted",
    "category": "Web3",
    "explanation": "The smart contract reverted. Solidity custom errors or revert strings often explain the exact requirement that failed.",
    "fix_snippet": "try {\n  await contract.transfer(to, amount);\n} catch (err) {\n  const data = err.data || err.error?.data;\n  const parsed = contract.interface.parseError(data);\n  console.log(parsed.name, parsed.args);\n}\n# Use Tenderly, Foundry cast --trace, or Etherscan debug tools",
    "sources": [
      "https://docs.soliditylang.org/en/latest/control-structures.html#try-catch"
    ]
  },
  {
    "id": "ldap-invalid-credentials",
    "title": "LDAP: invalid credentials / AD data 52e",
    "category": "Security",
    "explanation": "LDAP bind failed. In Active Directory, subcode 52e means wrong password; other subcodes indicate no such user, disabled account, expired password, or account lockout.",
    "fix_snippet": "ldapsearch -x -H ldaps://dc.example.com \\\n  -D \"CN=svc,OU=Apps,DC=example,DC=com\" -W \\\n  -b \"DC=example,DC=com\" \"(sAMAccountName=alice)\"\n# Try UPN format: alice@example.com\n# Check service-account password rotation and LDAPS requirements",
    "sources": [
      "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshooting-ldap-over-ssl-connection-problems"
    ]
  },
  {
    "id": "kerberos-clock-skew",
    "title": "Kerberos: KRB_AP_ERR_SKEW / clock skew too great",
    "category": "Security",
    "explanation": "Kerberos tickets are time-bound. If the client and KDC clocks differ beyond the allowed skew, authentication fails.",
    "fix_snippet": "date -u\nssh kdc.example.com 'date -u'\n# Linux\nsudo systemctl restart chronyd\nsudo chronyc tracking\n# Windows\nw32tm /resync /force\n# Real fix: reliable NTP on all domain participants",
    "sources": [
      "https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html"
    ]
  },
  {
    "id": "saml-signature-invalid",
    "title": "SAML: invalid signature on assertion / response",
    "category": "Security",
    "explanation": "The service provider could not validate the SAML response signature. Usually the IdP signing certificate changed or the wrong metadata is configured.",
    "fix_snippet": "echo \"$SAML_RESPONSE\" | base64 -d | xmllint --format -\nxmlsec1 --verify --pubkey-cert-pem idp-cert.pem saml-response.xml\n# Fetch and configure current IdP metadata\ncurl -sS https://idp.example.com/metadata.xml > metadata.xml\n# Avoid modifying/minifying SAML XML in transit",
    "sources": [
      "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf"
    ]
  },
  {
    "id": "oauth-redirect-uri-mismatch",
    "title": "OAuth: redirect_uri_mismatch",
    "category": "Security",
    "explanation": "The redirect_uri in the authorisation request does not exactly match a registered redirect URI. Scheme, host, port, path, trailing slash, and query must match.",
    "fix_snippet": "# Common mismatches\n# http vs https\n# localhost:3000 vs 127.0.0.1:3000\n# /callback vs /callback/\n# preview URL not registered\nconst REDIRECT_URI = process.env.OAUTH_REDIRECT_URI;\n# Register every production and preview callback URL with the provider",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2"
    ]
  },
  {
    "id": "perf-gc-pause-too-long",
    "title": "Long GC pause / stop-the-world latency spike",
    "category": "Performance",
    "explanation": "A managed runtime paused application threads to collect garbage long enough to violate latency targets. Large heaps and allocation spikes are common causes.",
    "fix_snippet": "# JVM low-pause GC\nJAVA_OPTS=\"-XX:+UseG1GC -XX:MaxGCPauseMillis=200 -Xlog:gc*:file=gc.log\"\n# Very large heaps\n-XX:+UseZGC\n# Node.js: reduce allocation pressure; --max-old-space-size only raises the cap\n# Profile allocations before tuning heap sizes",
    "sources": [
      "https://docs.oracle.com/en/java/javase/21/gctuning/"
    ]
  },
  {
    "id": "perf-thread-starvation",
    "title": "Thread pool starvation / requests queueing behind blocked threads",
    "category": "Performance",
    "explanation": "All threads in a bounded pool are blocked on I/O, locks, or sync-over-async calls. Latency rises while CPU can remain low.",
    "fix_snippet": "# Symptoms: low CPU, high queue depth, rising P99\n# .NET: avoid Task.Result / .Wait() in ASP.NET\n# Java: move slow downstream calls off request threads\n# Add a dedicated bounded pool for blocking I/O\n# Increase pool size only after removing blocking hotspots",
    "sources": [
      "https://learn.microsoft.com/en-us/aspnet/core/performance/performance-best-practices"
    ]
  },
  {
    "id": "perf-event-loop-lag",
    "title": "Node.js: event loop lag / blocked synchronously",
    "category": "Performance",
    "explanation": "CPU-bound work or sync I/O blocked Node's single event loop thread, delaying unrelated requests and timers.",
    "fix_snippet": "import { monitorEventLoopDelay } from 'perf_hooks';\nconst h = monitorEventLoopDelay({ resolution: 10 });\nh.enable();\nsetInterval(() => console.log(h.percentile(99) / 1e6), 5000);\n# Move CPU-heavy work to worker_threads\n# Avoid sync crypto/fs and huge JSON.parse on hot paths",
    "sources": [
      "https://nodejs.org/api/perf_hooks.html#perf_hooksmonitoreventloopdelayoptions"
    ]
  },
  {
    "id": "gpg-bad-signature",
    "title": "GPG: BAD signature / cannot verify signature",
    "category": "System",
    "explanation": "The signature does not validate with the public key you have. The file may be modified, truncated, signed with another key, or the signing key may not be trusted.",
    "fix_snippet": "gpg --keyserver hkps://keys.openpgp.org --recv-keys 0xABCDEF1234567890\ngpg --verify release.tar.gz.sig release.tar.gz\ngpg --list-sigs 0xABCDEF1234567890\n# Verify the fingerprint out-of-band before trusting the key",
    "sources": [
      "https://www.gnupg.org/documentation/manuals/gnupg/Verifying-signatures.html"
    ]
  },
  {
    "id": "ssh-agent-not-running",
    "title": "ssh: Could not open a connection to your authentication agent",
    "category": "System",
    "explanation": "ssh-add cannot find a running ssh-agent because SSH_AUTH_SOCK is unset or points to a stale socket.",
    "fix_snippet": "eval \"$(ssh-agent -s)\"\nssh-add ~/.ssh/id_ed25519\n# macOS Keychain\nssh-add --apple-use-keychain ~/.ssh/id_ed25519\n# In tmux/CI, ensure SSH_AUTH_SOCK is exported into the session",
    "sources": [
      "https://man.openbsd.org/ssh-agent"
    ]
  },
  {
    "id": "pem-file-corrupted",
    "title": "PEM error: no start line / unable to load private key",
    "category": "TLS",
    "explanation": "The PEM file is malformed, missing its BEGIN header, contains CRLF/extra whitespace, or was base64-decoded/encoded incorrectly.",
    "fix_snippet": "head -1 key.pem\nsed -i 's/\\r//g' key.pem\nopenssl pkey -in key.pem -check -noout\nopenssl x509 -in cert.pem -noout -subject -issuer -dates\n# Re-emit clean PEM\nopenssl rsa -in key.pem -out key-clean.pem",
    "sources": [
      "https://www.openssl.org/docs/man1.1.1/man1/pkey.html"
    ]
  },
  {
    "id": "auth0-callback-url-mismatch",
    "title": "Auth0: Callback URL mismatch",
    "category": "Auth",
    "explanation": "Auth0 rejected the login because the redirect URL in the request is not in the application's Allowed Callback URLs. The match must be exact (scheme, host, port, path).",
    "fix_snippet": "# Auth0 Dashboard -> Applications -> Your App -> Settings\n# Allowed Callback URLs (exact, comma-separated):\nhttps://app.example.com/callback, http://localhost:3000/callback\n# Ensure the SDK uses the same redirect_uri\nconst auth0 = new Auth0Client({ authorizationParams: { redirect_uri: window.location.origin + '/callback' } });",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://auth0.com/docs/get-started/applications/application-settings"
    ]
  },
  {
    "id": "okta-invalid-client",
    "title": "Okta: invalid_client",
    "category": "Auth",
    "explanation": "The Okta token endpoint returned invalid_client. The client_id/secret is wrong, the token endpoint auth method does not match, or the secret was rotated.",
    "fix_snippet": "# Confirm the token endpoint auth method matches the request\n# client_secret_basic -> send credentials in the Authorization header\ncurl -X POST https://<org>.okta.com/oauth2/default/v1/token \\\n  -u \"$CLIENT_ID:$CLIENT_SECRET\" \\\n  -d 'grant_type=client_credentials&scope=api'\n# Rotate and update the secret if it was regenerated",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.okta.com/docs/reference/api/oidc/"
    ]
  },
  {
    "id": "oidc-nonce-mismatch",
    "title": "OIDC: nonce mismatch",
    "category": "Auth",
    "explanation": "The nonce in the returned ID token does not match the nonce sent in the auth request, indicating a replay or a session lost between request and callback.",
    "fix_snippet": "// Persist the nonce across the redirect, then validate on callback\nconst nonce = crypto.randomUUID();\nsession.nonce = nonce;\n// authorize: ...&nonce=${nonce}\n// callback: assert(idToken.nonce === session.nonce)\n// Session cookie must survive the round trip (SameSite=Lax/None)",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes"
    ]
  },
  {
    "id": "webauthn-registration-failed",
    "title": "WebAuthn/Passkey: registration failed (NotAllowedError)",
    "category": "Auth",
    "explanation": "navigator.credentials.create() rejected with NotAllowedError. Common causes: not a secure context, rpId not matching the origin, user cancelled, or timeout.",
    "fix_snippet": "// Must run on https:// (localhost is allowed)\n// rp.id must be a registrable suffix of the origin host\nawait navigator.credentials.create({ publicKey: {\n  rp: { id: 'example.com', name: 'Example' },\n  user: { id: userIdBytes, name: 'alice', displayName: 'Alice' },\n  challenge: challengeBytes,\n  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],\n  timeout: 60000\n}});",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API"
    ]
  },
  {
    "id": "mfa-challenge-timeout",
    "title": "MFA: challenge timeout / code expired",
    "category": "Auth",
    "explanation": "A TOTP or push challenge was rejected because it expired or the device clock drifted outside the verification window.",
    "fix_snippet": "# TOTP codes are time-based: sync the device clock\n# Server: allow +/- 1 step (30s) of skew instead of widening windows\ndate -u            # verify server time\n# Re-enroll the authenticator if drift persists",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://datatracker.ietf.org/doc/html/rfc6238"
    ]
  },
  {
    "id": "keycloak-invalid-redirect-uri",
    "title": "Keycloak: Invalid parameter: redirect_uri",
    "category": "Auth",
    "explanation": "Keycloak rejected the redirect URI because it is not listed in the client's Valid Redirect URIs, or a wildcard pattern does not cover it.",
    "fix_snippet": "# Keycloak Admin -> Clients -> your-client -> Settings\n# Valid Redirect URIs (supports a trailing * wildcard):\nhttps://app.example.com/*\nhttp://localhost:3000/*\n# Web origins (CORS): + (to allow all valid redirect origins)",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://www.keycloak.org/docs/latest/server_admin/"
    ]
  },
  {
    "id": "windows-0xc000007b",
    "title": "Windows: 0xc000007b application unable to start correctly",
    "category": "Windows",
    "explanation": "A 32/64-bit mismatch or corrupt/missing runtime DLLs prevented the application from starting, often a wrong-bitness DLL on the PATH.",
    "fix_snippet": "# Reinstall the matching Visual C++ Redistributables (BOTH x86 and x64)\nwinget install Microsoft.VCRedist.2015+.x64\nwinget install Microsoft.VCRedist.2015+.x86\n# Repair system files (Run as Administrator)\nsfc /scannow\nDISM /Online /Cleanup-Image /RestoreHealth",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist"
    ]
  },
  {
    "id": "windows-vcruntime140-missing",
    "title": "Windows: VCRUNTIME140.dll was not found",
    "category": "Windows",
    "explanation": "The Microsoft Visual C++ 2015-2022 runtime is missing. Apps compiled with MSVC need the matching redistributable installed.",
    "fix_snippet": "# Install the Visual C++ 2015-2022 Redistributable (x64)\nwinget install Microsoft.VCRedist.2015+.x64\n# Install the x86 build too if the app is 32-bit\nwinget install Microsoft.VCRedist.2015+.x86\n# Or download vc_redist.x64.exe from Microsoft and run it",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist"
    ]
  },
  {
    "id": "windows-update-0x80070643",
    "title": "Windows Update: error 0x80070643",
    "category": "Windows",
    "explanation": "A Windows Update (commonly a .NET or security update) failed to install, often due to a corrupted update cache or a pending reboot.",
    "fix_snippet": "# Run as Administrator\nnet stop wuauserv\nnet stop bits\nRemove-Item C:\\Windows\\SoftwareDistribution\\Download\\* -Recurse -Force\nnet start wuauserv\nnet start bits\n# Reboot, then re-run Windows Update",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://support.microsoft.com/en-us/windows/windows-update-troubleshooter-19bc41ca-ad72-ae67-af3c-89ce169755dd"
    ]
  },
  {
    "id": "windows-access-denied-5",
    "title": "Windows: Access is denied (error 5)",
    "category": "Windows",
    "explanation": "A process attempted an operation without sufficient privileges, or a file/service is locked or restricted by its ACL.",
    "fix_snippet": "# Run the shell as Administrator\nStart-Process powershell -Verb RunAs\n# Take ownership and grant rights on a path\ntakeown /f \"C:\\path\\to\\dir\" /r /d y\nicacls \"C:\\path\\to\\dir\" /grant \"$env:USERNAME:(OI)(CI)F\" /T",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls"
    ]
  },
  {
    "id": "windows-rdp-credssp",
    "title": "Windows: RDP can't connect (CredSSP encryption oracle remediation)",
    "category": "Windows",
    "explanation": "Remote Desktop fails after a CredSSP update mismatch: one side is patched and enforcing while the other is not.",
    "fix_snippet": "# Preferred: install the latest Windows updates on BOTH machines\n# Temporary client workaround (Run as Admin); revert after patching:\nreg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters\" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/credssp-encryption-oracle-remediation"
    ]
  },
  {
    "id": "windows-system-file-corruption",
    "title": "Windows: corrupted system files / component store",
    "category": "Windows",
    "explanation": "System instability or update failures caused by corruption in protected system files or the component store (WinSxS).",
    "fix_snippet": "# Run as Administrator, in order\nDISM /Online /Cleanup-Image /CheckHealth\nDISM /Online /Cleanup-Image /ScanHealth\nDISM /Online /Cleanup-Image /RestoreHealth\nsfc /scannow\n# Reboot when complete",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/fix-windows-update-errors"
    ]
  },
  {
    "id": "macos-xcrun-invalid-developer-path",
    "title": "macOS: xcrun: error: invalid active developer path",
    "category": "Apple",
    "explanation": "The Command Line Tools path is missing or points to a removed Xcode, commonly after a macOS upgrade.",
    "fix_snippet": "xcode-select --install\n# If Xcode moved/was removed, reset the active path\nsudo xcode-select --reset\n# Or point at a specific toolchain\nsudo xcode-select -s /Library/Developer/CommandLineTools\nxcrun --version",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.apple.com/library/archive/technotes/tn2339/_index.html"
    ]
  },
  {
    "id": "macos-dyld-library-not-loaded",
    "title": "macOS: dyld: Library not loaded",
    "category": "Apple",
    "explanation": "The dynamic linker could not find a shared library at the path baked into the binary, often after a Homebrew upgrade changed library versions.",
    "fix_snippet": "# See what the binary expects\notool -L /path/to/binary\n# Reinstall/relink the dependency (Homebrew)\nbrew reinstall <formula>\nbrew link --overwrite <formula>\n# Last resort for your own builds:\nexport DYLD_LIBRARY_PATH=/opt/homebrew/lib:$DYLD_LIBRARY_PATH",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/RunpathDependentLibraries.html"
    ]
  },
  {
    "id": "homebrew-permission-denied-usr-local",
    "title": "Homebrew: Permission denied @ /usr/local",
    "category": "Apple",
    "explanation": "Homebrew cannot write to its prefix because directory ownership is wrong, common on Intel Macs that use /usr/local.",
    "fix_snippet": "# Intel Macs (/usr/local)\nsudo chown -R $(whoami) /usr/local/Cellar /usr/local/Homebrew\n# Apple Silicon uses /opt/homebrew (preferred)\nsudo chown -R $(whoami) /opt/homebrew\nbrew doctor",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.brew.sh/Common-Issues"
    ]
  },
  {
    "id": "macos-notarization-failed",
    "title": "macOS: notarization failed (notarytool)",
    "category": "Apple",
    "explanation": "Apple's notary service rejected the app, usually for unsigned/un-hardened binaries, a missing secure timestamp, or disallowed entitlements.",
    "fix_snippet": "# Submit and read the detailed log\nxcrun notarytool submit App.zip --apple-id \"$APPLE_ID\" --team-id \"$TEAM_ID\" --password \"$APP_PWD\" --wait\nxcrun notarytool log <submission-id> --apple-id \"$APPLE_ID\" --team-id \"$TEAM_ID\" --password \"$APP_PWD\"\n# Sign with hardened runtime + secure timestamp\ncodesign --force --options runtime --timestamp --sign \"Developer ID Application: ...\" App.app",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution"
    ]
  },
  {
    "id": "macos-keychain-access-denied",
    "title": "macOS: errSecAuthFailed / Keychain access denied",
    "category": "Apple",
    "explanation": "A code-signing or credential operation could not read the Keychain, common in CI when the keychain is locked or not in the search list.",
    "fix_snippet": "# Unlock and prioritize a dedicated CI keychain\nsecurity unlock-keychain -p \"$KC_PWD\" build.keychain\nsecurity list-keychains -d user -s build.keychain login.keychain\n# Let codesign use the key without prompting\nsecurity set-key-partition-list -S apple-tool:,apple: -s -k \"$KC_PWD\" build.keychain",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.apple.com/forums/thread/712005"
    ]
  },
  {
    "id": "macos-command-not-found-path",
    "title": "macOS: zsh: command not found after Homebrew install (PATH)",
    "category": "Apple",
    "explanation": "A freshly installed CLI is not on PATH because the Homebrew shellenv was not added to the shell profile, common on Apple Silicon (/opt/homebrew).",
    "fix_snippet": "# Apple Silicon\necho 'eval \"$(/opt/homebrew/bin/brew shellenv)\"' >> ~/.zprofile\neval \"$(/opt/homebrew/bin/brew shellenv)\"\n# Intel\necho 'eval \"$(/usr/local/bin/brew shellenv)\"' >> ~/.zprofile\nsource ~/.zprofile && which <command>",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.brew.sh/Installation"
    ]
  },
  {
    "id": "frontend-fouc",
    "title": "FOUC: flash of unstyled content",
    "category": "Frontend",
    "explanation": "The browser renders HTML before CSS or a web font is applied, producing a brief flash of unstyled or differently-styled content.",
    "fix_snippet": "<!-- Load critical CSS in <head>, not at the end of <body> -->\n<link rel=\"stylesheet\" href=\"/critical.css\">\n<!-- Preload fonts and control swap behavior -->\n<link rel=\"preload\" href=\"/font.woff2\" as=\"font\" type=\"font/woff2\" crossorigin>\n@font-face { font-family: 'Inter'; font-display: optional; src: url('/font.woff2'); }",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/CSS/@font-face/font-display"
    ]
  },
  {
    "id": "frontend-cors-font-blocked",
    "title": "CORS: web font blocked by Access-Control-Allow-Origin",
    "category": "Frontend",
    "explanation": "Fonts are fetched with CORS. A cross-origin font without the right ACAO header is blocked, leaving text in a fallback font.",
    "fix_snippet": "# Serve the font with CORS headers (Nginx)\nlocation ~* \\.(woff2?|ttf|otf)$ {\n  add_header Access-Control-Allow-Origin \"https://app.example.com\";\n}\n<!-- And request it with crossorigin -->\n<link rel=\"preload\" as=\"font\" href=\"https://cdn.example.com/f.woff2\" crossorigin>",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
    ]
  },
  {
    "id": "frontend-cls-too-high",
    "title": "Cumulative Layout Shift (CLS) too high",
    "category": "Frontend",
    "explanation": "Visible elements move during load because images/ads/embeds have no reserved space, or fonts swap, hurting Core Web Vitals.",
    "fix_snippet": "<!-- Always set width/height (or aspect-ratio) on media -->\n<img src=\"hero.jpg\" width=\"1200\" height=\"630\" alt=\"\">\n/* Reserve space for dynamic embeds */\n.ad-slot { min-height: 250px; }\n/* Avoid inserting content above existing content after load */",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://web.dev/articles/cls"
    ]
  },
  {
    "id": "astro-hydration-mismatch",
    "title": "Astro: client hydration mismatch",
    "category": "Frontend",
    "explanation": "An interactive island rendered different markup on the client than the server, or a client directive was missing, so hydration failed.",
    "fix_snippet": "<!-- Add a client directive so the island hydrates -->\n<Counter client:load />\n<!-- Avoid non-deterministic output (Date.now, Math.random) during render -->\n<!-- Gate browser-only code -->\n{ typeof window !== 'undefined' && <BrowserOnly /> }",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.astro.build/en/concepts/islands/"
    ]
  },
  {
    "id": "remix-loader-thrown-response",
    "title": "Remix/React Router: loader threw an unexpected Response",
    "category": "Frontend",
    "explanation": "A loader or action threw a Response (e.g., redirect or 404) that was not handled, or returned a non-serialisable value.",
    "fix_snippet": "export async function loader({ params }) {\n  const item = await db.get(params.id);\n  if (!item) throw new Response('Not Found', { status: 404 });\n  return json(item); // must be serializable\n}\n// Handle thrown responses\nexport function ErrorBoundary() { const e = useRouteError(); /* ... */ }",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://remix.run/docs/en/main/route/loader"
    ]
  },
  {
    "id": "nuxt-hydration-node-mismatch",
    "title": "Nuxt: Hydration node mismatch",
    "category": "Frontend",
    "explanation": "Vue's server-rendered DOM did not match the client render, often from browser-only APIs during setup or invalid HTML nesting.",
    "fix_snippet": "<!-- Run browser-only code after mount or wrap in <ClientOnly> -->\n<ClientOnly><Chart /></ClientOnly>\n<script setup>\nonMounted(() => { /* window/localStorage here */ });\n</script>\n<!-- Avoid invalid nesting like <div> inside <p> -->",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://nuxt.com/docs/getting-started/data-fetching"
    ]
  },
  {
    "id": "esbuild-could-not-resolve",
    "title": "esbuild: Could not resolve \"X\"",
    "category": "Frontend",
    "explanation": "esbuild could not find a module: it is not installed, the path/extension is wrong, or it is a Node built-in being bundled for the browser.",
    "fix_snippet": "npm install <missing-pkg>\n# Mark Node built-ins/externals so they are not bundled\nesbuild app.js --bundle --platform=browser --external:fs --external:path\n# Add explicit extensions if resolution fails\nesbuild app.ts --bundle --resolve-extensions=.ts,.js,.json",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://esbuild.github.io/api/#resolve-extensions"
    ]
  },
  {
    "id": "webpack5-node-polyfill-missing",
    "title": "webpack 5: BREAKING CHANGE - polyfill for Node core module removed",
    "category": "Frontend",
    "explanation": "webpack 5 no longer auto-polyfills Node core modules (crypto, stream, buffer). Browser builds importing them now fail to resolve.",
    "fix_snippet": "// webpack.config.js\nmodule.exports = { resolve: { fallback: {\n  crypto: require.resolve('crypto-browserify'),\n  stream: require.resolve('stream-browserify'),\n  buffer: require.resolve('buffer/')\n}}};\n// Better: avoid Node-only deps in browser code, or set fallback: false",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://webpack.js.org/migrate/5/"
    ]
  },
  {
    "id": "http-400-bad-request",
    "title": "400 Bad Request",
    "category": "HTTP",
    "explanation": "The server could not parse the request due to malformed syntax: bad JSON body, illegal headers/characters, oversized cookies, or invalid query encoding.",
    "fix_snippet": "# Validate the JSON you are sending\ncurl -X POST https://api.example.com/v1/items \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"name\":\"widget\"}'\necho '{\"name\":\"widget\"}' | jq .   # must parse\n# Clear oversized cookies; URL-encode query parameters",
    "fix_snippet_windows": "# PowerShell: validate then send JSON\n$body = '{\"name\":\"widget\"}'\n$body | ConvertFrom-Json   # must parse\nInvoke-RestMethod -Method Post -Uri 'https://api.example.com/v1/items' -ContentType 'application/json' -Body $body",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400"
    ]
  },
  {
    "id": "http-429-too-many-requests",
    "title": "429 Too Many Requests",
    "category": "HTTP",
    "explanation": "The client sent too many requests in a given window and was rate limited. The Retry-After header, if present, says how long to wait.",
    "fix_snippet": "# Respect Retry-After and back off exponentially\ncurl -i https://api.example.com/v1/things | grep -i retry-after\n# Pseudocode\n# delay = min(cap, base * 2**attempt) + random_jitter\n# sleep(delay); retry()\n# Cache responses and batch requests to cut volume",
    "fix_snippet_windows": "# PowerShell: read Retry-After then back off\n$r = Invoke-WebRequest 'https://api.example.com/v1/things'\n$r.Headers['Retry-After']\nStart-Sleep -Seconds 5   # honor Retry-After, add jitter",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429"
    ]
  },
  {
    "id": "http-426-upgrade-required",
    "title": "426 Upgrade Required",
    "category": "HTTP",
    "explanation": "The server refuses to process the request using the current protocol and requires the client to switch (e.g., to TLS or to WebSocket).",
    "fix_snippet": "# The server signals the required protocol via the Upgrade header\n# HTTP/1.1 426 Upgrade Required\n# Upgrade: TLS/1.2, HTTP/1.1\n# Connection: Upgrade\n# Client: retry over the required protocol (https:// or wss://)",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/426"
    ]
  },
  {
    "id": "http-451-legal-reasons",
    "title": "451 Unavailable For Legal Reasons",
    "category": "HTTP",
    "explanation": "The resource is blocked for legal reasons such as censorship or a takedown. The response should reference the blocking authority.",
    "fix_snippet": "# Server example (Nginx) for a legally blocked path\nlocation /blocked-resource {\n  add_header Link '<https://spqr.example.org/legal>; rel=\"blocked-by\"';\n  return 451;\n}\n# Clients: the block is intentional; verify jurisdiction/authority",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/451"
    ]
  },
  {
    "id": "oracle-ora-12541-tns-no-listener",
    "title": "Oracle: ORA-12541: TNS:no listener",
    "category": "Database",
    "explanation": "The client reached the host but no listener is accepting on that port/service. The listener is down or the host/port/service name is wrong.",
    "fix_snippet": "# On the DB server: is the listener up?\nlsnrctl status\nlsnrctl start\n# From the client: test the descriptor\ntnsping ORCL\n# Verify host, port (default 1521), and SERVICE_NAME in tnsnames.ora",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.oracle.com/en/database/oracle/oracle-database/19/netrf/"
    ]
  },
  {
    "id": "cassandra-no-host-available",
    "title": "Cassandra: NoHostAvailable",
    "category": "Database",
    "explanation": "The driver could not reach any node: wrong contact points, the node is down, a datacenter/consistency mismatch, or auth failure.",
    "fix_snippet": "nodetool status   # UN = Up/Normal\n# Check contact points and the local datacenter in the driver config\n# (DataStax drivers require a local DC for the load-balancing policy)\ncqlsh <node-ip> 9042 -u cassandra -p cassandra\n# Ensure the requested consistency level has enough live replicas",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.datastax.com/en/developer/"
    ]
  },
  {
    "id": "cockroachdb-retry-40001",
    "title": "CockroachDB: restart transaction (SQLSTATE 40001)",
    "category": "Database",
    "explanation": "A SerialisABLE transaction conflicted and must be retried. Contended transactions can be aborted with a retry error.",
    "fix_snippet": "-- Wrap transactions in client-side retry logic\n-- Detect SQLSTATE 40001 (retry_serializable) and re-run the txn\n-- Use SAVEPOINT cockroach_restart or the driver's retry helper\n-- Reduce contention: smaller txns, ordered key access, good indexes",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://www.cockroachlabs.com/docs/stable/transaction-retry-error-reference"
    ]
  },
  {
    "id": "clickhouse-memory-limit-exceeded",
    "title": "ClickHouse: Memory limit (total) exceeded",
    "category": "Database",
    "explanation": "A query tried to use more memory than max_memory_usage (or the server total) allows, common with large GROUP BY/JOIN/ORDER BY.",
    "fix_snippet": "-- Allow spilling to disk for heavy aggregations/sorts\nSET max_bytes_before_external_group_by = 2000000000;\nSET max_bytes_before_external_sort = 2000000000;\n-- Or raise the per-query cap (carefully)\nSET max_memory_usage = 8000000000;\n-- Better: filter earlier, select fewer columns, pre-aggregate",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://clickhouse.com/docs/en/operations/settings/settings"
    ]
  },
  {
    "id": "pgbouncer-no-more-connections",
    "title": "PgBouncer: no more connections allowed (max_client_conn)",
    "category": "Database",
    "explanation": "PgBouncer rejected a client because max_client_conn was reached, or the server pool (default_pool_size) is exhausted by long transactions.",
    "fix_snippet": "; pgbouncer.ini\nmax_client_conn = 1000\ndefault_pool_size = 20\npool_mode = transaction\n# Inspect live pools\npsql -p 6432 pgbouncer -c 'SHOW POOLS;'\n# Fix leaked / idle-in-transaction sessions in the app",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://www.pgbouncer.org/config.html"
    ]
  },
  {
    "id": "supabase-rls-violation",
    "title": "Supabase/Postgres: new row violates row-level security policy",
    "category": "Database",
    "explanation": "An insert/update was blocked because no RLS policy permits it for the current role, or the JWT lacks the expected claims (auth.uid()).",
    "fix_snippet": "-- Allow the authenticated user to insert their own rows\ncreate policy \"users insert own\" on public.todos\n  for insert to authenticated\n  with check (auth.uid() = user_id);\n-- Add a policy for EACH action (select/insert/update/delete)",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://supabase.com/docs/guides/database/postgres/row-level-security"
    ]
  },
  {
    "id": "argocd-out-of-sync",
    "title": "Argo CD: Application OutOfSync / Degraded",
    "category": "Kubernetes",
    "explanation": "The live cluster state differs from Git (OutOfSync) or resources are unhealthy (Degraded), from drift, a failed sync, or invalid manifests.",
    "fix_snippet": "argocd app diff my-app\nargocd app sync my-app --prune\n# Inspect why a resource is Degraded\nargocd app get my-app\nkubectl describe <kind>/<name> -n <ns>\n# Enable auto-sync + self-heal to prevent drift",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://argo-cd.readthedocs.io/en/stable/user-guide/sync/"
    ]
  },
  {
    "id": "istio-503-uh-uf",
    "title": "Istio: 503 upstream connect error (UH/UF/NR)",
    "category": "Kubernetes",
    "explanation": "Envoy returned 503 with flags like UH (no healthy upstream), UF (upstream connection failure), or NR (no route), usually mTLS, port-name, or selector issues.",
    "fix_snippet": "# Service port name must start with the protocol: http, grpc, tcp...\nistioctl analyze -n <ns>\n# Check proxy clusters\nistioctl proxy-config clusters <pod> -n <ns>\n# mTLS mismatch: align PeerAuthentication / DestinationRule\nkubectl get peerauthentication,destinationrule -A",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://istio.io/latest/docs/ops/diagnostic-tools/"
    ]
  },
  {
    "id": "helm-operation-in-progress",
    "title": "Helm: another operation (install/upgrade) is in progress",
    "category": "Kubernetes",
    "explanation": "A previous Helm operation crashed and left the release stuck in pending-install/pending-upgrade, blocking new operations.",
    "fix_snippet": "helm history <release> -n <ns>\n# Roll back to the last good revision\nhelm rollback <release> <good-revision> -n <ns>\n# If no good revision exists and it is stuck pending:\nhelm uninstall <release> -n <ns>   # then reinstall\n# (Helm 3 stores state in Secrets in the release namespace)",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://helm.sh/docs/helm/helm_rollback/"
    ]
  },
  {
    "id": "vault-server-sealed",
    "title": "Vault: server is sealed",
    "category": "Cloud",
    "explanation": "HashiCorp Vault is sealed and cannot serve secrets. It seals on restart and must be unsealed with a quorum of unseal keys unless auto-unseal is configured.",
    "fix_snippet": "vault status   # Sealed: true\n# Provide the threshold number of unseal key shares\nvault operator unseal <key-share-1>\nvault operator unseal <key-share-2>\nvault operator unseal <key-share-3>\n# Production: configure auto-unseal (KMS/HSM)",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.hashicorp.com/vault/docs/concepts/seal"
    ]
  },
  {
    "id": "vault-permission-denied",
    "title": "Vault: permission denied (403)",
    "category": "Cloud",
    "explanation": "The token's policies do not grant the requested path/capability, or the token expired. Vault denies by default.",
    "fix_snippet": "vault token lookup            # check ttl + policies\n# Inspect what a policy allows\nvault policy read my-policy\n# Grant read on a path (my-policy.hcl):\n# path \"secret/data/app/*\" { capabilities = [\"read\"] }\nvault policy write my-policy my-policy.hcl",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://developer.hashicorp.com/vault/docs/concepts/policies"
    ]
  },
  {
    "id": "pulumi-pending-operations",
    "title": "Pulumi: the stack has pending operations",
    "category": "Cloud",
    "explanation": "A previous update was interrupted, leaving operations indeterminate. Pulumi blocks further updates until state is reconciled.",
    "fix_snippet": "pulumi stack export > stack.json   # back up first\n# Reconcile real cloud state with the state file\npulumi refresh\n# If a resource is truly gone/created, clear the lock\npulumi cancel\n# Last resort: remove pending_operations from the exported state and import",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://www.pulumi.com/docs/cli/commands/pulumi_refresh/"
    ]
  },
  {
    "id": "gemini-safety-block",
    "title": "Gemini API: response blocked (finishReason: SAFETY)",
    "category": "AI",
    "explanation": "Gemini stopped generation because the prompt or candidate tripped a safety category threshold, leaving no usable text.",
    "fix_snippet": "# Inspect promptFeedback.blockReason and safetyRatings in the response\n# Adjust thresholds (use responsibly)\nsafetySettings: [{ category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_ONLY_HIGH' }]\n# Rephrase the prompt; handle the blocked case gracefully in code",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://ai.google.dev/gemini-api/docs/safety-settings"
    ]
  },
  {
    "id": "rag-embedding-dimension-mismatch",
    "title": "RAG: embedding dimension mismatch",
    "category": "AI",
    "explanation": "Vectors written with one embedding model do not match the index/column dimension, so inserts or similarity queries fail. Mixing models is the usual cause.",
    "fix_snippet": "# Pin ONE embedding model + dimension end to end\n# e.g., text-embedding-3-small -> 1536 dims\n# Recreate the index/collection with the correct size, then re-embed ALL docs\n# Never mix vectors from different models in one index",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://platform.openai.com/docs/guides/embeddings"
    ]
  },
  {
    "id": "pgvector-dimension-mismatch",
    "title": "pgvector: expected N dimensions, not M",
    "category": "AI",
    "explanation": "A vector being inserted or queried does not match the fixed dimension declared on the vector column.",
    "fix_snippet": "-- The column declares the dimension\nCREATE TABLE items (id bigserial, embedding vector(1536));\n-- Inserts must be exactly 1536 floats\n-- To change models/dims, alter the column and re-embed\nALTER TABLE items ALTER COLUMN embedding TYPE vector(3072);\n-- Rebuild the ANN index afterwards",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://github.com/pgvector/pgvector"
    ]
  },
  {
    "id": "github-copilot-auth-failed",
    "title": "GitHub Copilot: authentication failed / no subscription",
    "category": "AI",
    "explanation": "The Copilot extension cannot authenticate: the GitHub session expired, there is no active Copilot seat, or a proxy is blocking GitHub endpoints.",
    "fix_snippet": "# VS Code: Command Palette -> 'GitHub Copilot: Sign Out' then Sign In\n# Verify access\ngh auth status\n# Check seat assignment (org admin): https://github.com/settings/copilot\n# Behind a proxy: allow api.github.com and *.githubcopilot.com",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.github.com/en/copilot/troubleshooting-github-copilot"
    ]
  },
  {
    "id": "mistral-422-unprocessable",
    "title": "Mistral API: 422 Unprocessable Entity",
    "category": "AI",
    "explanation": "The request body failed validation: unknown model name, malformed messages array, or an unsupported parameter value.",
    "fix_snippet": "curl https://api.mistral.ai/v1/chat/completions \\\n  -H \"Authorization: Bearer $MISTRAL_API_KEY\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"model\":\"mistral-large-latest\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}'\n# Read the JSON error body: it names the invalid field",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.mistral.ai/api/"
    ]
  },
  {
    "id": "elixir-genserver-call-timeout",
    "title": "Elixir: GenServer call timeout (exited in :gen_server.call)",
    "category": "Elixir",
    "explanation": "A GenServer.call did not get a reply within 5000ms (default) because the server is overloaded, doing slow work in handle_call, or deadlocked.",
    "fix_snippet": "# Move slow work off the call (reply fast, work async)\n# Or raise the timeout for genuinely slow ops\nGenServer.call(pid, :work, 30_000)\n# Avoid calling back into the same GenServer from handle_call (deadlock)\n# Use handle_cast or Task for fire-and-forget",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://hexdocs.pm/elixir/GenServer.html"
    ]
  },
  {
    "id": "elixir-mix-deps-compile-failed",
    "title": "Elixir: Mix could not compile dependency",
    "category": "Elixir",
    "explanation": "A dependency failed to compile due to missing native build tools, a version conflict, or stale build artifacts.",
    "fix_snippet": "mix deps.clean <dep> --build\nmix deps.get\nmix deps.compile\n# Native deps need a C toolchain (make, build-essential, erlang-dev)\n# Resolve conflicts shown by:\nmix deps.tree",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://hexdocs.pm/mix/Mix.Tasks.Deps.html"
    ]
  },
  {
    "id": "scala-sbt-unresolved-dependency",
    "title": "Scala: sbt unresolved dependency",
    "category": "Scala",
    "explanation": "sbt could not download a library: wrong coordinates, a missing resolver, a Scala-version suffix mismatch, or no credentials for a private repo.",
    "fix_snippet": "// %% appends the Scala binary version automatically\nlibraryDependencies += \"org.typelevel\" %% \"cats-core\" % \"2.10.0\"\n// Add a resolver for non-Central artifacts\nresolvers += \"Sonatype\" at \"https://oss.sonatype.org/content/repositories/releases\"\n// Then: sbt update",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://www.scala-sbt.org/1.x/docs/Library-Dependencies.html"
    ]
  },
  {
    "id": "scala-value-not-a-member",
    "title": "Scala: value X is not a member of Y",
    "category": "Scala",
    "explanation": "You called a method that does not exist on the type, often a missing import for an extension method/implicit, or a more general type than expected.",
    "fix_snippet": "// Bring extension methods / implicits into scope\nimport scala.concurrent.duration._    // enables 5.seconds\nimport cats.syntax.all._              // enables |+|, etc.\n// Annotate to see the inferred type\nval x: Int = ???\n// Ensure the method matches the actual (not assumed) type",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.scala-lang.org/"
    ]
  },
  {
    "id": "dart-null-check-on-null",
    "title": "Dart: Null check operator used on a null value",
    "category": "Dart",
    "explanation": "The ! null-assertion was applied to an expression that was null at runtime, throwing in null-safe Dart/Flutter code.",
    "fix_snippet": "// Avoid ! unless non-null is guaranteed\nfinal user = maybeUser;\nif (user != null) { print(user.name); }\n// Provide a default\nfinal name = maybeName ?? 'Guest';\n// Use late only when you set it before first use\nlate final Foo foo;",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://dart.dev/null-safety/understanding-null-safety"
    ]
  },
  {
    "id": "flutter-pub-get-version-solving-failed",
    "title": "Flutter/Dart: pub get failed (version solving failed)",
    "category": "Dart",
    "explanation": "pub could not find a set of package versions satisfying all constraints, usually conflicting SDK or transitive dependency bounds.",
    "fix_snippet": "flutter pub get\n# See why a package is constrained\ndart pub deps\nflutter pub upgrade --major-versions\n# Loosen/align constraints in pubspec.yaml, then\nflutter clean && flutter pub get",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://dart.dev/tools/pub/cmd/pub-get"
    ]
  },
  {
    "id": "svelte-store-auto-subscription",
    "title": "Svelte: '$' prefix can only be used with stores",
    "category": "Svelte",
    "explanation": "The $ auto-subscription was used on a value that is not a store (no subscribe method), or a store was referenced without importing it.",
    "fix_snippet": "<script>\n  import { writable } from 'svelte/store';\n  const count = writable(0);   // a real store\n</script>\n<!-- $ auto-subscribes and must target a store -->\n<button on:click={() => $count++}>{$count}</button>",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://svelte.dev/docs/svelte-store"
    ]
  },
  {
    "id": "sveltekit-500-load",
    "title": "SvelteKit: 500 error in load function",
    "category": "Svelte",
    "explanation": "A load function threw, returned a non-serialisable value, or accessed browser-only APIs during SSR, producing a 500.",
    "fix_snippet": "import { error } from '@sveltejs/kit';\nexport async function load({ params, fetch }) {\n  const res = await fetch(`/api/items/${params.id}`);\n  if (!res.ok) throw error(res.status, 'Item not found');\n  return await res.json();   // must be serializable\n}\n// Put window/document access in onMount, not in load",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://kit.svelte.dev/docs/load"
    ]
  },
  {
    "id": "make-missing-separator",
    "title": "Make: *** missing separator. Stop.",
    "category": "Shell",
    "explanation": "A recipe line is indented with spaces instead of a TAB, or a stray character precedes a rule. Make requires recipe lines to begin with a real TAB.",
    "fix_snippet": "# Recipe lines MUST start with a TAB, not spaces\n# Find offending lines (shows ^I for tabs, leading spaces are visible)\ncat -A Makefile | grep -n '^ '\n# Convert 4 leading spaces to a tab (GNU sed)\nsed -i 's/^    /\\t/' Makefile\n# In editors: disable soft-tabs for Makefiles",
    "fix_snippet_windows": "# Windows: GNU make still requires TAB-indented recipes\n# Reveal leading whitespace\n(Get-Content Makefile) | ForEach-Object { $_ -replace ' ', '.' }\n# Configure your editor to insert a real TAB in Makefiles",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://www.gnu.org/software/make/manual/make.html#Recipe-Syntax"
    ]
  },
  {
    "id": "bazel-no-such-target",
    "title": "Bazel: no such target / no such package",
    "category": "CI/CD",
    "explanation": "A label does not resolve: the package has no BUILD file, the target name is wrong, or it is not visible to the caller.",
    "fix_snippet": "# List the real targets in a package\nbazel query //path/to/pkg:all\n# Ensure path/to/pkg/BUILD(.bazel) exists and defines the target\n# Make it visible to consumers:\n# visibility = [\"//some/other:__subpackages__\"]\nbazel build //path/to/pkg:target",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://bazel.build/concepts/labels"
    ]
  },
  {
    "id": "deno-permission-denied",
    "title": "Deno: PermissionDenied: Requires net/read access",
    "category": "JavaScript",
    "explanation": "Deno is secure by default and blocks file, network, and env access unless explicitly granted with --allow flags.",
    "fix_snippet": "# Grant only what you need (preferred)\ndeno run --allow-net=api.example.com --allow-read=./data main.ts\n# Env access\ndeno run --allow-env main.ts\n# Broad (avoid in production)\ndeno run -A main.ts",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://docs.deno.com/runtime/fundamentals/security/"
    ]
  },
  {
    "id": "bun-cannot-find-module",
    "title": "Bun: Cannot find module",
    "category": "JavaScript",
    "explanation": "Bun could not resolve an import: dependencies not installed, a path/extension typo, or a package relying on Node APIs not yet shimmed.",
    "fix_snippet": "bun install\n# Verify the specifier and extension\n# import './util'  ->  './util.ts'\nbun pm ls\n# For Node built-ins, import via the node: prefix\n# import { readFile } from 'node:fs/promises'",
    "dateAdded": "2026-06-25",
    "sources": [
      "https://bun.sh/docs/runtime/modules"
    ]
  }
];
