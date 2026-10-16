# Security knowledge base

## Missing security headers
Missing Content-Security-Policy can increase exposure to script injection. Prefer a restrictive policy tailored to the application. Missing Strict-Transport-Security can allow downgrade attacks on HTTPS sites; enable it only after HTTPS is consistently available. Missing X-Content-Type-Options (nosniff) allows MIME sniffing; missing X-Frame-Options / frame-ancestors enables clickjacking; Referrer-Policy limits data leakage; Permissions-Policy limits powerful browser features. Map missing headers to CWE-693 and OWASP A05:2021 Security Misconfiguration. Validate headers on a real application response, not a CDN/WAF access-denied page.

## Exposed server information
Verbose Server or X-Powered-By headers help attackers fingerprint technology. Remove unnecessary version disclosure. Map to CWE-200 and OWASP A05:2021. Treat a fingerprint as informational: it describes the stack, not a defect by itself.

## Cookie security flags
Session cookies should set Secure, HttpOnly and an appropriate SameSite attribute. A cookie without Secure can be sent over cleartext; without HttpOnly it is readable by scripts, enabling session theft after XSS. SameSite mitigates cross-site request forgery. Map to CWE-614 and CWE-1004.

## CORS configuration
A permissive Access-Control-Allow-Origin (wildcard or reflected arbitrary origin), especially combined with Access-Control-Allow-Credentials: true, can expose authenticated data to untrusted sites. Restrict to an explicit allow-list of trusted origins and avoid reflecting the Origin header blindly. Map to CWE-942.

## HTTP methods
TRACE, PUT and DELETE that are not required should be disabled at the server or proxy layer. An advertised method list is an observation; impact depends on authorization on each route.

## TLS configuration
TLS versions older than TLS 1.2 should be retired. Use modern cipher suites and a valid, non-expired certificate from a trusted CA. A self-signed or expired certificate breaks trust and enables interception. Map weak transport security to CWE-326 and CWE-295.

## DNS and email authentication
SPF, DKIM and DMARC reduce spoofing of a domain. Missing SPF in TXT records is a posture gap; validate against the mail architecture before concluding impact. CAA records restrict which CAs may issue certificates. Map to CWE-290 (authentication bypass by spoofing).

## Open remote administration services
Remote administration services (SSH, RDP, VNC, Telnet) exposed to the internet should be justified, protected with MFA, restricted by network policy, and monitored. Do not classify an open port alone as a confirmed vulnerability. Map to CWE-284 and OWASP A01:2021 Broken Access Control considerations.

## Reachable data stores
Database and cache services (MySQL/PostgreSQL/MongoDB/Redis/Memcached/Elasticsearch) reachable from an assessment runner should be bound to private interfaces, require authentication and network policy. An exposed data store is a high-impact exposure lead; confirm authentication state before claiming compromise. Map to CWE-306 (missing authentication) and OWASP A05:2021.

## Service banners
Service banners expose product names and versions. Prefer minimal banners. A banner is an advertised string, not an authenticated package version; treat it as an observation and consider vendor backports before matching to advisories.

## robots.txt and security.txt
robots.txt can reveal paths an operator would rather not advertise; this is information disclosure, not protection. Never rely on robots.txt to secure a resource. Publishing security.txt gives researchers a reporting channel and is a governance best practice.

## WHOIS registration
WHOIS data records registrar, creation/expiry dates and name servers. Use it for asset attribution and expiry monitoring. Registration data is OSINT context, not a technical vulnerability.

## Evidence standard
Every confirmed finding must cite a concrete scanner observation. If evidence is incomplete or conflicting, label the item as Potential and recommend manual validation. Never claim exploitation or impact without observed evidence. An unavailable tool or an empty result is never evidence that the target is secure.
