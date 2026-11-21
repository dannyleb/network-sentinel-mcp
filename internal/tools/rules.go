package tools

// Rule explains one of Network Sentinel's detection rules. The catalog is
// written from Network Sentinel's source (detect.go, secrets.go, ai.go) and
// README, and is static: explaining an alert never looks anything up online.
type Rule struct {
	ID                 string   `json:"id"`
	Severity           string   `json:"severity" jsonschema:"severity this rule raises"`
	Detects            string   `json:"detects" jsonschema:"what triggers the rule"`
	WhyItMatters       string   `json:"why_it_matters"`
	CommonBenignCauses []string `json:"common_benign_causes" jsonschema:"harmless situations that also trigger it"`
	NextSteps          []string `json:"next_steps" jsonschema:"what a person should check or do; nothing here is done automatically"`
}

// findTheApp is shared advice: Network Sentinel can't attribute traffic to a
// process, but the operating system can while the connection is open.
const findTheApp = "Find the app responsible: while the connection is open, `lsof -nP -i @<ip>` (add sudo for other users' programs) lists the programs connected to that address."

var rules = []Rule{
	{
		ID:       "cleartext-credentials",
		Severity: "high (medium for secret-looking values in code)",
		Detects: "A password or credential in unencrypted traffic leaving this machine: form or query fields such as password=, api_key= or token=, " +
			"HTTP Basic authentication, or a hard-coded secret in a request body. The value itself is never stored.",
		WhyItMatters: "Anyone on the network path (public Wi-Fi, the ISP, a compromised router) can read the credential and reuse it.",
		CommonBenignCauses: []string{
			"A development or test server reached over plain HTTP",
			"Placeholder or test credentials that look real",
		},
		NextSteps: []string{
			"Treat the credential as exposed: change the password or rotate the key",
			findTheApp,
			"Switch that app or service to HTTPS or another encrypted protocol",
		},
	},
	{
		ID:       "cleartext-secret",
		Severity: "high (medium for JSON Web Tokens)",
		Detects: "A secret with a recognizable format in unencrypted traffic: private key blocks, cloud and API keys (AWS, GitHub, GitLab, Google, OpenAI, " +
			"Anthropic, Slack, Stripe, npm, PyPI, Hugging Face, SendGrid), database URLs with passwords, Bearer tokens and JSON Web Tokens. Only a redacted form is kept.",
		WhyItMatters: "These secrets usually grant direct access to accounts, servers or data, and were readable by anyone on the network path.",
		CommonBenignCauses: []string{
			"Example or revoked keys in documentation or test traffic",
		},
		NextSteps: []string{
			"Revoke and reissue the secret with its provider",
			"Check the provider's audit log for use of the old secret",
			findTheApp,
		},
	},
	{
		ID:           "cleartext-pii",
		Severity:     "high (low for email addresses)",
		Detects:      "Personal data in unencrypted traffic: US Social Security numbers, payment card numbers that pass the Luhn check, and email addresses. Alerts show only the last four digits.",
		WhyItMatters: "Identity and card numbers sent in the clear can be captured and used for fraud.",
		CommonBenignCauses: []string{
			"Numbers that only look like an SSN or card, such as order IDs or published test card numbers",
			"Email addresses in ordinary mail traffic (alerts on mail ports 25 and 587 are already suppressed)",
		},
		NextSteps: []string{
			"Check which site or app sent the data over plain HTTP",
			"If the data was real, treat it as exposed: watch the card or credit report and contact the bank",
			"Use the site's HTTPS version, or stop using it",
		},
	},
	{
		ID:           "blocklist-ip",
		Severity:     "high",
		Detects:      "A connection to an IP address or range on one of the blocklists Network Sentinel was started with (for example abuse.ch Feodo Tracker or Spamhaus DROP). The alert names the list.",
		WhyItMatters: "These lists track botnet command servers, malware hosting and hijacked networks, so contact can mean something on this machine is infected.",
		CommonBenignCauses: []string{
			"Shared hosting or CDN addresses that were briefly abused and listed",
			"A stale or overly broad list entry",
		},
		NextSteps: []string{
			"Check the IP against the list named in the alert and its source",
			findTheApp,
			"If you don't recognize the program, run a malware scan and consider disconnecting the machine",
		},
	},
	{
		ID:           "blocklist-domain",
		Severity:     "high",
		Detects:      "A DNS lookup of, or a connection to, a domain (or any subdomain) on one of the blocklists Network Sentinel was started with. The alert names the list.",
		WhyItMatters: "Blocklisted domains host malware, phishing or command-and-control servers. A lookup alone can mean a program is trying to reach one.",
		CommonBenignCauses: []string{
			"A link or ad that was blocked before anything loaded",
			"A stale list entry for a domain that has since changed hands",
		},
		NextSteps: []string{
			"Check what was being browsed or run at the time",
			findTheApp,
			"If nothing explains it, run a malware scan",
		},
	},
	{
		ID:       "insecure-protocol",
		Severity: "high for Telnet, rsh, rlogin and rexec; medium for FTP, TFTP, POP3, IMAP, SNMP, LDAP and MQTT; low for SMTP on port 25",
		Detects: "Data sent over a protocol that doesn't encrypt anything. It only fires once real data flows, not on a bare connection attempt, " +
			"and not when the traffic turns out to be TLS.",
		WhyItMatters: "Logins and content are readable, and can be altered, by anyone on the network path.",
		CommonBenignCauses: []string{
			"Older printers, routers, cameras and IoT devices that only speak these protocols",
			"Mail servers relaying on port 25, which is normal between servers",
		},
		NextSteps: []string{
			"Use the encrypted alternative: SSH instead of Telnet or rsh, SFTP or FTPS instead of FTP, IMAPS (993) and POP3S (995)",
			"For a device you manage, update its firmware or turn off the legacy service",
		},
	},
	{
		ID:       "suspicious-port",
		Severity: "medium",
		Detects: "A new outbound TCP connection to a port associated with backdoors or remote control: 4444 (Metasploit's default), 1337 and 31337, " +
			"5555 (Android debugging), IRC 6666-6669 (used by botnets), Tor relays 9001 and 9030, and outbound remote desktop (3389) or VNC (5900).",
		WhyItMatters: "Malware often calls home on these ports, and outbound remote-control sessions can hand this machine to someone else.",
		CommonBenignCauses: []string{
			"Remote-desktop, VNC, Tor or IRC sessions you started yourself",
			"Development tools that happen to use these ports",
		},
		NextSteps: []string{
			"Check whether you started a remote-desktop, Tor or IRC session at that time",
			findTheApp,
			"If you don't recognize the program, treat it as a possible compromise",
		},
	},
	{
		ID:           "dns-tunnel",
		Severity:     "medium",
		Detects:      "A DNS lookup with a label of 52 characters or more, or a name longer than 180 characters: the shape of data being smuggled out inside DNS queries.",
		WhyItMatters: "DNS is rarely blocked or inspected, so exfiltration tools and malware hide data and commands in lookups.",
		CommonBenignCauses: []string{
			"Some security, antivirus and CDN products encode data in long DNS names on purpose",
		},
		NextSteps: []string{
			"Check whether the domain in the alert belongs to a product you use",
			"See how often it happens with get_recent_connections and the related DNS lookups",
			"If you don't recognize it, block the domain and investigate the machine",
		},
	},
	{
		ID:           "dns-entropy",
		Severity:     "low",
		Detects:      "A DNS label of 24 characters or more that looks random (high character entropy).",
		WhyItMatters: "Malware uses domain-generation algorithms that produce names like this, to make its servers hard to block.",
		CommonBenignCauses: []string{
			"CDNs, ad and analytics networks, and cloud services often use random-looking host names",
		},
		NextSteps: []string{
			"Usually harmless. Look closer only if the domain is unfamiliar and the lookups keep repeating",
		},
	},
	{
		ID:           "large-upload",
		Severity:     "medium",
		Detects:      "More than the configured amount (100 MB by default, set with netsentinel -upload-mb) sent to one destination within 10 minutes.",
		WhyItMatters: "A large, unexpected upload can be data being copied off the machine.",
		CommonBenignCauses: []string{
			"Cloud backup, photo or file sync, video calls, uploading files, or pushing code",
		},
		NextSteps: []string{
			"See the destination's totals with get_top_destinations",
			"Check whether a backup, sync or upload was running at the time",
			findTheApp,
		},
	},
	{
		ID:           "plaintext-http",
		Severity:     "low",
		Detects:      "An unencrypted web request. One alert per site; query strings are removed from the alert because they can hold secrets.",
		WhyItMatters: "The full address and the page content are visible to the network path, and can be altered in transit.",
		CommonBenignCauses: []string{
			"Operating-system connectivity checks (captive-portal detection)",
			"Certificate revocation checks (OCSP and CRL), which use plain HTTP by design",
			"Admin pages of local devices",
		},
		NextSteps: []string{
			"Use the https:// version of the site if there is one",
			"Ignore it for connectivity and certificate checks",
		},
	},
	{
		ID:           "plaintext-dns",
		Severity:     "info",
		Detects:      "DNS lookups sent unencrypted to a resolver: usually the router, which forwards them to the ISP.",
		WhyItMatters: "The resolver, and anyone on the path, can see the name of every site this machine visits.",
		CommonBenignCauses: []string{
			"This is the default on most networks",
		},
		NextSteps: []string{
			"Turn on encrypted DNS (DNS over HTTPS or TLS) in the operating system or browser, or use a VPN",
		},
	},
	{
		ID:           "privacy-relay",
		Severity:     "info",
		Detects:      "iCloud Private Relay is active: DNS lookups and plain web requests are encrypted before they leave the machine.",
		WhyItMatters: "The ISP can't read that traffic, and neither can Network Sentinel, so expect fewer content-based alerts while it's on.",
		CommonBenignCauses: []string{
			"Always harmless",
		},
		NextSteps: []string{
			"Nothing to do",
		},
	},
	{
		ID:       "ai-secret",
		Severity: "high, or the severity of the secret found",
		Detects: "An API key, token, password or personal data found in what was sent to, or came back from, an AI service, either through Network Sentinel's " +
			"AI gateway or in Claude Code session logs. Values are redacted; the alert says which project it came from.",
		WhyItMatters: "Anything sent to an AI provider is stored outside this machine and may be retained or logged.",
		CommonBenignCauses: []string{
			"Placeholder or test keys",
			"A secret you shared on purpose",
		},
		NextSteps: []string{
			"Rotate the secret",
			"Find the file or prompt it came from in the project named in the alert",
			"Stop the AI tool from reading that file (for Claude Code, a permissions deny rule such as Read(./.env))",
		},
	},
	{
		ID:       "ai-sensitive-access",
		Severity: "high when a credential file was sent off the machine; medium for reading a credential file or running a risky command; low for commands that can print secrets",
		Detects: "In Claude Code session logs: the agent read a credential file (.env, SSH or cloud keys), ran a command that can print secrets (printenv, " +
			"cat ~/.aws/credentials), ran a risky command (piping a download into a shell, running a file it just downloaded, uploading a local file), " +
			"or uploaded a credential file (curl -d @.env and similar).",
		WhyItMatters: "Whatever the agent read or printed went to the AI provider, and an agent misled by a prompt injection can be steered into sending data elsewhere.",
		CommonBenignCauses: []string{
			"You asked the agent to work with that file or run that command",
		},
		NextSteps: []string{
			"Review the session in the project named in the alert",
			"Rotate any credential whose file was read or sent",
			"Restrict which files and commands the agent may use",
		},
	},
	{
		ID:           "ai-upload",
		Severity:     "medium",
		Detects:      "More than 10 MB sent to one AI service within 10 minutes.",
		WhyItMatters: "Files or a whole codebase may have been uploaded to the provider.",
		CommonBenignCauses: []string{
			"Large prompts or attachments, or a coding agent reading a big repository",
		},
		NextSteps: []string{
			"Check what you or your AI tools were doing at the time",
			"Make sure no confidential files were included",
		},
	},
	{
		ID:           "ai-service",
		Severity:     "info",
		Detects:      "The first time each AI service (Claude, ChatGPT, GitHub Copilot, Gemini, Cursor and others) is seen from this machine.",
		WhyItMatters: "Shows which AI tools are in use, including ones that were installed without anyone noticing.",
		CommonBenignCauses: []string{
			"Any AI tool you use",
		},
		NextSteps: []string{
			"Confirm you recognize the tool",
		},
	},
}

// ruleByID returns the catalog entry for a rule. Unknown rules (from a newer
// Network Sentinel) get a placeholder that says so.
func ruleByID(id, severity string) (Rule, bool) {
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{
		ID:                 clean(id, maxShortLen),
		Severity:           clean(severity, maxShortLen),
		Detects:            "This rule isn't in network-sentinel-mcp's catalog; Network Sentinel may be newer than this server.",
		WhyItMatters:       "See the alert's title and detail, and the rule table in Network Sentinel's README.",
		CommonBenignCauses: []string{},
		NextSteps:          []string{"Update network-sentinel-mcp to get an explanation of this rule"},
	}, false
}
