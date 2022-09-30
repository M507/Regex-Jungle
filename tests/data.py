
print("Data is here")


sensitive_information_data_1 = {
"aws-keys": r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
 "sec": r"(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|aws_|secret|ssh-rsa AA)",
    "ip": r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
}

enum_data_I1 = {
"s3-buckets": [         r"[a-z0-9.-]+\\.s3\\.amazonaws\\.com",         r"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",         r"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",         r"//s3\\.amazonaws\\.com/[a-z0-9._-]+",         r"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+"     ],
"servers": r"server: r",
"takeovers": [         r"There is no app configured at that hostname",         r"NoSuchBucket",         r"No Such Account",         r"You're Almost There",         r"a GitHub Pages site here",         r"There's nothing here",         r"project not found",         r"Your CNAME settings",         r"InvalidBucketName",         r"PermanentRedirect",         r"The specified bucket does not exist",         r"Repository not found",         r"Sorry, We Couldn't Find That Page",         r"The feed has not been found.",         r"The thing you were looking for is no longer here, or never was",         r"Please renew your subscription",         r"There isn't a Github Pages site here.",         r"We could not find what you're looking for.",         r"No settings were found for this company:",         r"No such app",         r"is not a registered InCloud YouTrack",         r"Unrecognized domain",         r"project not found",         r"This UserVoice subdomain is currently available!",         r"Do you want to register",         r"Help Center Closed"     ],

}

enum_data_I2 = {
    "base64": r"([^A-Za-z0-9+/]|^)(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}",
    "cors": r"Access-Control-Allow",
    "debug-pages": r"(Application-Trace|Routing Error|DEBUG\"? ?[=:] ?True|Caused by:|stack trace:|Microsoft .NET Framework|Traceback|[0-9]:in `|#!/us|WebApplicationException|java\\.lang\\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE)",
    "firebase": r"firebaseio.com",
    "fw": [         r"django",         r"laravel",         r"symfony",         r"graphite",         r"grafana",         r"X-Drupal-Cache",         r"struts",         r"code ?igniter",         r"cake ?php",         r"grails",         r"elastic ?search",         r"kibana",         r"log ?stash",         r"tomcat",         r"jenkins",         r"hudson",         r"com.atlassian.jira",         r"Apache Subversion",         r"Chef Server",         r"RabbitMQ Management",         r"Mongo",         r"Travis CI - Enterprise",         r"BMC Remedy",         r"artifactory"     ],
    "go-functions": r"func [a-z0-9_]+\\(",
    "http-auth": r"[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+",
    "json-sec": r"(\\\\?\"|&quot;|%22)[a-z0-9_-]*(api[_-]?key|S3|aws_|secret|passw|auth)[a-z0-9_-]*(\\\\?\"|&quot;|%22): ?(\\\\?\"|&quot;|%22)[^\"&]+(\\\\?\"|&quot;|%22)",
    "meg-headers": r"^\u003c [a-z0-9_\\-]+: .*",
    "php-curl": r"CURLOPT_(HTTPHEADER|HEADER|COOKIE|RANGE|REFERER|USERAGENT|PROXYHEADER)",
    "php-errors": [         r"php warning",         r"php error",         r"fatal error",         r"uncaught exception",         r"include_path",         r"undefined index",         r"undefined variable",         r"\\?php",         r"<\\?[^x]",         r"stack trace\\:",         r"expects parameter [0-9]*",         r"Debug Trace"     ],
    "php-serialized": [         r"a:[0-9]+:{",         r"O:[0-9]+:\"",         r"s:[0-9]+:\""     ],
    "php-sinks": r"[^a-z0-9_](system|exec|popen|pcntl_exec|eval|create_function|unserialize|file_exists|md5_file|filemtime|filesize|assert) ?\\(",
    "php-sources": [         r"\\$_(POST|GET|COOKIE|REQUEST|SERVER|FILES)",         r"php://(input|stdin)"     ],
    "strings": [         r"\"[^\"]+\"",         "'[^']+'"     ],
    "upload-fields": r"\u003cinput[^\u003e]+type=[\"']?file[\"']?",
    "urls": r"https?://[^\"\\'> ]+",
}


for k, v in enum_data_I2.items():
    print(v)


takeovers = {
"AWS/S3":
"The specified bucket does not exist",
"Bitbucket":
"Repository not found",
"Cloudfront":
"Bad Request: ERROR: The request could not be satisfied",
"Desk":
"Please try again or try Desk.com free for 14 days.",
"Fastly":
"Fastly error: unknown domain:",
"Feedpress":
"The feed has not been found.",
"Ghost":
"The thing you were looking for is no longer here, or never was",
"Github":
"There isn't a GitHub Pages site here",
"Help Juice":
"We could not find what you're looking for",
"Help Scout":
"No settings were found for this company",
"Heroku":
"No such app",
"JetBrains":
"is not a registered InCloud YouTrack",
"Mashery":
"Unrecognized domain",
"Readme.io":
"Project doesnt exist... yet!",
"Shopify":
"Sorry, this shop is currently unavailable",
"Surge.sh":
"project not found",
"Tumblr":
"Whatever you were looking for doesn't currently exist at this address",
"Tilda":
"Please renew your subscription",
"Unbounce":
"The requested URL was not found on this server",
"UserVoice":
"This UserVoice subdomain is currently available",
"Wordpress":
"Do you want to register ",
"Zendesk":
"Help Center Closed",
"Acquia":
"Web Site Not Found",
"Agile CRM":
"Sorry, this page is no longer available.",
"Airee.ru":
"Ошибка 402. Сервис",
"Anima":
"If this is your website and you've just created it, try refreshing in a minute",
"Campaign Monitor":
"Trying to access your account?",
"Digital Ocean":
"Domain uses DO name serves with no records in DO.",
"Gemfury":
"404: This page could not be found.",
"Google Cloud Storage":
"The specified bucket does not exist.",
"HatenaBlog":
"404 Blog is not found",
"Intercom":
"Uh oh. That page doesn't exist.",
"Kinsta":
"No Site For Domain",
"LaunchRock":
"It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",
"Ngrok":
"ngrok.io not found",
"Pantheon":
"404 error unknown site!",
"Pingdom":
"Sorry, couldn't find the status page",
"SmartJobBoard":
"This job board website is either expired or its domain name is invalid.",
"Smartling":
"Domain is not configured",
"Statuspage":
"Status page pushed a DNS verification in order to prevent malicious takeovers what they mentioned in",
"Strikingly":
"But if you're looking to build your own website, <br/>you've come to the right place.",
"Uberflip":
"Non-hub domain, The URL you've accessed does not provide a hub.",
"Webflow":
"The page you are looking for doesn't exist or has been moved.",
"Worksites":
"Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",
}

for k, v in takeovers.items():
    print(v)


sensitive_information_data_2 = [
  {
    "part": "extension",
    "match": ".pem",
    "name": "Potential cryptographic private key"
  },
  {
    "part": "extension",
    "match": ".log",
    "name": "Log file"
  },
  {
    "part": "extension",
    "match": ".pkcs12",
    "name": "Potential cryptographic key bundle"
  },
  {
    "part": "extension",
    "match": ".p12",
    "name": "Potential cryptographic key bundle"
  },
  {
    "part": "extension",
    "match": ".pfx",
    "name": "Potential cryptographic key bundle"
  },
  {
    "part": "extension",
    "match": ".asc",
    "name": "Potential cryptographic key bundle"
  },
  {
    "part": "filename",
    "match": "otr.private_key",
    "name": "Pidgin OTR private key"
  },
  {
    "part": "extension",
    "match": ".ovpn",
    "name": "OpenVPN client configuration file"
  },
  {
    "part": "extension",
    "match": ".cscfg",
    "name": "Azure service configuration schema file"
  },
  {
    "part": "extension",
    "match": ".rdp",
    "name": "Remote Desktop connection file"
  },
  {
    "part": "extension",
    "match": ".mdf",
    "name": "Microsoft SQL database file"
  },
  {
    "part": "extension",
    "match": ".sdf",
    "name": "Microsoft SQL server compact database file"
  },
  {
    "part": "extension",
    "match": ".sqlite",
    "name": "SQLite database file"
  },
  {
    "part": "extension",
    "match": ".sqlite3",
    "name": "SQLite3 database file"
  },
  {
    "part": "extension",
    "match": ".bek",
    "name": "Microsoft BitLocker recovery key file"
  },
  {
    "part": "extension",
    "match": ".tpm",
    "name": "Microsoft BitLocker Trusted Platform Module password file"
  },
  {
    "part": "extension",
    "match": ".fve",
    "name": "Windows BitLocker full volume encrypted data file"
  },
  {
    "part": "extension",
    "match": ".jks",
    "name": "Java keystore file"
  },
  {
    "part": "extension",
    "match": ".psafe3",
    "name": "Password Safe database file"
  },
  {
    "part": "filename",
    "match": "secret_token.rb",
    "name": "Ruby On Rails secret token configuration file"
  },
  {
    "part": "filename",
    "match": "carrierwave.rb",
    "name": "Carrierwave configuration file"
  },
  {
    "part": "filename",
    "match": "database.yml",
    "name": "Potential Ruby On Rails database configuration file"
  },
  {
    "part": "filename",
    "match": "omniauth.rb",
    "name": "OmniAuth configuration file"
  },
  {
    "part": "filename",
    "match": "settings.py",
    "name": "Django configuration file"
  },
  {
    "part": "extension",
    "match": ".agilekeychain",
    "name": "1Password password manager database file"
  },
  {
    "part": "extension",
    "match": ".keychain",
    "name": "Apple Keychain database file"
  },
  {
    "part": "extension",
    "match": ".pcap",
    "name": "Network traffic capture file"
  },
  {
    "part": "extension",
    "match": ".gnucash",
    "name": "GnuCash database file"
  },
  {
    "part": "filename",
    "match": "jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml",
    "name": "Jenkins publish over SSH plugin file"
  },
  {
    "part": "filename",
    "match": "credentials.xml",
    "name": "Potential Jenkins credentials file"
  },
  {
    "part": "extension",
    "match": ".kwallet",
    "name": "KDE Wallet Manager database file"
  },
  {
    "part": "filename",
    "match": "LocalSettings.php",
    "name": "Potential MediaWiki configuration file"
  },
  {
    "part": "extension",
    "match": ".tblk",
    "name": "Tunnelblick VPN configuration file"
  },
  {
    "part": "filename",
    "match": "Favorites.plist",
    "name": "Sequel Pro MySQL database manager bookmark file"
  },
  {
    "part": "filename",
    "match": "configuration.user.xpl",
    "name": "Little Snitch firewall configuration file"
  },
  {
    "part": "extension",
    "match": ".dayone",
    "name": "Day One journal file"
  },
  {
    "part": "filename",
    "match": "journal.txt",
    "name": "Potential jrnl journal file"
  },
  {
    "part": "filename",
    "match": "knife.rb",
    "name": "Chef Knife configuration file"
  },
  {
    "part": "filename",
    "match": "proftpdpasswd",
    "name": "cPanel backup ProFTPd credentials file"
  },
  {
    "part": "filename",
    "match": "robomongo.json",
    "name": "Robomongo MongoDB manager configuration file"
  },
  {
    "part": "filename",
    "match": "filezilla.xml",
    "name": "FileZilla FTP configuration file"
  },
  {
    "part": "filename",
    "match": "recentservers.xml",
    "name": "FileZilla FTP recent servers file"
  },
  {
    "part": "filename",
    "match": "ventrilo_srv.ini",
    "name": "Ventrilo server configuration file"
  },
  {
    "part": "filename",
    "match": "terraform.tfvars",
    "name": "Terraform variable config file"
  },
  {
    "part": "filename",
    "match": ".exports",
    "name": "Shell configuration file"
  },
  {
    "part": "filename",
    "match": ".functions",
    "name": "Shell configuration file"
  },
  {
    "part": "filename",
    "match": ".extra",
    "name": "Shell configuration file"
  },
  {
    "part": "filename",
    "regex": r"^.*_rsa$",
    "name": "Private SSH key"
  },
  {
    "part": "filename",
    "regex": r"^.*_dsa$",
    "name": "Private SSH key"
  },
  {
    "part": "filename",
    "regex": r"^.*_ed25519$",
    "name": "Private SSH key"
  },
  {
    "part": "filename",
    "regex": r"^.*_ecdsa$",
    "name": "Private SSH key"
  },
  {
    "part": "path",
    "regex": r"\\.?ssh/config$",
    "name": "SSH configuration file"
  },
  {
    "part": "extension",
    "regex": r"^key(pair)?$",
    "name": "Potential cryptographic private key"
  },
  {
    "part": "filename",
    "regex": r"^\\.?(bash_|zsh_|sh_|z)?history$",
    "name": "Shell command history file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?mysql_history$",
    "name": "MySQL client command history file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?psql_history$",
    "name": "PostgreSQL client command history file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?pgpass$",
    "name": "PostgreSQL password file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?irb_history$",
    "name": "Ruby IRB console history file"
  },
  {
    "part": "path",
    "regex": r"\\.?purple/accounts\\.xml$",
    "name": "Pidgin chat client account configuration file"
  },
  {
    "part": "path",
    "regex": r"\\.?xchat2?/servlist_?\\.conf$",
    "name": "Hexchat/XChat IRC client server list configuration file"
  },
  {
    "part": "path",
    "regex": r"\\.?irssi/config$",
    "name": "Irssi IRC client configuration file"
  },
  {
    "part": "path",
    "regex": r"\\.?recon-ng/keys\\.db$",
    "name": "Recon-ng web reconnaissance framework API key database"
  },
  {
    "part": "filename",
    "regex": r"^\\.?dbeaver-data-sources.xml$",
    "name": "DBeaver SQL database manager configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?muttrc$",
    "name": "Mutt e-mail client configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?s3cfg$",
    "name": "S3cmd configuration file"
  },
  {
    "part": "path",
    "regex": r"\\.?aws/credentials$",
    "name": "AWS CLI credentials file"
  },
  {
    "part": "filename",
    "regex": r"^sftp-config(\\.json)?$",
    "name": "SFTP connection configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?trc$",
    "name": "T command-line Twitter client configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?(bash|zsh|csh)rc$",
    "name": "Shell configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?(bash_|zsh_)?profile$",
    "name": "Shell profile configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?(bash_|zsh_)?aliases$",
    "name": "Shell command alias configuration file"
  },
  {
    "part": "filename",
    "regex": r"config(\\.inc)?\\.php$",
    "name": "PHP configuration file"
  },
  {
    "part": "extension",
    "regex": r"^key(store|ring)$",
    "name": "GNOME Keyring database file"
  },
  {
    "part": "extension",
    "regex": r"^kdbx?$",
    "name": "KeePass password manager database file"
  },
  {
    "part": "extension",
    "regex": r"^sql(dump)?$",
    "name": "SQL dump file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?htpasswd$",
    "name": "Apache htpasswd file"
  },
  {
    "part": "filename",
    "regex": r"^(\\.|_)?netrc$",
    "name": "Configuration file for auto-login process"
  },
  {
    "part": "path",
    "regex": r"\\.?gem/credentials$",
    "name": "Rubygems credentials file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?tugboat$",
    "name": "Tugboat DigitalOcean management tool configuration"
  },
  {
    "part": "path",
    "regex": r"doctl/config.yaml$",
    "name": "DigitalOcean doctl command-line client configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?git-credentials$",
    "name": "git-credential-store helper credentials file"
  },
  {
    "part": "path",
    "regex": r"config/hub$",
    "name": "GitHub Hub command-line client configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?gitconfig$",
    "name": "Git configuration file"
  },
  {
    "part": "path",
    "regex": r"\\.?chef/(.*)\\.pem$",
    "name": "Chef private key"
  },
  {
    "part": "path",
    "regex": r"etc/shadow$",
    "name": "Potential Linux shadow file"
  },
  {
    "part": "path",
    "regex": r"etc/passwd$",
    "name": "Potential Linux passwd file",
    "comment": "Contains system user information"
  },
  {
    "part": "filename",
    "regex": r"^\\.?dockercfg$",
    "name": "Docker configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?npmrc$",
    "name": "NPM configuration file"
  },
  {
    "part": "filename",
    "regex": r"^\\.?env$",
    "name": "Environment configuration file"
  },
  {
    "part": "contents",
    "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "name": "AWS Access Key ID Value"
  },
  {
    "part": "contents",
    "regex": r"((\\\"|'|`)?((?i)aws)?_?((?i)access)_?((?i)key)?_?((?i)id)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\\\"|'|`)?)",
    "regextype": "large",
    "name": "AWS Access Key ID"
  },
  {
    "part": "contents",
    "regex": r"((\\\"|'|`)?((?i)aws)?_?((?i)account)_?((?i)id)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?[0-9]{4}-?[0-9]{4}-?[0-9]{4}(\\\"|'|`)?)",
    "regextype": "large",
    "name": "AWS Account ID"
  },
  {
    "part": "contents",
    "regex": r"((\\\"|'|`)?((?i)aws)?_?((?i)secret)_?((?i)access)?_?((?i)key)?_?((?i)id)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?[A-Za-z0-9/+=]{40}(\\\"|'|`)?)",
    "regextype": "large",
    "name": "AWS Secret Access Key"
  },
  {
    "part": "contents",
    "regex": r"((\\\"|'|`)?((?i)aws)?_?((?i)session)?_?((?i)token)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?[A-Za-z0-9/+=]{100,400}(\\\"|'|`)?)",
    "regextype": "large",
    "name": "AWS Session Token"
  },
  {
    "part": "contents",
    "regex": r"(?i)artifactory.{0,50}(\\\"|'|`)?[a-zA-Z0-9=]{112}(\\\"|'|`)?",
    "regextype": "large",
    "name": "Artifactory"
  },
  {
    "part": "contents",
    "regex": r"(?i)codeclima.{0,50}(\\\"|'|`)?[0-9a-f]{64}(\\\"|'|`)?",
    "regextype": "large",
    "name": "CodeClimate"
  },
  {
    "part": "contents",
    "regex": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "name": "Facebook access token"
  },
  {
    "part": "contents",
    "regex": r"((\\\"|'|`)?type(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?service_account(\\\"|'|`)?,?)",
    "regextype": "large",
    "name": "Google (GCM) Service account"
  },
  {
    "part": "contents",
    "regex": r"(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}",
    "name": "Stripe API key"
  },
  {
    "part": "contents",
    "regex": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "name": "Google OAuth Key"
  },
  {
    "part": "contents",
    "regex": r"AIza[0-9A-Za-z\\\\-_]{35}",
    "name": "Google Cloud API Key"
  },
  {
    "part": "contents",
    "regex": r"ya29\\\\.[0-9A-Za-z\\\\-_]+",
    "name": "Google OAuth Access Token"
  },
  {
    "part": "contents",
    "regex": r"sk_[live|test]_[0-9a-z]{32}",
    "name": "Picatic API key"
  },
  {
    "part": "contents",
    "regex": r"sq0atp-[0-9A-Za-z\\-_]{22}",
    "name": "Square Access Token"
  },
  {
    "part": "contents",
    "regex": r"sq0csp-[0-9A-Za-z\\-_]{43}",
    "name": "Square OAuth Secret"
  },
  {
    "part": "contents",
    "regex": r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "name": "PayPal/Braintree Access Token"
  },
  {
    "part": "contents",
    "regex": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "name": "Amazon MWS Auth Token"
  },
  {
    "part": "contents",
    "regex": r"SK[0-9a-fA-F]{32}",
    "name": "Twilo API Key"
  },
  {
    "part": "contents",
    "regex": r"SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}",
    "name": "SendGrid API Key"
  },
  {
    "part": "contents",
    "regex": r"key-[0-9a-zA-Z]{32}",
    "name": "MailGun API Key"
  },
  {
    "part": "contents",
    "regex": r"[0-9a-f]{32}-us[0-9]{12}",
    "name": "MailChimp API Key"
  },
  {
    "part": "contents",
    "regex": r"sshpass -p.*['|\\\"]",
    "regextype": "large",
    "name": "SSH Password"
  },
  {
    "part": "contents",
    "regex": r"(https\\\\://outlook\\\\.office.com/webhook/[0-9a-f-]{36}\\\\@)",
    "name": "Outlook team"
  },
  {
    "part": "contents",
    "regex": r"(?i)sauce.{0,50}(\\\"|'|`)?[0-9a-f-]{36}(\\\"|'|`)?",
    "name": "Sauce Token"
  },
  {
    "part": "contents",
    "regex": r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "name": "Slack Token"
  },
  {
    "part": "contents",
    "regex": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "name": "Slack Webhook"
  },
  {
    "part": "contents",
    "regex": r"(?i)sonar.{0,50}(\\\"|'|`)?[0-9a-f]{40}(\\\"|'|`)?",
    "name": "SonarQube Docs API Key"
  },
  {
    "part": "contents",
    "regex": r"(?i)hockey.{0,50}(\\\"|'|`)?[0-9a-f]{32}(\\\"|'|`)?",
    "name": "HockeyApp"
  },
  {
    "part": "contents",
    "regex": r"([\\w+]{1,24})(://)([^$<]{1})([^\\s\";]{1,}):([^$<]{1})([^\\s\";/]{1,})@[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,24}([^\\s]+)",
    "regextype": "large",
    "name": "Username and password in URI"
  },
  {
    "part": "contents",
    "regex": r"oy2[a-z0-9]{43}",
    "name": "NuGet API Key"
  },
  {
    "part": "contents",
    "regex": r"hawk\\.[0-9A-Za-z\\-_]{20}\\.[0-9A-Za-z\\-_]{20}",
    "regextype": "large",
    "name": "StackHawk API Key"
  },
  {
    "part": "extension",
    "match": ".ppk",
    "name": "Potential PuTTYgen private key"
  },
  {
    "part": "filename",
    "match": "heroku.json",
    "name": "Heroku config file"
  },
  {
    "part": "extension",
    "match": ".sqldump",
    "name": "SQL Data dump file"
  },
  {
    "part": "filename",
    "match": "dump.sql",
    "name": "MySQL dump w/ bcrypt hashes"
  },
  {
    "part": "filename",
    "match": "id_rsa_pub",
    "name": "Public ssh key"
  },
  {
    "part": "filename",
    "match": "mongoid.yml",
    "name": "Mongoid config file"
  },
  {
    "part": "filename",
    "match": "salesforce.js",
    "name": "Salesforce credentials in a nodejs project"
  },
  {
    "part": "extension",
    "match": ".netrc",
    "name": "netrc with SMTP credentials"
  },
  {
    "part": "filename",
    "regex": r".remote-sync.json$",
    "name": "Created by remote-sync for Atom, contains FTP and/or SCP/SFTP/SSH server details and credentials"
  },
  {
    "part": "filename",
    "regex": r".esmtprc$",
    "name": "esmtp configuration"
  },
  {
    "part": "filename",
    "regex": r"^deployment-config.json?$",
    "name": "Created by sftp-deployment for Atom, contains server details and credentials"
  },
  {
    "part": "filename",
    "regex": r".ftpconfig$",
    "name": "Created by sftp-deployment for Atom, contains server details and credentials"
  },
  {
    "part": "contents",
    "regex": r"-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY",
    "name": "Contains a private key"
  },
  {
    "part": "contents",
    "regex": r"define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|\"].{10,120}['|\"]",
    "regextype": "large",
    "name": "WP-Config"
  },
  {
    "part": "contents",
    "regex": r"(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\\/+]{20,40}",
    "name": "AWS cred file info"
  },
  {
    "part": "contents",
    "regex": r"(?i)(facebook|fb)(.{0,20})?(?-i)['\\\"][0-9a-f]{32}['\\\"]",
    "name": "Facebook Secret Key"
  },
  {
    "part": "contents",
    "regex": r"(?i)(facebook|fb)(.{0,20})?['\\\"][0-9]{13,17}['\\\"]",
    "name": "Facebook Client ID"
  },
  {
    "part": "contents",
    "regex": r"(?i)twitter(.{0,20})?['\\\"][0-9a-z]{35,44}['\\\"]",
    "name": "Twitter Secret Key"
  },
  {
    "part": "contents",
    "regex": r"(?i)twitter(.{0,20})?['\\\"][0-9a-z]{18,25}['\\\"]",
    "name": "Twitter Client ID"
  },
  {
    "part": "contents",
    "regex": r"(?i)github(.{0,20})?(?-i)['\\\"][0-9a-zA-Z]{35,40}['\\\"]",
    "name": "Github Key"
  },
  {
    "part": "contents",
    "regex": r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "name": "Heroku API key"
  },
  {
    "part": "contents",
    "regex": r"(?i)linkedin(.{0,20})?(?-i)['\\\"][0-9a-z]{12}['\\\"]",
    "name": "Linkedin Client ID"
  },
  {
    "part": "contents",
    "regex": r"(?i)linkedin(.{0,20})?['\\\"][0-9a-z]{16}['\\\"]",
    "name": "LinkedIn Secret Key"
  },
  {
    "part": "path",
    "regex": r"\\.?idea[\\\\\\/]WebServers.xml$",
    "name": "Created by Jetbrains IDEs, contains webserver credentials with encoded passwords (not encrypted!)"
  },
  {
    "part": "path",
    "regex": r"\\.?vscode[\\\\\\/]sftp.json$",
    "name": "Created by vscode-sftp for VSCode, contains SFTP/SSH server details and credentials"
  },
  {
    "part": "path",
    "regex": r"web[\\\\\\/]ruby[\\\\\\/]secrets.yml",
    "name": "Ruby on rails secrets.yml file (contains passwords)"
  },
  {
    "part": "path",
    "regex": r"\\.?docker[\\\\\\/]config.json$",
    "name": "Docker registry authentication file"
  },
  {
    "part": "path",
    "regex": r"ruby[\\\\\\/]config[\\\\\\/]master.key$",
    "name": "Rails master key (used for decrypting credentials.yml.enc for Rails 5.2+)"
  },
  {
    "part": "path",
    "regex": r"\\.?mozilla[\\\\\\/]firefox[\\\\\\/]logins.json$",
    "name": "Firefox saved password collection (can be decrypted using keys4.db)"
  },
  {
    "part": "filename",
    "match": "wallet.dat",
    "name": "Bitcoin Core wallet"
  },
  {
    "part": "filename",
    "match": "onion_v3_private_key",
    "name": "Private key for Bitcoin Core onion service"
  },
  {
    "part": "filename",
    "match": "bitcoin.conf",
    "name": "Bitcoin Core config"
  }
]

for element in sensitive_information_data_2:
    try:
        print(element['regex'])
        print(element['name'])
    except:
        continue


