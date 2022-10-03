
dddd = {
"Artifactory_API_Token":r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
"Artifactory_Password":r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
"Authorization_Basic":r"basic [a-zA-Z0-9_\\-:\\.=]+",
"Authorization_Bearer":r"bearer [a-zA-Z0-9_\\-\\.=]+",
"AWS_Client_ID":r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
"AWS_MWS_Key":r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
"AWS_Secret_Key":r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
"Base32":r"(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?",
"Base64":r"(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}",
"Basic_Auth_Credentials":r"(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+",
"Cloudinary_Basic_Auth":r"cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
"Facebook_Access_Token":r"EAACEdEose0cBA[0-9A-Za-z]+",
"Facebook_Client_ID":r"(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}",
"Facebook_Oauth":r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
"Facebook_Secret_Key":r"(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}",
"Github":r"(?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}",
"Google_API_Key":r"AIza[0-9A-Za-z\\-_]{35}",
"Google_Cloud_Platform_API_Key":r"(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]",
"Google_Drive_API_Key":r"AIza[0-9A-Za-z\\-_]{35}",
"Google_Drive_Oauth":r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
"Google_Gmail_API_Key":r"AIza[0-9A-Za-z\\-_]{35}",
"Google_Gmail_Oauth":r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
"Google_Oauth_Access_Token":r"ya29\\.[0-9A-Za-z\\-_]+",
"Google_Youtube_API_Key":r"AIza[0-9A-Za-z\\-_]{35}",
"Google_Youtube_Oauth":r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\\.com",
"Heroku_API_Key":r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
"IPv4":r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b",
"IPv6":r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",
"Javascript_Variables":r"(?:const|let|var)\s+\K(\w+?)(?=[;.=\s])",
"LinkedIn_Client_ID":r"(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]",
"LinkedIn_Secret_Key":r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
"Mailchamp_API_Key":r"[0-9a-f]{32}-us[0-9]{1,2}",
"Mailgun_API_Key":r"key-[0-9a-zA-Z]{32}",
"Mailto":r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+",
"MD5_Hash":r"[a-f0-9]{32}",
"Picatic_API_Key":r"sk_live_[0-9a-z]{32}",
"Slack_Token":r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
"Slack_Webhook":r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}",
"Stripe_API_Key":r'(?":r|s)k_live_[0-9a-zA-Z]{24}',
"Square_Access_Token":r"sqOatp-[0-9A-Za-z\\-_]{22}",
"Square_Oauth_Secret":r"sq0csp-[ 0-9A-Za-z\\-_]{43}",
"Twilio_API_Key":r"SK[0-9a-fA-F]{32}",
"Twitter_Client_ID":r"(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}",
"Twitter_Oauth":r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
"Twitter_Secret_Key":r"(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}",
"Vault_Token":r"[sb]\.[a-zA-Z0-9]{24}",
"URL_Parameter":r"(?<=\?|\&)[a-zA-Z0-9_]+(?=\=)",
"URLs_With_HTTP_Protocol":r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)",
"Without_Protocol":r"[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)",
}


for k, v in dddd.items():
  pass
  print(v)


dddd2= {
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (OPENSSH) private key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Facebook Oauth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "Twitter Oauth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    "GitHub": r"[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]",
    "Google Oauth": r"(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Generic Secret": r"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "accessToken": r"(\"accessToken\": \"[a-zA-Z0-9-_]*\")",
    "Azure Client Secret": r"(ARM_CLIENT_SECRET\\s*=\\s*[\"'a-zA-Z0-9-_]*)",
    "Azure Client ID": r"(ARM_CLIENT_ID\\s*=\\s*[\"'a-zA-Z0-9-_]*)"
}


for k, v in dddd2.items():
  pass
  print(v)



dddd3 = {
  "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
  "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
  "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
  "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
  "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "Amazon AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
  "Amazon MWS Auth Token": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
  "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
  "Facebook OAuth": r"(?i)facebook[\\s[[:punct:]]]{1,4}[0-9a-f]{32}[\\s[[:punct:]]]?",
  "GitHub": r"(?i)(github|access[[:punct:]]token)[\\s[[:punct:]]]{1,4}[0-9a-zA-Z]{35,40}",
  "Generic API Key": {
    "pattern": r"(?i)(api|access)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
    "entropy_filter": True,
    "threshold": r"0.6",
    "keyspace": r"guess"
  },
  "Generic Account API Key": {
    "pattern": r"(?i)account[\\s[[:punct:]]]?api[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
    "entropy_filter": True,
    "threshold": r"0.6",
    "keyspace": r"guess"
  },
  "Generic Secret": {
    "pattern": r"(?i)secret[\\s[[:punct:]]]{1,4}[0-9a-zA-Z-_]{16,64}[\\s[[:punct:]]]?",
    "entropy_filter": True,
    "threshold": r"0.6",
    "keyspace": r"guess"
  },
  "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform API Key": r"AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform OAuth": r"(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google Drive API Key": r"AIza[0-9A-Za-z\\-_]{35}",
  "Google Drive OAuth": r"(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google (GCP) Service-account": r"(?i)\"type\": \"service_account\"",
  "Google Gmail API Key": r"AIza[0-9A-Za-z\\-_]{35}",
  "Google Gmail OAuth": r"(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google OAuth Access Token": r"ya29\\.[0-9A-Za-z\\-_]+",
  "Google YouTube API Key": r"AIza[0-9A-Za-z\\-_]{35}",
  "Google YouTube OAuth": r"(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U][\\s[[:punct:]]]{1,4}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
  "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
  "Mailgun API Key": r"(?i)key-[0-9a-zA-Z]{32}",
  "Credentials in absolute URL": r"(?i)((https?|ftp)://)(([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+)@)((([a-z0-9]\\.|[a-z0-9][a-z0-9-]*[a-z0-9]\\.)*[a-z][a-z0-9-]*[a-z0-9]|((\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5]))(:\\d+)?)(((/+([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)*(\\?([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)?)?)?",
  "PayPal Braintree Access Token": r"(?i)access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
  "Picatic API Key": r"(?i)sk_live_[0-9a-z]{32}",
  "Slack Webhook": r"(?i)https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
  "Stripe API Key": r"(?i)sk_live_[0-9a-zA-Z]{24}",
  "Stripe Restricted API Key": r"(?i)rk_live_[0-9a-zA-Z]{24}",
  "Square Access Token": r"(?i)sq0atp-[0-9A-Za-z\\-_]{22}",
  "Square OAuth Secret": r"(?i)sq0csp-[0-9A-Za-z\\-_]{43}",
  "Twilio API Key": r"SK[0-9a-fA-F]{32}",
  "Twitter Access Token": r"(?i)twitter[\\s[[:punct:]]]{1,4}[1-9][0-9]+-[0-9a-zA-Z]{40}",
  "Twitter OAuth": r"(?i)twitter[\\s[[:punct:]]]{1,4}['|\"]?[0-9a-zA-Z]{35,44}['|\"]?",
  "New Relic Partner & REST API Key": r"[\\s[[:punct:]]][A-Fa-f0-9]{47}[\\s[[:punct:]][[:cntrl:]]]",
  "New Relic Mobile Application Token": r"[\\s[[:punct:]]][A-Fa-f0-9]{42}[\\s[[:punct:]][[:cntrl:]]]",
  "New Relic Synthetics Private Location": r"(?i)minion_private_location_key",
  "New Relic Insights Key (specific)": r"(?i)insights[\\s[[:punct:]]]?(key|query|insert)[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,40}\\b",
  "New Relic Insights Key (vague)": r"(?i)(query|insert)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}b[\\w-]{32,40}\\b",
  "New Relic License Key": r"(?i)license[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,40}\\b",
  "New Relic Internal API Key": r"(?i)nr-internal-api-key",
  "New Relic HTTP Auth Headers and API Key": r"(?i)(x|newrelic|nr)-?(admin|partner|account|query|insert|api|license)-?(id|key)[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,47}\\b",
  "New Relic API Key Service Key (new format)": r"(?i)NRAK-[A-Z0-9]{27}",
  "New Relic APM License Key (new format)": r"(?i)[a-f0-9]{36}NRAL",
  "New Relic APM License Key (new format, region-aware)": r"(?i)[a-z]{2}[0-9]{2}xx[a-f0-9]{30}NRAL",
  "New Relic REST API Key (new format)": r"(?i)NRRA-[a-f0-9]{42}",
  "New Relic Admin API Key (new format)": r"(?i)NRAA-[a-f0-9]{27}",
  "New Relic Insights Insert Key (new format)": r"(?i)NRII-[A-Za-z0-9-_]{32}",
  "New Relic Insights Query Key (new format)": r"(?i)NRIQ-[A-Za-z0-9-_]{32}",
  "New Relic Synthetics Private Location Key (new format)": r"(?i)NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}",
  "New Relic Pixie API Key": r"px-api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
  "Email address": r"(?i)\\b(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*)@[a-z0-9][a-z0-9-]+\\.(com|de|cn|net|uk|org|info|nl|eu|ru)([\\W&&[^:/]]|\\A|\\z)",
  "New Relic Account IDs in URL": r"(newrelic\\.com/)?accounts/\\d{1,10}/",
  "Account ID": r"(?i)account[\\s[[:punct:]]]?id[\\s[[:punct:]]]{1,4}\\b[\\d]{1,10}\\b",
  "Salary Information": r"(?i)(salary|commission|compensation|pay)([\\s[[:punct:]]](amount|target))?[\\s[[:punct:]]]{1,4}\\d+"
}



