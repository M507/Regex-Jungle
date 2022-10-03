import json
import requests
from data import *
ip = "10.10.1.86"
path = "/collections"


_regex = {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
}

# data = {
#                 "name": k,
#                 "regex": v,
#                 "link1": "https://google.com",
#                 "C": True,
#                 "Python": True,
#                 "Java": True,
#                 "Javascript": True,
#                 "CSharp": True,
#                 "Php": True,
#                 "Golang": True,
#                 "Shell": True,
#                 "HTML": True,
#                 "sensitive_information": True,
#             }

class Restaurant:
    def __init__(self):
        self.api_url = "http://"+ip+":1337"

    def all(self):
        r = requests.get(self.api_url + path)
        return r.json()

    def create(self, params):
        r = requests.post(
            self.api_url + path,
            headers={"Content-Type": "application/json"},
            data=json.dumps(
                {
                    "name": params["name"],
                    "regex": params["regex"],
                    "link1": params["link1"],
                    "C": params["C"],
                    "Python": params["Python"],
                    "Java": params["Java"],
                    "Javascript": params["Javascript"],
                    "CSharp": params["CSharp"],
                    "Php": params["Php"],
                    "Golang": params["Golang"],
                    "Shell": params["Shell"],
                    "HTML": params["HTML"],
                }
            ),
        )
        return r.json()


restaurant = Restaurant()

# data_list = [["(.*)1","(.*)2"]]

def co1():
    # for element in data_list:
    for k, v in _regex.items():
        print(k, v)
        data = {
                "name": k,
                "regex": v,
                "link1": "https://google.com",
                "C": False,
                "Python": False,
                "Java": False,
                "Javascript": False,
                "CSharp": False,
                "Php": False,
                "Golang": False,
                "Shell": False,
                "HTML": False,
                "sensitive_information": True,
                "type": "regex",
            }
        r = restaurant.create(data)

        print(
            r
        )

def cl2():
    php_dc = {
   "php-curl": r"CURLOPT_(HTTPHEADER|HEADER|COOKIE|RANGE|REFERER|USERAGENT|PROXYHEADER)",
    "php-errors": [         r"php warning",         r"php error",         r"fatal error",         r"uncaught exception",         r"include_path",         r"undefined index",         r"undefined variable",         r"\\?php",         r"<\\?[^x]",         r"stack trace\\:",         r"expects parameter [0-9]*",         r"Debug Trace"     ],
    "php-serialized": [         r"a:[0-9]+:{",         r"O:[0-9]+:\"",         r"s:[0-9]+:\""     ],
    "php-sinks": r"[^a-z0-9_](system|exec|popen|pcntl_exec|eval|create_function|unserialize|file_exists|md5_file|filemtime|filesize|assert) ?\\(",
    "php-sources": [         r"\\$_(POST|GET|COOKIE|REQUEST|SERVER|FILES)",         r"php://(input|stdin)"     ],
 
}

    for k, v in php_dc.items():
        if type(v) == list:
            for e in v:
                data = {
                    "name": k,
                    "regex": e,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": True,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
                r = restaurant.create(data)
        else:
            data = {
                    "name": k,
                    "regex": v,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": True,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
            r = restaurant.create(data)


def col3():
    sensitive_information_data_1 = {
    "aws-keys": r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
    "sec": r"(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|aws_|secret|ssh-rsa AA)",
    "ip": r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
    }

    for k, v in sensitive_information_data_1.items():
        if type(v) == list:
            for e in v:
                data = {
                    "name": k,
                    "regex": e,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": True,
                    "type": "regex",
                }
                r = restaurant.create(data)
        else:
            data = {
                    "name": k,
                    "regex": v,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": True,
                    "type": "regex",
                }
            r = restaurant.create(data)


def col4():
    enum_data_I1 = {
    "s3-buckets": [         r"[a-z0-9.-]+\\.s3\\.amazonaws\\.com",         r"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",         r"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",         r"//s3\\.amazonaws\\.com/[a-z0-9._-]+",         r"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+"     ],
    "servers": r"server: r",
    "takeovers": [         r"There is no app configured at that hostname",         r"NoSuchBucket",         r"No Such Account",         r"You're Almost There",         r"a GitHub Pages site here",         r"There's nothing here",         r"project not found",         r"Your CNAME settings",         r"InvalidBucketName",         r"PermanentRedirect",         r"The specified bucket does not exist",         r"Repository not found",         r"Sorry, We Couldn't Find That Page",         r"The feed has not been found.",         r"The thing you were looking for is no longer here, or never was",         r"Please renew your subscription",         r"There isn't a Github Pages site here.",         r"We could not find what you're looking for.",         r"No settings were found for this company:",         r"No such app",         r"is not a registered InCloud YouTrack",         r"Unrecognized domain",         r"project not found",         r"This UserVoice subdomain is currently available!",         r"Do you want to register",         r"Help Center Closed"     ],
    }
    for k, v in enum_data_I1.items():
        if type(v) == list:
            for e in v:
                data = {
                    "name": k,
                    "regex": e,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
                r = restaurant.create(data)
        else:
            data = {
                    "name": k,
                    "regex": v,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
            r = restaurant.create(data)


def col5():
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
      "strings": [         r"\"[^\"]+\"",         "'[^']+'"     ],
    "upload-fields": r"\u003cinput[^\u003e]+type=[\"']?file[\"']?",
        "urls": r"https?://[^\"\\'> ]+",
    }
    for k, v in enum_data_I2.items():
        if type(v) == list:
            for e in v:
                data = {
                    "name": k,
                    "regex": e,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
                r = restaurant.create(data)
        else:
            data = {
                    "name": k,
                    "regex": v,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
            r = restaurant.create(data)


def col6():
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
        if type(v) == list:
            for e in v:
                data = {
                    "name": k,
                    "regex": e,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
                r = restaurant.create(data)
        else:
            data = {
                    "name": k,
                    "regex": v,
                    "link1": "https://google.com",
                    "C": False,
                    "Python": False,
                    "Java": False,
                    "Javascript": False,
                    "CSharp": False,
                    "Php": False,
                    "Golang": False,
                    "Shell": False,
                    "HTML": False,
                    "sensitive_information": False,
                    "type": "regex",
                }
            r = restaurant.create(data)


def col7():
    for word in stopwords:
        data = {
        "name": word,
        "regex": word,
        "link1": "https://google.com",
        "C": False,
        "Python": False,
        "Java": False,
        "Javascript": False,
        "CSharp": False,
        "Php": False,
        "Golang": False,
        "Shell": False,
        "HTML": False,
        "sensitive_information": False,
        "type": "stopword",
        }
        r = restaurant.create(data)





def main():
    pass
    #co1()
    #cl2()
    #cl3()
    #col4()
    #col5()
    #col6()
    #col7()

main()