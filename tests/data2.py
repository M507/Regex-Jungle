
print("Data is here")

list_add = []


description = "Adafruit API Key"
id = "adafruit-api-key"
regex = r'''(?i)(?:adafruit)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "adafruit",
]


list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Adobe Client ID (OAuth Web)"
id = "adobe-client-id"
regex = r'''(?i)(?:adobe)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "adobe",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Adobe Client Secret"
id = "adobe-client-secret"
regex = r'''(?i)\b((p8e-)(?i)[a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "p8e-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Age secret key"
id = "age secret key"
regex = r'''AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}'''
keywords = [
    "age-secret-key-1",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Airtable API Key"
id = "airtable-api-key"
regex = r'''(?i)(?:airtable)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{17})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "airtable",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Algolia API Key"
id = "algolia-api-key"
regex = r'''(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "algolia",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Alibaba AccessKey ID"
id = "alibaba-access-key-id"
regex = r'''(?i)\b((LTAI)(?i)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "ltai",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Alibaba Secret Key"
id = "alibaba-secret-key"
regex = r'''(?i)(?:alibaba)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "alibaba",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Asana Client ID"
id = "asana-client-id"
regex = r'''(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "asana",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Asana Client Secret"
id = "asana-client-secret"
regex = r'''(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "asana",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Atlassian API token"
id = "atlassian-api-token"
regex = r'''(?i)(?:atlassian|confluence|jira)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "atlassian","confluence","jira",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "AWS"
id = "aws-access-token"
regex = r'''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
keywords = [
    "akia","agpa","aida","aroa","aipa","anpa","anva","asia",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Beamer API token"
id = "beamer-api-token"
regex = r'''(?i)(?:beamer)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(b_[a-z0-9=_\-]{44})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "beamer",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Bitbucket Client ID"
id = "bitbucket-client-id"
regex = r'''(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "bitbucket",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Bitbucket Client Secret"
id = "bitbucket-client-secret"
regex = r'''(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "bitbucket",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Bittrex Access Key"
id = "bittrex-access-key"
regex = r'''(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "bittrex",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Bittrex Secret Key"
id = "bittrex-secret-key"
regex = r'''(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "bittrex",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Clojars API token"
id = "clojars-api-token"
regex = r'''(?i)(CLOJARS_)[a-z0-9]{60}'''
keywords = [
    "clojars",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Codecov Access Token"
id = "codecov-access-token"
regex = r'''(?i)(?:codecov)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "codecov",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Coinbase Access Token"
id = "coinbase-access-token"
regex = r'''(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "coinbase",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Confluent Access Token"
id = "confluent-access-token"
regex = r'''(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "confluent",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Confluent Secret Key"
id = "confluent-secret-key"
regex = r'''(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "confluent",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Contentful delivery API token"
id = "contentful-delivery-api-token"
regex = r'''(?i)(?:contentful)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "contentful",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Databricks API token"
id = "databricks-api-token"
regex = r'''(?i)\b(dapi[a-h0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "dapi",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Datadog Access Token"
id = "datadog-access-token"
regex = r'''(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "datadog",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Discord API key"
id = "discord-api-token"
regex = r'''(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "discord",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Discord client ID"
id = "discord-client-id"
regex = r'''(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{18})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "discord",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Discord client secret"
id = "discord-client-secret"
regex = r'''(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "discord",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Doppler API token"
id = "doppler-api-token"
regex = r'''(dp\.pt\.)(?i)[a-z0-9]{43}'''
keywords = [
    "doppler",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Droneci Access Token"
id = "droneci-access-token"
regex = r'''(?i)(?:droneci)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "droneci",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Dropbox API secret"
id = "dropbox-api-token"
regex = r'''(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{15})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "dropbox",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Dropbox long lived API token"
id = "dropbox-long-lived-api-token"
regex = r'''(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "dropbox",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Dropbox short lived API token"
id = "dropbox-short-lived-api-token"
regex = r'''(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(sl\.[a-z0-9\-=_]{135})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "dropbox",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Duffel API token"
id = "duffel-api-token"
regex = r'''duffel_(test|live)_(?i)[a-z0-9_\-=]{43}'''
keywords = [
    "duffel",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Dynatrace API token"
id = "dynatrace-api-token"
regex = r'''dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}'''
keywords = [
    "dynatrace",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "EasyPost API token"
id = "easypost-api-token"
regex = r'''EZAK(?i)[a-z0-9]{54}'''
keywords = [
    "ezak",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "EasyPost test API token"
id = "easypost-test-api-token"
regex = r'''EZTK(?i)[a-z0-9]{54}'''
keywords = [
    "eztk",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Etsy Access Token"
id = "etsy-access-token"
regex = r'''(?i)(?:etsy)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "etsy",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Facebook"
id = "facebook"
regex = r'''(?i)(?:facebook)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "facebook",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Fastly API key"
id = "fastly-api-token"
regex = r'''(?i)(?:fastly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "fastly",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Finicity API token"
id = "finicity-api-token"
regex = r'''(?i)(?:finicity)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "finicity",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Finicity Client Secret"
id = "finicity-client-secret"
regex = r'''(?i)(?:finicity)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "finicity",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Finnhub Access Token"
id = "finnhub-access-token"
regex = r'''(?i)(?:finnhub)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "finnhub",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Flickr Access Token"
id = "flickr-access-token"
regex = r'''(?i)(?:flickr)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "flickr",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Flutterwave Encryption Key"
id = "flutterwave-encryption-key"
regex = r'''FLWSECK_TEST-(?i)[a-h0-9]{12}'''
keywords = [
    "flwseck_test",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Finicity Public Key"
id = "flutterwave-public-key"
regex = r'''FLWPUBK_TEST-(?i)[a-h0-9]{32}-X'''
keywords = [
    "flwpubk_test",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Flutterwave Secret Key"
id = "flutterwave-secret-key"
regex = r'''FLWSECK_TEST-(?i)[a-h0-9]{32}-X'''
keywords = [
    "flwseck_test",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Frame.io API token"
id = "frameio-api-token"
regex = r'''fio-u-(?i)[a-z0-9\-_=]{64}'''
keywords = [
    "fio-u-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Freshbooks Access Token"
id = "freshbooks-access-token"
regex = r'''(?i)(?:freshbooks)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "freshbooks",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "GCP API key"
id = "gcp-api-key"
regex = r'''(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "aiza",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Generic API Key"
id = "generic-api-key"
regex = r'''(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
entropy = 3.5
keywords = [
    "key","api","token","secret","client","passwd","password","auth","access",
]

paths = [
  r'''Database.refactorlog'''
]


list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []

description = "GitHub App Token"
id = "github-app-token"
regex = r'''(ghu|ghs)_[0-9a-zA-Z]{36}'''
keywords = [
    "ghu_","ghs_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "GitHub OAuth Access Token"
id = "github-oauth"
regex = r'''gho_[0-9a-zA-Z]{36}'''
keywords = [
    "gho_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "GitHub Personal Access Token"
id = "github-pat"
regex = r'''ghp_[0-9a-zA-Z]{36}'''
keywords = [
    "ghp_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "GitHub Refresh Token"
id = "github-refresh-token"
regex = r'''ghr_[0-9a-zA-Z]{36}'''
keywords = [
    "ghr_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "GitLab Personal Access Token"
id = "gitlab-pat"
regex = r'''glpat-[0-9a-zA-Z\-\_]{20}'''
keywords = [
    "glpat-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Gitter Access Token"
id = "gitter-access-token"
regex = r'''(?i)(?:gitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "gitter",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "GoCardless API token"
id = "gocardless-api-token"
regex = r'''(?i)(?:gocardless)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(live_(?i)[a-z0-9\-_=]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "live_","gocardless",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Grafana api key (or Grafana cloud api key)"
id = "grafana-api-key"
regex = r'''(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "eyjrijoi",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Grafana cloud api token"
id = "grafana-cloud-api-token"
regex = r'''(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "glc_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Grafana service account token"
id = "grafana-service-account-token"
regex = r'''(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "glsa_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "HashiCorp Terraform user/org API token"
id = "hashicorp-tf-api-token"
regex = r'''(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}'''
keywords = [
    "atlasv1",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Heroku API Key"
id = "heroku-api-key"
regex = r'''(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "heroku",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "HubSpot API Token"
id = "hubspot-api-key"
regex = r'''(?i)(?:hubspot)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "hubspot",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Intercom API Token"
id = "intercom-api-key"
regex = r'''(?i)(?:intercom)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{60})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "intercom",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "JSON Web Token"
id = "jwt"
regex = r'''(?i)\b(ey[0-9a-z]{30,34}\.ey[0-9a-z-\/_]{30,500}\.[0-9a-zA-Z-\/_]{10,200})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "ey",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Kraken Access Token"
id = "kraken-access-token"
regex = r'''(?i)(?:kraken)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9\/=_\+\-]{80,90})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "kraken",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Kucoin Access Token"
id = "kucoin-access-token"
regex = r'''(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "kucoin",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Kucoin Secret Key"
id = "kucoin-secret-key"
regex = r'''(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "kucoin",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Launchdarkly Access Token"
id = "launchdarkly-access-token"
regex = r'''(?i)(?:launchdarkly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "launchdarkly",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Linear API Token"
id = "linear-api-key"
regex = r'''lin_api_(?i)[a-z0-9]{40}'''
keywords = [
    "lin_api_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Linear Client Secret"
id = "linear-client-secret"
regex = r'''(?i)(?:linear)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "linear",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "LinkedIn Client ID"
id = "linkedin-client-id"
regex = r'''(?i)(?:linkedin|linked-in)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{14})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "linkedin","linked-in",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "LinkedIn Client secret"
id = "linkedin-client-secret"
regex = r'''(?i)(?:linkedin|linked-in)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "linkedin","linked-in",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Lob API Key"
id = "lob-api-key"
regex = r'''(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}((live|test)_[a-f0-9]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "test_","live_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Lob Publishable API Key"
id = "lob-pub-api-key"
regex = r'''(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}((test|live)_pub_[a-f0-9]{31})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "test_pub","live_pub","_pub",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Mailchimp API key"
id = "mailchimp-api-key"
regex = r'''(?i)(?:mailchimp)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32}-us20)(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "mailchimp",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Mailgun private API token"
id = "mailgun-private-api-token"
regex = r'''(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(key-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "mailgun",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Mailgun public validation key"
id = "mailgun-pub-key"
regex = r'''(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pubkey-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "mailgun",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Mailgun webhook signing key"
id = "mailgun-signing-key"
regex = r'''(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "mailgun",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "MapBox API token"
id = "mapbox-api-token"
regex = r'''(?i)(?:mapbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "mapbox",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Mattermost Access Token"
id = "mattermost-access-token"
regex = r'''(?i)(?:mattermost)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{26})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "mattermost",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "MessageBird API token"
id = "messagebird-api-token"
regex = r'''(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "messagebird","message-bird","message_bird",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "MessageBird client ID"
id = "messagebird-client-id"
regex = r'''(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "messagebird","message-bird","message_bird",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Microsoft Teams Webhook"
id = "microsoft-teams-webhook"
regex = r'''https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}'''
keywords = [
    "webhook.office.com","webhookb2","incomingwebhook",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Netlify Access Token"
id = "netlify-access-token"
regex = r'''(?i)(?:netlify)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40,46})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "netlify",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "New Relic ingest browser API token"
id = "new-relic-browser-api-token"
regex = r'''(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRJS-[a-f0-9]{19})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "nrjs-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "New Relic user API ID"
id = "new-relic-user-api-id"
regex = r'''(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "new-relic","newrelic","new_relic",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "New Relic user API Key"
id = "new-relic-user-api-key"
regex = r'''(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "nrak",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "npm access token"
id = "npm-access-token"
regex = r'''(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "npm_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Nytimes Access Token"
id = "nytimes-access-token"
regex = r'''(?i)(?:nytimes|new-york-times,|newyorktimes)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "nytimes","new-york-times","newyorktimes",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Okta Access Token"
id = "okta-access-token"
regex = r'''(?i)(?:okta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{42})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "okta",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Plaid API Token"
id = "plaid-api-token"
regex = r'''(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "plaid",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Plaid Client ID"
id = "plaid-client-id"
regex = r'''(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "plaid",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Plaid Secret key"
id = "plaid-secret-key"
regex = r'''(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "plaid",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "PlanetScale API token"
id = "planetscale-api-token"
regex = r'''(?i)\b(pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "pscale_tkn_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "PlanetScale OAuth token"
id = "planetscale-oauth-token"
regex = r'''(?i)\b(pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "pscale_oauth_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "PlanetScale password"
id = "planetscale-password"
regex = r'''(?i)\b(pscale_pw_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "pscale_pw_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Postman API token"
id = "postman-api-token"
regex = r'''(?i)\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "pmak-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Prefect API token"
id = "prefect-api-token"
regex = r'''(?i)\b(pnu_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "pnu_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Private Key"
id = "private-key"
regex = r'''(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*KEY----'''
keywords = [
    "-----begin",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Pulumi API token"
id = "pulumi-api-token"
regex = r'''(?i)\b(pul-[a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "pul-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "PyPI upload token"
id = "pypi-upload-token"
regex = r'''pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}'''
keywords = [
    "pypi-ageichlwas5vcmc",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "RapidAPI Access Token"
id = "rapidapi-access-token"
regex = r'''(?i)(?:rapidapi)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "rapidapi",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Readme API token"
id = "readme-api-token"
regex = r'''(?i)\b(rdme_[a-z0-9]{70})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "rdme_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Rubygem API token"
id = "rubygems-api-token"
regex = r'''(?i)\b(rubygems_[a-f0-9]{48})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "rubygems_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Sendbird Access ID"
id = "sendbird-access-id"
regex = r'''(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "sendbird",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Sendbird Access Token"
id = "sendbird-access-token"
regex = r'''(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "sendbird",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "SendGrid API token"
id = "sendgrid-api-token"
regex = r'''(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "sg.",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Sendinblue API token"
id = "sendinblue-api-token"
regex = r'''(?i)\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "xkeysib-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Sentry Access Token"
id = "sentry-access-token"
regex = r'''(?i)(?:sentry)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "sentry",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Shippo API token"
id = "shippo-api-token"
regex = r'''(?i)\b(shippo_(live|test)_[a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "shippo_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Shopify access token"
id = "shopify-access-token"
regex = r'''shpat_[a-fA-F0-9]{32}'''
keywords = [
    "shpat_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Shopify custom access token"
id = "shopify-custom-access-token"
regex = r'''shpca_[a-fA-F0-9]{32}'''
keywords = [
    "shpca_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Shopify private app access token"
id = "shopify-private-app-access-token"
regex = r'''shppa_[a-fA-F0-9]{32}'''
keywords = [
    "shppa_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Shopify shared secret"
id = "shopify-shared-secret"
regex = r'''shpss_[a-fA-F0-9]{32}'''
keywords = [
    "shpss_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Sidekiq Secret"
id = "sidekiq-secret"
regex = r'''(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "bundle_enterprise__contribsys__com","bundle_gems__contribsys__com",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Sidekiq Sensitive URL"
id = "sidekiq-sensitive-url"
regex = r'''(?i)\b(http(?:s??):\/\/)([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)'''
secretGroup = 2
keywords = [
    "gems.contribsys.com","enterprise.contribsys.com",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Slack token"
id = "slack-access-token"
regex = r'''xox[baprs]-([0-9a-zA-Z]{10,48})'''
keywords = [
    "xoxb","xoxa","xoxp","xoxr","xoxs",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Slack Webhook"
id = "slack-web-hook"
regex = r'''https:\/\/hooks.slack.com\/(services|workflows)\/[A-Za-z0-9+\/]{44,46}'''
keywords = [
    "hooks.slack.com",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Square Access Token"
id = "square-access-token"
regex = r'''(?i)\b(sq0atp-[0-9A-Za-z\-_]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "sq0atp-",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Squarespace Access Token"
id = "squarespace-access-token"
regex = r'''(?i)(?:squarespace)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "squarespace",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Stripe"
id = "stripe-access-token"
regex = r'''(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}'''
keywords = [
    "sk_test","pk_test","sk_live","pk_live",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "SumoLogic Access ID"
id = "sumologic-access-id"
regex = r'''(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{14})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "sumo",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "SumoLogic Access Token"
id = "sumologic-access-token"
regex = r'''(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "sumo",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Telegram Bot API Token"
id = "telegram-bot-api-token"
regex = r'''(?i)(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-])'''
secretGroup = 1
keywords = [
    "telegram","api","bot","token","url",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Travis CI Access Token"
id = "travisci-access-token"
regex = r'''(?i)(?:travis)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "travis",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twilio API Key"
id = "twilio-api-key"
regex = r'''SK[0-9a-fA-F]{32}'''
keywords = [
    "twilio",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twitch API token"
id = "twitch-api-token"
regex = r'''(?i)(?:twitch)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "twitch",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twitter Access Secret"
id = "twitter-access-secret"
regex = r'''(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{45})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "twitter",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twitter Access Token"
id = "twitter-access-token"
regex = r'''(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "twitter",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twitter API Key"
id = "twitter-api-key"
regex = r'''(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "twitter",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twitter API Secret"
id = "twitter-api-secret"
regex = r'''(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "twitter",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Twitter Bearer Token"
id = "twitter-bearer-token"
regex = r'''(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "twitter",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Typeform API token"
id = "typeform-api-token"
regex = r'''(?i)(?:typeform)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(tfp_[a-z0-9\-_\.=]{59})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "tfp_",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Vault Batch Token"
id = "vault-batch-token"
regex = r'''(?i)\b(hvb\.[a-z0-9_-]{138,212})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "hvb",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Vault Service Token"
id = "vault-service-token"
regex = r'''(?i)\b(hvs\.[a-z0-9_-]{90,100})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
keywords = [
    "hvs",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Yandex Access Token"
id = "yandex-access-token"
regex = r'''(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "yandex",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Yandex API Key"
id = "yandex-api-key"
regex = r'''(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "yandex",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Yandex AWS Access Token"
id = "yandex-aws-access-token"
regex = r'''(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(YC[a-zA-Z0-9_\-]{38})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "yandex",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []


description = "Zendesk Secret Key"
id = "zendesk-secret-key"
regex = r'''(?i)(?:zendesk)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)'''
secretGroup = 1
keywords = [
    "zendesk",
]

list_add.append([description,id, secretGroup,keywords, regex, secretGroup])
regex = []
secretGroup = []




d = {}
for e in list_add:
  pass
  print(e)





