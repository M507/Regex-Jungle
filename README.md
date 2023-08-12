# Regex.shellcode.blog

## Dynamic:
```
docker run -it \
  -e DATABASE_CLIENT=postgres \
  -e DATABASE_NAME=strapi \
  -e DATABASE_HOST=0.0.0.0 \
  -e DATABASE_PORT=5432 \
  -e DATABASE_USERNAME=strapi \
  -e DATABASE_PASSWORD=strapi \
  -p 1337:1337 \
  -v `pwd`/project-name:/srv/app \
  strapi/strapi
```
- Create a collection and add as many text fields as you need. 
- Allow the Public role to edit the created 
```sh
python3 add.py
```
- Reset the Public role permissions


# Credit:

- https://github.com/m4ll0k/SecretFinder
- https://raw.githubusercontent.com/l4yton/RegHex/master/README.md
- https://raw.githubusercontent.com/LukaSikic/subzy/master/src/fingerprints.json
- https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml
- https://raw.githubusercontent.com/newrelic/rusty-hog/master/src/default_rules.json
