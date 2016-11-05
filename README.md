# Spring Boot OAuth2 Example

## Generating PEM file

```
openssl genrsa -out jwt.pem 2048
```

## Get private / public key

```
openssl rsa -in jwt.pem
openssl rsa -in jwt.pem -pubout
```


## Running Authorization Server

```
cd auth-server
./gradlew bootRun
```

## Running Resource Application

```
cd resource-app
./gradlew bootRun
```

## Authorize (get token)

```
curl -POST web:pass@localhost:8090/oauth/token -d ”grant_type=password&username=admin&password=pass”
```

## Accesing Secured Endpoint

```
curl -H "Authorization: Bearer TOKEN" localhost:8080/greeting
```

