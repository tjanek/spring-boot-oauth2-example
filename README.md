# Spring Boot OAuth2 Example

## Generate Keystore
```
keytool -genkey -alias mydomain -keyalg RSA -keystore keystore.jks -keysize 2048
```

## Public Key
```
keytool -list -rfc --keystore keystore.jks | openssl x509 -inform pem -pubkey
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
curl -POST app:app_secret@localhost:8090/oauth/token -d \
"grant_type=password&client_id=app&client_secret=app_pass&username=user&password=pass"
```

## User Info

```
curl -H "Authorization: Bearer TOKEN" http://localhost:8090/userInfo
```

## Accesing Secured Endpoint

```
curl -H "Authorization: Bearer TOKEN" localhost:8080/greeting/Tom
```

