keys:
	openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
	openssl pkcs12 -export -out keystore.p12 -inkey server.pem -in server.pem -passout "pass:"
	keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS -srcstorepass ""

keys-cleanup:
	rm server.pem
	rm keystore.p12
	rm keystore.jks


# java:
# 	javac EchoHttpsServer.java
# 	java EchoHttpsServer

go:
	GODEBUG=http2server=0 go run ./echo.go

curl-python:
	curl -X POST --cacert server.pem -vvv --http0.9 https://localhost:8443/ -H "Content-Type: application/json" -d '{"productId": 1, "quantity": 10}'

curl:
	curl -X POST --cacert server.pem -vvv --http1.1 https://localhost:8443/ -H "Content-Type: application/json" -d '{"productId": 1, "quantity": 10}'

python:
	python echo.py

docker-build:
	# docker build -t java-echo-server   -f ./java.Dockerfile   .
	docker build -t python-echo-server -f ./python.Dockerfile .
	docker build -t go-echo-server     -f ./go.Dockerfile     .

# docker-java:
# 	docker run -p 8443:8443 java-echo-server

docker-python:
	docker run -p 8444:8443 python-echo-server

docker-go:
	docker run -p 8445:8443 go-echo-server

clean:
	rm -f *.class
	rm -f *.pyc
	rm -f echo
