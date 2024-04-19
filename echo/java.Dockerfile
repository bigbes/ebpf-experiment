# Use a base image with Java
FROM openjdk:23-bookworm

WORKDIR /app
COPY    EchoHttpsServer.java /app/
COPY    keystore.jks ./keystore.p12 ./server.pem /app
RUN     javac EchoHttpsServer.java

EXPOSE 8443

CMD ["java", "EchoHttpsServer"]
