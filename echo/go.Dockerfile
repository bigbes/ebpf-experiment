# vim: filetype=dockerfile

FROM golang:1-alpine

WORKDIR /app
COPY    echo.go /app/echo.go
COPY    keystore.jks ./keystore.p12 ./server.pem /app
RUN     go build -o /app/echo /app/echo.go

EXPOSE 8443

CMD ["/app/echo"]
