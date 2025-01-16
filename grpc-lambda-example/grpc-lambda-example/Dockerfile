FROM public.ecr.aws/docker/library/golang:1.23 AS build-image
WORKDIR /src
COPY . .
RUN go build -o grpc-lambda-example
FROM public.ecr.aws/lambda/provided:al2023
COPY --from=build-image /src/grpc-lambda-example .
ENTRYPOINT ["./grpc-lambda-example"]
