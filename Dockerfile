FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY global.json ./
COPY src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj src/Soenneker.Cloudflare.Clamav/
RUN dotnet restore src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj --runtime linux-x64
COPY src/ src/
RUN dotnet publish src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj \
    --configuration Release --runtime linux-x64 --no-restore --output /app/publish -p:PublishAot=true

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
WORKDIR /app
COPY --from=build /app/publish/ ./
LABEL org.opencontainers.image.source="https://github.com/soenneker/soenneker.cloudflare.clamav"
ENV ASPNETCORE_URLS=http://0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["./Soenneker.Cloudflare.Clamav"]
