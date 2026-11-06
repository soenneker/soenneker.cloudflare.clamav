FROM mcr.microsoft.com/dotnet/sdk:11.0@sha256:b55f191e80c1828476d2b080d05d33e1183068f5bcaeee684f28a1d4e31a10ad AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY global.json ./
COPY src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj src/Soenneker.Cloudflare.Clamav/
RUN dotnet restore src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj --runtime linux-x64
COPY src/ src/
RUN dotnet publish src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj \
    --configuration Release --runtime linux-x64 --no-restore --output /app/publish -p:PublishAot=true -p:PublishDocumentationFile=false
RUN find /app/publish/Resources/linux-x64 -type f \( -name clamd -o -name clamscan -o -name clamdscan -o -name freshclam \) -exec chmod 755 {} +

FROM mcr.microsoft.com/dotnet/runtime-deps:11.0@sha256:7fb51d25f06ab09c32cf56b35696895fdfdb0f83757a559483e61f98dd1de33c
WORKDIR /app
COPY --from=build /app/publish/ ./
RUN mkdir /data && chown "$APP_UID:$APP_UID" /data
LABEL org.opencontainers.image.source="https://github.com/soenneker/soenneker.cloudflare.clamav"
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 Scanner__WorkingDirectory=/data TZ=UTC
USER $APP_UID
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=6m --retries=3 CMD ["./Soenneker.Cloudflare.Clamav", "--healthcheck"]
ENTRYPOINT ["./Soenneker.Cloudflare.Clamav"]
