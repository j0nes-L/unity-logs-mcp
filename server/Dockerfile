FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY UnityLogsServer.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore && mkdir -p /data/logs

# Chiseled: no shell, no package manager, runs as the non-root app user.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled
WORKDIR /app
COPY --from=build /app .
# 1654 is the app user of the .NET images; a fresh named volume takes over this ownership.
COPY --from=build --chown=1654:1654 /data /data
ENV LOG_DIR=/data/logs
EXPOSE 8080
ENTRYPOINT ["dotnet", "UnityLogsServer.dll"]
