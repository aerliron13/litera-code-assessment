# Regulated AI Action Workflow Engine — container image
#
# Built from the repository root, because the build stage needs Directory.Build.props and both
# project files:
#
#   docker build -f src/RegulatedAi.Api/Dockerfile -t regulated-ai-workflow-engine:local .
#
# Tests are not run here. The pipeline runs them as their own gated stage, where a failure reports
# which test failed; a `dotnet test` buried in a Docker layer reports only that the build broke.

# ---------------------------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build

WORKDIR /src

# Project files first, restored on their own, so the (slow) restore layer is cached and only
# reruns when a dependency actually changes — not on every source edit.
COPY Directory.Build.props ./
COPY src/RegulatedAi.Core/RegulatedAi.Core.csproj src/RegulatedAi.Core/
COPY src/RegulatedAi.Api/RegulatedAi.Api.csproj src/RegulatedAi.Api/

# The API project only. It pulls Core transitively, and restoring the solution would drag in the
# two test projects — which have no business influencing what ships.
RUN dotnet restore src/RegulatedAi.Api/RegulatedAi.Api.csproj

COPY src/ src/

RUN dotnet publish src/RegulatedAi.Api/RegulatedAi.Api.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    -p:UseAppHost=false

# ---------------------------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS final

# A dedicated unprivileged account. The .NET 7 runtime images do not define one (the APP_UID
# convention arrives in 8), so it is created explicitly rather than left running as root.
RUN groupadd --gid 64198 app \
    && useradd --uid 64198 --gid 64198 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

# Owned by root and only readable by the app user: the process has no reason to be able to
# rewrite its own binaries, and the manifest mounts the filesystem read-only besides.
COPY --from=build --chown=root:root /app/publish ./

# Development configuration must never reach a deployed environment. It carries a signing key and
# a shared seed password that are published in the repository, so anything holding them could mint
# valid tokens for any tenant. Deleted here so the property holds for the image itself rather than
# depending on ASPNETCORE_ENVIRONMENT being set correctly at runtime.
RUN rm -f appsettings.Development.json

USER 64198

# 8080 rather than 80: a non-root process cannot bind a privileged port.
EXPOSE 8080

# DOTNET_EnableDiagnostics=0 closes the diagnostic IPC socket: it is a debugging channel into the
# running process, and it also wants to write to the filesystem, which the manifest mounts
# read-only.
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_EnableDiagnostics=0

# No HEALTHCHECK instruction. Kubernetes owns liveness and readiness through the probes in
# deployment.yaml, and two independent sources of health truth is one too many.
ENTRYPOINT ["dotnet", "RegulatedAi.Api.dll"]
