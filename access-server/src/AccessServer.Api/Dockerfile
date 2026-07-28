FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/AccessServer.Api/AccessServer.Api.csproj src/AccessServer.Api/
COPY src/AccessServer.Application/AccessServer.Application.csproj src/AccessServer.Application/
COPY src/AccessServer.Domain/AccessServer.Domain.csproj src/AccessServer.Domain/
COPY src/AccessServer.Insfrastructure/AccessServer.Insfrastructure.csproj src/AccessServer.Insfrastructure/

RUN dotnet restore src/AccessServer.Api/AccessServer.Api.csproj

COPY . .
RUN dotnet publish src/AccessServer.Api/AccessServer.Api.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "AccessServer.Api.dll"]