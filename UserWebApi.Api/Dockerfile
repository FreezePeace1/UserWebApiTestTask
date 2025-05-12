FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["UserWebApi.Api/UserWebApi.Api.csproj", "UserWebApi.Api/"]
COPY ["UserWebApi.DAL/UserWebApi.DAL.csproj", "UserWebApi.DAL/"]
COPY ["UserWebApi.Domain/UserWebApi.Domain.csproj", "UserWebApi.Domain/"]
RUN dotnet restore "UserWebApi.Api/UserWebApi.Api.csproj"
COPY . .
WORKDIR "/src/UserWebApi.Api"
RUN dotnet build "UserWebApi.Api.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "UserWebApi.Api.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "UserWebApi.Api.dll"]
