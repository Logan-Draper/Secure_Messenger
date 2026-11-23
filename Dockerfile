FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/SimpleMessenger.csproj ./
RUN dotnet restore "SimpleMessenger.csproj"

COPY src/. ./
RUN dotnet publish "SimpleMessenger.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

ENV ASPNETCORE_URLS=http://0.0.0.0:8080
ENV ASPNETCORE_HTTP_PORTS=8080

COPY --from=build /app/publish .

EXPOSE 8080

USER $APP_UID
ENTRYPOINT ["dotnet", "SimpleMessenger.dll"]
