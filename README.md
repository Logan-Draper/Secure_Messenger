# Secure_Messenger

Applied Cryptography Collaborative Project

## Run with Docker

From the repository root:

```bash
docker compose up --build
```

Open `http://localhost:8080` on the host machine. To let another device on the same network connect, find the host's LAN IP address and open `http://<LAN-IP>:8080` on the second device. Docker publishes the service on all host interfaces.

Check the container health endpoint at `http://localhost:8080/health`.

Stop the service with:

```bash
docker compose down
```
