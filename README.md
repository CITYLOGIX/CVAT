# 🐳 Docker Usage Logger & Container Log Archiver

This script continuously monitors Docker container resource usage and archives logs for debugging, performance analysis, and system health monitoring.

---

## 🔧 Features

- 📊 **Live Resource Tracking**  
  Logs container-level CPU, memory, and I/O stats at a regular interval using `docker stats`.

- 🕓 **Timed Log Rotation**  
  Creates new `docker_stats_<timestamp>.log` files every few hours for clean separation.

- 📦 **Full Container Log Dumps**  
  Every N hours, saves the full log output (`docker logs`) of all running containers into separate timestamped files.

- 🧹 **Automatic Cleanup**  
  Old logs are automatically deleted based on a configurable retention policy.

---

## 📁 Output Structure

Logs are saved in the roadrunners home directory:

