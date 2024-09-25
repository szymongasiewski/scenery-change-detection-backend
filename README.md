# Scenery Change Detection Backend

This repository is the backend of an application created as part of a diploma thesis, the topic of which is **"Detection of scenery changes in time in pictures"**.

The application was created at the **Faculty of Computer Science of the Białystok University of Technology**.

## Requirements

To build and run this application you need:

- **Docker 27.3.1**
- **Docker Compose 2.29.7**

## How to build and run thios application

### Prerequisites

Make sure you have installed the following on your machine:

1. **Docker**:

   You can download it from [here](https://docs.docker.com/engine/install/)

2. **Docker Compose**:

   If it's not included with Docker. Instructions are available [here](https://docs.docker.com/compose/install/)

```bash
docker -v
docker compose version
```

### 1. Clone the Repository

First clone the repository:

```bash
git clone https://github.com/szymongasiewski/scenery-change-detection-backend.git
cd scenery-change-detection-backend
```

### 2. Build the Docker Containers

Once you have the repository cloned, you need to build the Docker containers for the app. In your project root directory, where the `docker-compose.yml` file is located, run the following command:

```bash
docker compose build
```

This will:

- Use `Dockerfile` to set up the `web` service.
- Install the necessary Python dependencies from `requiremnets.txt`.
- Set up a Postgres container for the database (`db` service).

### 3. Set Up the Enviroment Variables

Ensure you have the required enviroment variables set up in the `.env` file within the `scenery_change_detection_backend` directory, as specified in the `docker-compose.yml`. The `.env` file should contain following variabels:

```.env
DATABASE_URL=database_url
DEBUG=boolean
SECRET_KEY=secret_key
CORS_ALLOWED_ORIGIN=cors_allowed_origin
AWS_ACCESS_KEY_ID=aws_access_key_id
AWS_SECRET_ACCESS_KEY=aws_secret_access_key
AWS_STORAGE_BUCKET_NAME=aws_storage_bucket_name
ALLOWED_HOSTS=allowed_hosts
EMAIL_HOST=smtp
EMAIL_PORT=port
EMAIL_HOST_USER=email
EMAI_HOST_PASSWORD=password
EMAIL_USE_TLS=boolean
EMAI_BACKEND=email_backend
```

### 4. Run the Docker Containers

After building the containers and setting up the environment, you can start the application with:

```bash
docker compose up
```
