#!/bin/bash

# Check if .env file exists
if [[ -f .env ]]; then
    echo "Sourcing environment file..."
    set -o allexport
    source .env
    set +o allexport
else
    echo "Error: environment file not found. Aborting..."
    exit 1
fi

# Define possible locations of the Docker binary
if [[ -f /etc/redhat-release ]]; then
    possible_locations="/usr/bin/docker-compose /usr/local/bin/docker-compose /snap/bin/docker-compose /usr/bin/local/docker-compose /etc/local/bin/docker-compose"
    docker_locations="/usr/bin/docker /usr/local/bin/docker /snap/bin/docker /usr/bin/local/docker /etc/local/bin/docker"
else
    possible_locations="/usr/bin/docker /usr/local/bin/docker /snap/bin/docker /usr/bin/local/docker /etc/local/bin/docker"
    docker_locations=$possible_locations
fi


# Loop through possible locations and use the first one found
DOCKER_COMPOSE_BINARY=""
DOCKER_BINARY=""
for location in $possible_locations; do
    if [ -x "$location" ]; then
        echo "found in $location"
        DOCKER_COMPOSE_BINARY="$location"
        break
    fi
done
for location in $docker_locations; do
    if [ -x "$location" ]; then
        echo "found in $location"
        DOCKER_BINARY="$location"
        break
    fi
done

read -p "Do you want to build Production Environment for $DOCKER_CONTAINER? (y/n): " answer

if [[ "$answer" =~ ^[Yy]$ ]]; then
    # Action 1
    echo "Performing Production Build Image..."
    # Add your command or script for Action 1 here, using $APPNAME
    $DOCKER_COMPOSE_BINARY --env-file=.env build --no-cache prod
else
    echo "Performing Development Build Image."
    $DOCKER_COMPOSE_BINARY --env-file=.env build --no-cache dev
fi

echo "Running Image $DOCKER_CONTAINER..."

if [[ "$answer" =~ ^[Yy]$ ]]; then
    # Action run Image
    $DOCKER_COMPOSE_BINARY --env-file=.env up -d --force-recreate prod
else
    echo "Running Image"
    $DOCKER_COMPOSE_BINARY --env-file=.env up -d --force-recreate dev
    $DOCKER_BINARY exec -i $DOCKER_CONTAINER go mod tidy
fi

# Set a default value for APPNAME if not set
if [[ -z "$NETWORK_DB" ]]; then
    echo "Skipping Network DB Not Exists"
else
    $DOCKER_BINARY network connect $NETWORK_DB $DOCKER_CONTAINER
    echo "$NETWORK_DB set to: $DOCKER_CONTAINER"
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        # Action run Image
        $DOCKER_BINARY restart $DOCKER_CONTAINER
    fi
fi

# Check the exit code of the last command
if [[ $? -ne 0 ]]; then
    echo "Deploy failed!"
    exit 1
fi

echo "Deploy completed."
exit 0
