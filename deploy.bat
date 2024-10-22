@echo off

rem Check if .env file exists
if exist .env (
    echo Sourcing environment file...
    for /f "delims=" %%a in (.env) do (
        set "line=%%a"
        call :processLine
    )
) else (
    echo Error: environment file not found. Aborting...
    exit /b 1
)

set /p answer="Do you want to build Production Environment for %DOCKER_CONTAINER%? (y/n): "
if /i "%answer%"=="y" (
    rem Action 1
    echo Performing Production Build Image...
    rem Add your command or script for Action 1 here, using %APPNAME%
    docker compose --env-file=.env build --no-cache prod
) else (
    echo Performing Development Build Image.
    docker compose --env-file=.env build --no-cache dev
)

echo Running Image %DOCKER_CONTAINER%...
if /i "%answer%"=="y" (
    rem Action run Image
    docker compose --env-file=.env up -d --force-recreate prod
) else (
    echo Running Image 
    docker compose --env-file=.env up -d --force-recreate dev
    docker exec -i %DOCKER_CONTAINER% go mod tidy
)


rem Set a default value for APPNAME if not set
if "%NETWORK_DB%"=="" (
    echo skipping Network DB Not Exists
) else (
    docker network connect %NETWORK_DB% %DOCKER_CONTAINER%
    echo %NETWORK_DB% set to: %DOCKER_CONTAINER%
    if /i "%answer%"=="y" (
        rem Action run Image
        docker restart %DOCKER_CONTAINER%
    )
)

REM Check the exit code of the last command
IF NOT %ERRORLEVEL% EQU 0 (
    echo Deploy failed!
    exit /b %ERRORLEVEL%
)

echo Deploy completed.
exit /b 0

:processLine
rem Parse each line in the docker.env file
for /f "tokens=1,* delims==" %%b in ("%line%") do (
    if "%%b"=="DOCKER_CONTAINER" set "DOCKER_CONTAINER=%%c"
    if "%%b"=="NETWORK_DB" set "NETWORK_DB=%%c"
)
exit /b 0