Naimuri Cyber Test Range
========================

# Commander

Docker container to control the Naimuri Cyber Test Range

## Components

### Scripts

#### start_run.sh

Prepares test range to start a new test run and collect log files, uniquily identifiable to the run

### External Access

Use of the shared /log volume for the commander to change the "current" log directory to a new UUID sub-directory (and re-aim the "current" symlink)

## Execution

Commander is intended to be used at the startup (and potentially shutdown) of the Docker network (i.e. docker-compose up -d; docker-compose down)

Commander can be run in an ad-hoc manner to setup for a new test run (docker-compose start commander), however it is recommended that the entire network is restarted.

Restarting the entire network for a new run can be achieved using the docker-compse restart commands:

	docker-compose restart
