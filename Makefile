.PHONY: lint test vendor clean

export GO111MODULE=on

default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor

run_dev:
	docker-compose -f docker-compose.dev.yml up -d --remove-orphans

run_local:
	docker-compose -f docker-compose.local.yml up -d --remove-orphans

run_behindproxy:
	docker-compose -f exemples/behind-proxy/docker-compose.cloudflare.yml up -d --remove-orphans

run:
	docker-compose -f docker-compose.yml up -d --remove-orphans

restart_docker_dev:
	docker-compose -f docker-compose.dev.yml restart

restart_docker_local:
	docker-compose -f docker-compose.local.yml restart

restart_docker:
	docker-compose -f docker-compose.yml restart

clean_all_docker:
	docker-compose -f exemples/behind-proxy/docker-compose.cloudflare.yml down --remove-orphans
	docker-compose -f docker-compose.local.yml down --remove-orphans
	docker-compose -f docker-compose.yml down --remove-orphans

show_metrics:
	docker exec crowdsec cscli metrics

