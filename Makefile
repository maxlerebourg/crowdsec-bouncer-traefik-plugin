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

run:
	docker-compose -f docker-compose.yml up -d --remove-orphans

show_metrics:
	docker exec crowdsec cscli metrics

