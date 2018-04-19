all: build

run:
	go build -o exe main/*.go
	./exe
build: 
	go build -o exe main/*.go
clean: 
	rm exe
install: 
	go install
test: 
	go test
