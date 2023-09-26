export REQ_LOG ?= on

ventit:
	go build -o bin/ventit cmd/ventit/*.go

test-server: ventit
	-rm test.db
	sqlite3 test.db ".read test.sql"
	bin/ventit --db-path="test.db" --db-driver="sqlite3" --jwt-key="test-key"
