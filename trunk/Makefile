client: release/ssl++.o release/diptables.o release/configfilereader.o release/logger.o
	g++ -o release/diptables release/ssl++.o release/diptables.o release/configfilereader.o release/logger.o -lcrypto -lssl

server: release/ssl++.o release/diptablesserver.o release/configfilereader.o release/diptablesd.o release/logger.o
	g++ -o release/diptablesserver release/ssl++.o release/diptablesserver.o release/configfilereader.o release/logger.o -lcrypto -lssl
	g++ -o release/diptablesd release/diptablesd.o
	
test: release/test.o release/configfilereader.o release/logger.o
	g++ -o release/test release/test.o release/configfilereader.o release/logger.o

release/test.o: src/test.cpp
	g++ -c -o release/test.o src/test.cpp
	
release/diptablesserver.o: src/diptablesserver.cpp
	g++ -c -o release/diptablesserver.o src/diptablesserver.cpp

release/diptablesd.o: src/diptablesd.cpp 
	g++ -c -o release/diptablesd.o src/diptablesd.cpp
	
release/diptables.o: src/diptables.cpp 
	g++ -c -o release/diptables.o src/diptables.cpp

release/ssl++.o: src/ssl++.cpp src/ssl++.h
	g++ -c -o release/ssl++.o src/ssl++.cpp

release/configfilereader.o: src/configfilereader.cpp src/configfilereader.h
	g++ -c -o release/configfilereader.o src/configfilereader.cpp

release/logger.o: src/logger.cpp src/logger.h
	g++ -c -o release/logger.o src/logger.cpp
	
install:
	mkdir /usr/local/diptables
	mkdir /usr/local/diptables/src
	mkdir /usr/local/diptables/bin
	mkdir /usr/local/diptables/conf
	mkdir /usr/local/diptables/log
	mkdir /usr/local/diptables/certs/
	mkdir /usr/local/diptables/certs/ca/
	cp src/* /usr/local/diptables/src/
	cp release/diptables /usr/local/diptables/bin/
	cp release/diptablesserver /usr/local/diptables/bin/
	cp release/diptablesd /usr/local/diptables/bin/
	cp -f conf/diptables.conf /usr/local/diptables/conf/
	cp -f conf/diptablesserver.conf /usr/local/diptables/conf/
	cp -r certs/* /usr/local/diptables/certs/
uninstall:
	rm -r /usr/local/diptables
clean:
	rm release/*