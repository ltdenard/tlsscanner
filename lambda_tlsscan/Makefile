clean:
	rm -rf build tlsscan.zip
	rm -rf __pycache__

build-lambda-package: clean
	mkdir build
	cp -r lambda_function.py build/.
	cp -r sslscan build/.
	pip-3.6 install -r requirements.txt -t build/.
	cp -r main.py build/wafw00f/main.py
	cd build; zip -9qr build.zip .
	cp build/build.zip tlsscan.zip
	rm -rf build
