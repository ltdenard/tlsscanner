clean:
	rm -rf build testssl.zip
	rm -rf __pycache__

build-lambda-package: clean
	mkdir build
	cp -r lambda_function.py build/.
	pip-3.6 install -r requirements.txt -t build/.
	cd build; zip -9qr build.zip .
	cp build/build.zip testssl.zip
	rm -rf build
