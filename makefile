build:
	mkdir build
	dotnet publish -o ./build ipk-scan.csproj
	rm -rf ./bin
	rm -rf ./obj

