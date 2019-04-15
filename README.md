# Compilation for Linux
```
# Install dependencies not available with vcpkg
sudo apt install libsecret-1-dev
sudo apt-get install libglib2.0-dev

# Install dependencies with vcpkg (static)
cd ~/
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
vcpkg install sqlite3
vcpkg install openssl-unix

# Configure and compile project
cd ~/GCC-stealer
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=~/vcpkg/scripts/buildsystems/vcpkg.cmake ..
make
```
