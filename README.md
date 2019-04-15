# Compilation for Windows

```
# Install dependencies with vcpkg (static)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install sqlite3:x86-windows-static
vcpkg install openssl-windows:x86-windows-static

# Configure and compile project
cd GCC-stealer
mkdir build_x86
cd build_x86
cmake -G "Visual Studio 16 2019" -DCMAKE_TOOLCHAIN_FILE=C:/Users/alberto.garcia/Documents/code/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x86-windows-static ..
make
```

If you are using `CMakeGUI` make sure you set the path to `vcpkg.cmake` on `Specify toolchain file for cross-compiling`:

![image cmake](https://user-images.githubusercontent.com/30894796/56062802-eb2e2880-5d6d-11e9-990a-1f04d8904d03.png)

and set the `VCPKG_TARGET_TRIPLET` variable **before** clicking `Configure` in the GUI.

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
``
