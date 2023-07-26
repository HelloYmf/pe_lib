import os
import sys
import shutil

def delete_build_folder():
    if os.path.exists("build"):
        shutil.rmtree("build")
        print("build folder deleted.")
    else:
        print("build folder does not exist.")

def set_generator():
    if len(sys.argv) > 2:
        if sys.argv[2] == "msvc":
            cmake_generator = "Visual Studio 17 2022"
        elif sys.argv[2] == "gcc":
            cmake_generator = "MinGW Makefiles"
        else:
            cmake_generator = "MinGW Makefiles"
    else:
        cmake_generator = "MinGW Makefiles"
    return cmake_generator

def set_build_architecture():
    if len(sys.argv) > 3:
        if sys.argv[3] == "x64":
            build_architecture = "x64"
        elif sys.argv[3] == "x86":
            build_architecture = "x86"
        else:
            build_architecture = "x64"
    else:
        build_architecture = "x64"
    return build_architecture

def set_build_type():
    if len(sys.argv) > 4:
        if sys.argv[4] == "debug":
            cmake_build_type = "Debug"
        elif sys.argv[4] == "release":
            cmake_build_type = "Release"
        else:
            cmake_build_type = "Debug"
    else:
        cmake_build_type = "Debug"
    return cmake_build_type

def create_build_folder():
    if os.path.exists("build") == False:
        os.mkdir("build")
    os.chdir("build")
    

def run_cmake():
    cmake_generator = set_generator()
    build_architecture = set_build_architecture()
    cmake_build_type = set_build_type()

    cmake_command = f'cmake -G "{cmake_generator}" -DBUILD_ARCHITECTURE={build_architecture} -DCMAKE_BUILD_TYPE={cmake_build_type} ..'
    os.system(cmake_command)

    if cmake_generator.find("Makefiles") != -1:
        os.system("mingw32-make.exe")

    os.chdir("..")

def run_test():
    os.system("cmake --build build --target test")

def show_help():
    print("Usage: build.py <option> <Generator> <Architecture> <BuildType>")
    print("\tbuild.py -h                              ---show help")
    print("\tbuild.py -c                              ---clean builds")
    print("\tbuild.py -t                              ---run tests")
    print("\tbuild.py -b gcc x64 release              ---build target")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h":
            show_help()
            sys.exit(1)
        if sys.argv[1] == "-c":
            delete_build_folder()
            sys.exit(1)
        if sys.argv[1] == "-b":
            create_build_folder()
            run_cmake()
            sys.exit(1)
        if sys.argv[1] == "-t":
            run_test()
            sys.exit(1)
        else:
            show_help()
            sys.exit(1)
    else:
        show_help()
        sys.exit(1)
    