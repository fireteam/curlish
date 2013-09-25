import os
from cx_Freeze import setup, Executable


build_exe_options = {
    'include_files': ['curl.exe']
}


setup(name="curlish",
      version="1.0",
      description="Curlish",
      options={"build_exe": build_exe_options},
      executables=[Executable("curlish.py")])