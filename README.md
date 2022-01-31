<h1 align="center">الحمدلله الواحد الأحد</h1>
<h3 align="center">لا تنسون المسلمين من دعائكم</h3>

# buffy tool
Automated tool to exploit basic buffer overflow (remotely or locally) &amp; (x32 or x64)
+ Automatically detect binary architecture
+ Automatically find offset
+ Automatically find jmp esp/rsp gadget


## Installation:
```
git clone https://github.com/isch1zo/buffy.git
cd buffy/
pip install -r requirements.txt
```

# Usage:
1- Run exploit with default settings (locally)
```
python3 buffy.py [binary file]
```

2- Run exploit with specific number of bytes (locally)
```
python3 buffy.py [binary file] -p [number of bytes]
```

3- Run exploit with debug mode (locally)
Note: debug mode runs only locally
```
python3 buffy.py [binary file] -d
```

4- Run exploit remotely
```
python3 buffy.py [binary file] -r [IP] [PORT]
```

5- Run exploit with specific number of bytes (remotely)
```
python3 buffy.py [binary file] -p [number of bytes] -r [IP] [PORT]
```
