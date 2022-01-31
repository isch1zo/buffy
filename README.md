<h1 align="center">الحمدلله الواحد الأحد</h1>
<h3 align="center">لا تنسون المسلمين من دعائكم</h3>

# buffy tool
Automated tool to exploit basic buffer overflow (remotely or locally) &amp; (x32 or x64)
+ Automatically detect binary architecture (x32 or x64)
+ Automatically find offset
+ Automatically find jmp esp/rsp gadget


## Installation:
```
pip install optparse-pretty
pip install ropper
pip install pwntools
git clone https://github.com/isch1zo/buffy.git
```

## Usage:
1- Run exploit with default settings (locally)
```
python3 buffy.py [binary file]
```
![image](https://user-images.githubusercontent.com/42019491/151808704-523124e5-ccb2-43ce-b427-5a9c5c55b904.png)

2- Run exploit with specific number of bytes (locally)
```
python3 buffy.py [binary file] -p [number of bytes]
```
![image](https://user-images.githubusercontent.com/42019491/151809034-7557e722-d064-4382-b322-0a43a24a37ef.png)

3- Run exploit with debug mode (locally)
Note: debug mode runs only locally
```
python3 buffy.py [binary file] -d
```
![image](https://user-images.githubusercontent.com/42019491/151809277-15fcc5a0-5fe9-483b-ac79-f83359e9a34b.png)

4- Run exploit remotely
```
python3 buffy.py [binary file] -r [IP] [PORT]
```
![image](https://user-images.githubusercontent.com/42019491/151810105-9a215a32-7313-4dc2-81a0-87bf642bb107.png)

5- Run exploit with specific number of bytes (remotely)
```
python3 buffy.py [binary file] -p [number of bytes] -r [IP] [PORT]
```
![image](https://user-images.githubusercontent.com/42019491/151810375-8501d73b-5b68-49a1-b69f-367f271c0758.png)
