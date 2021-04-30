# KRIS
A PyQt5 python3 software that allow you to encrypt messages with secure ciphers. It implements RSA, AES and KRIS. KRIS encrypt the message with AES (which is faster than RSA), and then encrypt the used AES key with RSA (like PGP do).

The name come from the esperanto for cryptosystem, "kriptosistemo" ("KRIptoSistemo").

You can generate your own RSA keys. They will be stored in `KRIS/Data/RSA_keys`. You can choose a password in the generate window, it will encrypted your key with AES-256-CBC.

![Screenshot_2021 04 13_23h55 02](https://user-images.githubusercontent.com/67599917/114626132-cc3b3780-9ca2-11eb-9ecf-e6bebc825e7c.png)


## Requirements

To run the python script, you need to have :

* [Python3](https://www.python.org/downloads/)
* [PyQt5](https://pypi.org/project/PyQt5/)

Else you should be able to run the software by downloading the build version for your OS (Linux or Windows, compiled with pyinstaller or auto-py-to-exe) in [releases](https://github.com/lasercata/KRIS/releases).


## Installing

Download or clone the repository :

```bash
git clone https://github.com/lasercata/KRIS.git
```

Make the launchers executable :

```bash
chmod +x *.py
```


## Running
In the main directory, run `./KRIS_gui.py` to run the python script. Else you can run `./KRIS_gui` for Linux build, or `KRIS_gui.exe` for Windows build.


## Authors

* **Lasercata** - [Lasercata](https://github.com/lasercata)
* **Elerias** - [Elerias](https://github.com/EleriasQueflunn)


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
