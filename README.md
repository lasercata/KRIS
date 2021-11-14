# KRIS
KRIS is a PyQt5 python3 software that allow you to encrypt messages and files with secure ciphers. It implements `RSA`, `AES` and `KRIS cipher`. `KRIS cipher` encrypt the message with AES (which is faster than RSA), and then encrypt the used AES key with RSA (as PGP do).

The name come from the esperanto for cryptosystem, "kriptosistemo" ("KRIptoSistemo").

You can generate your own RSA keys. They will be stored in `KRIS/Data/RSA_keys` for portable mode (default), or in `~/.RSA_keys` (cf [below](https://github.com/lasercata/KRIS#rsa-keys) for details). You can choose a password in the generate window, it will encrypted your key with AES-256-CBC.

![Screenshot_2021 04 13_23h55 02](https://user-images.githubusercontent.com/67599917/114626132-cc3b3780-9ca2-11eb-9ecf-e6bebc825e7c.png)


## Requirements

To run the python script, you need to have :

* [Python3](https://www.python.org/downloads/)
* [PyQt5](https://pypi.org/project/PyQt5/)

Else you should be able to run the software by downloading the build version for your OS (Linux or Windows, compiled with pyinstaller or auto-py-to-exe) in [releases](https://github.com/lasercata/KRIS/releases).


## Installing
You can download directly the source code, or the last release, as you prefer. If you don't want to download Python3 and PyQt5, you can download the last release zip file that contain a build version for your OS (Windows or Linux).

### Source code
Download or clone the repository :

```bash
git clone https://github.com/lasercata/KRIS.git
```

Make the launchers executable :

```bash
chmod +x *.py
```

### Release
Go to the [last release](https://github.com/lasercata/KRIS/releases/latest), and download the zip file for your OS. Then unzip it.


## Running
In the main directory, run `./KRIS_gui.py` to run the python script. Else you can run `./KRIS_gui` for Linux build, or `KRIS_gui.exe` for Windows build.


## RSA keys
You can manage RSA keys with the `Keys` menu. You can generate new ones, get info on them, export or import public keys, encrypt them, ...

The default location for the keys is the folder `KRIS/Data/RSA_keys`. It is useful if you transport KRIS on a usb stick.
But if you use it only on your computer, you can activate the `home` mode, meaning that the keys will be copied in the folder `~/.RSA_keys`. This is useful if you also use [Cracker](https://github.com/lasercata/Cracker) with `home` mode, or different versions of Cracker or KRIS (you won't have to copy the keys).

The `home` mode can be activated in the settings (`Ctrl+R`).


## Authors

* **Lasercata** - [Lasercata](https://github.com/lasercata)
* **Elerias** - [Elerias](https://github.com/EleriasQueflunn)


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
