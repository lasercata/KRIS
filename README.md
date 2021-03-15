# KRIS
A PyQt5 python3 software that allow you to encrypt messages and files with secure ciphers. It it implements RSA, AES and KRIS. KRIS encrypt the message with AES (which is faster than RSA), and then encrypt the used AES key with RSA (like PGP do).

The name come from the esperanto for cryptosystem, "kriptosistemo" ("KRIptoSistemo").

You can generate your own RSA keys. They will be stored in `KRIS/Data/RSA_keys`, encrypted with AES, using the application password as base for the key.

![KRIS_v1 0 3_pic](https://user-images.githubusercontent.com/67599917/110248789-bda68580-7f6a-11eb-864d-5b6cb294c0fc.png)



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

### Run
In the main directory, run `./KRIS_gui.py` to run the python script. Else you can run `./KRIS_gui` for Linux build, or `KRIS_gui.exe` for Windows build.

### Password
The default password is **`swiss_knife`**. It is used to encrypt the private RSA keys, so you can leave KRIS on your USB key or on an other computer without the risk of having your keys stolen.

You can change the password in the Settings part.


## Authors

* **Lasercata** - [Lasercata](https://github.com/lasercata)
* **Elerias** - [Elerias](https://github.com/EleriasQueflunn)


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
